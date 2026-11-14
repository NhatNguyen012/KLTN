"""KLTN endpoint agent: durable inbox + Log Processing & Feature Extraction + Detection Service (host ML).

General Architecture, END HOSTS: Fluent Bit forwards every raw record to the central raw store AND to this agent
(/v1/raw/<source>). The agent keeps a bounded SQLite inbox, turns the records of its platform domain into events and
token vectors with the training-time featurizer (kltn_features, vendored from the IL research code), scores each
event with the fused IL LightGBM bundle, and forwards Result + Score + Selected logs to the central Score Receiver:
  * score.v1   per selected event (score >= select threshold, or predicted attack): score, decision at the domain
               threshold, the event, its top feature contributions, references to the raw records;
  * summary.v1 every minute: event/row counts, score histogram, OOV-token statistics (drift + vocabulary extension
               evidence for incremental learning).
Domains: linux-audit (auditd) and windows-sysmon (Sysmon). A bundle serves a domain only if its manifest lists it;
`ready_active` is used only for domains validated offline, otherwise scores are `ready_shadow`.
Before serving, the agent re-runs the bundle fixtures and refuses to serve on any mismatch.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import shutil
import sqlite3
import ssl
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request

SOURCES = {"audit", "journal", "sysmon", "security", "powershell", "smoke"}
DOMAIN_SOURCE = {"linux-audit": "audit", "windows-sysmon": "sysmon"}
MAX_BODY = 4 * 1024 * 1024
READY_STATES = {"ready_shadow", "ready_active"}
AGENT_VERSION = "kltn-endpoint-il3-v1"


class CapacityError(Exception):
    pass


class BundleError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def event_id(host_id, source, raw):
    identity = {k: v for k, v in raw.items() if k != "date"}
    data = json.dumps([host_id, source, identity], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_manifest(root: Path, branch: str = "host_ml") -> dict[str, Any]:
    root = root.resolve()
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise BundleError("manifest_missing_or_invalid") from exc
    if manifest.get("schema_version") != "bundle.v2" or manifest.get("branch") != branch:
        raise BundleError("manifest_schema_or_branch_incompatible")
    if not manifest.get("activation", {}).get("eligible", False):
        raise BundleError("bundle_not_activation_eligible")
    if manifest.get("parity", {}).get("passed") is not True:
        raise BundleError("bundle_parity_not_passed")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > 200:
        raise BundleError("artifact_manifest_invalid")
    for relative, meta in artifacts.items():
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise BundleError("artifact_path_escape") from exc
        if not path.is_file() or path.is_symlink():
            raise BundleError("artifact_missing_or_symlink")
        if path.stat().st_size != meta.get("bytes") or not hmac.compare_digest(sha256_file(path), str(meta.get("sha256"))):
            raise BundleError("artifact_checksum_mismatch")
    return manifest


# ------------------------------------------------------------------------------------------------ inbox
class Inbox:
    def __init__(self, path, host_id, max_rows=200000, max_bytes=512 * 1024 * 1024, min_free_bytes=256 * 1024 * 1024,
                 retention_hours=6.0):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.host_id, self.max_rows, self.max_bytes = host_id, max_rows, max_bytes
        self.min_free_bytes, self.retention_hours = min_free_bytes, retention_hours
        with closing(self.connect()) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""CREATE TABLE IF NOT EXISTS inbox (
              event_id TEXT PRIMARY KEY, source TEXT NOT NULL, raw TEXT NOT NULL, raw_bytes INTEGER NOT NULL,
              received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
              state TEXT NOT NULL DEFAULT 'waiting_for_model');
              CREATE TABLE IF NOT EXISTS identity (host_id TEXT PRIMARY KEY);
              CREATE TABLE IF NOT EXISTS score_outbox (
                score_id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'score', payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                sent_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
              CREATE INDEX IF NOT EXISTS inbox_state ON inbox(state, source);""")
            cols = {row[1] for row in db.execute("PRAGMA table_info(inbox)")}
            for name, decl in (("score_id", "TEXT"), ("error", "TEXT"), ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                               ("updated_at", "TEXT NOT NULL DEFAULT ''")):
                if name not in cols:
                    db.execute(f"ALTER TABLE inbox ADD COLUMN {name} {decl}")
            ocols = {row[1] for row in db.execute("PRAGMA table_info(score_outbox)")}
            if "kind" not in ocols:
                db.execute("ALTER TABLE score_outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'score'")
            identity = db.execute("SELECT host_id FROM identity").fetchone()
            if identity and identity[0] != host_id:
                raise ValueError("Inbox belongs to a different host; use a separate state directory")
            db.execute("INSERT OR IGNORE INTO identity VALUES (?)", (host_id,))

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def put(self, source, records):
        encoded = [(event_id(self.host_id, source, r), json.dumps(r, ensure_ascii=False, allow_nan=False)) for r in records]
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            rows, size = db.execute("SELECT count(*), coalesce(sum(raw_bytes),0) FROM inbox").fetchone()
            inserted = 0
            for identity, raw in encoded:
                length = len(raw.encode())
                if (rows + 1 > self.max_rows or size + length > self.max_bytes or
                        shutil.disk_usage(self.path.parent).free < self.min_free_bytes):
                    raise CapacityError("inbox capacity reached; the central raw archive continues independently")
                cur = db.execute("INSERT OR IGNORE INTO inbox(event_id,source,raw,raw_bytes) VALUES (?,?,?,?)",
                                 (identity, source, raw, length))
                if cur.rowcount:
                    inserted += 1
                    rows += 1
                    size += length
            return inserted

    def waiting(self, source: str, limit: int = 500):
        """Unprocessed rows of one source in arrival order (rowid preserves the order inside a Fluent Bit batch)."""
        with closing(self.connect()) as db:
            rows = db.execute("""SELECT rowid,event_id,raw FROM inbox WHERE source=? AND state IN ('waiting_for_model','retry')
              ORDER BY rowid LIMIT ?""", (source, limit)).fetchall()
        return [(r[0], r[1], json.loads(r[2])) for r in rows]

    def recent_processed(self, source: str, minutes: float, limit: int = 200000):
        """Rows already processed in the last minutes (featurizer warm-up after a restart, no scoring)."""
        with closing(self.connect()) as db:
            rows = db.execute("""SELECT event_id,raw FROM inbox WHERE source=? AND state='processed'
              AND received_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) ORDER BY rowid LIMIT ?""",
                              (source, f"-{float(minutes)} minutes", limit)).fetchall()
        return [(r[0], json.loads(r[1])) for r in rows]

    def mark(self, rowids, state: str, error: str | None = None):
        if not rowids:
            return
        with closing(self.connect()) as db, db:
            db.executemany("""UPDATE inbox SET state=?,error=?,attempts=attempts+(CASE WHEN ? IS NULL THEN 0 ELSE 1 END),
              updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE rowid=?""",
                           [(state, error, error, r) for r in rowids])

    def mark_source_ignored(self, supported: set[str]):
        """Sources this host collects but does not score (journal, security, powershell, ...): keep, mark ignored."""
        with closing(self.connect()) as db, db:
            q = ",".join("?" for _ in supported) or "''"
            db.execute(f"""UPDATE inbox SET state='not_scored_source',updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
              WHERE state='waiting_for_model' AND source NOT IN ({q})""", tuple(supported))

    def enqueue(self, kind: str, payload: dict):
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        with closing(self.connect()) as db, db:
            db.execute("INSERT OR IGNORE INTO score_outbox(score_id,kind,payload) VALUES (?,?,?)",
                       (payload.get("score_id") or payload.get("summary_id"), kind, data))

    def outbox_batch(self, kind: str, limit=200):
        with closing(self.connect()) as db:
            return db.execute("""SELECT score_id,payload FROM score_outbox WHERE kind=? AND sent_at IS NULL
              AND next_attempt_at<=strftime('%Y-%m-%dT%H:%M:%fZ','now') ORDER BY created_at LIMIT ?""",
                              (kind, limit)).fetchall()

    def outbox_done(self, ids, ok: bool):
        if not ids:
            return
        with closing(self.connect()) as db, db:
            if ok:
                db.executemany("UPDATE score_outbox SET sent_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE score_id=?",
                               ((i,) for i in ids))
            else:
                db.executemany("""UPDATE score_outbox SET attempts=attempts+1,
                  next_attempt_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+30 seconds') WHERE score_id=?""", ((i,) for i in ids))

    def prune(self) -> dict:
        """Retention: processed/ignored rows older than retention_hours, delivered outbox rows older than 1 day."""
        with closing(self.connect()) as db, db:
            a = db.execute("""DELETE FROM inbox WHERE state IN ('processed','not_scored_source','error')
              AND received_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?)""", (f"-{self.retention_hours} hours",)).rowcount
            b = db.execute("""DELETE FROM score_outbox WHERE sent_at IS NOT NULL
              AND sent_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 day')""").rowcount
        return {"inbox_deleted": a, "outbox_deleted": b}

    def status(self):
        with closing(self.connect()) as db:
            rows = db.execute("SELECT source,count(*),max(received_at) FROM inbox GROUP BY source").fetchall()
            count, size = db.execute("SELECT count(*),coalesce(sum(raw_bytes),0) FROM inbox").fetchone()
            states = db.execute("SELECT state,count(*) FROM inbox GROUP BY state").fetchall()
            outbox = db.execute("SELECT kind,count(*) FROM score_outbox WHERE sent_at IS NULL GROUP BY kind").fetchall()
        return {"host_id": self.host_id, "inbox_rows": count, "raw_bytes": size, "max_rows": self.max_rows,
                "max_raw_bytes": self.max_bytes, "capacity_reached": count >= self.max_rows or size >= self.max_bytes,
                "pending_delivery": {k: n for k, n in outbox}, "states": {s: n for s, n in states},
                "sources": [{"source": s, "count": n, "last_received": t} for s, n, t in rows]}


# ------------------------------------------------------------------------------------------------ model
class HostModel:
    def __init__(self, root: Path, domain: str):
        self.root = root
        self.manifest = verify_manifest(root)
        dom = self.manifest.get("domains", {}).get(domain)
        if domain not in DOMAIN_SOURCE or dom is None:
            raise BundleError("unsupported_domain")
        here = Path(__file__).resolve().parent
        for rel, expected in self.manifest.get("runtime_code_sha256", {}).items():
            deployed = here / rel
            if not deployed.is_file() or not hmac.compare_digest(sha256_file(deployed), expected):
                raise BundleError("featurizer_runtime_hash_mismatch")
        import lightgbm
        import numpy as np
        self.np = np
        self.vocab = json.loads((root / "preprocess/vocab.json").read_text(encoding="utf-8"))
        self.inv = {c: t for t, c in self.vocab.items()}
        self.booster = lightgbm.Booster(model_file=str(root / self.manifest["model"]["path"]))
        if not self.booster.num_feature() == len(self.vocab) == self.manifest["feature_contract"]["width"]:
            raise BundleError("model_vocabulary_width_mismatch")
        self.domain = domain
        self.source = DOMAIN_SOURCE[domain]
        self.validation = dom["validation"]
        self.threshold = float(dom["threshold"])
        self.select_threshold = float(self.manifest["policy"].get("select_threshold", 0.5))
        if not (0 <= self.threshold <= 1 and 0 <= self.select_threshold <= 1):
            raise BundleError("threshold_invalid")
        self.bundle_id = self.manifest["bundle_id"]
        self.self_test = self._self_test()

    def featurizer(self, host: str):
        from kltn_features.host_ml import HostFeaturizer
        return HostFeaturizer(self.domain, self.vocab, host)

    def _self_test(self) -> dict:
        """Re-run the bundle fixture of this platform family; any difference blocks serving."""
        from kltn_features._vendor.common_schema import CanonicalEvent
        from kltn_features.host_ml import HostFeaturizer
        name = "fixture_linux_audit.json" if self.domain == "linux-audit" else "fixture_windows_cbc.json"
        fx = json.loads((self.root / "evidence" / name).read_text())
        fz = HostFeaturizer(fx["domain"], self.vocab, fx.get("host", "fixture"))
        rows = []
        if fx["domain"] == "linux-audit":
            for i, line in enumerate(fx["inputs"]):
                rows += fz.feed(line, ref=i)
            rows += fz.flush()
        else:
            rows = [r for r in (fz.feed_canonical(CanonicalEvent(**d)) for d in fx["inputs"]) if r is not None]
        if len(rows) != len(fx["expected"]):
            raise BundleError("self_test_row_count_mismatch")
        X = fz.matrix(rows)
        z = self.booster.predict(X, raw_score=True, num_threads=1)
        worst = 0.0
        for k, exp in enumerate(fx["expected"]):
            if X[k].indices.tolist() != exp["columns"]:
                raise BundleError("self_test_feature_mismatch")
            worst = max(worst, abs(float(z[k]) - exp["raw_score"]))
        if worst > 1e-6:
            raise BundleError("self_test_score_mismatch")
        return {"fixture": name, "rows": len(rows), "max_abs_dz": worst, "passed": True, "at": now_iso()}

    def score(self, X):
        z = self.booster.predict(X, raw_score=True, num_threads=1)
        return 1.0 / (1.0 + self.np.exp(-z))

    def contributions(self, X, k: int = 8) -> list[list]:
        contrib = self.booster.predict(X, pred_contrib=True, num_threads=1)
        if hasattr(contrib, "toarray"):          # sparse input -> sparse contributions (LightGBM >= 3)
            contrib = contrib.toarray()
        out = []
        for i in range(X.shape[0]):
            row = contrib[i, :-1]
            present = X[i].indices
            top = sorted(((float(row[c]), self.inv.get(int(c), str(c))) for c in present), reverse=True)[:k]
            out.append([[t, round(v, 4)] for v, t in top])
        return out


def iso_us(ts_us: int) -> str:
    return datetime.fromtimestamp(ts_us / 1e6, timezone.utc).isoformat()


def build_score(host_id: str, model: HostModel, mode: str, row, p: float, top) -> dict[str, Any]:
    refs = sorted(set(map(str, row.refs)))[:512] or [canonical_hash([host_id, row.ts, row.kind])]
    status = "ready_active" if (mode == "ready_active" and model.validation == "validated") else "ready_shadow"
    payload = {
        "schema_version": "score.v1", "host_id": host_id, "branch": "host_ml", "bundle_id": model.bundle_id,
        "event_refs": refs, "window": None, "status": status, "score": float(p), "threshold": model.threshold,
        "prediction": int(p >= model.threshold), "domain": model.domain, "domain_validation": model.validation,
        "processed_at": now_iso(),
        "evidence": {"event_time": iso_us(row.ts), "kind": row.kind, "event": row.event, "top_features": top,
                     "select_threshold": model.select_threshold, "agent": AGENT_VERSION},
    }
    payload["score_id"] = canonical_hash(["score.v1", host_id, "host_ml", model.bundle_id, refs, None, payload["processed_at"]])
    return payload


# ------------------------------------------------------------------------------------------------ loops
class Processor:
    """Inbox -> featurizer -> fused LightGBM -> selected scores + minute summaries."""

    def __init__(self, app):
        self.app = app
        self.model: HostModel = app.state.model
        self.fz = self.model.featurizer(app.state.config.get("host_name", app.state.config["host_id"]))
        self.hist = [0] * 10
        self.counts = {"rows": 0, "selected": 0, "predicted": 0, "errors": 0}
        self.period_start = now_iso()
        self.last_input = time.monotonic()

    def warm_up(self, minutes: float) -> int:
        n = 0
        for ident, raw in self.app.state.inbox.recent_processed(self.model.source, minutes):
            self.fz.feed(raw, ref=ident)
            n += 1
        self.fz.flush()
        self.fz.drain_stats()
        return n

    def step(self) -> int:
        inbox = self.app.state.inbox
        batch = inbox.waiting(self.model.source)
        rows = []
        if batch:
            self.last_input = time.monotonic()
            failed = set()
            for rowid, ident, raw in batch:
                try:
                    rows += self.fz.feed(raw, ref=ident)
                except Exception as exc:   # one malformed record must not stop the stream
                    self.counts["errors"] += 1
                    failed.add(rowid)
                    inbox.mark([rowid], "error", type(exc).__name__)
            inbox.mark([b[0] for b in batch if b[0] not in failed], "processed")
        elif time.monotonic() - self.last_input > 3:
            rows += self.fz.flush()
        if rows:
            self.score(rows)
        return len(batch)

    def score(self, rows):
        X = self.fz.matrix(rows)
        p = self.model.score(X)
        sel = [i for i in range(len(rows)) if p[i] >= self.model.select_threshold or p[i] >= self.model.threshold]
        tops = self.model.contributions(X[sel]) if sel else []
        for i in range(len(rows)):
            self.hist[min(9, int(p[i] * 10))] += 1
        self.counts["rows"] += len(rows)
        self.counts["predicted"] += int((p >= self.model.threshold).sum())
        self.counts["selected"] += len(sel)
        mode = self.app.state.config.get("mode", "ready_shadow")
        for j, i in enumerate(sel):
            self.app.state.inbox.enqueue("score", build_score(self.app.state.config["host_id"], self.model, mode, rows[i],
                                                              float(p[i]), tops[j]))

    def summary(self) -> dict:
        stats = self.fz.drain_stats()
        end = now_iso()
        payload = {"schema_version": "summary.v1", "host_id": self.app.state.config["host_id"],
                   "bundle_id": self.model.bundle_id, "domain": self.model.domain,
                   "domain_validation": self.model.validation, "period_start": self.period_start, "period_end": end,
                   "counts": dict(self.counts), "score_histogram": list(self.hist), "featurizer": stats,
                   "pending_groups": getattr(getattr(self.fz, "stream", None), "pending", 0), "agent": AGENT_VERSION}
        payload["summary_id"] = canonical_hash(["summary.v1", payload["host_id"], self.period_start, end])
        self.hist = [0] * 10
        self.counts = {k: 0 for k in self.counts}
        self.period_start = end
        return payload


async def inference_loop(app):
    if app.state.model is None:
        return
    proc = Processor(app)
    app.state.processor = proc
    app.state.warmed = await asyncio.to_thread(proc.warm_up, float(app.state.config.get("warmup_minutes", 30)))
    await asyncio.to_thread(app.state.inbox.mark_source_ignored, {app.state.model.source})
    last_summary, last_prune = time.monotonic(), 0.0
    while True:
        try:
            n = await asyncio.to_thread(proc.step)
        except Exception as exc:
            app.state.last_error = f"{type(exc).__name__}: {exc}"[:300]
            n = 0
            await asyncio.sleep(2)
        if time.monotonic() - last_summary >= 60:
            app.state.inbox.enqueue("summary", proc.summary())
            await asyncio.to_thread(app.state.inbox.mark_source_ignored, {app.state.model.source})
            last_summary = time.monotonic()
        if time.monotonic() - last_prune >= 600:
            app.state.pruned = await asyncio.to_thread(app.state.inbox.prune)
            last_prune = time.monotonic()
        if n == 0:
            await asyncio.sleep(1)


def deliver(config: dict, url: str, batch: list[tuple[str, str]]) -> None:
    payload = "[" + ",".join(item[1] for item in batch) + "]"
    request = urllib.request.Request(url, data=payload.encode(), method="POST",
                                     headers={"Authorization": "Bearer " + config["central_token"],
                                              "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=config.get("tls_ca"))
    with urllib.request.urlopen(request, timeout=20, context=context) as response:
        if response.status // 100 != 2:
            raise OSError("central receiver rejected batch")


async def outbox_loop(app):
    cfg = app.state.config
    urls = {"score": cfg.get("central_score_url"), "summary": cfg.get("central_summary_url")}
    while True:
        sent = 0
        for kind, url in urls.items():
            if not url:
                continue
            batch = await asyncio.to_thread(app.state.inbox.outbox_batch, kind)
            if not batch:
                continue
            ids = [row[0] for row in batch]
            try:
                await asyncio.to_thread(deliver, cfg, url, batch)
                await asyncio.to_thread(app.state.inbox.outbox_done, ids, True)
                sent += len(ids)
            except (OSError, urllib.error.URLError, ssl.SSLError):
                await asyncio.to_thread(app.state.inbox.outbox_done, ids, False)
        await asyncio.sleep(1 if sent else 5)


@asynccontextmanager
async def lifespan(app):
    cfg_path = Path(os.environ["KLTN_AGENT_CONFIG"])
    config = json.loads(cfg_path.read_text())
    # model.json is written only by the rollout playbook (deploy-host-model.yml), so re-provisioning a host
    # (site.yml re-renders config.json) never drops the deployed bundle back to model-free mode
    model_cfg = Path(config.get("model_config") or cfg_path.with_name("model.json"))
    if model_cfg.is_file():
        config.update({k: v for k, v in json.loads(model_cfg.read_text()).items() if k in ("bundle_path", "mode")})
    import lightgbm
    import numpy
    import scipy
    app.state.versions = {m.__name__: m.__version__ for m in (lightgbm, numpy, scipy)}
    app.state.config = config
    app.state.inbox = Inbox(config["database"], config["host_id"], config.get("max_rows", 200000),
                            config.get("max_bytes", 512 * 1024 * 1024), retention_hours=config.get("retention_hours", 6))
    app.state.model, app.state.processor = None, None
    app.state.inference, app.state.bundle_error, app.state.last_error = "waiting_for_model", None, None
    app.state.warmed, app.state.pruned = 0, {}
    if config.get("mode") in READY_STATES and config.get("bundle_path"):
        try:
            app.state.model = await asyncio.to_thread(HostModel, Path(config["bundle_path"]), config["platform_domain"])
            app.state.inference = config["mode"] if app.state.model.validation == "validated" else "ready_shadow"
        except BundleError as exc:
            app.state.bundle_error = str(exc)
            app.state.inference = "unsupported_domain" if str(exc) == "unsupported_domain" else "incompatible_bundle"
    tasks = [asyncio.create_task(inference_loop(app)), asyncio.create_task(outbox_loop(app))]
    yield
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(lifespan=lifespan)


@app.get("/healthz")
async def health():
    status = await asyncio.to_thread(app.state.inbox.status)
    m = app.state.model
    return dict(status, status="ok", agent=AGENT_VERSION, inference=app.state.inference,
                bundle_id=m.bundle_id if m else None, bundle_error=app.state.bundle_error,
                domain=app.state.config.get("platform_domain"), validation=m.validation if m else None,
                self_test=m.self_test if m else None, warmed_records=app.state.warmed, pruned=app.state.pruned,
                last_error=app.state.last_error, runtime=app.state.versions)


@app.get("/readyz")
async def ready():
    if app.state.inference not in READY_STATES or app.state.model is None:
        raise HTTPException(503, app.state.bundle_error or "waiting_for_eligible_model")
    m = app.state.model
    return {"status": "ready", "inference": app.state.inference, "bundle_id": m.bundle_id, "domain": m.domain,
            "validation": m.validation, "self_test": m.self_test}


@app.post("/v1/raw/{source}")
async def ingest(source: str, request: Request):
    if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + app.state.config["local_token"]):
        raise HTTPException(401, "unauthorized")
    if source not in SOURCES:
        raise HTTPException(422, "unknown source")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise HTTPException(413, "batch too large")

    def invalid_constant(value):
        raise ValueError(value)
    try:
        records = json.loads(body, parse_constant=invalid_constant)
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list) or not 1 <= len(records) <= 5000 or any(not isinstance(r, dict) for r in records):
            raise ValueError("expected event objects")
        inserted = await asyncio.to_thread(app.state.inbox.put, source, records)
    except (ValueError, UnicodeError):
        raise HTTPException(422, "expected 1..5000 valid JSON objects")
    except (sqlite3.Error, CapacityError, OSError):
        raise HTTPException(503, "inbox unavailable or full; retry batch")
    return {"accepted": len(records), "inserted": inserted, "inference": app.state.inference}
