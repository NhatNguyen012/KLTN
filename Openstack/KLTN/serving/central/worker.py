"""Central DL Inference (General Architecture, CENTRAL VM): IL BiLSTM per-chunk scores over host-event windows.

Input: `host_events` written by the central normalizer (auditd groups; Sysmon mapped to CBC-EDR semantics).
Per host: the training window recipe (kltn_features.dl_stream: 180 s windows every 30 s, >= 2 label-bearing events,
chunks of <= 512) on an absolute-time grid; a window is scored once the watermark min(now - lateness, newest event of
the host) has passed its end. Output: one `scores` row per chunk (branch host_dl) with the window logit, the domain
decision threshold, the most suspicious events (event-head logits) and the attack-stage read-out.
The bundle (bundle.v2, branch host_dl) is verified (checksums, parity flag, runtime code hashes) and self-tested on
its fixture windows before any score is written; failures leave the service in `incompatible_bundle`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import psycopg
import torch
from psycopg.types.json import Jsonb

from kltn_features.dl_stream import (STAGES, DLVocab, LinuxDLState, Windower, build_model, encode, predict,
                                     windows_record)
from kltn_features.sysmon import to_dl_record

SERVICE = "dl-worker"
LATENESS_S = float(os.environ.get("KLTN_DL_LATENESS", "90"))
REPLAY_S = 2 * 3600
BATCH = 20000
TOP_EVENTS = 24


class BundleError(Exception):
    pass


def config():
    return json.loads(Path(os.environ.get("KLTN_DL_CONFIG", "/run/kltn/dl.json")).read_text())


def connect():
    return psycopg.connect(host="127.0.0.1", port=15432, dbname="kltn", user="kltn_dl", password=config()["password"],
                           connect_timeout=5)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def canonical_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))


class Runtime:
    def __init__(self, root: Path):
        root = root.resolve()
        try:
            m = json.loads((root / "manifest.json").read_text())
        except (OSError, ValueError) as exc:
            raise BundleError("manifest_missing_or_invalid") from exc
        if m.get("schema_version") != "bundle.v2" or m.get("branch") != "host_dl":
            raise BundleError("bundle_contract_incompatible")
        if not m.get("activation", {}).get("eligible") or m.get("parity", {}).get("passed") is not True:
            raise BundleError("bundle_not_eligible_or_parity_failed")
        for rel, meta in m["artifacts"].items():
            p = (root / rel).resolve()
            p.relative_to(root)
            if not p.is_file() or p.is_symlink() or p.stat().st_size != meta["bytes"] or \
                    not hmac.compare_digest(sha256_file(p), meta["sha256"]):
                raise BundleError("artifact_checksum_mismatch")
        here = Path(__file__).resolve().parent
        for rel, expected in m.get("runtime_code_sha256", {}).items():
            p = here / rel
            if not p.is_file() or not hmac.compare_digest(sha256_file(p), expected):
                raise BundleError("runtime_code_hash_mismatch")
        sd = torch.load(root / m["model"]["weights"], map_location="cpu", weights_only=True)
        self.model = build_model(sd, json.loads((root / m["model"]["config"]).read_text()))
        self.vocab = DLVocab(json.loads((root / "preprocess/vocab.json").read_text()))
        self.manifest, self.bundle_id, self.domains = m, m["bundle_id"], m["domains"]
        self.self_test = self._self_test(root)

    def _self_test(self, root: Path) -> dict:
        fx = json.loads((root / "evidence/fixture_windows.json").read_text())
        worst, n = 0.0, 0
        for dom, items in fx.items():
            samples = [{k: np.asarray(v) for k, v in it["inputs"].items()} for it in items]
            for s in samples:
                s["x_cat"] = s["x_cat"].astype(np.int64); s["ctx_cat"] = s["ctx_cat"].astype(np.int64)
                s["delta"] = s["delta"].astype(np.float32); s["ctx_num"] = s["ctx_num"].astype(np.float32)
                if "bag" in s:
                    s["bag"] = s["bag"].astype(np.int64)
            for it, p in zip(items, predict(self.model, samples)):
                worst = max(worst, abs(p["z"] - it["z"]))
                n += 1
        if worst > 1e-3:
            raise BundleError(f"self_test_logit_mismatch_{worst:.2e}")
        return {"windows": n, "max_abs_dlogit": worst, "passed": True}


class Lane:
    def __init__(self, host_id: str, domain: str):
        self.host_id, self.domain = host_id, domain
        self.state = LinuxDLState() if domain == "linux-audit" else None
        self.win = Windower(origin_us=0)
        self.cursor = 0              # last host_events.id consumed
        self.resume_cur = None       # windows starting before this were scored before a restart
        self.max_ts = 0
        self.late = 0

    def add(self, rows):
        events = []
        for key, ev in rows:
            ev = dict(ev)
            ev["ref"] = key
            events.append(ev)
        if self.domain == "linux-audit":
            events.sort(key=lambda e: (e["ts"], e.get("line") or 0))
            recs = self.state.records(events)
        else:
            recs = []
            for e in sorted(events, key=lambda e: (e["ts"], e.get("record_id") or 0)):
                r = to_dl_record(e, line=e.get("record_id") or 0)
                if r is not None:
                    r["ref"] = e["ref"]
                    recs.append(windows_record(r))
        if events:
            self.max_ts = max(self.max_ts, max(e["ts"] for e in events))
        self.late += self.win.add(recs)
        if self.state is not None:
            self.state.pidx.prune(self.max_ts)


class Worker:
    def __init__(self, rt: Runtime):
        self.rt = rt
        self.lanes: dict[str, Lane] = {}

    def lane(self, conn, host_id: str, domain: str) -> Lane:
        if host_id in self.lanes:
            return self.lanes[host_id]
        lane = Lane(host_id, domain)
        cur = conn.execute("SELECT value FROM framework_cursors WHERE name=%s", (f"dl:{host_id}",)).fetchone()
        if cur:
            v = cur[0]
            lane.resume_cur = v.get("window_cur")
            row = conn.execute('''SELECT min(id) FROM host_events WHERE host_id=%s AND ts_us >= %s''',
                               (host_id, int(v.get("max_ts", 0)) - REPLAY_S * 1_000_000)).fetchone()
            lane.cursor = (int(row[0]) - 1) if row and row[0] else int(v.get("id", 0))
        self.lanes[host_id] = lane
        return lane

    def tick(self) -> dict:
        written = 0
        now_us = int(time.time() * 1e6)
        with connect() as conn:
            hosts = conn.execute('''SELECT host_id, domain FROM host_events WHERE ts > now() - interval '7 days'
              GROUP BY host_id, domain''').fetchall()
            for host_id, domain in hosts:
                if domain not in self.rt.domains:
                    continue
                lane = self.lane(conn, host_id, domain)
                rows = conn.execute('''SELECT id, event_key, event FROM host_events WHERE host_id=%s AND id>%s
                  ORDER BY id LIMIT %s''', (host_id, lane.cursor, BATCH)).fetchall()
                if rows:
                    lane.add([(r[1], r[2]) for r in rows])
                    lane.cursor = rows[-1][0]
                watermark = min(now_us - int(LATENESS_S * 1e6), lane.max_ts)
                if len(rows) == BATCH:   # more rows waiting: only windows before the last loaded event are final
                    watermark = min(watermark, lane.max_ts - 1)
                written += self.score(conn, lane, watermark)
                conn.execute('''INSERT INTO framework_cursors(name,value) VALUES (%s,%s) ON CONFLICT(name) DO UPDATE
                  SET value=excluded.value, updated_at=now()''',
                             (f"dl:{host_id}", Jsonb({"id": lane.cursor, "max_ts": lane.max_ts, "window_cur": lane.win.cur})))
            conn.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime) VALUES (%s,now(),%s,0,%s)
              ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,state=excluded.state,runtime=excluded.runtime''',
                         (SERVICE, "ready", Jsonb({"bundle_id": self.rt.bundle_id, "self_test": self.rt.self_test,
                                                   "lanes": {h: {"cursor": l.cursor, "late": l.late} for h, l in self.lanes.items()}})))
        return {"scores_written": written}

    def score(self, conn, lane: Lane, watermark: int) -> int:
        dom = self.rt.domains[lane.domain]
        with_bag = bool(dom.get("with_bag"))
        items = []
        for w, ci, start, end, evs in lane.win.ready(watermark):
            if lane.resume_cur is not None and start < lane.resume_cur:
                continue
            enc = encode(evs)
            items.append((start, end, ci, evs, enc, self.rt.vocab.sample(enc, with_bag=with_bag)))
        if not items:
            return 0
        preds = predict(self.rt.model, [it[5] for it in items])
        thr = sigmoid(float(dom["threshold_logit"]))
        status = "ready_active" if dom["validation"] == "validated" else "ready_shadow"
        out = []
        for (start, end, ci, evs, enc, _s), p in zip(items, preds):
            z = p["z"]
            prob = sigmoid(z)
            order = np.argsort(-p["event_logits"])[:TOP_EVENTS]
            top = [{"ref": evs[i].get("ref"), "kind": evs[i]["kind_raw"], "event_logit": round(float(p["event_logits"][i]), 3),
                    "actor": evs[i]["tok"][1], "target": evs[i]["tok"][4], "ts": evs[i]["ts"]} for i in order]
            refs = list(dict.fromkeys(t["ref"] for t in top if t["ref"]))[:512] or [f"{lane.host_id}:{start}:{ci}"]
            window = {"start": datetime.fromtimestamp(start / 1e6, timezone.utc).isoformat(),
                      "end": datetime.fromtimestamp(end / 1e6, timezone.utc).isoformat(), "chunk": ci,
                      "events": len(evs), "label_events": sum(1 for e in evs if e["is_label"])}
            stage_rank = np.argsort(-p["stage_presence"])
            evidence = {"z": z, "threshold_logit": dom["threshold_logit"], "stage_last": STAGES.get(p["stage_last"]),
                        "stage_presence_top": [STAGES.get(int(k) + 1) for k in stage_rank[:3]],
                        "top_events": top, "oov": self.rt.vocab.oov(enc), "pipeline": "kltn-features-il3-v1"}
            score_id = canonical_hash(["score.v1", lane.host_id, "host_dl", self.rt.bundle_id, start, ci])
            out.append((score_id, "score.v1", lane.host_id, "host_dl", self.rt.bundle_id, status, prob, thr, int(prob >= thr),
                        lane.domain, dom["validation"], Jsonb(refs), Jsonb(window), Jsonb(evidence),
                        datetime.fromtimestamp(end / 1e6, timezone.utc)))
        with conn.cursor() as cur:
            cur.executemany('''INSERT INTO scores(score_id,schema_version,host_id,branch,bundle_id,status,score,threshold,
              prediction,domain,domain_validation,event_refs,score_window,evidence,event_time,processed_at)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now()) ON CONFLICT(score_id) DO NOTHING''', out)
        return len(out)


def heartbeat(state: str, detail: dict):
    Path("/tmp/dl-health.json").write_text(json.dumps({"updated_at": time.time(), "state": state, **detail}))


def main():
    root = Path(os.environ.get("KLTN_DL_BUNDLE", "/models/current"))
    torch.set_num_threads(int(os.environ.get("KLTN_DL_THREADS", "2")))
    try:
        rt = Runtime(root)
    except Exception as exc:
        state = {"state": "incompatible_bundle", "error": str(exc)[:300]}
        print(json.dumps(state), flush=True)
        while True:   # stay up and report why nothing is scored
            heartbeat("incompatible_bundle", state)
            try:
                with connect() as conn:
                    conn.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime) VALUES (%s,now(),%s,0,%s)
                      ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,state=excluded.state,runtime=excluded.runtime''',
                                 (SERVICE, "incompatible_bundle", Jsonb(state)))
            except Exception:
                pass
            time.sleep(30)
    print(json.dumps({"service": SERVICE, "bundle_id": rt.bundle_id, "self_test": rt.self_test}), flush=True)
    w = Worker(rt)
    while True:
        try:
            r = w.tick()
            heartbeat("ready", r)
            if r["scores_written"]:
                print(json.dumps(r), flush=True)
        except Exception as exc:
            heartbeat("error", {"error": f"{type(exc).__name__}: {exc}"[:300]})
            print(json.dumps({"service": SERVICE, "error": f"{type(exc).__name__}: {exc}"[:500]}), flush=True)
            time.sleep(5)
        time.sleep(2)


if __name__ == "__main__":
    main()
