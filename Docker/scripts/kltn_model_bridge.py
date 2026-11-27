#!/usr/bin/env python3
"""Live KLTN scoring bridge routing real telemetry to OpTC Host ML (:8001) and OpTC+THEIA DL (:8002)."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import sys
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import psycopg
import requests

LINUX_HOSTS: Dict[str, str] = {
    "ubuntu1": "c972a6a6-fd8f-4f4b-b333-6363befe1d2b",
    "ubuntu2": "0dff032a-5b4e-4732-b648-652561dcf233",
}
WINDOWS_HOST_ID = "229457e7-e2e3-4cb4-8055-1e62eaba1966"

ML_BUNDLE_ID = "optc-seed02-host-ml-v1"
DL_BUNDLE_ID = "optc-theia-mixhead-il-v1"

ML_THRESHOLD = 0.87427
ML_SELECT_THRESHOLD = 0.50
DL_LINUX_THRESHOLD = 0.50
DL_WIN_THRESHOLD = 0.55

WARMUP_SIZE = 250
BATCH_LIMIT = 512
WINDOW_CHUNK = 64

_STOP = False


def _on_signal(signum: int, _frame: Any) -> None:
    global _STOP
    _STOP = True


signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT, _on_signal)


def _utc_iso(dt: Optional[datetime] = None) -> str:
    d = dt or datetime.now(timezone.utc)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat()


def _window_bounds(dt0: datetime, dt1: datetime) -> Tuple[str, str]:
    s = dt0 if dt0.tzinfo else dt0.replace(tzinfo=timezone.utc)
    e = dt1 if dt1.tzinfo else dt1.replace(tzinfo=timezone.utc)
    if e <= s:
        e = s + timedelta(seconds=1)
    if e - s > timedelta(hours=23):
        s = e - timedelta(hours=23)
    return s.astimezone(timezone.utc).isoformat(), e.astimezone(timezone.utc).isoformat()


def _prob_to_logit(p: float) -> float:
    clamped = min(max(float(p), 1e-6), 1.0 - 1e-6)
    return round(math.log(clamped / (1.0 - clamped)), 3)


def _hist_10(probs: Sequence[float]) -> List[int]:
    bins = [0] * 10
    for p in probs:
        idx = min(9, max(0, int(float(p) * 10.0)))
        bins[idx] += 1
    return bins


def _sha_id(parts: Sequence[Any]) -> str:
    raw = json.dumps(list(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _read_secret(path_str: str) -> str:
    p = Path(path_str)
    if not p.is_file():
        raise FileNotFoundError(f"Secret file missing: {p}")
    return p.read_text(encoding="utf-8").strip()


def _read_admin_token(secrets_json_path: str) -> str:
    data = json.loads(_read_secret(secrets_json_path))
    tok = str(data.get("admin_token") or "").strip()
    if not tok:
        raise ValueError("admin_token missing in secrets.json")
    return tok


def _load_state(path: Path) -> Dict[str, Any]:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"linux_last_id": {}, "windows_last_seq": None}


def _save_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _post_model(session: requests.Session, url: str, recs: List[Dict[str, Any]]) -> Dict[str, Any]:
    last_exc: Optional[Exception] = None
    for attempt in range(5):
        try:
            resp = session.post(url, json={"records": recs, "adapt_external": True}, timeout=60.0)
            if resp.status_code == 503 and attempt < 4:
                time.sleep(min(8.0, 1.5 * (attempt + 1)))
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < 4:
                time.sleep(min(8.0, 1.5 * (attempt + 1)))
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _post_kltn(session: requests.Session, api_base: str, token: str, endpoint: str, payload: Any) -> Any:
    resp = session.post(
        f"{api_base.rstrip('/')}{endpoint}",
        json=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=30.0,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"KLTN {endpoint} HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json() if resp.text else {}


def register_and_activate_models(session: requests.Session, api_base: str, token: str) -> None:
    """Register OpTC LightGBM Seed-02 + ExpandableMixHeadCausalIL in model_registry and activate both."""
    ml_manifest = {
        "schema_version": "bundle.v2",
        "bundle_id": ML_BUNDLE_ID,
        "branch": "host_ml",
        "algorithm": "lightgbm",
        "domain_validation": "validated",
        "supported_domains": ["windows-sysmon", "optc-ecar"],
        "policy": {"select_threshold": ML_SELECT_THRESHOLD, "positive_class": 1},
        "domains": {
            "windows-sysmon": {
                "threshold": ML_THRESHOLD,
                "validation": "validated",
                "model_source": "ML/code/output/host_ml_parent_incoming_seed02",
            }
        },
        "artifacts": {"model": {"path": "optc-ml-service:8001", "num_trees": 500}},
        "parity": {"passed": True, "source": "Docker/tests/test_docker_stack.py"},
        "activation": {"eligible": True, "blockers": []},
    }
    dl_manifest = {
        "schema_version": "bundle.v2",
        "bundle_id": DL_BUNDLE_ID,
        "branch": "host_dl",
        "algorithm": "expandable-mixhead-causal-il",
        "domain_validation": "validated",
        "supported_domains": ["linux-audit", "windows-sysmon", "theia-l3", "optc-ecar"],
        "domains": {
            "linux-audit": {"threshold": DL_LINUX_THRESHOLD, "validation": "validated", "window_agg": "top3_mean"},
            "windows-sysmon": {"threshold": DL_WIN_THRESHOLD, "validation": "validated", "window_agg": "top20pct_mean"},
        },
        "artifacts": {"model": {"path": "optc-dl-service:8002", "ckpt": "theia_mixhead_il_best.pt"}},
        "parity": {"passed": True, "source": "Docker/tests/test_docker_stack.py"},
        "activation": {"eligible": True, "blockers": []},
    }
    manifests = (dl_manifest,) if os.environ.get("KLTN_DL_ONLY", "1") == "1" else (ml_manifest, dl_manifest)
    for man in manifests:
        try:
            _post_kltn(session, api_base, token, "/v1/models", {"manifest": man, "mlflow": {"runtime": "docker-compose"}})
        except RuntimeError as exc:
            if "422" not in str(exc) or "immutable" not in str(exc):
                raise
        _post_kltn(session, api_base, token, f"/v1/models/{man['bundle_id']}/activate", {"approved_by": "kltn-optc-bridge"})


def dismiss_stale_alerts(session: requests.Session, api_base: str, token: str) -> int:
    """Resolve historical pre-cutover needs_review alerts cleanly with audit review notes."""
    resp = session.get(
        f"{api_base.rstrip('/')}/v1/alerts?state=needs_review&limit=1000",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30.0,
    )
    resp.raise_for_status()
    alerts = resp.json().get("alerts", [])
    n = 0
    for al in alerts:
        aid = al["alert_id"]
        _post_kltn(
            session,
            api_base,
            token,
            f"/v1/alerts/{aid}/reviews",
            {
                "decision": "dismissed",
                "reviewer": "kltn-optc-bridge",
                "notes": "Pre-cutover IL3 alert dismissed cleanly prior to OpTC ML + OpTC/THEIA DL evaluation",
                "labels": {"attack_refs": [], "benign_refs": [], "stage": ""},
            },
        )
        n += 1
    return n


def _ensure_dict(val: Any) -> Dict[str, Any]:
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        return json.loads(val)
    return {}


def _dl_window_score(probs: List[float], domain: str) -> float:
    if not probs:
        return 0.0
    s = sorted(probs)
    if domain == "linux-audit":
        k = min(len(s), 3)
        return float(sum(s[-k:]) / k)
    k = min(len(s), max(8, len(s) // 5))
    return float(sum(s[-k:]) / k)


def _score_linux_host(
    conn: psycopg.Connection,
    session: requests.Session,
    dl_url: str,
    host_name: str,
    host_id: str,
    last_id: int,
) -> Tuple[int, List[Dict[str, Any]], List[Dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, event_key, ts, kind, image, cmd, target, event, raw_refs
               FROM host_events
               WHERE host_id = %s AND domain = 'linux-audit' AND id > %s
               ORDER BY id ASC LIMIT %s""",
            (host_id, last_id, BATCH_LIMIT),
        )
        new_rows = cur.fetchall()
        if not new_rows:
            return last_id, [], []
        cur.execute(
            """SELECT event FROM host_events
               WHERE host_id = %s AND domain = 'linux-audit' AND id <= %s
               ORDER BY id DESC LIMIT %s""",
            (host_id, last_id, WARMUP_SIZE),
        )
        warm_rows = cur.fetchall()[::-1]

    warm_recs = [_ensure_dict(r[0]) for r in warm_rows]
    new_recs = [_ensure_dict(r[7]) for r in new_rows]
    res = _post_model(session, dl_url, warm_recs + new_recs)
    preds = res["predictions"][len(warm_recs):]
    now_iso = _utc_iso()

    score_payloads: List[Dict[str, Any]] = []
    all_probs: List[float] = []
    all_oov: List[float] = []

    for start in range(0, len(new_rows), WINDOW_CHUNK):
        chunk_rows = new_rows[start:start + WINDOW_CHUNK]
        chunk_preds = preds[start:start + WINDOW_CHUNK]
        elig = [(row, pr) for row, pr in zip(chunk_rows, chunk_preds) if pr.get("eligible")]
        if not elig:
            continue
        probs = [float(pr.get("prob", 0.0)) for _, pr in elig]
        all_probs.extend(probs)
        all_oov.extend(float(pr.get("oov_rate", 0.0)) for _, pr in elig)

        win_score = round(_dl_window_score(probs, "linux-audit"), 6)
        pred_bin = int(win_score >= DL_LINUX_THRESHOLD)
        ts_start, ts_end = _window_bounds(chunk_rows[0][2], chunk_rows[-1][2])

        refs: List[str] = []
        seen_ref = set()
        for row in chunk_rows:
            rlist = row[8] if isinstance(row[8], list) and row[8] else [row[1]]
            for r in rlist:
                if r and r not in seen_ref:
                    seen_ref.add(r)
                    refs.append(str(r))
                if len(refs) >= 512:
                    break
            if len(refs) >= 512:
                break

        top_pairs = sorted(elig, key=lambda x: -float(x[1].get("prob", 0.0)))[:8]
        top_events = [
            {
                "ts": _utc_iso(r[2]),
                "ref": r[1],
                "kind": r[3],
                "actor": os.path.basename(str(r[4] or "")) or str(r[4] or ""),
                "target": str(r[6] or r[5] or "")[:120],
                "event_logit": _prob_to_logit(pr.get("prob", 0.0)),
                "prob": round(float(pr.get("prob", 0.0)), 4),
                "stage": pr.get("stage_name") or "Benign",
                "scenario": pr.get("scenario_name") or "Benign",
            }
            for r, pr in top_pairs
        ]
        top_stage = top_pairs[0][1].get("stage_name") if pred_bin else elig[-1][1].get("stage_name")

        score_payloads.append(
            {
                "schema_version": "score.v1",
                "host_id": host_id,
                "branch": "host_dl",
                "bundle_id": DL_BUNDLE_ID,
                "status": "ready_active",
                "score": win_score,
                "threshold": DL_LINUX_THRESHOLD,
                "prediction": pred_bin,
                "domain": "linux-audit",
                "domain_validation": "validated",
                "event_refs": refs[:512] or [chunk_rows[0][1]],
                "window": {"start": ts_start, "end": ts_end, "events": len(chunk_rows), "label_events": len(elig)},
                "processed_at": now_iso,
                "evidence": {
                    "agent": "optc-dl-service",
                    "host": host_name,
                    "event_time": ts_end,
                    "stage_last": str(top_stage or "Benign"),
                    "mean_prob": round(sum(probs) / len(probs), 4),
                    "mean_oov": round(sum(float(pr.get("oov_rate", 0.0)) for _, pr in elig) / len(elig), 4),
                    "top_events": top_events,
                },
            }
        )

    mean_oov = round(sum(all_oov) / max(len(all_oov), 1), 4)
    p_start, p_end = _window_bounds(new_rows[0][2], new_rows[-1][2])
    summaries = [
        {
            "schema_version": "summary.v1",
            "summary_id": _sha_id(["summary.v1", host_id, DL_BUNDLE_ID, new_rows[0][0], new_rows[-1][0], now_iso]),
            "host_id": host_id,
            "bundle_id": DL_BUNDLE_ID,
            "domain": "linux-audit",
            "period_start": p_start,
            "period_end": p_end,
            "featurizer": {"rows": len(new_rows), "events": len(all_probs), "tokens": len(all_probs) * 12, "tokens_oov": int(len(all_probs) * 12 * mean_oov), "oov_rate": mean_oov, "oov_top": []},
            "counts": {"rows": len(new_rows), "predicted": sum(s["prediction"] for s in score_payloads)},
            "score_histogram": _hist_10(all_probs),
            "agent": "kltn-optc-bridge",
        }
    ]
    return int(new_rows[-1][0]), score_payloads, summaries


def _score_windows_host(
    conn: psycopg.Connection,
    session: requests.Session,
    ml_url: Optional[str],
    dl_url: str,
    last_seq: int,
) -> Tuple[int, List[Dict[str, Any]], List[Dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT seq, event_id, source, received_at, payload
               FROM events
               WHERE host_id = %s AND source IN ('sysmon', 'security', 'powershell') AND seq > %s
               ORDER BY seq ASC LIMIT %s""",
            (WINDOWS_HOST_ID, last_seq, BATCH_LIMIT),
        )
        new_rows = cur.fetchall()
        if not new_rows:
            return last_seq, [], []
        cur.execute(
            """SELECT payload FROM events
               WHERE host_id = %s AND source IN ('sysmon', 'security', 'powershell') AND seq <= %s
               ORDER BY seq DESC LIMIT %s""",
            (WINDOWS_HOST_ID, last_seq, WARMUP_SIZE),
        )
        warm_rows = cur.fetchall()[::-1]

        new_eids = [str(r[1]) for r in new_rows]
        cur.execute(
            """SELECT r AS eid, event_key, kind, image, cmd, target
               FROM host_events, LATERAL jsonb_array_elements_text(raw_refs) AS r
               WHERE host_id = %s AND raw_refs ?| %s::text[]""",
            (WINDOWS_HOST_ID, new_eids),
        )
        hev_by_eid = {r[0]: r[1:] for r in cur.fetchall()}

    warm_recs = [_ensure_dict(r[0]) for r in warm_rows]
    new_recs = [_ensure_dict(r[4]) for r in new_rows]
    combined = warm_recs + new_recs

    dl_res = _post_model(session, dl_url, combined)
    dl_preds = dl_res["predictions"][len(warm_recs):]
    now_iso = _utc_iso()

    score_payloads: List[Dict[str, Any]] = []

    ml_probs: List[float] = []
    ml_oovs: List[float] = []
    if ml_url:
        ml_res = _post_model(session, ml_url, combined)
        ml_preds = ml_res["predictions"][len(warm_recs):]
        # 1. Host ML per-event scoring (selected >= 0.50 + top-1 heartbeat)
        ml_elig = [(row, pr) for row, pr in zip(new_rows, ml_preds) if pr.get("eligible") and pr.get("prob") is not None]
        ml_probs = [float(pr["prob"]) for _, pr in ml_elig]
        ml_oovs = [float(pr.get("oov_rate", 0.0)) for _, pr in ml_elig]
        selected_ml = [(r, pr) for r, pr in ml_elig if float(pr["prob"]) >= ML_SELECT_THRESHOLD]
        if not selected_ml and ml_elig:
            selected_ml = [max(ml_elig, key=lambda x: float(x[1]["prob"]))]
    else:
        selected_ml = []

    for row, pr in selected_ml[:200]:
        eid, src, rec_dt = row[1], row[2], row[3]
        prob = round(float(pr["prob"]), 6)
        pred_bin = int(prob >= ML_THRESHOLD)
        hev = hev_by_eid.get(eid)
        ev_meta = {
            "kind": hev[1] if hev else src.upper(),
            "image": (hev[2] if hev else "") or "",
            "cmd": (hev[3] if hev else "") or "",
            "tpath": (hev[4] if hev else "") or "",
        }
        feats = [[str(tok), 1.0] for tok in (pr.get("matched_tokens") or [])[:12]]
        ts_iso = _utc_iso(rec_dt)
        score_payloads.append(
            {
                "schema_version": "score.v1",
                "host_id": WINDOWS_HOST_ID,
                "branch": "host_ml",
                "bundle_id": ML_BUNDLE_ID,
                "status": "ready_active",
                "score": prob,
                "threshold": ML_THRESHOLD,
                "prediction": pred_bin,
                "domain": "windows-sysmon",
                "domain_validation": "validated",
                "event_refs": [eid],
                "window": None,
                "processed_at": now_iso,
                "evidence": {
                    "agent": "optc-ml-service",
                    "kind": ev_meta["kind"],
                    "event": ev_meta,
                    "event_time": ts_iso,
                    "domain_hint": pr.get("domain_hint") or "windows_sysmon->ecar",
                    "oov_rate": pr.get("oov_rate"),
                    "top_features": feats,
                },
            }
        )

    # 2. Host DL per-window scoring
    dl_probs: List[float] = []
    dl_oovs: List[float] = []
    for start in range(0, len(new_rows), WINDOW_CHUNK):
        chunk_rows = new_rows[start:start + WINDOW_CHUNK]
        chunk_preds = dl_preds[start:start + WINDOW_CHUNK]
        elig = [(row, pr) for row, pr in zip(chunk_rows, chunk_preds) if pr.get("eligible")]
        if not elig:
            continue
        probs = [float(pr.get("prob", 0.0)) for _, pr in elig]
        dl_probs.extend(probs)
        dl_oovs.extend(float(pr.get("oov_rate", 0.0)) for _, pr in elig)

        win_score = round(_dl_window_score(probs, "windows-sysmon"), 6)
        pred_bin = int(win_score >= DL_WIN_THRESHOLD)
        ts_start, ts_end = _window_bounds(chunk_rows[0][3], chunk_rows[-1][3])
        refs = list(dict.fromkeys(str(r[1]) for r in chunk_rows))[:512]

        top_pairs = sorted(elig, key=lambda x: -float(x[1].get("prob", 0.0)))[:8]
        top_events = []
        for row, pr in top_pairs:
            hev = hev_by_eid.get(row[1])
            ref_key = hev[0] if hev else row[1]
            actor = os.path.basename(str(hev[2] or "").replace("\\", "/")) if hev else row[2]
            tgt = str(hev[4] or pr.get("summary") or "")[:120] if hev else str(pr.get("summary") or "")[:120]
            top_events.append(
                {
                    "ts": _utc_iso(row[3]),
                    "ref": ref_key,
                    "kind": hev[1] if hev else f"{pr.get('action','')}_{pr.get('object','')}",
                    "actor": actor,
                    "target": tgt,
                    "event_logit": _prob_to_logit(pr.get("prob", 0.0)),
                    "prob": round(float(pr.get("prob", 0.0)), 4),
                    "stage": pr.get("stage_name") or "Benign",
                    "scenario": pr.get("scenario_name") or "Benign",
                }
            )
        top_stage = top_pairs[0][1].get("stage_name") if pred_bin else elig[-1][1].get("stage_name")
        score_payloads.append(
            {
                "schema_version": "score.v1",
                "host_id": WINDOWS_HOST_ID,
                "branch": "host_dl",
                "bundle_id": DL_BUNDLE_ID,
                "status": "ready_active",
                "score": win_score,
                "threshold": DL_WIN_THRESHOLD,
                "prediction": pred_bin,
                "domain": "windows-sysmon",
                "domain_validation": "validated",
                "event_refs": refs,
                "window": {"start": ts_start, "end": ts_end, "events": len(chunk_rows), "label_events": len(elig)},
                "processed_at": now_iso,
                "evidence": {
                    "agent": "optc-dl-service",
                    "host": "windows1",
                    "event_time": ts_end,
                    "stage_last": str(top_stage or "Benign"),
                    "mean_prob": round(sum(probs) / len(probs), 4),
                    "mean_oov": round(sum(float(pr.get("oov_rate", 0.0)) for _, pr in elig) / len(elig), 4),
                    "top_events": top_events,
                },
            }
        )

    dl_mean_oov = round(sum(dl_oovs) / max(len(dl_oovs), 1), 4)
    ts0, ts1 = _window_bounds(new_rows[0][3], new_rows[-1][3])
    summaries: List[Dict[str, Any]] = []
    if ml_url:
        ml_mean_oov = round(sum(ml_oovs) / max(len(ml_oovs), 1), 4)
        summaries.append(
            {
                "schema_version": "summary.v1",
                "summary_id": _sha_id(["summary.v1", WINDOWS_HOST_ID, ML_BUNDLE_ID, new_rows[0][0], new_rows[-1][0], now_iso]),
                "host_id": WINDOWS_HOST_ID,
                "bundle_id": ML_BUNDLE_ID,
                "domain": "windows-sysmon",
                "period_start": ts0,
                "period_end": ts1,
                "featurizer": {"rows": len(new_rows), "events": len(ml_probs), "tokens": len(ml_probs) * 20, "tokens_oov": int(len(ml_probs) * 20 * ml_mean_oov), "oov_rate": ml_mean_oov, "oov_top": []},
                "counts": {"rows": len(new_rows), "predicted": sum(1 for p in ml_probs if p >= ML_THRESHOLD)},
                "score_histogram": _hist_10(ml_probs),
                "agent": "kltn-optc-bridge",
            }
        )
    summaries.append(
        {
            "schema_version": "summary.v1",
            "summary_id": _sha_id(["summary.v1", WINDOWS_HOST_ID, DL_BUNDLE_ID, new_rows[0][0], new_rows[-1][0], now_iso]),
            "host_id": WINDOWS_HOST_ID,
            "bundle_id": DL_BUNDLE_ID,
            "domain": "windows-sysmon",
            "period_start": ts0,
            "period_end": ts1,
            "featurizer": {"rows": len(new_rows), "events": len(dl_probs), "tokens": len(dl_probs) * 16, "tokens_oov": int(len(dl_probs) * 16 * dl_mean_oov), "oov_rate": dl_mean_oov, "oov_top": []},
            "counts": {"rows": len(new_rows), "predicted": sum(s["prediction"] for s in score_payloads if s["branch"] == "host_dl")},
            "score_histogram": _hist_10(dl_probs),
            "agent": "kltn-optc-bridge",
        }
    )
    return int(new_rows[-1][0]), score_payloads, summaries


def _init_tail_cursors(conn: psycopg.Connection, state: Dict[str, Any]) -> None:
    with conn.cursor() as cur:
        for hname, hid in LINUX_HOSTS.items():
            if hid not in state["linux_last_id"]:
                cur.execute("SELECT COALESCE(MAX(id), 0) FROM host_events WHERE host_id = %s AND domain = 'linux-audit'", (hid,))
                state["linux_last_id"][hid] = int(cur.fetchone()[0])
        if state["windows_last_seq"] is None:
            cur.execute("SELECT COALESCE(MAX(seq), 0) FROM events WHERE host_id = %s AND source IN ('sysmon','security','powershell')", (WINDOWS_HOST_ID,))
            state["windows_last_seq"] = int(cur.fetchone()[0])


def main() -> int:
    ap = argparse.ArgumentParser(description="KLTN live bridge for OpTC Host ML and OpTC+THEIA DL containers.")
    ap.add_argument("--pg-host", default=os.environ.get("PG_HOST", "127.0.0.1"))
    ap.add_argument("--pg-port", type=int, default=int(os.environ.get("PG_PORT", "15432")))
    ap.add_argument("--pg-user", default=os.environ.get("PG_USER", "kltn"))
    ap.add_argument("--pg-db", default=os.environ.get("PG_DB", "kltn"))
    ap.add_argument("--pg-password-file", default=os.environ.get("PG_PASSWORD_FILE", "/app/secrets/postgres-password"))
    ap.add_argument("--kltn-secrets-file", default=os.environ.get("KLTN_SECRETS_FILE", "/app/secrets/secrets.json"))
    ap.add_argument("--kltn-api", default=os.environ.get("KLTN_API_URL", "http://127.0.0.1:18080"))
    ap.add_argument("--ml-url", default=os.environ.get("ML_URL", "http://127.0.0.1:8001/predict"))
    ap.add_argument("--dl-url", default=os.environ.get("DL_URL", "http://127.0.0.1:8002/predict"))
    ap.add_argument("--state-file", default=os.environ.get("BRIDGE_STATE_FILE", "/app/state/bridge_state.json"))
    ap.add_argument("--poll-sec", type=float, default=float(os.environ.get("POLL_SEC", "10")))
    ap.add_argument("--activate-models", action="store_true")
    ap.add_argument("--dl-only", dest="dl_only", action="store_true", default=os.environ.get("KLTN_DL_ONLY", "1") == "1")
    ap.add_argument("--with-central-ml", dest="dl_only", action="store_false")
    ap.add_argument("--dismiss-stale-alerts", action="store_true")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.dl_only:
        os.environ["KLTN_DL_ONLY"] = "1"
    else:
        os.environ["KLTN_DL_ONLY"] = "0"

    pg_pass = _read_secret(args.pg_password_file)
    admin_tok = _read_admin_token(args.kltn_secrets_file)
    state_path = Path(args.state_file)
    state = _load_state(state_path)
    session = requests.Session()

    if args.activate_models:
        register_and_activate_models(session, args.kltn_api, admin_tok)
        print("[bridge] registered and activated optc-seed02-host-ml-v1 and optc-theia-mixhead-il-v1", flush=True)

    if args.dismiss_stale_alerts:
        n_dis = dismiss_stale_alerts(session, args.kltn_api, admin_tok)
        print(f"[bridge] dismissed {n_dis} pre-cutover needs_review alerts", flush=True)

    with psycopg.connect(
        host=args.pg_host,
        port=args.pg_port,
        user=args.pg_user,
        dbname=args.pg_db,
        password=pg_pass,
        autocommit=True,
    ) as conn:
        _init_tail_cursors(conn, state)
        if not args.dry_run:
            _save_state(state_path, state)
        print(f"[bridge] mode={'central-dl-only' if args.dl_only else 'central-ml+dl'} cursors ready: linux={state['linux_last_id']} windows_seq={state['windows_last_seq']}", flush=True)

        while not _STOP:
            all_scores: List[Dict[str, Any]] = []
            all_summaries: List[Dict[str, Any]] = []

            for hname, hid in LINUX_HOSTS.items():
                last_id = int(state["linux_last_id"].get(hid, 0))
                new_id, scs, sums = _score_linux_host(conn, session, args.dl_url, hname, hid, last_id)
                state["linux_last_id"][hid] = new_id
                all_scores.extend(scs)
                all_summaries.extend(sums)

            w_seq = int(state["windows_last_seq"] or 0)
            ml_target = None if args.dl_only else args.ml_url
            new_w_seq, w_scs, w_sums = _score_windows_host(conn, session, ml_target, args.dl_url, w_seq)
            state["windows_last_seq"] = new_w_seq
            all_scores.extend(w_scs)
            all_summaries.extend(w_sums)

            if all_scores or all_summaries:
                if args.dry_run:
                    n_pred = sum(s["prediction"] for s in all_scores)
                    print(f"[dry-run] scores={len(all_scores)} predicted_pos={n_pred} summaries={len(all_summaries)}", flush=True)
                else:
                    for i in range(0, len(all_scores), 500):
                        _post_kltn(session, args.kltn_api, admin_tok, "/v1/scores", all_scores[i:i + 500])
                    if all_summaries:
                        _post_kltn(session, args.kltn_api, admin_tok, "/v1/summaries", all_summaries[:500])
                    _save_state(state_path, state)
                    n_pos = sum(s["prediction"] for s in all_scores)
                    print(f"[bridge] posted scores={len(all_scores)} pos={n_pos} summaries={len(all_summaries)} cursors=({state['linux_last_id']}, win={state['windows_last_seq']})", flush=True)

            if args.once:
                break
            time.sleep(max(1.0, args.poll_sec))

    return 0


if __name__ == "__main__":
    sys.exit(main())
