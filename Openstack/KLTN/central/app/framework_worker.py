"""Context-aware fusion, incidents, drift monitoring and incremental-learning triggers (CENTRAL VM).

* Fusion: every (host, 5-minute event-time bucket) that received new scores is (re)fused with the policy in
  framework.FUSION_POLICY (idempotent upsert, so late scores update their bucket; no ledger, no starvation).
* Incidents: positive buckets of a host closer than 15 minutes are one alert (SOC verification unit); the alert keeps
  the strongest ML events / DL windows, auditd rule hits and whether any contributing branch is shadow (unvalidated).
* Drift (hourly, per host): endpoint OOV-token rate and score histogram (summary.v1), DL input OOV, event-kind mix,
  each against the host's first 24 h (reference) and an absolute OOV ceiling.
* IL triggers (General Architecture: drift || scheduled || enough data): approval-gated training requests per branch.
Nothing here trains, deploys or isolates a host.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from common import DDL, db_connect
from framework import (FUSION_POLICY, ContractError, alert_severity_rank, canonical_hash, fuse_bucket,
                       population_stability_index)

SERVICE = "framework-worker"
BUCKET = FUSION_POLICY["bucket_seconds"]
GAP = timedelta(seconds=FUSION_POLICY["incident_gap_seconds"])
OOV_CEILING = 0.20           # absolute OOV-token rate that always counts as drift
OOV_RATIO = 1.5              # or 1.5x the host's reference rate
PSI_DRIFT = 0.25
MIN_LABELS = 50              # verified SOC labels (confirmed + false positive) since the last training of a branch
MIN_CONFIRMED = 3            # = scripts/il/dataset.MIN_INCIDENTS: fewer confirmed attack alerts can never pass the gate
SCHEDULE_DAYS = 7


def bucket_of(t: datetime) -> datetime:
    s = int(t.timestamp())
    return datetime.fromtimestamp(s - s % BUCKET, tz=timezone.utc)


def cursor(conn, name, default):
    row = conn.execute("SELECT value FROM framework_cursors WHERE name=%s", (name,)).fetchone()
    return row[0] if row else default


def set_cursor(conn, name, value):
    conn.execute('''INSERT INTO framework_cursors(name,value) VALUES (%s,%s) ON CONFLICT(name) DO UPDATE
      SET value=excluded.value, updated_at=now()''', (name, Jsonb(value)))


# ------------------------------------------------------------------------------------------------ fusion
def fuse_pending(conn) -> dict:
    cur = cursor(conn, "fusion-il3", {"seq": 0})
    rows = conn.execute('''SELECT host_id, event_time, seq FROM scores WHERE seq > %s ORDER BY seq LIMIT 20000''',
                        (cur["seq"],)).fetchall()
    if not rows:
        return {"buckets": 0, "alerts": 0}
    keys = sorted({(h, bucket_of(t)) for h, t, _ in rows if t is not None})
    alerts = 0
    for host_id, b in keys:
        srows = conn.execute('''SELECT score_id,branch,bundle_id,status,score,threshold,prediction,domain,domain_validation,
          event_refs,score_window,evidence,event_time FROM scores WHERE host_id=%s AND event_time>=%s AND event_time<%s''',
                             (host_id, b, b + timedelta(seconds=BUCKET))).fetchall()
        payload = [dict(zip(("score_id", "branch", "bundle_id", "status", "score", "threshold", "prediction", "domain",
                             "domain_validation", "event_refs", "score_window", "evidence", "event_time"), r)) for r in srows]
        hits = dict(Counter(k for (keys_,) in conn.execute(
            '''SELECT rule_keys FROM host_events WHERE host_id=%s AND ts>=%s AND ts<%s AND rule_keys IS NOT NULL
               AND cardinality(rule_keys)>0''', (host_id, b, b + timedelta(seconds=BUCKET))).fetchall() for k in keys_).most_common(10))
        try:
            f = fuse_bucket(host_id, b, payload, hits)
        except ContractError:
            continue
        conn.execute('''INSERT INTO fusion_results(fusion_id,host_id,bucket_start,bucket_end,algorithm,policy_version,
          risk_score,threshold,prediction,source_mask,score_refs,evidence) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
          ON CONFLICT (fusion_id) DO UPDATE SET risk_score=excluded.risk_score, prediction=excluded.prediction,
          source_mask=excluded.source_mask, score_refs=excluded.score_refs, evidence=excluded.evidence, updated_at=now()''',
                     (f["fusion_id"], host_id, f["bucket_start"], f["bucket_end"], f["algorithm"], f["policy_version"],
                      f["risk_score"], f["threshold"], f["prediction"], Jsonb(f["source_mask"]), Jsonb(f["score_refs"]),
                      Jsonb(f["evidence"])))
        if f["prediction"]:
            alerts += attach_incident(conn, f)
    set_cursor(conn, "fusion-il3", {"seq": rows[-1][2]})
    return {"buckets": len(keys), "alerts": alerts}


def attach_incident(conn, f) -> int:
    """Join the host's open incident if the bucket is within the gap, otherwise open a new alert.
    A bucket an analyst already reviewed (late scores re-fuse it) opens nothing unless its risk went up."""
    seen = conn.execute('''SELECT (evidence->'buckets'->(%s::text)->>'risk')::float8 FROM alerts WHERE host_id=%s
      AND state<>'needs_review' AND fusion_ids ? (%s::text) ORDER BY updated_at DESC LIMIT 1''',
                        (f["bucket_start"].isoformat(), f["host_id"], f["fusion_id"])).fetchone()
    if seen is not None and seen[0] is not None and f["risk_score"] <= seen[0] + 1e-9:
        return 0
    row = conn.execute('''SELECT alert_id, risk_score, severity, evidence, fusion_ids, shadow FROM alerts
      WHERE host_id=%s AND state='needs_review' AND last_seen >= %s AND first_seen <= %s
      ORDER BY last_seen DESC LIMIT 1''', (f["host_id"], f["bucket_start"] - GAP, f["bucket_end"] + GAP)).fetchone()
    ev_new = {"policy_version": f["policy_version"], "buckets": {f["bucket_start"].isoformat(): {
        "risk": f["risk_score"], "severity": f["severity"], "source_mask": f["source_mask"],
        "branches": f["evidence"]["branches"], "rule_hits": f["evidence"]["rule_hits"]}},
        "ml_events": f["evidence"]["ml_events"], "dl_windows": f["evidence"]["dl_windows"]}
    if row is None:
        alert_id = canonical_hash(["alert.v2", f["host_id"], f["bucket_start"].isoformat()])
        conn.execute('''INSERT INTO alerts(alert_id,host_id,risk_score,severity,shadow,first_seen,last_seen,fusion_ids,evidence)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (alert_id) DO NOTHING''',
                     (alert_id, f["host_id"], f["risk_score"], f["severity"], f["shadow"], f["bucket_start"], f["bucket_end"],
                      Jsonb([f["fusion_id"]]), Jsonb(ev_new)))
        return 1
    alert_id, risk, sev, ev, fids, shadow = row
    buckets = dict(ev.get("buckets", {}))
    buckets.update(ev_new["buckets"])
    ml = {e["score_id"]: e for e in ev.get("ml_events", []) + ev_new["ml_events"]}
    dl = {w["score_id"]: w for w in ev.get("dl_windows", []) + ev_new["dl_windows"]}
    merged = {"policy_version": f["policy_version"], "buckets": buckets,
              "ml_events": sorted(ml.values(), key=lambda e: -e["score"])[:50],
              "dl_windows": sorted(dl.values(), key=lambda w: -w["score"])[:20]}
    new_sev = sev if alert_severity_rank(sev) >= alert_severity_rank(f["severity"]) else f["severity"]
    conn.execute('''UPDATE alerts SET risk_score=%s, severity=%s, shadow=%s, first_seen=LEAST(first_seen,%s),
      last_seen=GREATEST(last_seen,%s), fusion_ids=%s, evidence=%s, updated_at=now() WHERE alert_id=%s''',
                 (max(risk, f["risk_score"]), new_sev, shadow or f["shadow"], f["bucket_start"], f["bucket_end"],
                  Jsonb(sorted(set(fids) | {f["fusion_id"]})), Jsonb(merged), alert_id))
    return 0


# ------------------------------------------------------------------------------------------------ drift
def drift_tick(conn, now: datetime) -> dict:
    last = cursor(conn, "drift-il3", {"at": "1970-01-01T00:00:00+00:00"})
    if now - datetime.fromisoformat(last["at"]) < timedelta(hours=1):
        return {"skipped": True}
    states = {}
    # The reference is the first 24 h of the host's CURRENT bundle (a new model changes scores and vocabulary), started
    # no earlier than the operator's re-baseline mark (scripts/drift_baseline.py, e.g. after a sensor change).
    baseline = cursor(conn, "drift-baseline", {})
    hosts = conn.execute('''SELECT DISTINCT ON (host_id) host_id, domain, bundle_id FROM endpoint_summaries
      ORDER BY host_id, period_end DESC''').fetchall()
    for host_id, domain, bundle in hosts:
        first = conn.execute('SELECT min(period_start) FROM endpoint_summaries WHERE host_id=%s AND bundle_id=%s',
                             (host_id, bundle)).fetchone()[0]
        mark = baseline.get(host_id) or baseline.get("*")
        if mark:
            first = max(first, datetime.fromisoformat(mark["from"]))
        ref_end = first + timedelta(hours=24)
        def agg(start, end):
            rows = conn.execute('''SELECT payload FROM endpoint_summaries WHERE host_id=%s AND bundle_id=%s AND period_start>=%s
              AND period_end<=%s''', (host_id, bundle, start, end)).fetchall()
            tok = sum((p["featurizer"]["tokens"] or 0) for (p,) in rows)
            oov = sum((p["featurizer"]["tokens_oov"] or 0) for (p,) in rows)
            hist = [0] * 10
            top = Counter()
            for (p,) in rows:
                hist = [a + b for a, b in zip(hist, p.get("score_histogram", [0] * 10))]
                top.update(dict(p["featurizer"].get("oov_top", [])))
            return {"rows": sum(p["counts"]["rows"] for (p,) in rows), "oov_rate": oov / tok if tok else None, "hist": hist,
                    "oov_top": top.most_common(50)}
        if now < ref_end:
            states[host_id] = "reference_building"
            continue
        cur_start = max(now - timedelta(hours=24), ref_end)      # never overlaps the reference
        ref, cur = agg(first, ref_end), agg(cur_start, now)
        psi = population_stability_index({str(i): v for i, v in enumerate(ref["hist"])}, {str(i): v for i, v in enumerate(cur["hist"])})
        oov_drift = cur["oov_rate"] is not None and (cur["oov_rate"] >= OOV_CEILING or
                                                     (ref["oov_rate"] and cur["oov_rate"] >= OOV_RATIO * ref["oov_rate"]))
        state = "insufficient_data" if cur["rows"] < 1000 else ("drift" if oov_drift or (psi or 0) >= PSI_DRIFT else "stable")
        states[host_id] = state
        conn.execute('''INSERT INTO drift_snapshots(snapshot_id,branch,domain,host_id,window_start,window_end,sample_count,
          metric,value,threshold,state,details) VALUES (%s,'host_ml',%s,%s,%s,%s,%s,'oov_rate+score_psi',%s,%s,%s,%s)
          ON CONFLICT(snapshot_id) DO NOTHING''',
                     (canonical_hash(["drift.v2", host_id, now.strftime("%Y-%m-%dT%H")]), domain, host_id,
                      cur_start, now, cur["rows"], cur["oov_rate"], OOV_CEILING, state,
                      Jsonb({"score_psi": psi, "bundle_id": bundle, "reference_window": [first.isoformat(), ref_end.isoformat()],
                             "baseline_mark": mark, "reference": ref, "current": cur})))
    set_cursor(conn, "drift-il3", {"at": now.isoformat(), "states": states})
    return {"states": states}


# ------------------------------------------------------------------------------------------------ IL triggers
def lifecycle_tick(conn, now: datetime) -> list[str]:
    created = []
    for branch in ("host_ml", "host_dl"):
        last = conn.execute('''SELECT max(completed_at) FROM training_requests WHERE branch=%s AND state='completed' ''',
                            (branch,)).fetchone()[0] or datetime(1970, 1, 1, tzinfo=timezone.utc)
        labels = conn.execute('''SELECT count(*), count(*) FILTER (WHERE decision='confirmed') FROM alert_reviews
          WHERE decision IN ('confirmed','false_positive') AND created_at > %s''', (last,)).fetchone()
        drift_hosts = [r[0] for r in conn.execute('''SELECT DISTINCT host_id FROM drift_snapshots
          WHERE state='drift' AND created_at > now() - interval '24 hours' ''').fetchall()]
        common = {"since": last.isoformat(), "verified_labels": labels[0], "confirmed_attacks": labels[1],
                  "drift_hosts": drift_hosts}

        def request(trigger: str, identity: str):
            rid = canonical_hash(["training.v2", branch, trigger, identity])
            row = conn.execute('''INSERT INTO training_requests(request_id,branch,trigger_type,dataset_query,trigger_evidence)
              VALUES (%s,%s,%s,%s,%s) ON CONFLICT(request_id) DO NOTHING RETURNING request_id''',
                               (rid, branch, trigger, Jsonb({"from": last.isoformat(), "to": now.isoformat(),
                                                             "labels": ["confirmed", "false_positive"],
                                                             "benign_baseline": "reviewed hosts without open alerts"}),
                                Jsonb(common))).fetchone()
            if row:
                created.append(rid)

        # enough data / schedule only when the labels can pass the IL gate (false positives alone cannot: the gate
        # needs confirmed attack incidents to evaluate); drift always asks, since it also means "label this host".
        if labels[0] >= MIN_LABELS and labels[1] >= MIN_CONFIRMED:
            request("enough_data", f"{last.isoformat()}:{labels[0] // MIN_LABELS}")
        if drift_hosts:
            request("drift", now.date().isoformat())
        if now - last >= timedelta(days=SCHEDULE_DAYS) and labels[1] >= MIN_CONFIRMED:
            request("scheduled", now.strftime("%G-W%V"))
    return created


def tick() -> dict:
    now = datetime.now(timezone.utc)
    with db_connect() as conn:
        fused = fuse_pending(conn)
        drift = drift_tick(conn, now)
        training = lifecycle_tick(conn, now)
        pending = conn.execute("SELECT count(*) FROM alerts WHERE state='needs_review'").fetchone()[0]
        runtime = {"fusion_policy": FUSION_POLICY, "fusion": fused, "drift": drift, "training_requests_created": training,
                   "response_execution": "approval-gated external controller", "incremental_learning": "approval-gated IL service"}
        conn.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime) VALUES (%s,now(),'running',%s,%s)
          ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,state=excluded.state,pending=excluded.pending,
          runtime=excluded.runtime''', (SERVICE, pending, Jsonb(runtime)))
    return runtime


if __name__ == "__main__":
    with db_connect() as db:
        db.execute(DDL)
    print(json.dumps({"service": SERVICE, "state": "started", "policy": FUSION_POLICY["version"]}), flush=True)
    while True:
        try:
            r = tick()
            if r["fusion"].get("buckets"):
                print(json.dumps({"fusion": r["fusion"]}), flush=True)
        except Exception as exc:
            print(json.dumps({"service": SERVICE, "error": f"{type(exc).__name__}: {exc}"[:500]}), flush=True)
        time.sleep(10)
