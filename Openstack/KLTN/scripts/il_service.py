#!/usr/bin/env python3
"""Incremental Learning Service (General Architecture, CENTRAL VM): approved training request -> candidate bundle.

  claim (approved -> running) -> export SOC-verified dataset (il/dataset.py) -> per trainable domain: IL step on the
  ACTIVE bundle of the branch (il/ml_step.py or il/dl_step.py) -> candidate bundle in runtime/releases ->
  MLflow run + model version (alias `candidate`) + central ledger -> request completed with metrics.
It never activates or deploys: an operator reviews the candidate in MLflow / the API, activates it
(POST /v1/models/{id}/activate) and rolls it out (scripts/deploy_bundles.sh). Requests whose data does not pass the
gates (incidents, attack/benign events, VAL+TEST attacks) end as `rejected_insufficient_data` with the counts.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "central/app"))
sys.path.insert(0, str(ROOT / "scripts"))
from common import db_connect  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

RELEASES = ROOT / "runtime/releases"


def active_bundle(conn, branch: str) -> Path:
    row = conn.execute("SELECT bundle_id FROM model_registry WHERE branch=%s AND stage='active'", (branch,)).fetchone()
    if not row:
        raise RuntimeError(f"no active {branch} bundle in the ledger")
    return RELEASES / row[0]


def claim(conn):
    row = conn.execute('''SELECT request_id, branch, dataset_query FROM training_requests WHERE state='approved'
      ORDER BY approved_at LIMIT 1 FOR UPDATE SKIP LOCKED''').fetchone()
    if row:
        conn.execute("UPDATE training_requests SET state='running', result=%s WHERE request_id=%s",
                     (Jsonb({"claimed_at": datetime.now(timezone.utc).isoformat()}), row[0]))
    return row


def finish(request_id: str, state: str, result: dict):
    with db_connect() as conn:
        conn.execute("UPDATE training_requests SET state=%s, result=%s, completed_at=now() WHERE request_id=%s",
                     (state, Jsonb(result), request_id))


def handle(request_id: str, branch: str, query: dict) -> tuple[str, dict]:
    from il import dataset
    with db_connect() as conn:
        parent = active_bundle(conn, branch)
        data = dataset.export(conn, query or {})
    summary = {d: {k: v for k, v in x.items() if k != "events"} for d, x in data["domains"].items()}
    trainable = [d for d, x in data["domains"].items() if x["trainable"]]
    if not trainable:
        return "rejected_insufficient_data", {"export": summary, "parent": parent.name,
                                              "gates": {"min_incidents": dataset.MIN_INCIDENTS, "min_attack_events": dataset.MIN_ATTACK_EVENTS,
                                                        "min_benign_events": dataset.MIN_BENIGN_EVENTS}}
    step = __import__("il.ml_step" if branch == "host_ml" else "il.dl_step", fromlist=["run"])
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
    results, current = [], parent
    for domain in trainable:
        out = RELEASES / f".building-{branch}-{domain}-{tag}"
        out.mkdir(parents=True)
        r = step.run(current, domain, data["domains"][domain], out, tag)
        final = RELEASES / r["bundle_id"]
        out.rename(final)
        reg = subprocess.run([sys.executable, str(ROOT / "scripts/mlflow_register.py"), str(final)], capture_output=True, text=True)
        r["mlflow"] = json.loads(reg.stdout.strip().splitlines()[-1]) if reg.returncode == 0 else {"error": reg.stderr[-500:]}
        results.append(r)
        current = final            # a second domain continues from the first candidate
    return "completed", {"export": summary, "parent": parent.name, "candidates": results}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--interval", type=int, default=60)
    a = ap.parse_args()
    while True:
        with db_connect() as conn:
            row = claim(conn)
        if row:
            rid, branch, query = row
            print(json.dumps({"request_id": rid, "branch": branch, "state": "running"}), flush=True)
            try:
                state, result = handle(rid, branch, query)
            except Exception as exc:
                state, result = "failed", {"error": f"{type(exc).__name__}: {exc}"[:1000], "trace": traceback.format_exc()[-3000:]}
            finish(rid, state, result)
            print(json.dumps({"request_id": rid, "state": state}), flush=True)
            continue
        if not a.daemon:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
