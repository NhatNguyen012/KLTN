#!/usr/bin/env python3
"""Evaluation & Model Registry: log a bundle to MLflow (params, offline metrics, parity evidence, the bundle itself)
and register it as a version of `kltn-host-ml` / `kltn-host-dl`; then record it (stage candidate) in the central
deployment ledger. Aliases: `candidate` on registration; `champion` is set by --champion only after the operator
activated the bundle through the API (POST /v1/models/{id}/activate).

Usage: mlflow_register.py <bundle_dir> [--champion] [--tracking http://127.0.0.1:15000] [--experiment kltn-il]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_NAMES = {"host_ml": "kltn-host-ml", "host_dl": "kltn-host-dl"}


def flat_metrics(prefix: str, obj, out: dict):
    if isinstance(obj, dict):
        for k, v in obj.items():
            flat_metrics(f"{prefix}.{k}" if prefix else str(k), v, out)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        out[prefix.replace(" ", "_")[:250]] = float(obj)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--tracking", default="http://127.0.0.1:15000")
    ap.add_argument("--experiment", default="kltn-il")
    ap.add_argument("--champion", action="store_true")
    ap.add_argument("--central", default="http://127.0.0.1:18080")
    a = ap.parse_args()
    import mlflow
    from mlflow import MlflowClient
    bundle = Path(a.bundle).resolve()
    m = json.loads((bundle / "manifest.json").read_text())
    parity = json.loads((bundle / "evidence/parity.json").read_text())
    mlflow.set_tracking_uri(a.tracking)
    mlflow.set_experiment(a.experiment)
    client = MlflowClient()
    name = MODEL_NAMES[m["branch"]]
    with mlflow.start_run(run_name=m["bundle_id"]) as run:
        mlflow.set_tags({"bundle_id": m["bundle_id"], "branch": m["branch"], "algorithm": m["algorithm"],
                         "parity_passed": str(m["parity"]["passed"]), "eligible": str(m["activation"]["eligible"]),
                         **{f"domain.{d}": v["validation"] for d, v in m["domains"].items()}})
        params = {"schema": m["schema_version"], "lineage": " -> ".join(x["domain"] for x in m["lineage"])}
        if m["branch"] == "host_ml":
            params.update(width=m["feature_contract"]["width"], trees=m["model"]["num_trees"],
                          composition=m["model"]["composition"][:250])
        else:
            params.update(seed=m["model"]["seed"], window=json.dumps(m["window"]))
        for d, v in m["domains"].items():
            params[f"threshold.{d}"] = v.get("threshold", v.get("threshold_logit"))
        mlflow.log_params(params)
        metrics = {}
        for d, v in m["domains"].items():
            flat_metrics(f"offline.{d}", v.get("offline_test") or v.get("offline"), metrics)
        flat_metrics("parity", {k: v for k, v in parity.items() if k not in ("verified_at",)}, metrics)
        mlflow.log_metrics(metrics)
        mlflow.log_artifacts(str(bundle), artifact_path="bundle")
        uri = f"runs:/{run.info.run_id}/bundle"
    try:
        client.create_registered_model(name, description=f"KLTN {m['branch']} (IL: OpTC -> ATLASv2 -> SL700 and later steps)")
    except Exception:
        pass
    mv = client.create_model_version(name, uri, run_id=run.info.run_id, tags={"bundle_id": m["bundle_id"]},
                                     description=f"{m['bundle_id']} parity={m['parity']['passed']}")
    client.set_registered_model_alias(name, "candidate", mv.version)
    if a.champion:
        client.set_registered_model_alias(name, "champion", mv.version)
    info = {"tracking_uri": a.tracking, "run_id": run.info.run_id, "model": name, "version": int(mv.version),
            "aliases": ["candidate"] + (["champion"] if a.champion else [])}
    secrets = json.loads((ROOT / "runtime/secrets.json").read_text())
    req = urllib.request.Request(f"{a.central}/v1/models", method="POST",
                                 data=json.dumps({"manifest": m, "mlflow": info}).encode(),
                                 headers={"Authorization": "Bearer " + secrets["admin_token"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        ledger = json.loads(r.read())
    print(json.dumps({"mlflow": info, "ledger": ledger}))


if __name__ == "__main__":
    sys.exit(main())
