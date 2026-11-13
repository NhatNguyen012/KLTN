#!/usr/bin/env bash
# Bring up the IL3 central stack (General Architecture, CENTRAL VM) on the lab host.
#  1. private config from Terraform outputs (host tokens are kept), 2. images (central, DL CPU runtime, MLflow),
#  3. Postgres/NATS/API, 4. DB roles + host inventory + MLflow database, 5. every service.
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
py="$root/runtime/venv/bin/python"
compose=(docker compose -f "$root/central/compose.yaml")
"$py" "$root/scripts/prepare_central.py" "$@"
find "$root/serving" -name __pycache__ -type d -prune -exec rm -rf {} +
docker build --network host -f "$root/central/Dockerfile" -t kltn-central:il3 "$root"
docker build --network host -f "$root/serving/central/Dockerfile" -t kltn-dl:il3 "$root"
docker build --network host -t kltn-mlflow:il3 "$root/central/mlflow"
"${compose[@]}" up -d --no-build postgres nats api
"$py" "$root/scripts/prepare_serving.py"
"${compose[@]}" up -d --no-build
"${compose[@]}" ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
