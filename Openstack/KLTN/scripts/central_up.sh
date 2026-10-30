#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$root/scripts/prepare_central.py"
# Compose v5's Bake requires extra host-network entitlement. Build explicitly.
docker build --network host -t kltn-central:pilot "$root/central"
docker compose -f "$root/central/compose.yaml" up -d --no-build
