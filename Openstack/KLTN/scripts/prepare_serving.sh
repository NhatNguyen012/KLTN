#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/runtime/venv/bin/python"
export ANSIBLE_CONFIG="$ROOT/ansible/ansible.cfg"
"$PY" "$ROOT/scripts/fetch_serving_assets.py"
"$PY" "$ROOT/scripts/prepare_serving.py"
docker build --network host -t kltn-dl:prepared "$ROOT/serving/central"
docker compose -f "$ROOT/central/compose.yaml" --profile model-prep up -d --no-build dl-prep
"$ROOT/runtime/venv/bin/ansible-playbook" "$ROOT/ansible/prepare-serving.yml"
"$PY" - "$ROOT/runtime" <<'PY'
from pathlib import Path
import os,sys,yaml
root=Path(sys.argv[1]); p=root/'inventory.yml'
inv=yaml.safe_load(p.read_text()); inv['all']['vars']['endpoint_agent_enabled']=True
q=p.with_suffix('.tmp');q.write_text(yaml.safe_dump(inv));q.chmod(0o600);q.replace(p)
(root/'serving-enabled').touch(mode=0o600)
PY
