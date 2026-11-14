#!/usr/bin/env bash
# Roll out the bundles marked active in the central ledger (or given explicitly):
#   deploy_bundles.sh --host-ml runtime/releases/host-ml-il3-<tag> --host-dl runtime/releases/host-dl-il3-<tag> [--mode ready_shadow]
# host-ml -> every endpoint (Ansible, per-host readiness + self-test asserted); host-dl -> central DL worker.
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
py="$root/runtime/venv/bin/python"
mode=ready_shadow; ml=""; dl=""
while [[ $# -gt 0 ]]; do case "$1" in
  --host-ml) ml="$2"; shift 2;; --host-dl) dl="$2"; shift 2;; --mode) mode="$2"; shift 2;;
  *) echo "unknown argument $1"; exit 2;; esac; done
export ANSIBLE_CONFIG="$root/ansible/ansible.cfg"
if [[ -n "$dl" ]]; then "$py" "$root/scripts/stage_dl_bundle.py" "$(realpath "$dl")"; fi
if [[ -n "$ml" ]]; then
  "$root/runtime/venv/bin/ansible-playbook" "$root/ansible/deploy-host-model.yml" \
    -e host_model_bundle="$(realpath "$ml")" -e agent_mode="$mode"
fi
