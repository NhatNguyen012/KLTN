#!/bin/bash
# Dry-run driver: execute every action of one scenario back-to-back (no dwell). Usage: run_campaign.sh <L1..L5>
set +u  # resilient
SCN="${1:?scenario}"; DIR="$(cd "$(dirname "$0")"&&pwd)"
source "$DIR/lib_actions.sh"
acts=$(grep -E "^$SCN " "$DIR/scenarios.conf"|cut -d' ' -f2-)
[ -z "$acts" ] && { echo "no scenario $SCN"; exit 1; }
export RUNID="$SCN-$(date -u +%Y%m%dT%H%M%SZ)"; export GT="$HOME/gt_${RUNID}.jsonl"
echo "=== $RUNID start $(date -u +%FT%TZ) actions: $acts ==="
for a in $acts; do do_action "$a"; done
echo "=== $RUNID end $(date -u +%FT%TZ) GT=$GT ==="
