#!/usr/bin/env bash
# IL step 3 (OpTC -> ATLASv2 -> AInception SL700): 4 settings x 3 seeds on two GPU lanes.
# Usage: bash run_matrix_step3.sh [output_dir]     (a finished run, i.e. with result.json, is skipped)
set -u
cd "$(dirname "$0")"
O=${1:-../../output/il_step3_20261113}
mkdir -p "$O/runs" "$O/logs"
run() {  # name seed extra-args...
  local name=$1 seed=$2; shift 2
  local d="$O/runs/${name}_s${seed}"
  if [ -e "$d/result.json" ]; then echo "skip $d"; return; fi
  rm -rf "$d"
  python3 train_il_step3.py --out "$d" --seed "$seed" "$@" > "$O/logs/${name}_s${seed}.log" 2>&1
}
lane1() {
  for s in 42 43 44; do run freeze_replay2 $s --schedule freeze --replay-optc 1 --replay-atlas 1 --select all; done
  for s in 42 43 44; do run full_noreplay_selsl $s --schedule full --replay-optc 0 --replay-atlas 0 --select sl700; done
}
lane2() {
  for s in 42 43 44; do run freeze_replayoptc $s --schedule freeze --replay-optc 1 --replay-atlas 0 --select all; done
  for s in 42 43 44; do run scratch_selsl $s --init random --schedule full --replay-optc 0 --replay-atlas 0 --select sl700; done
}
lane1 & lane2 & wait
echo MATRIX_DONE
