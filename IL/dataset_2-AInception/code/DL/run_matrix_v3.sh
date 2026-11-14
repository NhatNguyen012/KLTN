#!/usr/bin/env bash
# IL step 3 on relabel_v3 labels (sl700_windows_v3 / events_v3): input v1 vs Linux token bag (+ login/connection
# address scope), freeze + OpTC/ATLASv2 replay, and the scratch baseline; 3 seeds, two GPU lanes.
# Usage: bash run_matrix_v3.sh [output_dir]      (a finished run, i.e. with result.json, is skipped)
set -u
cd "$(dirname "$0")"
O=${1:-../../output/il_step3v3_20261113}
D=/mnt/SSD_Data/optc/IL/dataset_2-AInception/output
mkdir -p "$O/runs" "$O/logs"
run() {  # name seed extra-args...
  local name=$1 seed=$2; shift 2
  local d="$O/runs/${name}_s${seed}"
  if [ -e "$d/result.json" ]; then echo "skip $d"; return; fi
  rm -rf "$d"
  python3 train_il_step3_v2.py --out "$d" --seed "$seed" --sl700-data $D/sl700_windows_v3/dataset.pkl \
    --events-dir $D/rootcause_20261113/events_v3 "$@" > "$O/logs/${name}_s${seed}.log" 2>&1
}
FR="--schedule freeze --replay-optc 1 --replay-atlas 1 --select all"
SC="--init random --schedule full --epochs 40 --replay-optc 0 --replay-atlas 0 --select sl700"
lane1() {
  for s in 42 43 44; do run v1in_freeze_replay2 $s $FR --bag-groups none; done
  for s in 42 43 44; do run bagscope_freeze_replay2 $s $FR --bag-groups g_ev,g_par,g_ses,g_scope; done
}
lane2() {
  for s in 42 43 44; do run bag_freeze_replay2 $s $FR --bag-groups g_ev,g_par,g_ses; done
  for s in 42 43 44; do run bagscope_scratch_ep40 $s $SC --bag-groups g_ev,g_par,g_ses,g_scope; done
}
lane1 & lane2 & wait
echo MATRIX_DONE
