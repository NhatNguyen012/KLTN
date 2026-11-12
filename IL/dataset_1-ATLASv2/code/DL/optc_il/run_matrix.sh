#!/usr/bin/env bash
# OpTC -> ATLASv2 DL incremental learning: 6 settings x 3 seeds, two GPU lanes (~25 min on RTX 3050).
# Usage: bash optc_il/run_matrix.sh [output_dir]   (refuses a non-empty run dir per run)
set -u
cd "$(dirname "$0")/.."
DATA=output/bilstm_v9_20261112/dataset_v9b_stage_optc.pkl
O=${1:-output/optc_il_20261112}
mkdir -p "$O/runs" "$O/logs"
run() {  # name seed extra-args...
  local name=$1 seed=$2; shift 2
  local d="$O/runs/${name}_s${seed}"
  if [ -e "$d/result.json" ]; then echo "skip $d"; return; fi
  python3 optc_il/train_il.py --data "$DATA" --out "$d" --seed "$seed" "$@" > "$O/logs/${name}_s${seed}.log" 2>&1
}
lane1() {
  for s in 42 43 44; do run freeze_replay $s --schedule freeze --replay 1; done
  for s in 42 43 44; do run full_noreplay $s --schedule full --replay 0; done
  for s in 42 43 44; do run full_noreplay_selatlas $s --schedule full --replay 0 --select atlas; done
}
lane2() {
  for s in 42 43 44; do run full_replay $s --schedule full --replay 1; done
  for s in 42 43 44; do run freeze_noreplay $s --schedule freeze --replay 0; done
  for s in 42 43 44; do run scratch_full_noreplay_selatlas $s --init random --schedule full --replay 0 --select atlas; done
}
lane1 & lane2 & wait
python3 optc_il/summarize.py "$O/runs"
echo MATRIX_DONE
