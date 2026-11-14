#!/usr/bin/env bash
# Held-out-variant check on relabel_v3 labels: TEST = run e_a (cron persistence, unseen in training),
# VAL = a_c, TRAIN = a_a, a_b, b_a, f_a. Input v1 vs Linux token bag (+ address scope); seed 42.
# Lane B starts at once; lane A waits for run_matrix_v3.sh (at most two trainings on the 4 GB GPU).
set -u
cd "$(dirname "$0")"
O=${1:-../../output/il_step3v3_testea_20261113}
D=/mnt/SSD_Data/optc/IL/dataset_2-AInception/output
mkdir -p "$O/runs" "$O/logs"
run() {
  local name=$1 seed=$2; shift 2
  local d="$O/runs/${name}_s${seed}"
  if [ -e "$d/result.json" ]; then echo "skip $d"; return; fi
  rm -rf "$d"
  python3 train_il_step3_v2.py --out "$d" --seed "$seed" --sl700-data $D/sl700_windows_v3_test_ea/dataset.pkl \
    --events-dir $D/rootcause_20261113/events_v3 "$@" > "$O/logs/${name}_s${seed}.log" 2>&1
}
FR="--schedule freeze --replay-optc 1 --replay-atlas 1 --select all"
( until grep -q MATRIX_DONE $D/il_step3v3_matrix_driver.log 2>/dev/null; do sleep 30; done
  run ea_v1in_freeze_replay2 42 $FR --bag-groups none
  run ea_bagscope_freeze_replay2 42 $FR --bag-groups g_ev,g_par,g_ses,g_scope ) &
( run ea_bag_freeze_replay2 42 $FR --bag-groups g_ev,g_par,g_ses ) &
wait
echo TESTEA_DONE
