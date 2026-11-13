#!/usr/bin/env bash
# Check of the transfer claim: same-architecture scratch baseline with 40 epochs (the 20-epoch runs peaked at epoch 19-20).
set -u
cd "$(dirname "$0")"
O=../../output/il_step3_20261113
run() { local s=$1; local d=$O/runs/scratch_selsl_ep40_s$s; [ -e $d/result.json ] && return; rm -rf $d
  python3 train_il_step3.py --out $d --seed $s --init random --schedule full --epochs 40 --replay-optc 0 --replay-atlas 0 --select sl700 > $O/logs/scratch_selsl_ep40_s$s.log 2>&1; }
(run 42; run 44) & (run 43) & wait
echo SCRATCH40_DONE
