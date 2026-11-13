#!/usr/bin/env bash
# ML IL step 3 (CPU). Final model: residual boosting + replay with replay-positive alpha 0.5 (chosen on the VAL sets of
# SL700, ATLASv2 and OpTC by eval_old_val.py among 0.25 / 0.5 / 0.8), three SL700 feature sets, 3 replay seeds.
# Ablations: alpha 0.25 (step-2 rule) and 0.8, no replay, scratch. A finished run (result.json) is skipped.
set -u
cd "$(dirname "$0")"
O=${1:-../../output/ml_il_step3_20261113}
mkdir -p "$O/runs" "$O/logs"
run() {
  local name=$1; shift
  [ -e "$O/runs/$name/result.json" ] && { echo "skip $name"; return; }
  rm -rf "$O/runs/$name"
  python3 train_ml_il_step3.py --out "$O/runs/$name" "$@" > "$O/logs/$name.log" 2>&1
}
for c in ecar_lx ecar ecar_lx_scope; do
  for s in 1 2 3; do
    run incA05_${c}_s$s --config $c --mode inc --seed $s --rep-pos-alpha 0.5
    run inc_${c}_s$s --config $c --mode inc --seed $s --rep-pos-alpha 0.25
  done
  run norep_${c}_s1 --config $c --mode inc --no-replay --seed 1
  run scratch_${c}_s1 --config $c --mode scratch --seed 1
done
for s in 1 2 3; do run incA08_ecar_lx_s$s --config ecar_lx --mode inc --seed $s --rep-pos-alpha 0.8; done
python3 eval_old_val.py "$O"/runs/inc*_s[123] "$O"/runs/norep_*_s1 > "$O/logs/eval_old_val.log" 2>&1
python3 summarize_ml_step3.py "$O/runs" > "$O/summary.md"
echo ML_MATRIX_DONE
