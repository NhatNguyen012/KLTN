#!/bin/bash
# Reproduce the v9 single-BiLSTM result from raw CBC-EDR (read-only) into a NEW output dir.
set -euo pipefail
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=${1:-output/bilstm_v9_repro_$(date +%Y%m%d_%H%M)}
[ -e "$O" ] && { echo "refusing to reuse $O"; exit 1; }
python3 bilstm_v9/parse_events.py --out "$O"
python3 bilstm_v9/build_dataset.py --work "$O" --out-name dataset_v9b_stage.pkl
for s in 42 43 44 45 46; do
  python3 bilstm_v9/train.py --data "$O/dataset_v9b_stage.pkl" --out "$O/runs/v9b_noip_s$s" \
    --label v9b --drop-fields ip_scope --lr 5e-4 --epochs 20 --stage-w 0.5 --seed $s | tail -4
done
python3 bilstm_v9/summarize.py "$O/runs"
python3 bilstm_v9/summarize_stage.py "$O/runs"
