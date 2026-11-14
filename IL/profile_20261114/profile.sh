#!/usr/bin/env bash
# Resource profile of the final IL configs (1 seed each), written to a new dir only.
set -u
P=/mnt/SSD_Data/optc/IL/profile_20261114
D=/mnt/SSD_Data/optc/IL/dataset_2-AInception/output
prof() {  # name cmd...
  local name=$1; shift
  nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv,noheader,nounits -lms 500 > $P/$name.gpu.csv &
  local g=$!
  /usr/bin/time -v -o $P/$name.time "$@" > $P/$name.log 2>&1
  kill $g
}
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
prof dl_step2 python3 optc_il/train_il.py --data output/bilstm_v9_20261112/dataset_v9b_stage_optc.pkl --out $P/runs/dl_step2 --seed 42 --schedule freeze --replay 1
cd /mnt/SSD_Data/optc/IL/dataset_2-AInception/code/DL
prof dl_step3 python3 train_il_step3_v2.py --out $P/runs/dl_step3 --seed 42 --sl700-data $D/sl700_windows_v3/dataset.pkl --events-dir $D/rootcause_20261113/events_v3 --schedule freeze --replay-optc 1 --replay-atlas 1 --select all --bag-groups g_ev,g_par,g_ses
cd /mnt/SSD_Data/optc/IL/dataset_2-AInception/code/ML
prof ml_step3 python3 train_ml_il_step3.py --out $P/runs/ml_step3 --config ecar_lx --mode inc --seed 1 --rep-pos-alpha 0.5
prof ml_step3_scratch python3 train_ml_il_step3.py --out $P/runs/ml_step3_scratch --config ecar_lx --mode scratch --seed 1
echo PROFILE_DONE > $P/DONE
