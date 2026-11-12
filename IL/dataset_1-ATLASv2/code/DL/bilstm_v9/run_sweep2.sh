#!/bin/bash
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=output/bilstm_v9_20261112
run() { name=$1; shift; for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset.pkl --out $O/sweep2/${name}_s$s --seed $s "$@" > $O/logs/${name}_s$s.log 2>&1; done; }
run v9_swa --select swa &
run v9_swa_wd --select swa --wd 0.01 &
run v9_swa_noextra --select swa --use-extra 0 &
wait
echo done > $O/logs/SWEEP2_DONE
