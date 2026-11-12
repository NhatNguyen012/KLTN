#!/bin/bash
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=output/bilstm_v9_20261112
run() { name=$1; shift; for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset.pkl --out $O/sweep3/${name}_s$s --seed $s "$@" > $O/logs/${name}_s$s.log 2>&1; done; }
run lr5e4_best --lr 5e-4 --epochs 20 &
run lr5e4_swa --lr 5e-4 --epochs 20 --select swa --swa-start 11 &
run lr5e4_best_noextra --lr 5e-4 --epochs 20 --use-extra 0 &
wait
echo done > $O/logs/SWEEP3_DONE
