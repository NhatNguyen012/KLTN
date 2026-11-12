#!/bin/bash
# Final recipe (lr 5e-4, 20 epochs, val-selected epoch/head/threshold) under each label policy.
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=output/bilstm_v9_20261112
run() { name=$1; lab=$2; shift 2; for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset_v9b.pkl --out $O/sweep4/${name}_s$s --label $lab --seed $s --lr 5e-4 --epochs 20 "$@" > $O/logs/sw4_${name}_s$s.log 2>&1; done; }
run final_v9b v9b &
run final_legacy legacy &
wait
echo done > $O/logs/SWEEP4_DONE
