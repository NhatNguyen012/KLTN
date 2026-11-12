#!/bin/bash
# queue A: main v9 + legacy-label control ; queue B: ablations
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=output/bilstm_v9_20261112
(
for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset.pkl --out $O/sweep/v9_main_s$s --seed $s > $O/logs/v9_main_s$s.log 2>&1; done
for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset.pkl --out $O/sweep/legacy_main_s$s --label legacy --seed $s > $O/logs/legacy_main_s$s.log 2>&1; done
) &
(
for s in 42 43 44; do python3 bilstm_v9/train.py --data $O/dataset.pkl --out $O/sweep/v9_noaux_s$s --aux 0 --seed $s > $O/logs/v9_noaux_s$s.log 2>&1; done
for s in 42 43 44; do python3 bilstm_v9/train.py --data $O/dataset.pkl --out $O/sweep/v9_noextra_s$s --use-extra 0 --seed $s > $O/logs/v9_noextra_s$s.log 2>&1; done
) &
wait
echo SWEEP_DONE > $O/logs/SWEEP_DONE
