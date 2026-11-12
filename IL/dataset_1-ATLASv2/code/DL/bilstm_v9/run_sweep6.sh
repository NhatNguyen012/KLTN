#!/bin/bash
# Stage head (stage-w 0.5) with the final recipe under each label policy.
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=output/bilstm_v9_20261112
run() { name=$1; lab=$2; shift 2; for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset_v9b_stage.pkl --out $O/sweep6/${name}_s$s --label $lab --seed $s --lr 5e-4 --epochs 20 --drop-fields ip_scope --stage-w 0.5 "$@" > $O/logs/sw6_${name}_s$s.log 2>&1; done; }
( run stage_v9b v9b; run stage_legacy legacy ) &
( run stage_v9 v9 ) &
wait
echo done > $O/logs/SWEEP6_DONE
