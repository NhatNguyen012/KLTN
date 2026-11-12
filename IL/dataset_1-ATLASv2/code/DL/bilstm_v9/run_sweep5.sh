#!/bin/bash
# Shortcut ablations of the final recipe.
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
O=output/bilstm_v9_20261112
run() { name=$1; lab=$2; shift 2; for s in 42 43 44 45 46; do python3 bilstm_v9/train.py --data $O/dataset_v9b.pkl --out $O/sweep5/${name}_s$s --label $lab --seed $s --lr 5e-4 --epochs 20 "$@" > $O/logs/sw5_${name}_s$s.log 2>&1; done; }
( run v9b_noip v9b --drop-fields ip_scope; run v9_noip v9 --drop-fields ip_scope ) &
( run v9b_noip_nopub_nocmd v9b --drop-fields ip_scope,pub,tpub --drop-cmd 1; run v9_noip_nopub_nocmd v9 --drop-fields ip_scope,pub,tpub --drop-cmd 1 ) &
wait
echo done > $O/logs/SWEEP5_DONE
