# STEP 05F-C — Random scenario-stratified host split preprocessing (seed_1)

## Trạng thái

**FROZEN — READY FOR STEP 05F-D**

## Leakage policy

- Category maps chỉ fit trên fold TRAIN.
- Numeric mean/std chỉ fit trên fold TRAIN.
- Held-out scenario không tham gia fit.
- VAL/TEST chỉ được dùng để audit OOV/missing sau khi TRAIN mapping đã được tạo.
- Label không được dùng để chọn feature.

## Split statistics

- `train`: hosts=434, events=62,057,568, positive_events=8,721
- `val`: hosts=93, events=12,337,336, positive_events=1,526
- `test`: hosts=93, events=11,217,869, positive_events=1,062

## Active categorical

- `app_family`
- `proto`
- `service`
- `conn_state`
- `resp_port_class`

## Active numerical

- `duration`
- `orig_bytes`
- `resp_bytes`
- `orig_pkts`
- `orig_ip_bytes`
- `resp_pkts`
- `resp_ip_bytes`

## Derived binary

- `has_missed_bytes`

## OOV audit

- `app_family`: VAL UNK=0.00090%, TEST UNK=0.00136%
- `direction`: VAL UNK=0.00000%, TEST UNK=0.00001%
- `proto`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `service`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `conn_state`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `local_orig`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `local_resp`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `orig_ip_scope`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `resp_ip_scope`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `orig_port_class`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `resp_port_class`: VAL UNK=0.00000%, TEST UNK=0.00001%

## Gates

- `mapping_sha_matches_contract`: PASS
- `hostname_profile_exact_match`: PASS
- `event_conservation`: PASS
- `train_rows_exist`: PASS
- `val_rows_exist`: PASS
- `test_rows_exist`: PASS
- `train_positive_exists`: PASS
- `val_positive_exists`: PASS
- `test_positive_exists`: PASS
- `all_category_maps_nonempty`: PASS
- `all_numeric_stats_present`: PASS
- `val_not_used_for_fit`: PASS
- `test_not_used_for_fit`: PASS
- `heldout_scenario_not_used_for_fit`: PASS
- `label_not_used_for_feature_selection`: PASS

## Warnings

- Không có warning tự động.

## Frozen fingerprint

`b5ac4f6a6fa1f925a982347090765e2a9d70aceca2f8713ee993802318369e45`

## Next step

STEP 10C — build random-split 15-minute/512 shards.
