# STEP 05F-C — Random scenario-stratified host split preprocessing (seed_3)

## Trạng thái

**FROZEN — READY FOR STEP 05F-D**

## Leakage policy

- Category maps chỉ fit trên fold TRAIN.
- Numeric mean/std chỉ fit trên fold TRAIN.
- Held-out scenario không tham gia fit.
- VAL/TEST chỉ được dùng để audit OOV/missing sau khi TRAIN mapping đã được tạo.
- Label không được dùng để chọn feature.

## Split statistics

- `train`: hosts=434, events=60,461,805, positive_events=18,052
- `val`: hosts=93, events=12,081,151, positive_events=3,502
- `test`: hosts=93, events=13,083,229, positive_events=3,167

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

- `app_family`: VAL UNK=0.00560%, TEST UNK=0.00644%
- `direction`: VAL UNK=0.00000%, TEST UNK=0.00001%
- `proto`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `service`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `conn_state`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `local_orig`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `local_resp`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `orig_ip_scope`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `resp_ip_scope`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `orig_port_class`: VAL UNK=0.00000%, TEST UNK=0.00000%
- `resp_port_class`: VAL UNK=0.00012%, TEST UNK=0.00001%

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

`c485c4d15008aebcb304e2be5b049bc7542c09985b14c64d8d66a2b386af94e8`

## Next step

STEP 10C — build random-split 15-minute/512 shards.
