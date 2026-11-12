# STEP 05F-D — Validation seed_3

## Status

**PASS**

## Core statistics

- `train`: samples=161,472; positive=391; events=60,461,805; hosts_with_samples=434; shards=246.
- `val`: samples=32,297; positive=88; events=12,081,151; hosts_with_samples=93; shards=53.
- `test`: samples=35,215; positive=87; events=13,083,229; hosts_with_samples=93; shards=56.

## Positive samples by UTC day

```text
train: {"2019-09-23": 60, "2019-09-24": 98, "2019-09-25": 233}
val: {"2019-09-23": 12, "2019-09-24": 23, "2019-09-25": 53}
test: {"2019-09-23": 6, "2019-09-24": 23, "2019-09-25": 58}
```

## Gates

- `dataset_status_ready_for_validation`: PASS
- `heldout_scenario_matches_build_config`: PASS
- `host_split_disjoint`: PASS
- `manifest_no_logic_errors`: PASS
- `manifest_stats_match_dataset_manifest`: PASS
- `integrity_no_missing_files`: PASS
- `integrity_no_size_mismatch`: PASS
- `integrity_sha_pass`: PASS
- `npz_smoke_pass`: PASS

## Interpretation

`seed_3` là split ngẫu nhiên host-disjoint (không có scenario held-out); positive window theo scenario × split nằm trong validation_report.json (`positive_samples_by_scenario_split`).

TEST positive count thường nhỏ hơn positive event count vì nhiều malicious events nằm chung một 15-minute/512-event chunk.

## Next

Nếu PASS: dataset sẵn sàng upload Kaggle để train.
