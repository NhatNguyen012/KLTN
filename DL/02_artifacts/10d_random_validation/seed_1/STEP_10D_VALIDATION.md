# STEP 05F-D — Validation seed_1

## Status

**PASS**

## Core statistics

- `train`: samples=165,326; positive=444; events=62,068,074; hosts_with_samples=434; shards=254.
- `val`: samples=33,245; positive=39; events=12,338,145; hosts_with_samples=93; shards=54.
- `test`: samples=30,413; positive=83; events=11,219,966; hosts_with_samples=93; shards=51.

## Positive samples by UTC day

```text
train: {"2019-09-23": 62, "2019-09-24": 111, "2019-09-25": 271}
val: {"2019-09-23": 10, "2019-09-24": 13, "2019-09-25": 16}
test: {"2019-09-23": 6, "2019-09-24": 20, "2019-09-25": 57}
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

`seed_1` là split ngẫu nhiên host-disjoint (không có scenario held-out); positive window theo scenario × split nằm trong validation_report.json (`positive_samples_by_scenario_split`).

TEST positive count thường nhỏ hơn positive event count vì nhiều malicious events nằm chung một 15-minute/512-event chunk.

## Next

Nếu PASS: dataset sẵn sàng upload Kaggle để train.
