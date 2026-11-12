# STEP 05F-D — Validation seed_1

## Status

**PASS**

## Core statistics

- `train`: samples=164,975; positive=79; events=62,057,568; hosts_with_samples=434; shards=254.
- `val`: samples=33,222; positive=14; events=12,337,336; hosts_with_samples=93; shards=54.
- `test`: samples=30,344; positive=10; events=11,217,869; hosts_with_samples=93; shards=51.

## Positive samples by UTC day

```text
train: {"2019-09-23": 62, "2019-09-24": 15, "2019-09-25": 2}
val: {"2019-09-23": 10, "2019-09-24": 4}
test: {"2019-09-23": 6, "2019-09-25": 4}
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
