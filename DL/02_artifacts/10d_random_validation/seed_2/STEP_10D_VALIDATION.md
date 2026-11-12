# STEP 05F-D — Validation seed_2

## Status

**PASS**

## Core statistics

- `train`: samples=163,027; positive=316; events=61,122,797; hosts_with_samples=434; shards=250.
- `val`: samples=30,019; positive=168; events=11,010,382; hosts_with_samples=93; shards=50.
- `test`: samples=35,938; positive=82; events=13,493,006; hosts_with_samples=93; shards=58.

## Positive samples by UTC day

```text
train: {"2019-09-23": 53, "2019-09-24": 85, "2019-09-25": 178}
val: {"2019-09-23": 19, "2019-09-24": 41, "2019-09-25": 108}
test: {"2019-09-23": 6, "2019-09-24": 18, "2019-09-25": 58}
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

`seed_2` là split ngẫu nhiên host-disjoint (không có scenario held-out); positive window theo scenario × split nằm trong validation_report.json (`positive_samples_by_scenario_split`).

TEST positive count thường nhỏ hơn positive event count vì nhiều malicious events nằm chung một 15-minute/512-event chunk.

## Next

Nếu PASS: dataset sẵn sàng upload Kaggle để train.
