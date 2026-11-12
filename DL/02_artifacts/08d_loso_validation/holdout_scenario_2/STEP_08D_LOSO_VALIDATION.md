# STEP 05F-D — Validation scenario_2

## Status

**PASS**

## Core statistics

- `train`: samples=161,127; positive=59; events=60,551,078; hosts_with_samples=427; shards=247.
- `val`: samples=35,928; positive=25; events=13,474,646; hosts_with_samples=93; shards=59.
- `test`: samples=31,929; positive=482; events=11,600,461; hosts_with_samples=100; shards=52.

## Positive samples by UTC day

```text
train: {"2019-09-23": 57, "2019-09-25": 2}
val: {"2019-09-23": 21, "2019-09-25": 4}
test: {"2019-09-24": 144, "2019-09-25": 338}
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

`scenario_2` là unseen-scenario TEST fold. TRAIN/VAL không được chứa positive sample của scenario này.

TEST positive count thường nhỏ hơn positive event count vì nhiều malicious events nằm chung một 15-minute/512-event chunk.

## Next

Nếu PASS: build fold kế tiếp. Chưa train LOSO cho tới khi cả 3 folds đều PASS validation.
