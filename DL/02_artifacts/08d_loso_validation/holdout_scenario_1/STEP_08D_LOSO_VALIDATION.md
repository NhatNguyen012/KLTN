# STEP 05F-D — Validation scenario_1

## Status

**PASS**

## Core statistics

- `train`: samples=158,871; positive=335; events=59,586,600; hosts_with_samples=421; shards=244.
- `val`: samples=35,370; positive=153; events=13,260,258; hosts_with_samples=92; shards=57.
- `test`: samples=34,743; positive=78; events=12,779,327; hosts_with_samples=107; shards=57.

## Positive samples by UTC day

```text
train: {"2019-09-24": 103, "2019-09-25": 232}
val: {"2019-09-24": 41, "2019-09-25": 112}
test: {"2019-09-23": 78}
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

`scenario_1` là unseen-scenario TEST fold. TRAIN/VAL không được chứa positive sample của scenario này.

TEST positive count thường nhỏ hơn positive event count vì nhiều malicious events nằm chung một 15-minute/512-event chunk.

## Next

Nếu PASS: build fold kế tiếp. Chưa train LOSO cho tới khi cả 3 folds đều PASS validation.
