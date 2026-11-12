# STEP 05F-D — Validation scenario_3

## Status

**PASS**

## Core statistics

- `train`: samples=163,537; positive=406; events=61,292,090; hosts_with_samples=434; shards=250.
- `val`: samples=36,468; positive=154; events=13,693,955; hosts_with_samples=94; shards=59.
- `test`: samples=28,979; positive=6; events=10,640,140; hosts_with_samples=92; shards=48.

## Positive samples by UTC day

```text
train: {"2019-09-23": 68, "2019-09-24": 108, "2019-09-25": 230}
val: {"2019-09-23": 10, "2019-09-24": 36, "2019-09-25": 108}
test: {"2019-09-25": 6}
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

`scenario_3` là unseen-scenario TEST fold. TRAIN/VAL không được chứa positive sample của scenario này.

TEST positive count thường nhỏ hơn positive event count vì nhiều malicious events nằm chung một 15-minute/512-event chunk.

## Next

Nếu PASS: build fold kế tiếp. Chưa train LOSO cho tới khi cả 3 folds đều PASS validation.
