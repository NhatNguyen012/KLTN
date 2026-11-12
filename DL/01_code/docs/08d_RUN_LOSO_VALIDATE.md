# STEP 05F-D — Validate một LOSO fold

## Mục tiêu

Không train ngay sau khi build shard.

Mỗi fold phải PASS các kiểm tra:

```text
frozen host split disjoint
sample_id unique
(hostname, window, chunk) unique
manifest host -> correct LOSO split
sample label == (positive_event_count > 0)
event_count in 1..512
15-minute window alignment
timestamp-derived UTC date consistency
positive samples only on positive hosts
TEST positive samples belong to held-out scenario
TRAIN/VAL positive samples do not belong to held-out scenario
manifest statistics == dataset_manifest
integrity file existence/size
optional full SHA-256 verification
NPZ tensor smoke test
```

## Scenario 1

Chạy:

```powershell
cd D:\UIT\KLTN\KLTN_bootstrap_step01

python step05f_d_validate\scripts\05f_d_validate_loso_fold.py `
  --dataset-root "D:\UIT\KLTN\kaggle\loso_network_dl_v1_1_15m\holdout_scenario_1" `
  --output-root "D:\UIT\KLTN" `
  --verify-sha `
  --smoke-samples-per-split 3
```

`--verify-sha` đọc lại toàn bộ file trong integrity manifest nên sẽ lâu hơn một chút, nhưng nên chạy trước khi upload Kaggle.

Expected:

```text
[STATS MATCH] PASS
[INTEGRITY] ... missing=0 | size_mismatch=0 | sha_mismatch=0
[NPZ SMOKE] ... errors=0
[STATUS] PASS
```

## Output

```text
D:\UIT\KLTN\artifacts\step05f_d_loso_validation\
└── holdout_scenario_1\
    ├── validation_report.json
    └── STEP_05F_D_VALIDATION.md
```

## Sau PASS

Mới build:

```text
scenario_2
scenario_3
```

Sau đó validate từng fold bằng cùng script.

Chỉ khi cả 3 fold PASS mới package/upload Kaggle và retrain:

```text
BiLSTM x 3
Mixed-Type x 3
```
