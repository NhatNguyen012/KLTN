# STEP 05F-C — Fit Network preprocessing riêng cho 3 LOSO folds

## Trạng thái

```text
READY TO RUN
```

## Mục tiêu

Refit preprocessing cho từng fold:

```text
holdout scenario_1
holdout scenario_2
holdout scenario_3
```

với nguyên tắc:

```text
FIT = fold TRAIN only
```

Không dùng:

```text
VAL
TEST
held-out scenario
```

để tạo category map, mean/std hoặc quyết định active feature.

## Tối ưu tốc độ

Không scan 85.6M events 6 lần.

STEP 05F-C scan STEP 04B joined Parquet đúng 2 lượt nặng:

```text
Scan 1:
exact categorical counts per hostname

Scan 2:
exact numerical moments per hostname
```

Sau đó tạo 3 fold preprocessors từ compact per-host profiles:

```text
shared host profiles
      |
      +-> S1 TRAIN aggregation
      +-> S2 TRAIN aggregation
      +-> S3 TRAIN aggregation
```

Khi chạy lại `--freeze`, shared profiles được reuse nên không scan lại 85.6M rows.

## Policy giữ đúng STEP 04C v1.1

Categorical:

```text
<UNK>     = 0
<MISSING> = 1

app_family min_freq = 5
service min_freq    = 5
other cat min_freq  = 1
```

Numerical:

```text
raw non-negative
-> log1p
-> fold-TRAIN z-score
-> clip ±10
```

Active numerical:

```text
fold TRAIN log1p std >= 0.01
```

`missed_bytes` variance thấp sẽ được thay bằng:

```text
has_missed_bytes
```

nếu rule TRAIN-only xác định raw field không ổn định.

## Chạy candidate trước

```powershell
cd D:\UIT\KLTN\KLTN_bootstrap_step01

python step05f_c\scripts\05f_c_fit_loso_network_preprocessing.py `
  --output-root "D:\UIT\KLTN" `
  --joined-root "D:\UIT\KLTN\artifacts\step04_network_joined_v1\joined" `
  --frozen-dir "D:\UIT\KLTN\artifacts\step05f_loso_remap_v1\frozen" `
  --threads 8 `
  --duckdb-memory-limit "8GB"
```

Expected cuối:

```text
[STATUS] ALL FOLDS READY TO FREEZE
```

## Sau khi review thì freeze

Chạy lại command trên và thêm:

```text
--freeze
```

```powershell
python step05f_c\scripts\05f_c_fit_loso_network_preprocessing.py `
  --output-root "D:\UIT\KLTN" `
  --joined-root "D:\UIT\KLTN\artifacts\step04_network_joined_v1\joined" `
  --frozen-dir "D:\UIT\KLTN\artifacts\step05f_loso_remap_v1\frozen" `
  --threads 8 `
  --duckdb-memory-limit "8GB" `
  --freeze
```

Lần freeze sẽ reuse host profiles:

```text
[PROFILE CACHE] Input signature match -> reuse per-host profiles.
```

nên không scan lại full joined dataset.

## Output

```text
D:\UIT\KLTN\artifacts\step05f_loso_preprocess_v1\
│
├── _shared_host_profiles\
│   ├── host_category_counts.parquet
│   ├── host_numeric_moments.parquet
│   └── profile_state.json
│
├── holdout_scenario_1\
│   ├── network_category_maps_candidate.json
│   ├── network_numeric_stats_candidate.json
│   ├── network_preprocess_spec_candidate.json
│   ├── network_preprocess_report.json
│   ├── candidate_state.json
│   └── STEP_05F_C_NETWORK_PREPROCESS.md
│
├── holdout_scenario_2\
├── holdout_scenario_3\
│
└── STEP_05F_C_LOSO_PREPROCESS_SUMMARY.json
```

Sau `--freeze`, mỗi fold có thêm:

```text
network_category_maps.json
network_numeric_stats.json
network_preprocess_spec.json
network_preprocess_fingerprint.json
```

## Gate

Mỗi fold bắt buộc:

```text
mapping SHA matches frozen contract
hostname profile == frozen mapping
event conservation = 85,626,185
TRAIN/VAL/TEST rows > 0
TRAIN/VAL/TEST positive events > 0
category maps valid
numeric stats complete
VAL not used for fit
TEST not used for fit
held-out scenario not used for fit
label not used for feature selection
```

## Sau bước này

```text
STEP 05F-D
```

sẽ build lại 15-minute / 512-event shards cho từng LOSO fold bằng:

```text
original STEP 04B joined Parquet
+
frozen LOSO hostname split
+
frozen fold-specific preprocessing
```

Không cần raw dataset ở ổ E:.
