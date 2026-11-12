# STEP 05F-D — Build LOSO Network DL shards v1.1

## Trạng thái

```text
READY TO RUN
```

STEP 05F-C đã freeze cả 3 preprocessing folds.

Bước này build model-facing datasets cho unseen-scenario ablation với cùng representation baseline:

```text
15-minute window
MAX_EVENTS = 512
packed NPZ
chronological sequence
APP -> REMOTE_ENDPOINT graph transport
sample positive iff >=1 positive event
```

## Fix/optimization quan trọng

STEP 04B Parquet đang vật lý theo original split:

```text
joined\split=train
joined\split=val
joined\split=test
```

Không được dùng các folder đó như LOSO split.

05F-D đọc:

```text
joined\split=*\date=*\*.parquet
```

sau đó:

```text
hostname
   ↓
frozen STEP 05F-B mapping
   ↓
LOSO train / val / test
```

Ngoài ra v1.1 chỉ scan joined data **một lần cho mỗi logical day của một fold** rồi xuất TRAIN/VAL/TEST cùng lúc:

```text
one day source scan
       |
       +--> TRAIN writer
       +--> VAL writer
       +--> TEST writer
```

không scan cùng ngày ba lần.

## Dependency

Package tự chứa:

```text
scripts\
├── 04d_build_network_dl_shards.py
└── 05f_d_build_loso_network_dl_shards.py
```

Nếu thiếu package:

```powershell
python -m pip install duckdb pyarrow numpy pandas
```

## Nên build từng fold

Để dễ quản lý disk/resume, bắt đầu scenario_1:

```powershell
cd D:\UIT\KLTN\KLTN_bootstrap_step01

python step05f_d\scripts\05f_d_build_loso_network_dl_shards.py `
  --output-root "D:\UIT\KLTN" `
  --joined-root "D:\UIT\KLTN\artifacts\step04_network_joined_v1\joined" `
  --frozen-dir "D:\UIT\KLTN\artifacts\step05f_loso_remap_v1\frozen" `
  --preprocess-root "D:\UIT\KLTN\artifacts\step05f_loso_preprocess_v1" `
  --fold scenario_1 `
  --window-minutes 15 `
  --max-events 512 `
  --shard-max-events 250000 `
  --threads 8 `
  --duckdb-memory-limit "8GB"
```

Sau khi xong:

```text
--fold scenario_2
```

rồi:

```text
--fold scenario_3
```

Nếu disk đủ và muốn để máy chạy liên tục:

```text
--fold all
```

## Resume

Mỗi logical day chỉ được coi complete khi cả:

```text
TRAIN
VAL
TEST
```

của ngày đó đều có `_SUCCESS.json`.

Nếu job dừng:

```text
all 3 split outputs của day complete -> SKIP
partial day                         -> rebuild cả day bằng một scan
```

Không dùng `--reset-fold` khi resume.

## Event conservation bắt buộc

### Holdout scenario_1

```text
TRAIN = 59,586,600 events
VAL   = 13,260,258
TEST  = 12,779,327
TOTAL = 85,626,185
```

Positive events:

```text
TRAIN = 11,319
VAL   = 4,372
TEST  = 9,030
```

### Holdout scenario_2

```text
TRAIN = 60,551,078
VAL   = 13,474,646
TEST  = 11,600,461
TOTAL = 85,626,185
```

Positive:

```text
TRAIN = 6,226
VAL   = 2,993
TEST  = 15,502
```

### Holdout scenario_3

```text
TRAIN = 61,292,090
VAL   = 13,693,955
TEST  = 10,640,140
TOTAL = 85,626,185
```

Positive:

```text
TRAIN = 18,981
VAL   = 5,551
TEST  = 189
```

Script check cả total event và positive-event conservation từng split.

## Output

```text
D:\UIT\KLTN\kaggle\loso_network_dl_v1_1_15m\
├── holdout_scenario_1\
├── holdout_scenario_2\
└── holdout_scenario_3\
```

Mỗi fold:

```text
README_DATASET.md
build_config.json
dataset_manifest.json

preprocessing\
    network_category_maps.json
    network_numeric_stats.json
    network_preprocess_spec.json
    network_preprocess_fingerprint.json

split\
    host_split_frozen.csv
    loso_fold_contract.json
    network_sample_manifest.csv

shards\
    train\
    val\
    test\

integrity\
    sha256sums.txt
```

## Disk

Script check tối thiểu:

```text
18 GiB free
```

trước khi chạy.

Nếu không đủ, build/upload/archive từng fold thay vì `--fold all`.

## Không cần ổ E:

Chỉ đọc:

```text
STEP 04B joined Parquet
STEP 05F-B frozen split
STEP 05F-C frozen preprocessing
```

## Sau khi build xong

Chưa train ngay.

Chạy validation + DataLoader smoke test cho từng fold trước. Sau khi cả 3 PASS mới upload Kaggle và chạy:

```text
BiLSTM x 3 folds
Mixed-Type x 3 folds
```
