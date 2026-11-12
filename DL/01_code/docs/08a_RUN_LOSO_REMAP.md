# STEP 05F-B — LOSO logical remap audit/freeze

## Mục tiêu

Kiểm tra và freeze 3 `Leave-One-Scenario-Out` hostname mappings mà **không copy lại toàn bộ ~85.6M supervised joined events 3 lần**.

Đây là quyết định có chủ đích:

```text
STEP 04B joined Parquet
        |
        | scan đúng 1 lần
        v
exact per-host row/positive counts
        |
        +-----------------------------+
        |             |               |
        v             v               v
 holdout S1      holdout S2      holdout S3
 hostname map    hostname map    hostname map
```

Sau khi freeze, STEP 05F-C/05F-D sẽ query trực tiếp original STEP 04B joined dataset bằng frozen hostname mapping.

## Tại sao không materialize 3 bản joined dataset?

Nếu copy vật lý:

```text
85M rows x 3 folds
```

sẽ tốn rất nhiều disk + I/O nhưng không tạo thêm information.

LOSO split chỉ thay đổi:

```text
hostname -> train / val / test
```

nên mapping + exact audit là đủ.

## Cài dependency

```powershell
python -m pip install duckdb pandas
```

## Copy package

Có thể giải nén package ở:

```text
D:\UIT\KLTN\KLTN_bootstrap_step01\step05f_b\
```

hoặc copy:

```text
scripts\05f_b_audit_freeze_loso_remap.py
candidate_folds\
```

vào project.

## Run candidate audit trước

Ví dụ nếu package được giải nén thành:

```text
D:\UIT\KLTN\KLTN_bootstrap_step01\step05f_b\
```

chạy:

```powershell
cd D:\UIT\KLTN\KLTN_bootstrap_step01

python step05f_b\scripts\05f_b_audit_freeze_loso_remap.py `
  --joined-root "D:\UIT\KLTN\artifacts\step04_network_joined_v1\joined" `
  --candidate-root "D:\UIT\KLTN\KLTN_bootstrap_step01\step05f_b\candidate_folds" `
  --output-root "D:\UIT\KLTN" `
  --threads 8 `
  --duckdb-memory-limit "8GB"
```

Expected:

```text
[STATUS] ALL FOLDS PASS — READY TO FREEZE
```

## Sau khi PASS mới freeze

Chạy lại đúng command, thêm:

```text
--freeze
```

Full:

```powershell
python step05f_b\scripts\05f_b_audit_freeze_loso_remap.py `
  --joined-root "D:\UIT\KLTN\artifacts\step04_network_joined_v1\joined" `
  --candidate-root "D:\UIT\KLTN\KLTN_bootstrap_step01\step05f_b\candidate_folds" `
  --output-root "D:\UIT\KLTN" `
  --threads 8 `
  --duckdb-memory-limit "8GB" `
  --freeze
```

## Output

```text
D:\UIT\KLTN\artifacts\step05f_loso_remap_v1\
├── joined_host_event_stats.csv
├── loso_remap_plan.csv
├── STEP_05F_B_LOSO_REMAP_AUDIT.json
├── holdout_scenario_1\
│   ├── host_split_audited.csv
│   └── fold_remap_audit.json
├── holdout_scenario_2\
├── holdout_scenario_3\
└── frozen\
    ├── host_split_holdout_scenario_1.csv
    ├── host_split_holdout_scenario_2.csv
    ├── host_split_holdout_scenario_3.csv
    └── loso_fold_contract.json
```

## Gates

Script bắt buộc kiểm tra:

```text
candidate hostname unique
valid train/val/test values
joined hostname appears in exactly one original split
candidate covers every joined hostname
candidate has no extra hostname
candidate original split matches STEP 04B joined split
held-out positive hosts are TEST only
seen positive hosts never enter TEST
pure-benign hosts preserve original split
event conservation
```

Nếu một gate fail:

```text
--freeze bị chặn
```

## Sau 05F-B

Không train ngay.

Bước kế tiếp:

```text
STEP 05F-C
fit network preprocessing riêng cho mỗi LOSO fold

fit:
TRAIN only

do not fit:
VAL
TEST
held-out scenario
```
