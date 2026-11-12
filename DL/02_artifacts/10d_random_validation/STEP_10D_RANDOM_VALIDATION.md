# STEP 10D — Validation dataset random-split (seed_1)

## Trạng thái

**seed_1, seed_2, seed_3: PASS** (mọi gate, sha256 toàn bộ file, smoke test npz).

Dùng lại `01_code/pipeline/08d_loso_validate.py` với `--mode random` (sửa tại chỗ, mặc định giữ hành vi LOSO cũ):

```text
python 01_code/pipeline/08d_loso_validate.py --dataset-root 03_datasets\random_network_dl_v1_1_15m\seed_1 ^
  --output-root D:\UIT\KLTNv2 --mode random --verify-sha
```

## Thay đổi code 08d

| Argument | Mặc định LOSO | Mặc định random |
|---|---|---|
| `--mode {loso,random}` | `loso` | — (phải khớp `dataset_manifest`: `heldout_scenario` = null) |
| `--artifact-dir` | `02_artifacts/08d_loso_validation` | `02_artifacts/10d_random_validation` |
| `--fold-dir-template` | `holdout_{fold}` | `{fold}` |

Mode random đọc `split_contract` trong manifest và cột `assigned_split`; **bỏ hai gate riêng của LOSO** (`test_positive_not_heldout_scenario`, `train_val_positive_from_heldout_scenario`), giữ nguyên các gate còn lại: trùng `sample_id`/khóa sample, host ↔ split khớp mapping, nhãn = `positive_event_count>0`, `event_count` trong [1, 512], căn window, khớp ngày UTC, positive chỉ trên host GT-positive, khớp `dataset_manifest`, sha256 toàn bộ file, smoke test `.npz`. Thêm `positive_samples_by_scenario_split` và `positive_samples_by_split_host` vào `validation_report.json`.

## Kết quả seed_1

- Host: train 434, val 93, test 93; **host overlap = 0**.
- Sample: TRAIN 165,326 (444 positive), VAL 33,245 (39), TEST 30,413 (83). Khớp `dataset_manifest`.
- Integrity: 369 file, missing 0, size mismatch 0, sha mismatch 0. NPZ smoke: 9 file, 0 lỗi.
- Lỗi logic manifest: 0 ở mọi loại.

Positive window theo scenario × split:

| scenario | TRAIN | VAL | TEST |
|---|---:|---:|---:|
| scenario_1 | 62 | 10 | 6 |
| scenario_2 | 380 | 29 | 73 |
| scenario_3 | 2 | 0 | 4 |
| **tổng** | 444 | 39 | 83 |

Positive window theo host:

- TEST: `sysclient0618` (SC2) **73**, `sysclient0051` (SC3) 4, `sysclient0104` (SC1) 3, `sysclient0255` (SC1) 3.
- VAL: `sysclient0501` (SC2) 29, `sysclient0402` 4, `sysclient0503` 3, `sysclient0955` 3.

## Nhận xét (không phải kết luận về model)

1. Split ngẫu nhiên **không khắc phục** việc TEST tập trung vào một host: 73/83 positive window (88%) đến từ **một** host SC2 (beacon qua đêm), giống split cũ (72/83 ở `sysclient0851`). Với policy hiện tại (SC2 chỉ 1 host vào TEST) điều này gần như không tránh được; nguyên nhân gốc (template beacon lặp trên nhiều host, shortcut `app_family`) không đổi, đúng dự báo STEP 09 §11.
2. VAL chỉ có 39 positive window (29 từ một host) ⇒ early stopping và threshold trên VAL sẽ kém ổn định.
3. Khi đọc kết quả retrain cần báo cáo thêm recall theo host, host-level detection và so với baseline B1–B3 (STEP 09B §4.1); không dùng số window-level đơn lẻ làm kết luận.

## File

`02_artifacts/10d_random_validation/seed_{1,2,3}/validation_report.json`, `STEP_10D_VALIDATION.md`; log: `validate_seed_{2,3}.log`.

## Kết quả seed_2 và seed_3

| seed | host overlap | TRAIN / VAL / TEST sample | positive window (TRAIN / VAL / TEST) | integrity | lỗi logic manifest |
|---|---|---|---|---|---|
| seed_2 | 0 | 163,027 / 30,019 / 35,938 | 316 / 168 / 82 | 368 file, 0 lỗi | 0 |
| seed_3 | 0 | 161,472 / 32,297 / 35,215 | 391 / 88 / 87 | 365 file, 0 lỗi | 0 |

Positive window theo scenario × split:

| seed | scenario | TRAIN | VAL | TEST |
|---|---|---:|---:|---:|
| seed_2 | scenario_1 | 53 | 19 | 6 |
| seed_2 | scenario_2 | 261 | 149 | 72 |
| seed_2 | scenario_3 | 2 | 0 | 4 |
| seed_3 | scenario_1 | 60 | 12 | 6 |
| seed_3 | scenario_2 | 329 | 76 | 77 |
| seed_3 | scenario_3 | 2 | 0 | 4 |

Positive window theo host (TEST / VAL):

- seed_2 TEST: `sysclient0203` (SC2) **72**, `sysclient0051` (SC3) 4, `sysclient0355` 3, `sysclient0660` 3. VAL: `sysclient0069` 77, `sysclient0358` 72, `sysclient0201` 13, `sysclient0462` 3, `sysclient0609` 3.
- seed_3 TEST: `sysclient0069` (SC2) **77**, `sysclient0051` (SC3) 4, `sysclient0104` 3, `sysclient0503` 3. VAL: `sysclient0618` 73, `sysclient0419` 5, `sysclient0402` 4, `sysclient0005` 3, `sysclient0609` 3.

Nhận xét thêm:

1. Cả 3 seed đều có TEST tập trung vào **một host SC2** (73, 72, 77 trên 83, 82, 87 positive window, tức 88–89%) cộng 4 window SC3 của `sysclient0051`; SC1 chỉ 6 window. Dao động giữa các seed nằm chủ yếu ở việc **host SC2 nào** vào TEST/VAL.
2. VAL rất khác nhau giữa các seed: seed_2 có 168 positive window (149 từ hai host SC2), seed_3 có 88 (73 từ một host SC2), seed_1 chỉ 39. Tỉ lệ `pos_weight` TRAIN cũng khác (371 / 515 / 412). Khi so sánh metric giữa các seed phải lưu ý điều này.
3. Mọi seed đều không có positive SC3 ở VAL (SC3 chỉ có 2 host: 1 vào TRAIN, 1 vào TEST theo policy).
