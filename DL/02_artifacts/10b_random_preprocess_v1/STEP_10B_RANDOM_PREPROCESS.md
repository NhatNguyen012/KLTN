# STEP 10B — Preprocessing TRAIN-only cho 3 split ngẫu nhiên

## Trạng thái

**FROZEN cho seed_1, seed_2, seed_3.** Dùng lại `01_code/pipeline/08b_loso_preprocess.py` với `--mode random` (sửa tại chỗ, mặc định giữ hành vi LOSO cũ).

Lệnh (chạy hai lần: candidate review, rồi thêm `--freeze`):

```text
python 01_code/pipeline/08b_loso_preprocess.py --output-root D:\UIT\KLTNv2 --mode random ^
  --profile-source-dir 02_artifacts\08b_loso_preprocess_v1\_shared_host_profiles [--freeze]
```

## Thay đổi code 08b (chỉ thêm tham số, mặc định = cũ)

| Argument | Mặc định LOSO | Mặc định random |
|---|---|---|
| `--mode {loso,random}` | `loso` | — |
| `--contract-name` | `loso_fold_contract.json` | `random_split_contract.json` |
| `--folds` | tất cả fold trong contract | tất cả (`seed_1..3`) |
| `--artifact-dir` | `02_artifacts/08b_loso_preprocess_v1` | `02_artifacts/10b_random_preprocess_v1` |
| `--fold-dir-template` | `holdout_{fold}` | `{fold}` |
| `--profile-source-dir` | (không dùng) | copy profile per-host có sẵn |
| `--frozen-dir` (đã có) | `08a…/frozen` | `02_artifacts/10a_random_split_v1` |

Mode random khác LOSO ở bốn điểm (xem thêm mục Quy ước đặt tên): (1) contract version chấp nhận `step10a-random-scenario-split-v1.0` và không ép tên fold `scenario_1/2/3`; (2) cột `heldout_scenario` của mapping phải là `NONE` (không có scenario giữ riêng); (3) nhãn `experiment` trong spec/fingerprint là `Random scenario-stratified host split` và fingerprint có thêm `experiment_mode: random`. Ở mode LOSO các nội dung này không đổi.

## Không có leakage

- Category map và numeric mean/std của mỗi seed chỉ fit trên **TRAIN của seed đó** (`fit_split = train`, `val_used_for_fit = test_used_for_fit = False`).
- Profile per-host (đếm category, moments numeric) không phụ thuộc split nên dùng lại bản của STEP 08B; phép gộp theo split diễn ra **bên trong** `build_fold` bằng mapping của seed ⇒ TRAIN-only.
- Sha mapping trong fingerprint khớp `host_split_frozen.csv` của seed.
- Cache profile được xác thực trước khi copy bằng: `profile_version`, sha256 `network_join_exact_report.json` (`4f413699…`), tổng số row supervised (85,626,185), số file parquet (29) và tổng bytes (3,148,862,423). Không so `mtime`/đường dẫn vì dữ liệu đã được di chuyển thư mục. Ghi chú nằm ở `_shared_host_profiles/profile_reuse_note.json`.

## Kết quả

| seed | TRAIN host / event / positive event | VAL | TEST | fingerprint (12 ký tự đầu) |
|---|---|---|---|---|
| seed_1 | 434 / 62,068,074 / 19,227 | 93 / 12,338,145 / 2,335 | 93 / 11,219,966 / 3,159 | `99feefc8aaf8` |
| seed_2 | 434 / 61,122,797 / 14,649 | 93 / 11,010,382 / 6,991 | 93 / 13,493,006 / 3,081 | `6305d03c30c6` |
| seed_3 | 434 / 60,461,805 / 18,052 | 93 / 12,081,151 / 3,502 | 93 / 13,083,229 / 3,167 | `c485c4d15008` |

- Mọi gate của 08b **PASS** ở cả 3 seed; không có cảnh báo OOV > 5%.
- Feature active giống split cũ: categorical `app_family, proto, service, conn_state, resp_port_class`; numeric `duration, orig_bytes, resp_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes` (+ `has_missed_bytes`).
- Kích thước vocab `app_family`: 67 (seed_1), 63 (seed_2), 62 (seed_3) ⇒ vocab khác nhau theo seed vì TRAIN khác nhau (đúng kỳ vọng: refit theo từng TRAIN).
- Tỉ lệ `<UNK>` của `app_family` trên TEST: 0.0014% (seed_1), 0.0040% (seed_2), 0.0064% (seed_3).

## File

`02_artifacts/10b_random_preprocess_v1/seed_{1,2,3}/` (`network_category_maps.json`, `network_numeric_stats.json`, `network_preprocess_spec.json`, `network_preprocess_fingerprint.json`, `network_preprocess_report.json`, `STEP_10B_PREPROCESS.md`), `_shared_host_profiles/`, `STEP_10B_PREPROCESS_SUMMARY.json`.

## Bước tiếp theo

STEP 10C: build shards. Theo yêu cầu, chỉ build `seed_1` trước.

## Quy ước đặt tên (mode random)

Sau yêu cầu bỏ tên "loso" khỏi output của split ngẫu nhiên, ở `--mode random` các script 08b/08c/08d ghi artifact với tên trung tính; mode mặc định (LOSO cũ) không đổi:

| Thành phần | Tên ở mode LOSO (cũ) | Tên ở mode random |
|---|---|---|
| Cột split trong `host_split_frozen.csv` | `loso_split` | `assigned_split` |
| Khóa trong `dataset_manifest.json` | `loso_contract`, `loso_mapping(_sha256)`, `loso_contract_sha256` | `split_contract`, `split_mapping(_sha256)`, `split_contract_sha256` |
| File contract trong dataset | `split/loso_fold_contract.json` | `split/split_contract.json` |
| Report shard | `network_dl_loso_shard_report.json` | `network_dl_shard_report.json` |
| Report preprocess | `STEP_08B_LOSO_PREPROCESS.md`, `STEP_05F_C_LOSO_PREPROCESS_SUMMARY.json` | `STEP_10B_PREPROCESS.md`, `STEP_10B_PREPROCESS_SUMMARY.json` |
| Report validation | `STEP_08D_LOSO_VALIDATION.md` | `STEP_10D_VALIDATION.md` |
| `script_version` / `dataset_version` | `step05f-…-loso-…` / `loso-network-dl-v1.1-15m` | `step10b/10c/10d-random-split-…` / `random-network-dl-v1.1-15m` |

Cơ chế: một hàm `neutral()` đổi `loso` → `split` (và `loso_split` → `assigned_split`) ở mọi JSON/README/report ghi ra, chỉ bật khi `--mode random`; tên cột mapping được đọc qua biến `SPLIT_COL`. Tên script (`08b_loso_*.py`…) vẫn giữ vì script dùng chung cho cả hai mode.

Còn sót "loso" (chủ ý): `10b_random_preprocess_v1/_shared_host_profiles/profile_reuse_note.json` (ghi **đường dẫn thật** của cache profile nguồn `08b_loso_preprocess_v1`, để truy vết nguồn gốc) và một dòng cảnh báo deprecation trong `build_seed_1.log` có tên file script. Không có file hay thư mục nào của split ngẫu nhiên có "loso" trong tên.
