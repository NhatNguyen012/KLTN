# STEP 10C — Build shards 15 phút / 512 event cho split ngẫu nhiên (seed_1, seed_2, seed_3)

## Trạng thái

**seed_1, seed_2, seed_3: HOÀN TẤT và PASS validation (STEP 10D).** seed_1 build trước để kiểm tra; seed_2 và seed_3 build sau khi có kết quả train seed_1.

Dùng lại `01_code/pipeline/08c_loso_dl_shards.py` với `--mode random` (sửa tại chỗ, mặc định giữ hành vi LOSO cũ):

```text
python 01_code/pipeline/08c_loso_dl_shards.py --output-root D:\UIT\KLTNv2 --mode random --fold seed_1
```

## Thay đổi code 08c (chỉ thêm tham số, mặc định = cũ)

| Argument | Mặc định LOSO | Mặc định random |
|---|---|---|
| `--mode {loso,random}` | `loso` | — |
| `--fold` | `all` (bỏ `choices=SCENARIOS`; kiểm theo contract) | `all` / `seed_k` |
| `--contract-name` | `loso_fold_contract.json` | `random_split_contract.json` |
| `--artifact-dir` | `02_artifacts/08c_loso_dl_shards_v1_1_15m` | `02_artifacts/10c_random_dl_shards_v1_1_15m` |
| `--dataset-dir` | `03_datasets/loso_network_dl_v1_1_15m` | `03_datasets/random_network_dl_v1_1_15m` |
| `--fold-dir-template` | `holdout_{fold}` | `{fold}` |
| `--preprocess-root`, `--frozen-dir` (đã có) | 08b / 08a | 10b / 10a |

Mode random: không ghi `heldout_scenario` (để `null`) mà ghi `fold_name`; README và `build_config.experiment` ghi "Random scenario-stratified host split"; file summary đặt tên `STEP_10C_RANDOM_SHARDS_SUMMARY_<fold>.json` để không ghi đè khi build từng seed.

Định nghĩa sample giữ nguyên: window 15 phút, tối đa 512 event/chunk, sample positive ⇔ chunk có ≥1 positive event, sắp xếp theo thời gian. Split theo mapping hostname đông cứng của seed (bỏ qua split vật lý của STEP 04B).

## Kết quả seed_1

| split | host | sample | sample positive | tỉ lệ positive | event | pos_weight (neg/pos) |
|---|---:|---:|---:|---:|---:|---:|
| TRAIN | 434 | 165,326 | 444 | 0.2686% | 62,068,074 | 371.36 |
| VAL | 93 | 33,245 | 39 | 0.1173% | 12,338,145 | 851.44 |
| TEST | 93 | 30,413 | 83 | 0.2729% | 11,219,966 | 365.42 |

- Bảo toàn event và positive event ở cả 3 split: PASS (khớp 10A/10B).
- Dataset: `03_datasets/random_network_dl_v1_1_15m/seed_1` — **4.4 GB**, 359 file `.npz` (train 3.2 GB, val 0.64 GB, test 0.58 GB), không nén.
- Thời gian build thực tế: **~11–14 phút** (lần đầu 14 phút; build lại sau khi đổi tên: 11 phút), nhanh hơn ước tính 30 phút ban đầu. Dataset hiện tại là bản **build lại** sau khi đổi tên (số liệu sample/event giống hệt lần đầu).
- Log: `build_seed_1.log`; report: `seed_1/network_dl_shard_report.json`.

## Lưu ý

- **Train trên Kaggle**: upload thư mục `seed_1` như một Kaggle dataset (notebook v2 tự tìm `dataset_manifest.json`). Dataset build bằng 08c ghi khóa `step05f_c_preprocess_fingerprint` trong manifest (khóa này không đổi khi đổi tên); notebook 06/07 gốc sẽ `KeyError` với dataset này, nên dùng 06b/07b (đã xử lý cả hai khóa).
- VAL chỉ có **39 positive window** (4 host positive có positive event) ⇒ chọn checkpoint/threshold trên VAL sẽ nhiễu; cần nêu khi đọc kết quả.

## Kết quả seed_2 và seed_3

| seed | split | host | sample | sample positive | tỉ lệ positive | event | pos_weight (neg/pos) |
|---|---|---:|---:|---:|---:|---:|---:|
| seed_2 | TRAIN | 434 | 163,027 | 316 | 0.1938% | 61,122,797 | 514.91 |
| seed_2 | VAL | 93 | 30,019 | 168 | 0.5596% | 11,010,382 | 177.68 |
| seed_2 | TEST | 93 | 35,938 | 82 | 0.2282% | 13,493,006 | 437.27 |
| seed_3 | TRAIN | 434 | 161,472 | 391 | 0.2421% | 60,461,805 | 411.97 |
| seed_3 | VAL | 93 | 32,297 | 88 | 0.2725% | 12,081,151 | 366.01 |
| seed_3 | TEST | 93 | 35,215 | 87 | 0.2471% | 13,083,229 | 403.77 |

- Mỗi dataset 4.4 GB (412 file shards ở seed_2, 409 ở seed_3). Bảo toàn event/positive event: PASS.
- Mỗi seed có thêm thư mục đóng gói `seed_{k}_kaggle_upload/` (4 zip + 3 file lẻ, ~4.4 GB) tạo bằng `01_code/pipeline/10_pack_kaggle_upload.py`; dataset gốc không bị đụng.
- Tên artifact trung tính ("loso" không còn trong tên file/thư mục/nội dung JSON/MD của seed_2, seed_3).
- Log: `build_seed_2.log`, `build_seed_3.log`.
