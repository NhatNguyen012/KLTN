# STEP 10G — Thí nghiệm "beacon chưa từng thấy" (bỏ beacon khỏi TRAIN, bỏ `app_family`)

## Trạng thái

**CHUẨN BỊ XONG, CHƯA TRAIN.** Gồm 2 dataset đóng gói sẵn để upload Kaggle, 2 notebook, và script đặc trưng beacon. Kết quả train sẽ được phân tích ở bước sau (chưa có).

## 1. Vì sao không thể "bỏ beacon khỏi cả train lẫn test"

Script `01_code/pipeline/10g_beacon_profile.py` (đọc joined parquet, kết quả ở `beacon_profile/`) cho thấy positive flow gần như toàn là beacon C2 gọi đều đặn, cùng một template trên nhiều host:

| Template beacon | Endpoint C2 | Nhịp (trung vị) | Event/window | Bytes gửi/nhận (trung vị) | Số host | Positive window |
|---|---|---:|---:|---|---:|---:|
| SC2 (qua đêm 24→25/9) | `202.6.172.98:443` | 30.1 giây | 30 | 667 / 2277 | 7 | 456 + một số window lẻ |
| SC1 (và 2 host SC2) | `132.197.158.98:80` | 5.1 giây | 169 | 199 / 1443 | 19 | 74 |

- Tổng **541 positive window (host, 15 phút)**: **530 là beacon (98%)**, chỉ **11 không phải beacon** (5 window lẻ của SC2 và 6 window SC3).
- Không có flow benign nào tới `202.6.172.98`; toàn bộ app tới endpoint này là `powershell.exe`.
- Bỏ beacon khỏi dữ liệu thì cả dataset chỉ còn 11 positive window, không đủ để train và đánh giá. Chính con số 98% đã là bằng chứng rằng lớp positive của nhánh Network chủ yếu là beacon.

## 2. Thiết kế thí nghiệm khả thi: bỏ beacon khỏi TRAIN, test trên beacon

Dùng lại hai fold LOSO đã build và đã PASS validation (`03_datasets/loso_network_dl_v1_1_15m/holdout_scenario_{1,2}`), không build lại. Scenario gần như trùng một template beacon, nên giữ scenario ra ngoài TRAIN/VAL tương đương "model chưa từng thấy template này":

| Dataset | TRAIN positive window | VAL positive window | TEST positive window (toàn bộ scenario giữ lại) | pos_weight TRAIN |
|---|---|---|---|---:|
| `holdout_scenario_2` (bỏ beacon SC2) | 59 = 57 SC1 + 2 SC3 | 25 = 21 SC1 + 4 SC3 | **482 SC2, 9 host** | ≈ 2,730 |
| `holdout_scenario_1` (bỏ beacon SC1) | 335 = 333 SC2 + 2 SC3 | 153 = 149 SC2 + 4 SC3 | **78 SC1, 17 host** | ≈ 473 |

Cả hai fold: preprocessing (từ điển, mean/std) chỉ fit trên TRAIN của fold; split theo hostname, host-disjoint; threshold chọn trên VAL (VAL chỉ chứa scenario đã thấy).

Luật một dòng B1 ("window có `powershell.exe`") trên TEST của hai fold (tham chiếu): `holdout_scenario_2` TP 477 / FP 0 / FN 5 (F1 0.995); `holdout_scenario_1` TP 78 / FP 0 / FN 0 (F1 1.000). Nghĩa là nếu model còn dùng `app_family` thì beacon lạ vẫn bị bắt vì vẫn là PowerShell; vì vậy notebook mặc định **bỏ `app_family`** để chỉ còn timing/bytes/service/port.

### Cách đọc kết quả sau khi train
- Recall trên TEST (beacon chưa từng thấy) **thấp rõ so với split ngẫu nhiên (~0.95 khi bỏ `app_family`)** ⇒ điểm cao trước đây phụ thuộc vào việc TRAIN có cùng template beacon.
- Recall **vẫn cao** ⇒ model bắt được hành vi "C2 gọi đều đặn" nói chung, không chỉ thuộc một template (khi đó giả thuyết "do thuộc template" yếu đi).
- Lưu ý khi diễn giải (hạn chế): (1) scenario ≈ ngày (SC1 = 23/9, SC2 = 24–25/9) nên template lạ cũng là ngày lạ; (2) `holdout_scenario_2` chỉ có 59 positive window ở TRAIN nên training có thể kém ổn định; (3) VAL không chứa template của TEST nên threshold chọn trên VAL có thể lệch so với TEST, nên cần đọc cả PR-AUC/ROC-AUC (không phụ thuộc threshold); (4) chỉ 1 lần chạy mỗi cấu hình (seed khởi tạo 42), chưa có độ dao động giữa các seed.

## 3. File để upload Kaggle

Mỗi dataset gồm 4 file zip + 3 file lẻ (tạo bằng `01_code/pipeline/10_pack_kaggle_upload.py`, giống kiểu `seed_k_kaggle_upload`), ~4.4 GB mỗi dataset:

| Dataset Kaggle (tên gợi ý) | Thư mục để upload |
|---|---|
| `kltn-unseen-beacon-sc2` | `03_datasets/loso_network_dl_v1_1_15m/holdout_scenario_2_kaggle_upload` |
| `kltn-unseen-beacon-sc1` | `03_datasets/loso_network_dl_v1_1_15m/holdout_scenario_1_kaggle_upload` |

Nội dung bên trong dataset (tên cột `loso_split`, khóa `loso_contract`…) vẫn mang tên "loso" vì được build trước đây bằng pipeline LOSO; đây là thí nghiệm leave-one-scenario-out thật nên tên đúng nghĩa.

## 4. Notebook

| Notebook | Model |
|---|---|
| `04_notebooks/06c_BiLSTM_Kaggle_unseen_beacon.ipynb` | BiLSTM |
| `04_notebooks/07c_Mixed_Type_Self_Attention_Kaggle_unseen_beacon.ipynb` | Mixed-Type Self-Attention |

Sinh từ 06b/07b (code train/dataset giữ nguyên, kiến trúc và siêu tham số không đổi) bằng `01_code/pipeline/10g_make_unseen_notebooks.py`. Khác 06b/07b ở cell cấu hình:
- `DROP_APP_FAMILY = True` (mặc định), `HOLDOUT_TAG = 'sc2'` hoặc `'sc1'`.
- Output: `bilstm_unseen_{sc2|sc1}_{noapp|full}` và `mixed_unseen_{sc2|sc1}_{noapp|full}` (không trùng output cũ).
- Có `assert` kiểm tra dataset gắn vào đúng holdout đã khai báo (gắn sai thì dừng ngay, không train nhầm).
- Vẫn chỉ gắn **một** dataset cho mỗi notebook.

### Danh sách chạy
Bắt buộc (4 run, `DROP_APP_FAMILY = True`):

| Run | Dataset | Notebook | `HOLDOUT_TAG` |
|---|---|---|---|
| 1 | `kltn-unseen-beacon-sc2` | 06c (BiLSTM) | `sc2` |
| 2 | `kltn-unseen-beacon-sc2` | 07c (Mixed-Type) | `sc2` |
| 3 | `kltn-unseen-beacon-sc1` | 06c | `sc1` |
| 4 | `kltn-unseen-beacon-sc1` | 07c | `sc1` |

Tuỳ chọn (đối chứng, `DROP_APP_FAMILY = False`): 4 run tương ứng. Kỳ vọng vẫn cao vì template lạ vẫn là PowerShell; nếu đúng thì cho thấy shortcut `app_family` không phụ thuộc beacon.

Ước lượng thời gian Kaggle (từ lần chạy trước): BiLSTM ~130 giây/epoch, Mixed-Type ~400 giây/epoch, tối đa 8 epoch mỗi run.

## 5. Đã kiểm tra

- 2 fold LOSO đã PASS validation (STEP 05F-D) trước đó; thống kê TRAIN/VAL/TEST ở bảng trên đọc từ manifest và mapping host.
- Mô phỏng bố cục Kaggle lồng nhau (zip tự giải nén thành `split/split`, `shards/shards`…) từ chính các zip vừa tạo: resolver tìm đúng root, `assert` heldout: khớp tag thì qua, sai tag thì dừng, ở cả hai notebook.
- Module dataset với `drop_app_family=True` trên shards thật của `holdout_scenario_2`: cột `app_family` về 0, các cột khác giữ nguyên; đọc được 161,127 sample TRAIN và 31,929 sample TEST.
- Manifest có đủ khóa mà script train cần (`step05f_c_preprocess_fingerprint`, `build_config.max_events`, `split_stats`).
- **Chưa chạy trên Kaggle** (không train local).

## 6. File

- `01_code/pipeline/10g_beacon_profile.py`, `10g_make_unseen_notebooks.py`
- `02_artifacts/10g_unseen_beacon_v1/beacon_profile/` (`summary.json`, `host_endpoint_profile.csv`, `positive_windows.csv`, `windows_by_scenario_endpoint.csv`)
- `03_datasets/loso_network_dl_v1_1_15m/holdout_scenario_{1,2}_kaggle_upload/`
- `04_notebooks/06c_…unseen_beacon.ipynb`, `07c_…unseen_beacon.ipynb`
