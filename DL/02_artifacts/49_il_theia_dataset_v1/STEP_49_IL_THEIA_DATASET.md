# STEP 49 — Gói IL OpTC → ATLASv2 + THEIA (dataset + notebook Kaggle)

Ngày 2026-11-05. Mở rộng gói STEP 48 (chỉ ATLASv2) thành **hai miền gộp**. Gói ATLASv2 riêng (notebook 10a/10b) **không bị đổi**.

## 1. Sản phẩm
| Thứ | Đường dẫn |
|---|---|
| Gói Kaggle (3.8 MB zip, 46 MB giải nén) | `03_datasets/il_atlas_theia_kaggle_upload/` (+ `.zip`) |
| Notebook BiLSTM / Mixed-Type | `04_notebooks/11a_BiLSTM_IL_ATLASv2_THEIA_Kaggle.ipynb`, `11b_Mixed_IL_ATLASv2_THEIA_Kaggle.ipynb` |
| Mã | `01_code/pipeline_v2/s37_theia_flows.py`, `s37_prepare_il_multi.py`, `s37_il_train.py`, `s37_notebooks.py`, `s37_smoke_test.py` |
| Flow/cửa sổ THEIA | `02_artifacts/49_il_theia_dataset_v1/data/{flows_theia.parquet, windows.csv}`, `checks_flows.json` |

Kaggle: gắn **hai** dataset (`v2_network_dl_kaggle_upload` và `il_atlas_theia_kaggle_upload`), bật GPU, chạy 3 fold × seed 42. Từ điển mở rộng fit trên TRAIN của fold (gộp hai miền); id mới nối tiếp (61 → 81, 10 → 14 ở fold 0).

## 2. THEIA dựng thế nào
- Nguồn: các bảng đã trích ở STEP 40 (`40_why_malicious_v1/theia`), không quét lại raw. 1 flow = 1 khóa (Subject, NetFlowObject có đầu xa thật): **226,692 flow, 127 dương**, 306 cửa sổ 15 phút (1 máy `theia_host`), **11 cửa sổ dương** (10/4: 4; 11/4: 2; 12/4: 5; ngày 13/4 không có).
- `app_family` = chương trình từ `EVENT_EXECUTE` cuối; nếu thiếu thì basename `Subject.path` (tên lúc fork). **Chỉ 0.36% flow có EXECUTE** (13.4% ở flow dương) ⇒ tên chủ yếu là tên lúc fork.
- `proto` rỗng (THEIA không có `ipProtocol`) ⇒ `<MISSING>`. `image_dir_class` Linux: sửa `v2_common.image_dir_class` (+ bản SQL) thêm nhánh POSIX (`SYSTEM_BIN, SYSTEM_LIB, TEMP_LINUX, VAR_LOG, HOME_USER, ETC_OPT`). Hồi quy: không đổi trên mọi đường dẫn không phải POSIX (OpTC S1, ATLASv2); Python == SQL.
- Chia: 3 fold × 5 nhóm VAL (seed 42), cửa sổ dương phân tầng theo ngày, cửa sổ âm theo ngày. 144 cửa sổ > 512 flow được cắt chunk như OpTC.
- Kiểm `s10_shards`: 6/6 (fold × miền) PASS.

## 3. Cỡ mẫu mỗi fold (mẫu, dương)
| Fold | ATLASv2 train / val / test | THEIA train / val / test |
|---|---|---|
| 0 | 227,25 / 73,15 / 163,23 | 344,7 / 77,2 / 210,7 |
| 1 | 237,33 / 74,9 / 152,21 | 329,8 / 92,2 / 210,6 |
| 2 | 252,32 / 63,12 / 148,19 | 343,11 / 77,2 / 211,3 |

Replay OpTC thật: 401 dương + 1,601 âm (mỗi epoch rút 600, trong đó 150 dương).

## 4. Cách chạy và báo cáo
`s37_il_train.py` giống `s36_il_train.py` (mở dần A→B1→B2→C, kiểm tra tương đương lúc khởi tạo, dừng sớm) nhưng **VAL gộp hai miền** để chọn checkpoint/ngưỡng; ma trận nhầm lẫn TRAIN/VAL/TEST báo **cho từng miền và gộp** ở cùng một ngưỡng, thêm OpTC TEST (ngưỡng VAL gộp và ngưỡng gốc OpTC). Không có so sánh trước/sau fine-tune.

Chạy thử CPU (1 fold, mỗi giai đoạn 1 epoch): cả BiLSTM và Mixed-Type chạy hết, kiểm tra tương đương khởi tạo chênh logit 0.000000, ra đủ file kết quả. Đây **chỉ là kiểm mã chạy**, không phải đánh giá (không dùng số F1 của lần thử).

## 5. Hạn chế (phải nêu khi báo kết quả)
1. **Quá ít dương ở THEIA**: 16 mẫu dương mỗi fold (train 7–11, VAL chỉ 2, TEST 3–7). Ngưỡng và checkpoint chọn trên VAL gộp (ATLASv2 chiếm phần lớn dương VAL) rất không ổn định; kết quả THEIA theo fold dao động mạnh, không thể kết luận ổn định.
2. **Đường tắt tên chương trình**: flow dương THEIA chủ yếu mang token do kẻ tấn công đặt (`profile (deleted)` 38, `gtcache` 35, `clean (deleted)` 16, `mail` 9, `pass_mgr` 2); `firefox` có cả dương (23) lẫn âm (~213k). Mô hình có thể học "tên lạ ⇒ độc" chứ không phải hành vi mạng.
3. Nhãn REAPr là nhãn mức tiến trình/cạnh, không phải nhãn từng flow chuẩn; `proto` trống ở THEIA; tên chương trình chủ yếu từ `Subject.path` (tên lúc fork).
4. Chia trộn theo cửa sổ (không host-disjoint) ⇒ cửa sổ kề cùng cuộc tấn công ở các phần khác nhau (rò rỉ có chủ ý); ATLASv2 có 10 cuộc tấn công gần giống nhau. Điểm cao chỉ đo nhận ra mẫu đã thấy.
5. THEIA một máy, vài ngày; không đại diện cho Linux nói chung.
6. Ngưỡng/tốc độ học chưa tinh chỉnh; không chỉnh theo TEST.
