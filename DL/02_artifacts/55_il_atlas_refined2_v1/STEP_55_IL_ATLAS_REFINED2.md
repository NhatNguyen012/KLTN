# STEP 55 — Gói IL v3: sửa cổng thời gian + chunk ≤ 32 flow + ngưỡng thay thế

Ngày 2026-11-07. Làm cả 3 hướng của STEP 54.

## Sản phẩm
Mã: `01_code/pipeline_v2/s40_atlas_flows.py`, `s40_prepare_il_refined2.py`, `s40_il_train.py`, `s40_notebooks.py`, `s40_smoke_test.py`; `s10_shards.py` và `s4_shards.py` thêm biến môi trường `S10_MAX_EVENTS` (mặc định 512, hành vi cũ không đổi). Gói `03_datasets/il_atlas_refined2_kaggle_upload(.zip)` (1.38 MB, tên file dùng `/`). Notebook `04_notebooks/14a_BiLSTM_IL_ATLASv2_refined2_Kaggle.ipynb`, `14b_Mixed_IL_ATLASv2_refined2_Kaggle.ipynb` (gắn `v2_network_dl_kaggle_upload` + `il_atlas_refined2_kaggle_upload`). CPU smoke cả hai chạy hết (chỉ kiểm mã).

## 1. Kiểm nhãn s3 → sửa cổng thời gian
- Mốc tấn công s3 của Nguyễn (15:36 UTC) nằm NGOÀI khoảng dữ liệu s3 (14:21–15:01); s3 có 7 flow tới IOC (IP C2/cổng 9999) từ 14:33 nhưng cổng thời gian loại hết ⇒ s3 có 0 dương (724 dương thô). Đây chính là cửa sổ s3 bị cả hai mô hình báo dương ở STEP 54 ⇒ rất có thể là nhãn thiếu, không phải FP thật (giả thuyết, mốc đúng chưa xác nhận).
- Các kịch bản khác: flow IOC đầu tiên cách mốc vài phút; m5 (23:25 vs 23:38), s1, s4, m6 có flow IOC trước mốc.
- Sửa: cổng hiệu dụng = min(mốc Nguyễn, flow IOC đầu tiên của kịch bản). Dương: 51 → **74 flow**, 17 → **19 cửa sổ**. Đây là độ lệch có chủ ý so với LabelRefiner gốc.

## 2. Chunk ≤ 32 flow
Mẫu = chunk 32 flow liên tiếp của cùng (máy, cửa sổ), nhãn = có flow dương; fold/VAL thừa hưởng từ cửa sổ ⇒ mọi chunk của một cửa sổ cùng fold. Mẫu (dương): fold 0 train 557 (12) / val 247 (4) / test 430 (9); fold 1: 572 (11) / 214 (7) / 448 (7); fold 2: 643 (11) / 235 (5) / 356 (9). Tốt hơn STEP 53 (TEST 5–6 dương), nhưng vẫn rất ít. Replay OpTC giữ cửa sổ 512 flow (đơn vị khác).

## 3. Ngưỡng
Ngưỡng chính vẫn chọn trên VAL. Thêm để so sánh (không phải ngưỡng chính): ngưỡng chọn trên TRAIN+VAL (nhiều dương hơn) và ngưỡng gốc OpTC; notebook in cả ba. Bất kỳ lựa chọn sau khi nhìn TEST đều không hợp lệ.

## Hạn chế
Vẫn ≤ 9 dương TEST/fold (F1 nhảy ±0.1); nhãn ≈ luật IOC/cổng; mốc s3 hiệu dụng là giả định; chia trộn theo cửa sổ.
