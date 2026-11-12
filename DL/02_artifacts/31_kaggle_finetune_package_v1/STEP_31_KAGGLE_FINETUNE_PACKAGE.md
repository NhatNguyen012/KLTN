# STEP 31 — Gói và notebook fine-tune để chạy trên Kaggle (3 fold, seed 42, từ điển mở rộng, replay OpTC)

Ngày: 2026-10-23. Thực hiện thiết kế `30_finetune_design_final_v1`. **Chưa chạy trên Kaggle** (bạn chạy). Mã: `01_code/pipeline_v2/s14_prepare_ft.py` (dựng gói), `s14_ft_train.py` (huấn luyện), `s14_notebooks.py` (sinh notebook), `s14_smoke_test.py` (chạy thử CPU).

## 1. Cái cần upload và chạy
| Việc | File | Ghi chú |
|---|---|---|
| Dataset OpTC v2 (đã có trên Kaggle từ lần train trước) | `03_datasets/v2_network_dl_kaggle_upload` | dùng cho replay và đánh giá OpTC TEST; **không upload lại nếu còn** |
| **Dataset mới: gói fine-tune (25 MB)** | `03_datasets/v3_ft_kaggle_upload` | upload thư mục này thành một Kaggle dataset (không chứa `dataset_manifest.json` nên không lẫn với gói v2) |
| Notebook BiLSTM | `04_notebooks/08a_BiLSTM_finetune_Kaggle.ipynb` | gắn **cả hai** dataset, bật GPU, chạy hết |
| Notebook Mixed-Type | `04_notebooks/08b_Mixed_finetune_Kaggle.ipynb` | như trên |
Kết quả: mỗi notebook xuất `<mô hình>_finetune_seed42.zip` (bỏ vào `output_kaggle/` rồi báo mình phân tích): `result_<mô hình>_fold<k>.json`, dự đoán từng mẫu (miền mới và OpTC TEST), checkpoint từng fold.
Thời gian ước tính trên GPU: vài phút cho phần fine-tune mỗi fold; phần đánh giá OpTC TEST (34,413 mẫu) chiếm đa số, vài phút mỗi fold. Đặt `OPTC_EVAL = 'none'` trong ô cấu hình để bỏ qua phần đó nếu cần chạy nhanh (khi đó không đo được quên).

## 2. Nội dung gói `v3_ft_kaggle_upload`
- `ft_manifest.json`, `folds.csv` (mẫu → fold, 3 fold), `replay_R.csv` (401 mẫu dương + 1,601 mẫu âm của OpTC TRAIN, âm phân tầng theo ngày, seed 20261022; trỏ vào shards gói v2).
- `fold0..2/spec_ext.json` (spec OpTC + từ điển nối thêm, tính chỉ trên cửa sổ TRAIN của fold) và `fold<k>/<bộ>/` shards đã mã hóa lại bằng spec mở rộng (skrghosh 196 sample, FiveDirections 930 sample).
- `base_models/{bilstm,mixed}` (checkpoint, config, ngưỡng VAL OpTC, metrics STEP 24) và `ref_zeroshot/` (dự đoán zero-shot STEP 26 và 29 để kiểm tra khớp).
Token mới (tối thiểu 5 flow trong cửa sổ TRAIN): app_family 15, 17, 16 tên cho fold 0, 1, 2 (ví dụ `msedge.exe`, `python3.11.exe`, `tvnserver.exe`, `nbtscan.exe`, `thunderbird.exe`...) và 4–5 lớp cổng (`EPHEMERAL`, `PORT_143_IMAP`, `PORT_25_SMTP`...). `nbtscan.exe` có token ở fold 0 và 1, không ở fold 2 (các flow của nó chỉ nằm ở cửa sổ test của fold 2). Sau mở rộng, tỉ lệ flow `<UNK>` của `app_family` chỉ còn 0.02–0.6% (từ 74.5% ở skrghosh) vì chia trộn khiến cùng tên tiến trình xuất hiện cả ở train và test.
Kích thước fold (train/test sample; dương): fold 0: 753/373 (9/7); fold 1: 746/380 (11/5); fold 2: 753/373 (12/4).

## 3. Quy trình trong notebook (mỗi fold)
1. Dựng mô hình với embedding mở rộng (hàng mới = bản sao hàng `<UNK>`, chiều embedding giữ nguyên; kiến trúc không đổi).
2. **Kiểm tra bắt buộc:** logit trên mẫu test của fold phải trùng dự đoán zero-shot (dung sai 0.02); không khớp thì dừng.
3. Giai đoạn A (3 epoch, lr 1e-3, weight decay 0): chỉ học hàng embedding mới và đầu phân loại. Giai đoạn B (3 epoch, lr BiLSTM 1e-4, Mixed-Type 3e-5, weight decay 1e-4): mở khóa toàn bộ. Mỗi epoch = toàn bộ mẫu TRAIN hai miền + 600 mẫu replay rút mới (150 dương, 450 âm), `pos_weight` theo thành phần epoch.
4. Đánh giá một lần: mẫu test của fold (cả hai miền, tách riêng từng miền) tại hai ngưỡng cố định (ngưỡng VAL OpTC cũ 0.9956/1.0 và 0.5) và OpTC TEST. Không chọn ngưỡng/epoch theo dữ liệu mới.

## 4. Đã kiểm tra cục bộ (CPU, một fold, 1+1 epoch, 60 mẫu replay)
- **Khớp zero-shot: chênh logit lớn nhất 0.00000** trên 373 mẫu test (cả hai mô hình, cả hai miền) → mở rộng từ điển và copy trọng số đúng.
- Hai giai đoạn train chạy hết; ghi đủ `result_*.json`, dự đoán, checkpoint; đánh giá OpTC TEST (150 mẫu âm + 82 mẫu dương) chạy được. Kết quả số của lần chạy thử không có ý nghĩa (1+1 epoch, 60 replay).
- Một lỗi thật đã bắt được nhờ kiểm tra chiều embedding: hàm gốc của BiLSTM suy chiều embedding từ số hàng (cổng 11 → 16 hàng đổi chiều 7 → 8). Đã sửa để giữ chiều của mô hình gốc.
- Chưa chạy được trên Kaggle/GPU; chưa đo thời gian thật trên GPU. Trên CPU một epoch ~110 giây (Mixed-Type) với ~810 mẫu.

## 5. Điều cần nhớ khi đọc kết quả (nhắc lại từ STEP 30)
Chỉ 16 sample dương và 7 đợt; cửa sổ kề cùng đợt luôn ở fold khác nhau (rò rỉ có chủ ý); nhãn mức tiến trình hoặc suy ra; một seed nên không so BiLSTM với Mixed-Type nếu chênh vài mẫu; 99% flow dương của FiveDirections là `firefox.exe` mà đầu vào hiện tại không tách được. Luôn đặt cạnh zero-shot và luật token đơn giản.
