# STEP 33 — Kết quả fine-tune BiLSTM (Kaggle, 3 fold, seed 42, từ điển mở rộng, replay OpTC)

Ngày: 2026-10-23. Mã: `01_code/pipeline_v2/s14_collect.py`. Kết quả giải nén ở `05_models/v3_finetune/bilstm_finetune_seed42/`; số liệu gộp ở `results_bilstm.json`, `positives_bilstm.csv`. **Mixed-Type chưa có** (không thấy `mixed_finetune_seed42.zip`; file duy nhất tìm thấy là `bilstm_finetune_seed42.zip`, nằm ở thư mục gốc chứ không phải `output_kaggle/`).

## Thiết lập đã chạy
Theo STEP 30/31: 3 fold, seed 42; giai đoạn A 3 epoch (lr 1e-3, chỉ hàng embedding mới + đầu phân loại), giai đoạn B 3 epoch (lr 1e-4, mở khóa toàn bộ); mỗi epoch: toàn bộ mẫu TRAIN hai miền (746–753 mẫu, 9–12 mẫu dương) + 600 mẫu replay OpTC (150 dương, 450 âm). Ngưỡng cố định: ngưỡng VAL OpTC (0.9956) và 0.5; không chọn gì theo dữ liệu mới. Mỗi epoch ~2 giây, đánh giá OpTC TEST 7–52 giây trên GPU.
**Kiểm tra bắt buộc đã qua ở cả 3 fold:** mô hình mở rộng chưa train khớp zero-shot (chênh logit lớn nhất ~4e-6 trên toàn bộ mẫu test).

## 1. Kết quả trên dữ liệu mới (dự đoán out-of-fold ghép của 3 fold: 1,126 mẫu, 16 mẫu dương)
| | ROC-AUC | PR-AUC (mức nền 0.0142) | Tại ngưỡng VAL OpTC | Tại 0.5 |
|---|---:|---:|---|---|
| Zero-shot (trước) | 0.421 | 0.0125 | TP 2, FP 318, FN 14 (F1 0.012) | TP 7, FP 549, FN 9 (F1 0.025) |
| **Sau fine-tune** | **0.550** | **0.0218** | **TP 0, FP 0, FN 16** | **TP 0, FP 0, FN 16** |
| Luật "có `powershell.exe`" | – | – | TP 5, FP 0, FN 11 (F1 0.476) | |
Theo từng miền (ROC-AUC trước → sau): skrghosh 0.684 → **0.452**; FiveDirections 0.228 → **0.351**. Không fold nào bắt được mẫu dương nào (0/7, 0/5, 0/4) ở cả hai ngưỡng; khoảng tin cậy 95% cho recall khi bắt 0/16 là [0, 0.206].
Điểm hạng của 16 mẫu dương (tỉ lệ mẫu âm cùng bộ có điểm cao hơn, trung vị): trước 0.58, sau **0.70**; số mẫu dương nằm trong top 10%: 3 → **1**.
Đọc kết quả: fine-tune **không cải thiện** và ở ngưỡng cố định còn làm mất hết các phát hiện lẻ của zero-shot; thứ tự điểm gần như ngẫu nhiên (ROC-AUC 0.55). Với chỉ 16 mẫu dương, chênh lệch AUC không có ý nghĩa thống kê.

## 2. Mô hình không khớp được cả dữ liệu TRAIN của chính nó
Mình chạy lại checkpoint từng fold trên các mẫu TRAIN của fold đó (hai miền, không replay):
| Fold | Mẫu TRAIN (dương) | Phát hiện được tại 0.5 / tại ngưỡng VAL | ROC-AUC | PR-AUC |
|---|---|---|---:|---:|
| 0 | 753 (9) | 0 / 0 | 0.740 | 0.046 |
| 1 | 746 (11) | 0 / 0 | 0.637 | 0.051 |
| 2 | 753 (12) | 0 / 0 | 0.722 | 0.064 |
**Mô hình không tách được cả những mẫu dương nó được học (0/32 sau gộp ba fold).** Vì vậy thất bại không chỉ là "không khái quát sang cửa sổ chưa thấy"; trong cấu hình đã đặt (6 epoch, lr nhỏ, replay chiếm ~1/3 số mẫu mỗi epoch) mô hình chưa fit được nhãn mới. Loss huấn luyện giảm (1.5 → 0.25) chủ yếu nhờ các mẫu replay dễ của OpTC và mẫu âm. Mình **chưa biết** nguyên nhân là:
(a) đầu vào hiện tại không đủ để tách (cùng ý với giả thuyết H2 ở STEP 30: các mẫu dương chứa 1–5 flow dương lẫn trong tới 512 flow, và 99% flow dương của FiveDirections là `firefox.exe`), hay
(b) huấn luyện quá ngắn/lr quá nhỏ cho phần dữ liệu mới.
Hai khả năng này phân biệt được bằng một chẩn đoán chỉ trên TRAIN (cho học lâu hơn, lr cao hơn, rồi xem có fit được các mẫu dương TRAIN không), không dùng TEST; chưa làm vì ngoài thiết kế đã chốt.

## 3. Quên (OpTC TEST, 34,413 mẫu, 82 dương)
| | Tại ngưỡng VAL OpTC (0.9956) | Tại 0.5 | PR-AUC / ROC-AUC |
|---|---|---|---|
| Trước (STEP 24) | TP 80, FP 0, FN 2 (F1 0.9877) | TP 81, FP 3, FN 1 (F1 0.9759) | 0.9888 / 0.9997 |
| Sau, cả 3 fold | TP 79, FP 0, FN 3 (F1 0.9814) | TP 80, FP 0, FN 2 (F1 0.9877) | 0.9885–0.9888 / 0.9997 |
BWT tại ngưỡng VAL: **−0.0063 F1 (mất 1 mẫu dương)**; tại 0.5: +0.0118 (bỏ được 3 báo nhầm, mất 1 mẫu dương). Mỗi fold chỉ đổi 1 quyết định ở ngưỡng VAL và 4 ở 0.5; thay đổi xác suất lớn nhất 0.88–0.92. **Không thấy quên đáng kể** (trong khoảng ±2 mẫu dương không phân biệt được với dao động).

## 4. Hạn chế
Chỉ BiLSTM; một seed; 16 mẫu dương, 7 đợt tấn công, cửa sổ kề cùng đợt ở fold khác nhau; nhãn mức tiến trình hoặc suy ra; siêu tham số cố định từ trước nên kết quả này cũng không chứng minh rằng "không thể học được". Mixed-Type chưa có.
