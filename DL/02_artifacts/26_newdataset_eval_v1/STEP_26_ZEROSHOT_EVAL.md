# STEP 26 — Thử zero-shot mô hình B (OpTC) trên skrghosh và AIT

Ngày: 2026-10-22. Mã: `01_code/pipeline_v2/s11_eval_subsetB.py` (suy luận CPU, 107 giây). File: `results.json`, `verification_optc.json`, `predictions_<bộ>_<mô hình>.csv`, `sample_features_<bộ>.csv`, `run.log`. Không train, không chọn lại ngưỡng, không sửa mô hình.

## Thiết lập
- Mô hình: `bilstm_v2_subsetB` và `mixed_v2_subsetB` (STEP 24, đầu vào `app_family`, `proto`, `resp_port_class`, `image_dir_class`, `delta_t_log1p`), seed 42.
- **Ngưỡng lấy nguyên từ VAL của OpTC:** BiLSTM 0.9956, Mixed-Type 1.0 (cả hai gần bão hòa).
- Dữ liệu: shards STEP 25 (mã hóa bằng spec OpTC, không fit lại). Nhãn skrghosh do script KLTN gán; nhãn AIT là nhãn suy ra theo IP kẻ tấn công và cửa sổ thời gian (xem STEP 25).
- **Kiểm tra mã suy luận:** chạy lại trên 682 mẫu TEST OpTC (82 dương + 600 âm) và so với xác suất Kaggle: chênh lệch tối đa 0.0, cùng quyết định 100%, cùng 80 mẫu dương bị phát hiện ở cả hai mô hình. Xác suất được tính theo mô phỏng AMP fp16 như trên Kaggle.

## Kết quả tại ngưỡng đã chốt (VAL OpTC)
| Bộ | Mô hình | TP / FP / FN / TN | Precision | Recall | F1 | PR-AUC (thứ tự điểm) | ROC-AUC |
|---|---|---|---:|---:|---:|---:|---:|
| skrghosh (196 sample, 8 dương, tỉ lệ dương 4.1%) | BiLSTM | 1 / 2 / 7 / 186 | 0.333 | 0.125 | **0.182** | 0.163 | 0.684 |
| skrghosh | Mixed-Type | 0 / 0 / 8 / 188 | 0 | 0 | **0** | 0.503 | 0.847 |
| AIT (8,259 sample, 302 dương, tỉ lệ dương 3.7%) | BiLSTM | 4 / 1,405 / 298 / 6,552 | 0.003 | 0.013 | **0.005** | 0.022 | 0.215 |
| AIT | Mixed-Type | 0 / 0 / 302 / 7,957 | 0 | 0 | **0** | 0.020 | 0.147 |
Để so: trên TEST OpTC cùng hai mô hình đạt F1 0.988 (STEP 24). Luật "sample có `powershell.exe`": skrghosh F1 0.667 (4/8 mẫu dương, 0 báo nhầm), AIT F1 0 (không có field tiến trình).

## Đọc kết quả (có ghi giới hạn)
1. **Không có chuyển giao zero-shot ở cả hai bộ.** F1 rơi từ 0.99 (OpTC) xuống 0–0.18 trên skrghosh và ~0 trên AIT tại ngưỡng đã chốt.
2. **skrghosh, BiLSTM:** xác suất bão hòa cao với hầu hết mẫu (161/188 mẫu âm có xác suất ≥ 0.5, trung vị 0.953; trung vị mẫu dương 0.979), nên ngưỡng 0.9956 gần như không tách được; phát hiện duy nhất là 1 trong 4 mẫu dương của menuPass, kèm 2 báo nhầm. Cửa sổ mẫu dương có tới 52–79% flow có `app_family = <UNK>` (mẫu âm trung bình 64%), tức nhiễu do tên tiến trình lạ ảnh hưởng ngang nhau lên cả hai lớp.
3. **skrghosh, Mixed-Type:** xác suất rất thấp cho mọi mẫu (mẫu âm lớn nhất 0.028, mẫu dương từ 0.0002 đến 0.29, trung vị 0.0005), không có mẫu nào vượt ngưỡng 1.0. Thứ tự điểm có tín hiệu yếu (ROC-AUC 0.847, PR-AUC 0.503 so với tỉ lệ nền 0.041), nhưng chỉ có 8 mẫu dương nên con số này rất không chắc chắn. Chỉ số "ngưỡng tốt nhất trên chính bộ này" (F1 0.556) chỉ là chẩn đoán cho thấy thang điểm lệch với ngưỡng OpTC, không được dùng để chọn gì.
4. **Mixed-Type cho điểm thấp cả với 4/8 cửa sổ dương có `powershell.exe`** (xác suất 0.0004–0.29) trong khi trên OpTC mọi flow `powershell.exe` đều là dương (24,503 flow; 20,010 dạng tên trần, 4,493 dạng đường dẫn đầy đủ). Ở skrghosh các flow `powershell.exe` chỉ là 1–5 flow trong cửa sổ hàng trăm flow, và hầu hết app còn lại là `<UNK>`. Mình chưa xác định nguyên nhân (giả thuyết, chưa kiểm chứng: cửa sổ bị loãng giống ca `sysclient0851` bị sót ở OpTC, và ngữ cảnh tiến trình lạ nằm ngoài phân phối train).
5. **AIT, BiLSTM:** ROC-AUC 0.215 < 0.5, tức mẫu dương nhận điểm **thấp hơn** mẫu âm. Mô hình đang phản ứng với đặc điểm không liên quan tấn công: điểm tương quan +0.47 với tỉ lệ flow có giao thức lạ (ICMP) và −0.46 với số flow trong mẫu; mẫu dương có trung vị 512 flow và 0% giao thức lạ. 1,409 mẫu bị đánh dấu dương (1,405 báo nhầm, FPR 17.7%) dồn ở các máy `cloud_share`, `internal_share`, `webserver`, `vpn`.
6. **AIT, Mixed-Type:** mọi xác suất < 0.001 (ROC-AUC 0.147), không phát hiện gì.
7. **Vì sao hợp lý:** mô hình B chỉ dựa vào tên tiến trình, thư mục chạy, cổng và giao thức (S7/STEP 24 cho thấy `app_family` và `image_dir_class` là nguồn tách chính). Ở skrghosh từ điển tên tiến trình khác OpTC (`<UNK>` 74.5% flow), ở AIT hai field này trống 100%, nên thứ còn lại là các field gần như không phân biệt được tấn công.

## Hạn chế khi phát biểu
- **Số mẫu dương rất ít ở skrghosh (8)**: một mẫu = 12.5 điểm recall; các AUC không đủ tin cậy để so hai mô hình hay kết luận "có tín hiệu yếu".
- **Nhãn AIT là nhãn suy ra** (IP NAT dùng chung, pha `dnsteal` không gán); kết quả AIT không phải đo trên nhãn chuẩn. Dù vậy ROC-AUC dưới 0.5 ở cả hai mô hình cho thấy không có tín hiệu dùng được.
- **Nhãn skrghosh do script lan nhãn theo tiến trình** nên có nguy cơ tuần hoàn với một mô hình dùng tên tiến trình.
- Các lựa chọn tiền xử lý của STEP 25 (gộp kết nối 120 giây, `l4_protocol = 4` coi là TCP, hướng đầu phản hồi) có thể ảnh hưởng kết quả; chưa kiểm độ nhạy.
- Đây là zero-shot **không fine-tune**. Kết quả không nói gì về khả năng thích ứng sau khi học thêm (mục tiêu 5 của đề cương: F1 OpTC trước/sau, F1 dữ liệu mới, ổn định) vì chưa làm.
- Cách nói đúng: "mô hình OpTC (đầu vào ngữ cảnh tiến trình + cổng/giao thức) không chuyển giao zero-shot sang skrghosh và AIT; kết quả bị giới hạn bởi số mẫu dương ít và nhãn của hai bộ".
