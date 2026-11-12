# STEP 50 — Kết quả IL OpTC → ATLASv2 (Kaggle, 3 fold, seed 42) và nguyên nhân F1 thấp

Nguồn: `output_kaggle/bilstm_il_atlasv2_seed42.zip`, `mixed_il_atlasv2_seed42.zip`. Ngưỡng chọn trên VAL, TEST tính một lần.

## 1. F1 (ngưỡng VAL)
| Mô hình | Fold | TRAIN F1 | VAL F1 | TEST F1 (TP/FP/FN) | OpTC TEST F1 (ngưỡng VAL) | OpTC TEST F1 (ngưỡng gốc) |
|---|---|---|---|---|---|---|
| BiLSTM | 0 | 0.778 | 0.593 | **0.432** (8/6/15) | 0.982 | 0.981 |
| BiLSTM | 1 | 0.536 | 0.444 | **0.462** (18/39/3) | **0.159** (FP 868) | 0.988 |
| BiLSTM | 2 | 0.717 | 0.609 | **0.629** (11/5/8) | 0.994 | 0.988 |
| Mixed | 0 | 0.808 | 0.560 | **0.651** (14/6/9) | 0.964 | 0.988 |
| Mixed | 1 | 0.468 | 0.364 | **0.345** (5/3/16) | 0.976 | 0.994 |
| Mixed | 2 | 0.794 | 0.571 | **0.684** (13/6/6) | 0.976 | 0.988 |

Trung bình TEST ATLASv2: BiLSTM ≈ 0.51, Mixed ≈ 0.56 (3 fold, rất dao động; không kết luận mô hình nào hơn). OpTC TEST với ngưỡng gốc vẫn ≈ 0.98–0.99: **không quên OpTC**. Khớp khởi tạo: chênh logit 0.

## 2. Nguyên nhân F1 thấp (đã kiểm chứng trên `flows_atlas.parquet`)
1. **Mô hình không đủ thông tin để phân biệt (nguyên nhân chính).** 7,696/7,761 flow dương (99.2%) là `firefox.exe`. Trong file tấn công, firefox bị gán dương 96% (7,696/8,046); trong file benign, firefox 0/19,241. Cùng là firefox, cùng thư mục `Mozilla Firefox`, cổng 443/80 (dương 28%/32% trên mọi cổng) ⇒ 4 trường category + `delta_t` giống hệt giữa dương và âm. Cái phân biệt thật là đầu xa (IP C2), máy/kịch bản, thời gian: **không nằm trong đầu vào bản B**.
2. **Nhãn mức tiến trình, không phải hành vi mạng**: firefox của kẻ tấn công bị khai thác nhìn như firefox bình thường. Cửa sổ dương trung vị 81 flow, 87% flow dương; cửa sổ âm trung vị 10 flow, nên mô hình chỉ có tín hiệu yếu về "kích thước/độ dày cửa sổ" (gián tiếp qua `delta_t`), PR-AUC TRAIN chỉ 0.75–0.88 và ROC-AUC TEST 0.66–0.90.
3. **Ngay TRAIN cũng thấp (F1 0.47–0.81)**: mô hình không khớp nổi dữ liệu huấn luyện ⇒ giới hạn của đặc trưng, không phải "rò rỉ" hay quá khớp.
4. **Quá ít mẫu**: 25–33 mẫu dương TRAIN, VAL 9–15 dương ⇒ checkpoint/ngưỡng dao động. Ngưỡng VAL: BiLSTM fold 1 chọn prob 0.07 (recall cao, FP nhiều: TEST FP 39; OpTC FP 868 ⇒ F1 0.159), fold 0 chọn 0.40, fold 2 chọn 0.74. Mixed fold 1 dừng ở B1, PR-AUC VAL 0.34, ROC-AUC VAL 0.50 (gần ngẫu nhiên).
5. Mixed-Type học chậm hơn ở giai đoạn A (lr 1e-3 nhưng PR-AUC VAL ~0.1–0.3), một phần do lr cơ sở 1e-4 ở B/C; chưa tinh chỉnh.

## 3. Về mục tiêu "0.9 như bạn"
Với các đầu vào này không thể đạt 0.9 một cách trung thực trên ATLASv2: giới hạn nằm ở thông tin, không ở cách mở dần/lr. Số 0.9 của bạn (nếu có) dùng tập/nhãn/đặc trưng khác (xem STEP 45–46), hoặc OpTC test tổng hợp.

## 4. Hướng (cần bạn quyết, không chạy khi chưa được cho phép)
- Thêm đặc trưng mức đầu xa (ví dụ lớp IP đích/độ hiếm của `resp_h` trong TRAIN, số flow tới cùng đích) hoặc ngữ cảnh cửa sổ vào đầu vào → đổi hợp đồng bản B (khác quyết định đã chốt).
- Hoặc đổi định nghĩa nhãn/đơn vị (cửa sổ dương theo host-event như bên Nguyễn).
- Hoặc nhận kết quả như thực tế: IL ATLASv2 trên bản B ≈ 0.4–0.7, nêu rõ nguyên nhân trên.

## 5. Thử thêm đặc trưng (probe LightGBM mức flow, 3 fold theo cửa sổ, 06/11)
Mục đích: kiểm xem thêm thông tin có cứu được không, TRƯỚC khi sửa mô hình DL. Đặc trưng phụ fit chỉ trên TRAIN của fold. Trung bình 3 fold trên flow TEST:
| Bộ đặc trưng | ROC-AUC | PR-AUC |
|---|---|---|
| Bản B (app, cổng, delta_t) | 0.596 | 0.329 |
| + IP riêng/công cộng | 0.597 | 0.328 |
| + độ hiếm `resp_h` (số máy/số flow đã thấy ở TRAIN) | 0.649 | 0.377 |
| + ngữ cảnh cửa sổ (số flow, số đích khác nhau, tỉ lệ firefox) | 0.658 | 0.464 |
| + cả hai | 0.661 | 0.438 |

Kết luận: thêm đặc trưng chỉ nâng ROC-AUC 0.60 → 0.66, **không đủ** để lên 0.9. Lý do (kiểm trên dữ liệu): flow firefox dương trong file tấn công tới các đích bình thường (72.21.91.29, 142.250.x.x, Cloudflare…), và 1,987 flow benign cũng tới đúng các IP đó; 81% flow dương tới IP có tỉ lệ dương 100% nhưng IP đó cũng xuất hiện ở benign. Nhãn REAPr thực chất là "firefox trong khoảng ghi tấn công" (tỉ lệ dương 0.83–0.99 gần như đều theo thời gian), phân biệt bằng **tập/phiên ghi**, không bằng đặc trưng mạng. Vì vậy không sửa mô hình DL; chưa chạy Kaggle thêm.

## 6. Thử đổi đơn vị mẫu (probe LightGBM, 07/11)
Đơn vị mới = (máy, chương trình, cửa sổ 15 phút), nhãn = có flow dương; đặc trưng tổng hợp (số flow, số đích, tỉ lệ cổng 443/80, khoảng cách thời gian, span, app). 885 đơn vị, 99 dương (firefox 59, payload.exe 16, plugin-container 5, winword 4). ROC-AUC/PR-AUC trung bình 3 fold: **toàn bộ đơn vị 0.911 / 0.643** (tỉ lệ nền 0.112); **chỉ đơn vị firefox 0.735 / 0.401** (tỉ lệ nền 0.186).
Đọc: phần lớn mức tăng đến từ tách các chương trình tấn công hiếm (payload.exe…) khỏi firefox; với firefox (59/317 đơn vị dương, 99% dương của ATLASv2) vẫn chỉ ROC 0.735. So sánh không công bằng với DL hiện tại (khác đơn vị, khác mô hình); chưa dựng shards/notebook.
