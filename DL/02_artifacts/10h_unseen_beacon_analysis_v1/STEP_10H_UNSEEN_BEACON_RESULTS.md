# STEP 10H — Kết quả thí nghiệm "beacon chưa từng thấy" (4 run Kaggle, bỏ `app_family`)

Ngày: 2026-10-07. Script: `01_code/pipeline/10h_analyze_unseen_beacon.py`. Model giải nén ở `05_models/10g_unseen_v1/`. Bảng: `unseen_beacon_summary.csv`, `unseen_beacon_per_host.csv`. Chỉ đọc kết quả; không train lại, không sửa artifact cũ.

## Mục đích và cách đọc
Trả lời câu hỏi: điểm F1 ~0.96–0.99 ở split ngẫu nhiên là do model **hiểu hành vi C2** hay do **thuộc lòng template beacon** có mặt cả ở TRAIN và TEST? Cách thử: bỏ toàn bộ một scenario (và beacon của nó) khỏi TRAIN/VAL, rồi test trên scenario đó. Đây là thí nghiệm **chẩn đoán phụ**, không thay thế benchmark chính (split ngẫu nhiên theo host, 3 seed). Tên "loso" còn trong dataset vì hai fold này được dựng từ pipeline leave-one-scenario-out trước đó; về bản chất đúng là giữ một scenario ra ngoài.
- `holdout sc2`: TRAIN/VAL chỉ có SC1 (+2 window SC3); TEST là SC2 (beacon 30 giây tới `202.6.172.98:443`; 482 window dương, 9 host).
- `holdout sc1`: TRAIN/VAL có SC2 (+SC3); TEST là SC1 (beacon 5 giây tới `132.197.158.98:80`; 78 window dương, 17 host).
- Cả hai bỏ `app_family`; ngưỡng chọn trên VAL (VAL chỉ chứa scenario đã thấy); TEST chạy một lần.

## Kết quả TEST (ngưỡng chọn trên VAL)
| Run | Best epoch | VAL recall / PR-AUC (scenario đã thấy) | TEST TP / FN / FP | **TEST recall** | TEST PR-AUC | TEST ROC-AUC | Host bắt được ≥1 window |
|---|---:|---|---|---:|---:|---:|---|
| BiLSTM, giữ ngoài SC2 | 7 | 0.96 / 0.96 | 13 / 469 / 0 | **0.027** | 0.048 | 0.242 | 2 / 9 |
| Mixed-Type, giữ ngoài SC2 | 4 | 0.84 / 0.86 | 12 / 470 / 1 | **0.025** | 0.068 | 0.748 | 2 / 9 |
| BiLSTM, giữ ngoài SC1 | 7 | 0.97 / 0.98 | 51 / 27 / 2 | **0.654** | 0.614 | 0.891 | 16 / 17 |
| Mixed-Type, giữ ngoài SC1 | 7 | 0.94 / 0.95 | 0 / 78 / 4 | **0.000** | 0.018 | 0.775 | 0 / 17 |

Tham chiếu split ngẫu nhiên, bỏ `app_family` (STEP 10E, gộp 3 seed): BiLSTM bắt 213/222 window SC2 (0.96) và 18/18 SC1; Mixed-Type 210/222 (0.95) và 18/18. Độ phổ biến dương ở TEST: SC2 1.5%, SC1 0.22%, nên PR-AUC ngẫu nhiên lần lượt ≈ 0.015 và 0.002.

Chẩn đoán không phụ thuộc ngưỡng (dùng TEST, **chỉ để xem, không để chọn ngưỡng**): recall tại FPR 1% chỉ 0.037 (BiLSTM, SC2), 0.029 (Mixed, SC2), 0.718 (BiLSTM, SC1), 0.026 (Mixed, SC1). Nghĩa là không phải ngưỡng chọn kém: điểm của window beacon lạ thật sự thấp (trung vị điểm của window beacon lạ là 10⁻⁶–10⁻⁴ ở ba run, riêng BiLSTM bỏ SC1 là 6×10⁻³; ở BiLSTM bỏ SC2 trung vị 10⁻⁶ thấp hơn cả phân vị 99% của window benign).

## Diễn giải (có ghi giới hạn)
1. **Giả thuyết "thuộc template" được ủng hộ mạnh.** Khi template beacon chưa từng thấy, recall tụt từ ~0.95 xuống ~0.03 (ba trong bốn run). BiLSTM bỏ SC2 còn có ROC-AUC 0.24 (<0.5): window beacon lạ bị chấm *thấp hơn* window benign. Điểm cao ở split ngẫu nhiên phần lớn do beacon cùng template có mặt ở cả TRAIN và TEST, chứ không chứng minh model nhận ra hành vi C2 mới.
2. **Ngoại lệ có ích:** BiLSTM bỏ SC1 bắt 65% (51/78), 16/17 host có ít nhất một window bị bắt, ROC-AUC 0.89. Model học từ beacon 30 giây (SC2) vẫn bắt được một phần beacon 5 giây (SC1). Chưa có đủ dữ liệu để nói vì sao (có thể vì số event/window lớn hơn, nhịp đều hơn). Mixed-Type thì không (0/78).
3. **Chưa kết luận BiLSTM tốt hơn Mixed-Type:** một seed, bốn run, sự khác biệt chỉ ở một nhánh (SC1).
4. **Giới hạn:** (a) 1 seed khởi tạo; (b) `holdout sc2` chỉ có 59 window dương ở TRAIN (57 SC1 + 2 SC3) nên huấn luyện kém ổn định (Mixed dừng ở epoch 4); (c) VAL chỉ chứa scenario đã thấy, nên ngưỡng không "nhìn" scenario lạ (phần chẩn đoán ở trên cho thấy điều này không giải thích được kết quả); (d) scenario ≈ ngày (SC1 = 23/9, SC2 = 24–25/9), nên "template lạ" lẫn với "ngày lạ"; (e) chưa chạy 4 run đối chứng có `app_family`.
5. **Hệ quả cho khóa luận:** kết quả split ngẫu nhiên không được diễn giải là khả năng phát hiện tấn công mới. Đây là lý do mạnh cho hướng fusion với ngữ cảnh host (process tree, command line) và cho việc ghi rõ hạn chế "nhãn dương gần như toàn là beacon".

## Việc có thể làm tiếp (chưa làm)
- Thêm seed 43, 44 cho 4 run để xem BiLSTM bỏ SC1 có ổn định không.
- Chạy 4 run đối chứng `DROP_APP_FAMILY = False` (kỳ vọng vẫn cao nhờ `powershell.exe`).
- Phân tích điểm theo đặc trưng beacon (số event/window, nhịp) để hiểu vì sao BiLSTM bỏ SC1 chuyển được một phần.
