# STEP 24 — Kết quả train phương án B (bỏ field Bro và `principal_class`)

Ngày: 2026-10-21. Mã: `01_code/pipeline_v2/s9_analyze_subsetB.py`. File: `results.json`, `per_scenario.csv`, `test_positive_samples.csv`, `diagnostics.json`. Mô hình giải nén ở `05_models/v2_subsetB/{bilstm_v2_subsetB,mixed_v2_subsetB}/`. Không ghi đè `S7_results`.

## Thiết lập
Notebook `06e`/`07e` trên Kaggle (người dùng chạy), gói dataset v2 cũ, một lần chạy mỗi mô hình (seed 42). Đầu vào còn lại: `app_family`, `proto`, `resp_port_class`, `image_dir_class` (4 category, 0 numeric) và `delta_t_log1p`; `has_missed_bytes` đặt hằng 0. Kiến trúc và siêu tham số giữ nguyên bản 06d/07d. Checkpoint và ngưỡng chọn trên VAL; TEST chỉ tính chỉ số tại ngưỡng đã chốt. Sample TEST: 34,413 (82 dương). Tham số: BiLSTM 78,698; Mixed-Type 144,065. BiLSTM dừng ở epoch 5 (tốt nhất epoch 2), Mixed-Type dừng ở epoch 4 (tốt nhất epoch 1).

## Kết quả TEST (ngưỡng chọn trên VAL), so với bản đầy đủ (S7)
| Mô hình | Bản | Ngưỡng | Precision | Recall | F1 | PR-AUC | TP / FP / FN |
|---|---|---:|---:|---:|---:|---:|---|
| BiLSTM | đầy đủ (S7) | 1.0 | 1.000 | 0.976 | 0.988 | 0.989 | 80 / 0 / 2 |
| BiLSTM | **B** | 0.9956 | 1.000 | 0.976 | **0.988** | 0.989 | 80 / 0 / 2 |
| Mixed-Type | đầy đủ (S7) | 1.0 | 1.000 | 0.988 | 0.994 | 1.000 | 81 / 0 / 1 |
| Mixed-Type | **B** | 1.0 | 1.000 | 0.976 | **0.988** | 1.000 | 80 / 0 / 2 |

Theo scenario (mẫu dương TEST bị phát hiện, bản B): BiLSTM SC1 9/9, SC2 70/72, SC3 1/1; Mixed-Type SC1 9/9, SC2 71/72, SC3 0/1. (Bản đầy đủ: BiLSTM 9/70/1; Mixed-Type 9/72/0.)

## Đọc kết quả (có ghi giới hạn)
1. **Bỏ các field Bro và `principal_class` gần như không đổi kết quả trên TEST.** BiLSTM giữ nguyên TP/FP/FN. Mixed-Type mất 1 mẫu dương (F1 0.994 → 0.988). Một seed và TEST chỉ 82 mẫu dương, một mẫu = 1.2 điểm recall, nên không kết luận được chênh lệch này là thật hay do dao động.
2. **Điều này phù hợp với kết quả S7: tín hiệu nằm ở tên tiến trình và nơi chạy.** Trên cùng TEST, luật "sample có `powershell.exe`" đạt F1 0.9939 (81/82, 0 báo nhầm), luật "có `powershell.exe` hoặc thư mục Temp/AppData" đạt 82/82 và 0 báo nhầm. Cả hai dùng đúng các field còn lại trong bản B. Không mẫu âm nào trong TEST (34,331) có `powershell.exe` hoặc Temp/AppData. Vì vậy kết quả này cho thấy các field Bro và `principal_class` dư thừa với bài toán này trên OpTC, **không** cho thấy mô hình học được hành vi mạng nào sâu hơn luật đơn giản.
3. **Attention của Mixed-Type (audit trên VAL, 8 mẫu dương và 8 mẫu âm):** mẫu dương dồn vào `app_family` 0.33, `image_dir_class` 0.30, `delta_t_log1p` 0.14, `proto` 0.14, `resp_port_class` 0.06; mẫu âm dồn vào `app_family` 0.74 và `image_dir_class` 0.18. Chỉ là mô tả sự chú ý, không phải bằng chứng nhân quả.
4. **Ngưỡng bão hòa:** Mixed-Type có ngưỡng VAL = 1.0, xác suất âm lớn nhất 0.0085; không phụ thuộc ngưỡng thì PR-AUC 1.000 và ROC-AUC 1.000, hạ ngưỡng xuống 0.01 thì bắt đủ 82/82 với 0 báo nhầm (chỉ để chẩn đoán, không dùng chọn). Hai mẫu bị sót của Mixed-Type có hai nguyên nhân khác nhau (mục 5). BiLSTM có 8 mẫu âm ≥ 0.01 (lớn nhất 0.953) và 3 mẫu ≥ 0.5, nên hạ ngưỡng xuống 0.9 sẽ có 2 báo nhầm.
5. **Các mẫu bị sót:**
   - Cả hai mô hình: một chunk của cửa sổ `sysclient0851` (24/9 19:30 UTC, SC2) với 1,800 flow `firefox.exe` và chỉ 8 flow beacon `powershell.exe` tới `202.6.172.98:443`. BiLSTM chunk 272 flow có xác suất 0.0005 (mẫu không bắt được); chunk 512 flow có xác suất 0.973 (dưới ngưỡng 0.9956). Mixed-Type chunk 512 flow có xác suất 0.9985, dưới ngưỡng 1.0, nên bị tính là sót chỉ vì ngưỡng bão hòa.
   - Mixed-Type: mẫu SC3 duy nhất ở TEST (`sysclient0351`, 25/9 15:15 UTC, 18 flow): `cKfGW.exe` chạy từ Temp tới `53.192.68.50:8080`, xác suất 0.0146. Đây là tín hiệu `TEMP_OR_APPDATA` duy nhất (1/82 mẫu dương), và `conn_state = REJ` đã bị bỏ trong bản B. BiLSTM bản B bắt được mẫu này (như bản đầy đủ). Một mẫu SC3 không đủ để nói gì về SC3.
6. **Mixed-Type bản B dừng sớm** (tốt nhất epoch 1, chạy 4 epoch). Không kết luận gì từ việc này; chỉ ghi nhận.

## Hạn chế khi phát biểu
- Split cấp cửa sổ, **không host-disjoint**; điểm đo khả năng nhận ra mẫu/máy đã thấy, không đo phát hiện máy mới. Một seed.
- Không kết luận "BiLSTM hơn Mixed-Type" hay ngược lại; chênh lệch là 0 hoặc 1 mẫu.
- Kết quả này **chưa nói gì về dataset mới**. Từ điển `app_family` của OpTC không chứa `splunkd.exe`, `python3.11.exe` (skrghosh), nên chúng sẽ thành `<UNK>`; chưa thử nên chưa biết mô hình xử lý ra sao.
- Cách nói đúng: "bỏ các field của Bro và loại tài khoản không làm giảm F1 trên OpTC; các field còn lại (tên tiến trình, nơi chạy) đã đủ để tách, giống một luật đơn giản".
