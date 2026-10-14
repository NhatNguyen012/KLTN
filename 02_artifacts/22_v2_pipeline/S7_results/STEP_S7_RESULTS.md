# S7 — Kết quả train bản cuối (BiLSTM và Mixed-Type, dataset v2)

Ngày: 2026-10-13. Mã: `01_code/pipeline_v2/s7_analyze.py` (chỉ số), `s7b_diagnostics.py` (chẩn đoán). Mô hình giải nén ở `05_models/v2_final/{bilstm_v2,mixed_v2}/`. File: `results.json`, `per_scenario.csv`, `test_positive_samples.csv`, `diagnostics.json`.

## Thiết lập
Một lần chạy mỗi mô hình (seed 42, Kaggle), đủ feature (có 3 field host: `app_family`, `image_dir_class`, `principal_class`), không drop/ablation. Split cấp cửa sổ phân tầng theo scenario (không host-disjoint). Checkpoint và ngưỡng chọn trên VAL; TEST chỉ dùng để tính chỉ số một lần tại ngưỡng đã chốt. Sample TEST: 34,413 (82 dương, 34,331 âm). BiLSTM dừng ở epoch 5 (tốt nhất epoch 2), Mixed-Type dừng ở epoch 7 (tốt nhất epoch 4).

## Kết quả TEST (ngưỡng chọn trên VAL)
| Mô hình | Precision | Recall | F1 | PR-AUC | ROC-AUC | TP / FP / FN |
|---|---:|---:|---:|---:|---:|---|
| BiLSTM | 1.000 | 0.976 | **0.988** | 0.989 | 0.9996 | 80 / 0 / 2 |
| Mixed-Type | 1.000 | 0.988 | **0.994** | 1.000 | 1.000 | 81 / 0 / 1 |
VAL: BiLSTM F1 1.000, Mixed-Type F1 0.994.

Theo scenario (sample dương TEST bị phát hiện):
| Scenario | Số sample dương | BiLSTM | Mixed-Type |
|---|---:|---:|---:|
| SC1 | 9 | 9 | 9 |
| SC2 | 72 | 70 | 72 |
| SC3 | 1 | 1 | 0 |

## Đọc kết quả (có ghi giới hạn)
1. **Hai mô hình chênh nhau đúng 1 sample dương** (80 so với 81 trên 82), một seed. Chưa kết luận được Mixed-Type tốt hơn BiLSTM.
2. **Ngưỡng chọn trên VAL của cả hai là 1.0** (bão hòa: xác suất của hầu hết mẫu dương bằng đúng 1.0 trong float). Chỉ số không phụ thuộc ngưỡng cho thấy tách được: Mixed-Type có xác suất âm lớn nhất 8.3e-7; BiLSTM có 4 mẫu âm ≥ 0.01 (lớn nhất 0.164) và hạ ngưỡng xuống 0.5 thì bắt thêm 1 mẫu dương mà vẫn 0 báo nhầm. Đây là chẩn đoán, không dùng để chọn ngưỡng.
3. **Luật một dòng đạt ngang mô hình.** Trên chính TEST này: "sample có `powershell.exe`" cho F1 0.994 (81/82), bằng Mixed-Type và hơn BiLSTM; "có `powershell.exe` hoặc `image_dir_class = TEMP_OR_APPDATA`" cho 82/82, F1 1.000, 0 báo nhầm. Không mẫu âm nào trong TEST (34,331) có `powershell.exe`, thư mục Temp/AppData hay tài khoản Administrator. Vì vậy điểm cao này không chứng minh mô hình học được điều gì hơn các field host đơn giản.
4. **Mô hình dựa vào field host.** Attention của Mixed-Type trên mẫu dương dồn vào `principal_class` (0.32), `app_family` (0.25), `image_dir_class` (0.16); trên mẫu âm là `app_family` (0.34), `image_dir_class` (0.28). Các feature còn lại đều ≤ 0.10 mỗi feature (`delta_t_log1p` 0.10; `resp_port_class` 0.03 ở mẫu dương và 0.08 ở mẫu âm).
5. **Các mẫu bị bỏ sót:**
   - BiLSTM: hai chunk của cùng một cửa sổ `sysclient0851` (24/9 19:30 UTC, SC2): cửa sổ có 1,800 flow `firefox.exe` và chỉ 8 flow beacon `powershell.exe` → `202.6.172.98:443` bị chìm; xác suất 1.2e-5 (chunk 512 flow) và 0.80 (chunk 272 flow).
   - Mixed-Type: mẫu SC3 duy nhất ở TEST (`sysclient0351`, 25/9 15:15 UTC, 18 flow): `cKfGW.exe` chạy từ Temp bị từ chối (`REJ`) tới `53.192.68.50:8080`, cùng `gup.exe`, `notepad++.exe`, `f.exe`; xác suất 2.1e-6. BiLSTM bắt được mẫu này. Một mẫu SC3 không đủ để nói gì về khả năng với SC3.
6. **So với benchmark cũ (host-disjoint, 3 seed, STEP 10E):** F1 BiLSTM 0.969 → 0.988 và Mixed-Type 0.988 → 0.994 khi giữ `app_family`. Không phải so sánh có kiểm soát (split khác, thêm 2 field host, 1 seed), nhưng cùng chiều với kỳ vọng khi bỏ ràng buộc host-disjoint.

## Hạn chế khi phát biểu
- Split cấp cửa sổ, **không host-disjoint**: 80/81 cửa sổ dương của TEST (seed_1 của STEP 21A) có cửa sổ dương cùng máy ở TRAIN, nên điểm đo khả năng nhận ra mẫu và máy đã thấy, không đo phát hiện trên máy mới.
- Một seed; TEST chỉ 82 mẫu dương nên một mẫu = 1.2 điểm recall.
- Field host mang đặc điểm của testbed: `principal_class = ADMINISTRATOR` có 13,297 flow dương và 0 benign trên toàn bộ dữ liệu.
- Cách nói đúng với thầy và bạn: "Flow mạng được bổ sung ngữ cảnh tiến trình từ eCAR-Bro (tên tiến trình, nơi chạy, loại tài khoản)". Không nói là đã fusion với nhánh Host ML; fusion với Host ML mới ở mức điểm (STEP 17).
