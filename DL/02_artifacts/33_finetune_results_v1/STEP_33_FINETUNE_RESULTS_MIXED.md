# STEP 33 (phần Mixed-Type) — Kết quả fine-tune Mixed-Type (Kaggle, 3 fold, seed 42, từ điển mở rộng, replay OpTC)

Ngày: 2026-10-23. Mã: `01_code/pipeline_v2/s14_collect.py mixed` (số liệu gộp) và `s14_mixed_ps_breakdown.py` (tách theo có/không `powershell.exe`, chạy cho cả `mixed` và `bilstm`). Kết quả giải nén ở `05_models/v3_finetune/mixed_finetune_seed42/` (file nguồn thực tế nằm ở `output_kaggle/mixed_finetune_seed42.zip`, không ở thư mục gốc như handoff ghi). Số liệu gộp: `results_mixed.json`, `positives_mixed.csv`, `ps_breakdown_mixed.json`, `ps_breakdown_bilstm.json`. Thiết lập y hệt BiLSTM (STEP 33 BiLSTM, mục "Thiết lập"), chỉ khác lr giai đoạn B = 3e-5. Ngưỡng VAL OpTC của Mixed-Type = **1.0** (bão hòa), nên "tại ngưỡng VAL" thực chất là xác suất làm tròn = 1.0.
**Kiểm tra bắt buộc đã qua ở cả 3 fold:** mô hình mở rộng chưa train khớp zero-shot (chênh logit lớn nhất 2.1e-6 – 3.0e-6).

## 1. Dữ liệu mới (out-of-fold ghép của 3 fold: 1,126 mẫu, 16 mẫu dương)
| | ROC-AUC | PR-AUC (nền 0.0142) | Tại ngưỡng VAL OpTC (1.0) | Tại 0.5 |
|---|---:|---:|---|---|
| Zero-shot (trước) | 0.479 | 0.201 | TP 1, FP 0, FN 15 (F1 0.118) | TP 1, FP 0, FN 15 (F1 0.118) |
| **Sau fine-tune** | **0.568** | **0.278** | **TP 3, FP 0, FN 13 (F1 0.316)** | **TP 4, FP 0, FN 12 (F1 0.400)** |
| Luật "có `powershell.exe`" | – | – | TP 5, FP 0, FN 11 (F1 0.476) | |
Theo miền (sau, tại 0.5): skrghosh TP 3/8 (trước 0/8), ROC-AUC 0.847 → 0.826, PR-AUC 0.503 → 0.551; FiveDirections TP 1/8 (như trước), ROC-AUC 0.257 → 0.292.
Điểm hạng của 16 mẫu dương: trung vị tỉ lệ mẫu âm cao điểm hơn 0.39 → 0.46; số mẫu dương trong top 10%: 6 → 6 (**không đổi**). Khoảng tin cậy 95% cho recall: 4/16 → [0.07, 0.52].

## 2. Phát hiện then chốt: các lần bắt được đều là mẫu có `powershell.exe`
Trong 1,126 mẫu của hai miền, **không mẫu âm nào chứa `powershell.exe`** (0 mẫu âm), và 5/16 mẫu dương có nó. Tách theo đặc điểm này (`ps_breakdown_mixed.json`):
| | Mẫu dương có `powershell.exe` (5) | Mẫu dương không có (11) |
|---|---|---|
| Out-of-fold sau fine-tune, tại 0.5 | **4/5** (tại ngưỡng 1.0: 3/5) | **0/11** (xác suất cao nhất 0.021) |
| Khớp TRAIN (32 lượt mẫu dương = mỗi mẫu xuất hiện ở 2 fold) | **8/10** (tại 1.0: 7/10), xác suất trung vị 1.0 | **0/22** (xác suất cao nhất 0.032, trung vị 0.009) |
Nghĩa là: (i) Mixed-Type fine-tune chỉ bắt đúng nhóm mà luật token một dòng cũng bắt (luật bắt 5/5), không bắt thêm nhóm nào; (ii) 3 mẫu "thu thêm" so với zero-shot (`86519309…`, `775ef78d…`, `a1a1a95c…`) đều có `powershell.exe` và **đã nằm ở top 0–0.5% điểm từ trước** (hạng 0.000, 0.000, 0.005) nhưng xác suất zero-shot thấp (0.08, 0.29, 0.002); fine-tune chỉ nâng điểm của chúng qua ngưỡng, tức là **dịch hiệu chuẩn (calibration) hơn là học mẫu mới**; (iii) 11 mẫu dương không có `powershell.exe` (7/8 của FiveDirections và 4/8 của skrghosh) không có dấu hiệu nào được học, kể cả trên TRAIN.
Đối chiếu BiLSTM (`ps_breakdown_bilstm.json`): 0/5 và 0/11 out-of-fold; khớp TRAIN 0/10 và 0/22 (xác suất trung vị mẫu có `powershell.exe` chỉ 0.11). Tức là Mixed-Type khớp được đường tắt `powershell.exe` trên TRAIN còn BiLSTM thì chưa trong cùng cấu hình; không suy ra "Mixed-Type tốt hơn" từ đây (một seed, 16 mẫu dương, chênh 3–4 mẫu, lr giai đoạn B khác nhau).

## 3. Khớp dữ liệu TRAIN
Khớp TRAIN theo từng fold tại ngưỡng 1.0: 1/9, 2/11, 4/12 (ROC-AUC 0.58, 0.57, 0.59). Tức **cũng không fit được hết mẫu dương TRAIN** (7/32; 8/32 tại 0.5), nhưng phần fit được toàn là mẫu có `powershell.exe`. Loss huấn luyện 0.5–0.7 → ~0.25 và không giảm thêm ở giai đoạn B (có epoch tăng nhẹ, ví dụ fold 0: 0.235 → 0.283); loss chủ yếu do replay OpTC và mẫu âm dễ.

## 4. Quên (OpTC TEST, 34,413 mẫu, 82 dương)
| | Tại ngưỡng VAL OpTC | Tại 0.5 | ROC-AUC / PR-AUC |
|---|---|---|---|
| Trước (STEP 24) | TP 80, FP 0, FN 2 (F1 0.9877) | TP 81, FP 0, FN 1 (F1 0.9939) | – |
| Sau, cả 3 fold | TP 81, FP 0, FN 1 (F1 0.9939) | TP 81, FP 0, FN 1 (F1 0.9939) | 1.0 / 1.0 |
Mỗi fold chỉ đổi 1 quyết định ở ngưỡng VAL và 0 ở 0.5; thay đổi xác suất lớn nhất 0.11–0.23. BWT tại ngưỡng VAL = +0.0062 F1 (thêm 1 mẫu dương, tức 1 mẫu, nằm trong dao động). **Không thấy quên.**

## 5. Kết luận được phép và hạn chế
- Có thể nói: sau fine-tune, Mixed-Type bắt 3–4/16 mẫu dương của hai miền mới (precision 1.0, 0 báo nhầm) và không quên OpTC; BiLSTM bắt 0/16 trong cùng cấu hình.
- **Không nên nói** "mô hình học được tấn công mới": toàn bộ phát hiện là các cửa sổ có `powershell.exe`, đã được xếp hạng cao từ zero-shot; 0/11 mẫu không có token này được bắt, kể cả trên TRAIN. Đây chính là đường tắt đã biết ở OpTC (luật `powershell.exe` F1 0.994) xuất hiện ở hai miền mới; không mẫu âm nào có `powershell.exe` nên luật cũng đạt precision 1.0.
- Hạn chế: chỉ 16 mẫu dương, 7 đợt; chia trộn theo cửa sổ nên cửa sổ kề cùng đợt ở fold khác (rò rỉ có chủ ý); nhãn skrghosh do script lan theo cây tiến trình, nhãn FiveDirections mức tiến trình (xem STEP 29/30); một seed; ngưỡng Mixed-Type = 1.0 bão hòa; vẫn chưa phân biệt được "đầu vào không đủ tách" với "huấn luyện quá ngắn" (cần chẩn đoán TRAIN, việc B).
