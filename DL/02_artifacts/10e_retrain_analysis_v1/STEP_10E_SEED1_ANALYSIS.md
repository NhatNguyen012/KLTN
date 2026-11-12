# STEP 10E — Phân tích retrain trên split ngẫu nhiên seed_1 (A0 full vs A1 noapp × BiLSTM vs Mixed-Type)

## Trạng thái

**ANALYSIS COMPLETE cho seed_1.** Chỉ có **1 split × 1 seed train (42)** nên đây là kết quả thăm dò, **chưa đủ để kết luận** về so sánh feature hay so sánh model (xem §5). Script tái lập: `01_code/pipeline/10e_analyze_retrain.py` (chỉ đọc, numpy thuần). Số liệu chi tiết: `seed_1/analysis.json`.

Nguồn: 4 file zip kết quả Kaggle ở thư mục gốc repo (`bilstm_v2_{full,noapp}_seed1.zip`, `mixed_v2_{full,noapp}_seed1.zip`), đã giải nén vào thư mục mới `05_models/10_random_seed1_v1/<run>/` (zip gốc không bị đụng; `05_models/06_*`, `07_*` cũ không bị đụng).

## 1. Kiểm tra nguồn gốc (provenance)

| Kiểm tra | Kết quả |
|---|---|
| Fingerprint preprocessing trong `config.json` của cả 4 run | `99feefc8aaf8…` = fingerprint 10B của seed_1 ✅ |
| `drop_app_family` trong `config.json` | full: `False`, noapp: `True` ✅ |
| Cấu hình còn lại (epochs 8, batch, lr, `pos_weight` 371.36, seed 42) | giống nhau giữa full/noapp ✅ |
| `*_predictions.csv` | đủ 33,245 (VAL) và 30,413 (TEST) sample; mọi `sample_id` thuộc đúng split theo manifest ✅ |
| Tính lại TP/FP/FN, PR-AUC, ROC-AUC từ CSV | **khớp `metrics.json`** cả VAL và TEST của 4 run ✅ |
| Cột `prediction` trong CSV | khớp `probability ≥ threshold` ✅ |

## 2. Kết quả TEST (83 positive window / 4 host positive; threshold chọn trên VAL)

| Run | TP / FP / FN | Precision | Recall | F1 | PR-AUC | ROC-AUC | host positive bị bắt | recall trung bình theo host |
|---|---|---:|---:|---:|---:|---:|---|---:|
| BiLSTM full (A0) | 79 / 0 / 4 | 1.000 | 0.952 | **0.975** | 0.994 | 1.0000 | 4/4 | 0.809 |
| BiLSTM noapp (A1) | 76 / 0 / 7 | 1.000 | 0.916 | 0.956 | 0.973 | 0.9994 | 3/4 | 0.740 |
| Mixed-Type full (A0) | 82 / 0 / 1 | 1.000 | 0.988 | **0.994** | 1.000 | 1.0000 | 4/4 | 0.938 |
| Mixed-Type noapp (A1) | 75 / 1 / 8 | 0.987 | 0.904 | 0.943 | 0.909 | 0.9913 | 3/4 | 0.736 |
| *B1: luật "window có `powershell.exe`"* | 79 / 0 / 4 | 1.000 | 0.952 | **0.975** | — | — | 3/4 | — |
| *B2-lite: cây quyết định depth 3 trên 4 số metadata* | 69 / 27 / 14 | 0.719 | 0.831 | 0.771 | 0.643 | 0.9953 | — | — |

VAL (39 positive window): BiLSTM full F1 1.000; BiLSTM noapp 0.987 (PR-AUC 0.978); Mixed full 0.987 (PR-AUC 0.975); Mixed noapp 0.947 (PR-AUC 0.924).

Ghi chú B2-lite: thay cho HGB của STEP 09B vì máy local không có scikit-learn; là cây depth 3 tự cài bằng numpy, nên **không so trực tiếp** với con số HGB cũ (F1 0.887). B3 (oracle IP C2) chưa làm vì IP không nằm trong shards.

### Theo host positive (số positive window bị bắt / tổng)

| Host (scenario) | B1 luật | BiLSTM full | BiLSTM noapp | Mixed full | Mixed noapp |
|---|---:|---:|---:|---:|---:|
| `sysclient0618` (SC2, beacon qua đêm) | 73/73 | 72/73 | 70/73 | 73/73 | 69/73 |
| `sysclient0051` (SC3) | **0/4** | 1/4 | **0/4** | 3/4 | **0/4** |
| `sysclient0104` (SC1) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| `sysclient0255` (SC1) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |

FP: chỉ Mixed noapp có 1 window sai (host benign `sysclient0362`). Các run còn lại 0 FP window / 0 host benign sai.

## 3. Nhận xét

1. **Split ngẫu nhiên không đổi bức tranh, đúng dự báo STEP 09 §11.** Với A0, BiLSTM F1 0.975 và Mixed-Type 0.994 gần như trùng số trên host split cũ (0.976 và 0.994), và TEST vẫn gồm 83 positive window trong đó 73 (88%) đến từ **một** host SC2 (`sysclient0618`, trước đây 72/83 ở `sysclient0851`). Hai nguyên nhân gốc (shortcut `app_family`, beacon SC2 lặp trên nhiều host) không bị split mới chạm tới.
2. **A0 gần như trùng luật một dòng B1.** BiLSTM full đạt F1 0.975 đúng bằng B1. Phần model làm hơn B1 chỉ nằm ở 4 window của `sysclient0051` (SC3, không có PowerShell): Mixed full bắt 3/4, BiLSTM full bắt 1/4, B1 bắt 0/4. Giống kết luận STEP 09 §8.3.
3. **Bỏ `app_family` (A1) chỉ giảm nhẹ trên SC1/SC2, nhưng mất hẳn SC3.** Cả hai model noapp vẫn bắt 6/6 window SC1 và 69–70/73 window SC2 (ROC-AUC ≥ 0.99) từ timing/bytes/service/port; nhưng 0/4 ở SC3. Phù hợp dự báo E2 ở STEP 09B §4.2: network-only phát hiện tốt **beacon của chiến dịch đã thấy**; SC3 (flow giống hệt benign trên nhiều host khác) cần ngữ cảnh host, đây là lập luận cho hướng fusion của đề tài. Đây **không** phải bằng chứng model nhận ra hành vi APT mới.
4. **Mất window khi bỏ `app_family` chỉ theo một chiều nhưng rất ít host.** Ghép cặp trên 83 positive window TEST: BiLSTM full vs noapp: 3 window chỉ full bắt, 0 chỉ noapp bắt; Mixed: 7 và 0. Các window này thuộc 2 host (`0618`, `0051`), nên số đơn vị độc lập thực sự ≈ 4 host; không có kiểm định có ý nghĩa.
5. **Attention audit (chẩn đoán, không phải độ quan trọng nhân quả)** của Mixed-Type: bản full dồn 0.68 attention (window positive) và 0.49 (negative) vào `app_family`, sau đó `service` (0.11 / 0.32). Bản noapp chuyển sang `delta_t_log1p` (0.22), `orig_ip_bytes`, `proto`, `service`, `conn_state`, tức chữ ký nhịp và kích thước của beacon. Nhất quán với việc A0 dựa vào `app_family`.

## 4. Các điểm kỹ thuật làm số TEST kém tin cậy

1. **A1 chưa hội tụ.** BiLSTM noapp có best epoch = 8 (epoch cuối, ngân sách tối đa 8); Mixed noapp best epoch = 7. VAL PR-AUC dao động mạnh giữa các epoch liên tiếp (BiLSTM noapp: 0.36 → 0.94 → 0.96 → 0.80 → 0.97 → 0.93 → 0.975 → 0.978; Mixed noapp: 0.33 → 0.04 → 0.01 → 0.75 → 0.84 → 0.92 → 0.92 → 0.92) với train loss 6.9 ở epoch 1 (BiLSTM noapp) và 4.2–5.3 ở 4 epoch đầu (Mixed noapp). Khác biệt A0/A1 vì vậy **lẫn với ngân sách train** (A1 có thể bị đánh giá thấp).
2. **Mixed full chọn checkpoint ở epoch 1** (VAL PR-AUC 0.9747, 0.9747, 0.9744, 0.9744 ở epoch 1–4; early stopping dừng ở epoch 4). Chênh lệch giữa các epoch chỉ ~0.0003, nên việc chọn epoch 1 gần như ngẫu nhiên; checkpoint này mới qua 1 epoch (train loss 1.78; xác suất của các window khó cỡ 1e-4, threshold VAL = 2.6e-4). Trên TEST, các window positive vẫn xếp cao hơn mọi negative (ROC-AUC = 1.0) nhưng 1 window `sysclient0051` (điểm 1.66e-4) nằm dưới threshold. Điều này phù hợp với việc A0 phân tách "dễ" (shortcut), không chứng minh mô hình học hành vi.
3. **Threshold bão hòa ở BiLSTM full.** VAL bão hòa (PR-AUC 1.0, mọi positive có xác suất đúng 1.0), tie của F1 làm threshold = **1.0**; 1 window `sysclient0618` có xác suất 0.999 bị bỏ lỡ chỉ vì thế. Nếu cho phép tối đa 20 FP window thì recall = 1.0 (chẩn đoán trên TEST, không dùng để chọn threshold). Số TEST ở mức window vì vậy nhạy với policy tie-break; PR-AUC/ROC-AUC (threshold-free) ổn định hơn.
4. **VAL rất nhỏ:** 39 positive window, 29 từ một host (`sysclient0501`), nên chọn checkpoint/threshold nhiễu (đã nêu ở STEP 10D).
5. **Chưa có bootstrap CI theo host**: chỉ 4 host positive trong TEST, ước lượng CI theo host không có ý nghĩa; cần nhiều seed (xem §6).
6. **Chưa làm:** hard-negative set (E6), B3 oracle IP-C2, HGB thật (cần scikit-learn).

## 5. Những điều chưa thể kết luận (theo CLAUDE.md)

- **Không** kết luận "Mixed-Type tốt hơn BiLSTM". Trên A0 Mixed hơn 3 window (cả 3 ở `sysclient0051`); trên A1 BiLSTM hơn 1 window. Chỉ có 1 seed train và 1 split; dao động giữa các epoch của cùng một run (§4.1) đã lớn hơn các chênh lệch này.
- **Không** kết luận "bỏ `app_family` làm model kém đi": chiều giảm nhất quán (3 và 7 window) nhưng lẫn với hội tụ chưa đủ (§4.1) và chỉ 2 host quyết định.
- **Không** dùng từ "overfit": không có bằng chứng train–test gap.

## 6. Đề xuất bước tiếp theo (cần bạn quyết)

1. **Seed_2 và seed_3 đã được khởi động build** (10C/10D). Sau đó train đủ 4 run × 3 seed rồi báo cáo mean ± std theo seed, recall theo host, host-level detection.
2. **Hai quyết định về cấu hình train** (tôi chưa đổi gì; cần bạn đồng ý để so sánh A0/A1 công bằng):
   - **Ngân sách epoch cho noapp**: tăng `--epochs` (ví dụ 16) cho **cả** full và noapp ở các lần chạy sau, hoặc chấp nhận 8 và ghi rõ hạn chế.
   - **Tie-break threshold** khi VAL bão hòa (hiện chọn threshold lớn nhất đạt F1 tối đa): chuyển sang trung điểm giữa positive thấp nhất và negative cao nhất trên VAL. Thay đổi này chỉ dựa trên VAL và nên áp dụng trước khi chạy 3 seed, không điều chỉnh sau khi xem TEST.
3. Thêm lần chạy lặp với seed train khác (43, 44) trên cùng split để đo dao động do khởi tạo, vì hiện chưa có.
4. Ước lượng thời gian Kaggle mỗi seed (từ lần chạy này): BiLSTM ~130 giây/epoch, Mixed-Type ~400 giây/epoch; với 8 epoch tối đa: 2 run BiLSTM ≈ 35 phút, 2 run Mixed ≈ 107 phút.

## 7. File

- `01_code/pipeline/10e_analyze_retrain.py`
- `02_artifacts/10e_retrain_analysis_v1/seed_1/analysis.json`
- Model: `05_models/10_random_seed1_v1/{bilstm,mixed}_v2_{full,noapp}_seed1/`
