# STEP 54 — Kết quả IL ATLASv2 nhãn tinh chỉnh (13a/13b, 3 fold, seed 42)

Nguồn: `bilstm_il_atlas_refined_seed42.zip`, `mixed_il_atlas_refined_seed42.zip` (đặt ở thư mục gốc dự án, không phải `output_kaggle/`).

## F1 TEST (ngưỡng chọn trên VAL)
| Mô hình | Fold 0 (TP/FP/FN) | Fold 1 | Fold 2 | TB F1 3 fold | Gộp 3 fold (TP/FP/FN → F1) |
|---|---|---|---|---|---|
| BiLSTM | 0.000 (0/2/6) | 0.462 (3/4/3) | 0.800 (4/1/1) | 0.421 | 7/7/10 → 0.452 |
| Mixed-Type | 0.857 (6/2/0) | 0.667 (5/4/1) | 0.889 (4/0/1) | 0.804 | 15/6/2 → 0.789 |
OpTC TEST (ngưỡng VAL): BiLSTM 0.994/0.994/0.988; Mixed 0.965/0.988/0.970; ngưỡng gốc 0.98–0.99 ⇒ không quên. Mỗi TEST chỉ 5–6 mẫu dương: một mẫu = ±0.1 F1; chênh Mixed > BiLSTM chưa đủ để kết luận (1 seed, 17 dương tổng).

## Vì sao không cao hơn (kiểm chứng)
1. **Kim trong đống cỏ**: 17 cửa sổ dương, trung vị chỉ **2.1% flow dương trong cửa sổ**. 8/17 cửa sổ dương chỉ có **1 flow** (payload.exe → cổng 9999) giữa 17–514 flow. Nhãn ở mức cửa sổ nhưng tín hiệu là 1 flow. BiLSTM bỏ lỡ gần hết kiểu này (fold 0: logit −5.4, −4.4, −4.1, −0.03 với ngưỡng 1.44; fold 1 m4 −5.95); Mixed (attention) bắt được hầu hết.
2. **Quá ít dương**: TRAIN 7–8, VAL 3–5 mẫu dương ⇒ ngưỡng VAL nhảy (BiLSTM prob 0.81/0.91/0.07; Mixed 0.12/0.99/0.12). BiLSTM fold 0 chọn ngưỡng 0.81 ⇒ F1 TEST 0 dù TRAIN/VAL còn tách được (ROC VAL 0.88). Fold 2 BiLSTM TEST PR-AUC 0.97 nhưng F1 0.8 vì chọn ngưỡng.
3. **Các cửa sổ vẫn bị bỏ lỡ**: (a) firefox → 10.193.66.115:8080 (m3, 400 flow, 2 dương) — Mixed fold 1 bỏ lỡ; (b) s1, 392 flow, dương là osppsvc 1688/plugin-container, firefox:8080/8443 — cả hai mô hình fold 2 bỏ lỡ; (c) BiLSTM fold 1 bỏ lỡ s2.
4. **FP phần lớn là nhiễu nhãn có thể**: cửa sổ kịch bản `s3` (88 flow, 717 flow firefox thô là dương theo REAPr nhưng 0 sau tinh chỉnh vì không có IP C2) bị cả hai mô hình báo dương mạnh (Mixed logit 13.9); các FP còn lại là cửa sổ benign nhỏ (2–51 flow). Chưa đối chiếu s3 với raw nên chỉ là giả thuyết: nhãn tinh chỉnh có thể thiếu dương.
5. **Nhãn ≈ luật cổng** (người dùng đã chấp nhận): cổng 9999 dương 15/16 flow, 8443 9/10, 8080 23/43 (neg chủ yếu winword/regsvr32/mshta), 8000 2/17. Mô hình bắt được khi cổng không bị chìm trong cửa sổ lớn.

## Hướng tăng F1 (chưa chạy, cần bạn quyết)
- Nhãn và mẫu mức flow, hoặc chunk nhỏ (ví dụ ≤ 32 flow) để flow 9999 không chìm.
- Chọn ngưỡng ổn định hơn (cố định theo mô hình gốc hoặc gộp VAL qua fold) thay vì 3–5 dương.
- Kiểm nhãn s3.
