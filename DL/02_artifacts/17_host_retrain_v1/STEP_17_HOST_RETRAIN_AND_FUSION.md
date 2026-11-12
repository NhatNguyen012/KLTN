# STEP 17 — Retrain nhánh Host theo split host-disjoint và fusion với điểm host thật

Ngày: 2026-10-07/08. Split: `host_split_seed1.csv` (434/93/93 host, cùng split của nhánh Network seed_1). Mã: `01_code/pipeline/17a..17d`. Dùng lại tokenizer và tham số của Nguyễn (`D:\UIT\KLTN\KLTN-main\code`, không sửa).

## 1. Cách làm (bản gọn của pipeline Nguyễn)
1. **17a:** quét 4,685 file eCAR thô (E:), 16.5 tỷ dòng. Event hợp lệ = object không phải FLOW; nhãn lấy từ đuôi dòng (`"label": 1}`). Giữ 100% event dương; event âm lấy Bernoulli rồi cắt về đúng 30:1 mỗi tập. Từ điển đếm trên 100% dương + 3% âm của host TRAIN.
2. **17b:** từ điển 90,011 token (chỉ TRAIN), ma trận thưa (TRAIN 5,252,104 dòng; VAL 2,179,235; TEST 907,098), LightGBM (31 lá, lr 0.05) và XGBoost (depth 8, eta 0.05, hist, max_bin 16), 300 vòng, `scale_pos_weight` ≈ 30, ngưỡng chọn trên VAL, TEST chạy một lần.
3. **17c:** đọc lại log thô của host VAL/TEST, chấm mọi event hợp lệ trong 1,103 cửa sổ 15 phút của `eval_windows_seed1.csv`, gộp từ event lên cửa sổ (max, p99, tỉ lệ vượt ngưỡng, số event vượt ngưỡng).
4. **17d:** ghép với điểm network (Mixed-Type bỏ `app_family`, seed_1): chỉ network, chỉ host, OR, trung bình, stacking. Cách gộp event→cửa sổ và ngưỡng/trọng số chọn trên VAL; TEST chạy một lần.

Khác phương pháp gốc của Nguyễn: split theo host (không theo event), từ điển fit trên mẫu thay vì mọi event TRAIN, chỉ LightGBM/XGBoost (RF cần 64 GB RAM; GraphSAGE không có code trong repo).

## 2. Kết quả mức event (TEST, ngưỡng chọn trên VAL, mẫu 30:1)
| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | TP / FN / FP |
|---|---:|---:|---:|---:|---:|---|
| LightGBM | 0.981 | 0.715 | 0.827 | 0.755 | 0.948 | 20,884 / 8,326 / 399 |
| XGBoost | 0.982 | 0.715 | 0.827 | 0.755 | 0.948 | 20,881 / 8,329 / 393 |
(VAL: recall 0.57, F1 0.72.) Thấp hơn F1 0.95 của Nguyễn, đúng dự đoán: trước đó event cùng host nằm ở cả TRAIN và TEST.

## 3. Kết quả mức cửa sổ (1,103 cửa sổ; TEST 509 cửa sổ: 95 có event độc hại, 414 benign lấy mẫu)
Nhãn mạng `y_net` (81 cửa sổ dương trong TEST):
| Phương pháp (host = LightGBM, gộp bằng `max`) | TP | FP | FN | F1 |
|---|---:|---:|---:|---:|
| Chỉ network | 75 | 0 | 6 | 0.962 |
| Chỉ host | 77 | 0 | 4 | 0.975 |
| OR | 77 | 0 | 4 | 0.975 |
| Trung bình | 77 | 1 | 4 | 0.969 |
| Stacking | 77 | 0 | 4 | 0.975 |
Với XGBoost: chỉ host 0.963, OR 0.963, trung bình và stacking 0.969. Nhãn host `y_host` (95 dương): chỉ network 0.874; chỉ host 0.860 (LightGBM) / 0.898 (XGBoost); stacking 0.899 / 0.896.

**Phần cải thiện nhờ host chỉ là 2 cửa sổ** (`sysclient0618`, SC2, 15:30 và 15:45 EDT 24/9) mà network chấm 0.0 nhưng host bắt được. Đây không phải bằng chứng thống kê.

## 4. SC3 (`sysclient0051`, host TEST duy nhất của SC3)
- Ở mức **event**, model host chấm các event của 4 cửa sổ tấn công (10:15, 10:45, 11:00, 11:15 EDT) rất cao: `max_prob` của LightGBM 0.9998 / 0.9923 / 0.9964 / 0.9957, với 668 / 360 / 610 / 212 event vượt ngưỡng 0.67. Network chấm 0.0 ở cả bốn cửa sổ.
- Nhưng ở mức **cửa sổ**, cách gộp `max` được chọn trên VAL cho ngưỡng 0.99999, nên **cả bốn cửa sổ SC3 vẫn bị bỏ sót**. Nguyên nhân là `max` trên ~12,000 event mỗi cửa sổ gần như luôn lớn kể cả ở cửa sổ benign (ví dụ `0051` 24/9 10:00: max 0.995, 265 event vượt ngưỡng), nên ngưỡng phải rất cao. Cách gộp theo **số event vượt ngưỡng** có vẻ phù hợp hơn cho SC3 nhưng **chưa được thử** (xem mục 6).
- Các cửa sổ "implant chạy yên" của `0051` (11:30–14:00) host chấm ~0.56, như benign, giống tín hiệu luật tay trước đây.

## 5. Giới hạn (quan trọng)
1. **SC3 không phải kịch bản "chưa thấy":** trong split seed_1, host SC3 còn lại (`sysclient0351`, 19k event độc hại) nằm ở **TRAIN**. Việc model host chấm cao `0051` không chứng minh khả năng tổng quát sang tấn công mới; nhánh host của Nguyễn đo walk-forward SC3 chỉ F1 0.2. Cần thí nghiệm giữ cả hai host SC3 ngoài TRAIN.
2. **Benign trong tập cửa sổ chỉ là mẫu** (2 cửa sổ mỗi host-ngày: 414 trong TEST trên ~17,000 cửa sổ thật). Số FP và precision ở mức cửa sổ bị lạc quan, không thể suy ra tỉ lệ báo nhầm thật.
3. Cách gộp event→cửa sổ (`max`) và ngưỡng được chọn trên VAL theo F1 của `y_host`, dùng chung cho `y_net`. TEST đã mở một lần cho bản này; thêm cách gộp mới (số event vượt ngưỡng) sau khi đã xem kết quả TEST sẽ là lần mở thứ hai và phải ghi rõ.
4. 1 seed, 1 split; từ điển fit trên mẫu 3% event âm; 26 file ngày 17/9 bị cắt do hỏng trên ổ E: (~0.5% số dòng; không chứa event dương); không có RF, không có GraphSAGE.
5. Chênh lệch giữa các phương pháp ghép chỉ 0–2 cửa sổ trên 81 cửa sổ dương (một host): chưa kết luận được fusion tốt hơn.

## 6. Việc tiếp theo đề xuất
- **v2 cách gộp event→cửa sổ:** thêm "số event vượt ngưỡng" (và tỉ lệ) vào danh sách chọn trên VAL; ghi rõ TEST mở lần hai; báo cả v1 và v2.
- **Thí nghiệm giữ SC3 ngoài TRAIN** (host và network) để so công bằng với walk-forward của Nguyễn; cần sinh lại từ điển/mẫu cho split mới (cần ổ E:).
- Lặp seed_2, seed_3; tập cửa sổ benign đầy đủ hơn để ước lượng FP thật.
- Fusion mức đặc trưng/gating ở mức cửa sổ (nối vector host hoặc `p_host` vào biểu diễn network) nếu v2 cho thấy host bổ sung được thông tin.

## 7. Tệp
`metrics_event_level.json`, `window_scores_host.csv`, `fusion_results_host_model.json`, `fusion_table_{lgbm,xgb}.csv`, `vocab.json`, `models/`, `matrices/`, `sampling_totals_by_split.csv`, nhật ký `pass_log*.txt`, `train_log_*.txt`, `score_log.txt`.
