# STEP 12C — Baseline fusion mức A (điểm host dạng luật + điểm network)

Ngày: 2026-10-07. Split seed_1. Script: `01_code/pipeline/12c_make_file_list.py`, `12c_host_window_features.py`, `12c_fusion_baseline.py`. Kết quả: `fusion_baseline_results.json`, `window_scores_test_val_seed1.csv`.

## 1. Đã làm
- Quét eCAR thô trên ổ E:: 591 file (TRAIN 150 host ngày benign 22/9; VAL 78 host và TEST 69 host, các ngày 23–25/9), 2.25 tỷ event, 133.5 GB, 78 phút, không lỗi. Đầu ra: `features/*.csv` (một dòng mỗi cửa sổ host 15 phút).
- Chỉ các host có log host tham gia (TRAIN 330/434 host có log; VAL 78/93; TEST 69/93). Host chỉ có log mạng bị loại khỏi phần này.
- **Điểm host dạng luật** (không có tham số học từ VAL/TEST): 4 đặc trưng hành vi: `n_parent_lsass`, `n_cmd_susp`, `n_proc_writable`, `n_novel_pairs`; mỗi đặc trưng đổi thành độ hiếm so với cửa sổ benign TRAIN; `s_host` = giá trị lớn nhất.
- **Điểm network:** xác suất `max` theo chunk của 4 model seed_1 (BiLSTM/Mixed-Type × có/bỏ `app_family`).
- 3 cách kết hợp, ngưỡng và trọng số chọn trên VAL: OR (mỗi nhánh một ngưỡng), trung bình có trọng số, stacking (logistic hồi quy tự cài bằng numpy).
- Nhãn đánh giá, mỗi cửa sổ (host, 15 phút): (A) `y_net`: nhãn mạng của pipeline; (B) `y_host`: có ≥1 event host độc hại theo A New Hope.
- Số cửa sổ: TRAIN 14,307; VAL 19,528; TEST 17,266. TEST có 81 cửa sổ `y_net` dương và 95 cửa sổ `y_host` dương.

## 2. Thống kê TRAIN benign (4 đặc trưng)
| Đặc trưng | Giá trị lớn nhất | Tỷ lệ cửa sổ khác 0 |
|---|---:|---:|
| `n_parent_lsass` | 0 | 0% |
| `n_cmd_susp` | 0 | 0% |
| `n_proc_writable` | 1 | 9.0% |
| `n_novel_pairs` | 6 | 0.6% |

## 3. Kết quả TEST (mỗi cấu hình chạy TEST một lần; ngưỡng/trọng số chọn trên VAL)
Mixed-Type bỏ `app_family` (cấu hình khó nhất, giống STEP 10), nhãn `y_net`:
| Phương pháp | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Chỉ network | 75 | 0 | 6 | 1.000 | 0.926 | 0.962 |
| Chỉ host (luật) | 5 | 542 | 76 | 0.009 | 0.062 | 0.016 |
| OR | 80 | 542 | 1 | 0.129 | 0.988 | 0.228 |
| Trung bình | 75 | 0 | 6 | 1.000 | 0.926 | 0.962 |
| Stacking | 77 | 9 | 4 | 0.895 | 0.951 | 0.922 |

Cả 4 model (nhãn `y_net`), F1 chỉ network → F1 sau fusion tốt nhất (cách nào):
| Model | Chỉ network | OR | Trung bình | Stacking |
|---|---:|---:|---:|---:|
| BiLSTM full | 0.981 | 0.230 | 0.981 | 0.981 |
| BiLSTM noapp | 0.968 | 0.230 | 0.970 | 0.970 |
| Mixed full | 0.994 | 0.230 | 0.994 | 0.994 |
| Mixed noapp | 0.962 | 0.228 | 0.962 | 0.922 |

Nhãn `y_host` (95 cửa sổ dương): chỉ network có F1 0.882–0.914 (recall 0.79–0.84); OR đưa recall lên 0.895–0.905 nhưng precision chỉ 0.14; trung bình và stacking gần như không đổi so với chỉ network.

## 4. Kết luận (trung thực)
1. **Baseline mức A không cải thiện so với chỉ network.** Trên VAL, trung bình có trọng số chọn `w_net` = 0.6 (host 0.4) cho BiLSTM full/noapp và Mixed full, và `w_net` = 1.0 (không dùng host) cho Mixed noapp. Với ngưỡng đi kèm (0.4–0.6), điểm host đứng một mình hầu như không đủ để kích hoạt, nên kết quả gần như trùng chỉ network. Stacking có hệ số dương cho điểm host (1.3–2.7 ở `y_net` với BiLSTM/Mixed noapp và Mixed full) nhưng F1 TEST thay đổi từ +0.002 (BiLSTM noapp) đến −0.040 (Mixed noapp); chênh lệch nằm trong dao động, không có ý nghĩa.
2. **Luật host dùng một mình rất kém:** precision 0.9–1.8%, 537–542 cửa sổ benign bị báo nhầm trên TEST. Các nguồn báo nhầm chính (đo trên VAL): `n_novel_pairs` (979 FP), `n_proc_writable` (818 FP); `n_cmd_susp` sạch (3 lần kích hoạt, 3 đúng) nhưng quá hiếm; `n_parent_lsass` lại kích hoạt ở 2 cửa sổ benign VAL và 9 cửa sổ benign TEST. Một số host (`sysclient0222`, `0024`) tạo 265/537 báo nhầm.
3. **Đính chính pilot:** ở lượt trước tôi chọn 3 tín hiệu (lsass-parent, `net user`, process từ Temp) khi nhìn riêng `sysclient0051`; trên 78+69 host chúng không đạt độ chính xác đó. Đây là sai lệch do chọn đặc trưng trên đúng host cần giải thích.
4. **Điểm tích cực duy nhất, ở mức mô tả:** trong TEST, `sysclient0051` có 4 cửa sổ `y_net` = 1 (10:15, 10:45, 11:00, 11:15 EDT) mà `p_net` ≈ 0 (Mixed noapp); cả 4 đều có `s_host` = 1.0. Nhưng cùng điểm này cũng báo ~540 cửa sổ benign nên không thể dùng làm luật độc lập. Đây là 1 host, 4 cửa sổ: không kết luận thống kê.
5. **Giới hạn của nhãn `y_host`:** là "có event độc hại bất kỳ trong cửa sổ", gồm cả cửa sổ implant đang chạy nhưng không có hành động đáng kể (ví dụ `sysclient0051` 11:30–13:15 không có tín hiệu nào). Ngược lại cửa sổ 14:15 của `0051` bị `y_host` = 0 nhưng nhật ký red team ghi chạy lại `update.exe` lúc 14:24 (có thể là nhãn A New Hope bỏ sót), và host rule báo `s_host` = 1.0 ở cửa sổ đó (đếm là FP).
6. Chỉ seed_1 và 1 host SC3 trong TEST (`sysclient0351` thuộc TRAIN ở seed_1); chưa đo seed_2, seed_3; chưa có khoảng tin cậy.

## 5. Hướng đi hợp lý tiếp theo
- Luật tay 4 đặc trưng không đủ. Cần **mô hình host học có giám sát** trên vector đặc trưng phong phú hơn (đếm theo `(object, action)`, cặp cha→con, thư mục, registry...), hoặc dùng kết quả nhánh Host sẵn có của Nguyễn (LightGBM/XGBoost/RF/GraphSAGE) làm `p_host` thật cho stacking. **Tôi vẫn chưa có đường dẫn kết quả nhánh Host; cần bạn hoặc Nguyễn cung cấp điểm dự đoán theo (host, cửa sổ) và file split.**
- Nếu tự dựng nhánh host: cần quét thêm ngày tấn công của các host TRAIN dương (khoảng 21 host × 3 ngày, ~9 GB, ~10 phút) để huấn luyện bộ phân loại cửa sổ host; vẫn cần mask nhãn tactic chưa có giai đoạn.
- Làm baseline này cho seed_2, seed_3 (rẻ, dữ liệu đã có) để biết kết luận có ổn định không.
