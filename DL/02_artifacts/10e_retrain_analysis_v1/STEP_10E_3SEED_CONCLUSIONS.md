# STEP 10E — Kết luận retrain trên 3 split ngẫu nhiên (12 run: 3 seed × {BiLSTM, Mixed-Type} × {full, noapp})

## Trạng thái

**ANALYSIS COMPLETE (3 seed).** Số liệu: `seed_{1,2,3}/analysis.json` (STEP 10E, script `01_code/pipeline/10e_analyze_retrain.py`) và `aggregate/aggregate.json` (script `01_code/pipeline/10f_aggregate_seeds.py`). Cấu hình train giống nhau ở cả 12 run (8 epoch tối đa, patience 3, seed khởi tạo 42, checkpoint/threshold chọn trên VAL, TEST chạy một lần).

Chú ý về "seed": ở đây **seed = seed của split** (tập host nào vào train/val/test), không phải seed khởi tạo model. Chưa có lần chạy lặp với seed khởi tạo khác.

## 1. Kiểm tra nguồn gốc

| Kiểm tra | Kết quả |
|---|---|
| 12 file zip kết quả (`output_kaggle/`) giải nén vào `05_models/10_random_seed{k}_v1/` (thư mục mới; zip gốc và `05_models/06_*`, `07_*` cũ không bị đụng) | ✅ |
| Fingerprint preprocessing trong `config.json` | khớp đúng seed: `99feefc8…` (seed_1), `6305d03c…` (seed_2), `c485c4d1…` (seed_3) ✅ |
| `drop_app_family` | full = `False`, noapp = `True`, ở cả 12 run ✅ |
| `train_pos_weight` | 371.4 / 514.9 / 412.0 theo seed, khớp 10C ✅ |
| Tính lại TP/FP/FN, PR-AUC, ROC-AUC từ `*_predictions.csv` | khớp `metrics.json` cho cả VAL và TEST của 12 run ✅ |

## 2. Kết quả TEST (mean ± độ lệch chuẩn mẫu trên 3 seed; mô tả, không phải kiểm định)

Mỗi seed có 82–87 positive window trong TEST, 4 host positive.

| Run | F1 | PR-AUC | ROC-AUC | window bỏ sót (FN) | host positive bị bắt (/4) | recall trung bình theo host |
|---|---:|---:|---:|---:|---:|---:|
| BiLSTM full (A0) | 0.969 ± 0.010 | 0.974 ± 0.036 | 0.985 ± 0.026 | 5.0 ± 1.7 | 3.3 ± 0.6 | 0.766 ± 0.037 |
| BiLSTM noapp (A1) | 0.959 ± 0.021 | 0.974 ± 0.025 | 0.994 ± 0.010 | 6.7 ± 3.5 | 3.3 ± 0.6 | 0.761 ± 0.045 |
| Mixed-Type full (A0) | **0.988 ± 0.011** | 0.998 ± 0.003 | 1.0000 ± 0.0000 | 2.0 ± 1.7 | 3.7 ± 0.6 | 0.875 ± 0.108 |
| Mixed-Type noapp (A1) | 0.957 ± 0.027 | 0.951 ± 0.040 | 0.995 ± 0.004 | 6.7 ± 4.2 | 3.7 ± 0.6 | 0.820 ± 0.102 |
| *B1: luật "window có `powershell.exe`"* | **0.976 ± 0.001** | — | — | 4.0 ± 0.0 | 3/4 mỗi seed | — |
| *B2-lite: cây quyết định depth 3 trên 4 số metadata* | 0.683 ± 0.186 | 0.537 ± 0.214 | 0.991 ± 0.003 | 15.0 ± 3.6 | — | — |

F1 theo từng seed (seed_1, seed_2, seed_3):

| Run | seed_1 | seed_2 | seed_3 |
|---|---:|---:|---:|
| BiLSTM full | 0.975 | 0.975 | 0.958 |
| BiLSTM noapp | 0.956 | **0.981** | 0.939 |
| Mixed full | 0.994 | 0.975 | 0.994 |
| Mixed noapp | 0.943 | **0.988** | 0.939 |
| B1 (luật) | 0.975 | 0.975 | 0.976 |

Precision = 1.000 ở hầu hết run (chỉ 1 window FP trong cả 12 run, ở Mixed noapp seed_1): **lỗi gần như hoàn toàn là bỏ sót, không phải báo nhầm.**

B2-lite là cây tự cài bằng numpy (máy local không có scikit-learn), không so trực tiếp với HGB ở STEP 09. B3 (oracle IP C2) chưa làm vì IP không nằm trong shards.

### Window bắt được theo scenario (gộp 3 seed, tp / số positive window)

| Run | SC1 | SC2 | SC3 |
|---|---:|---:|---:|
| BiLSTM full | 18/18 | 218/222 | 1/12 |
| BiLSTM noapp | 18/18 | 213/222 | 1/12 |
| Mixed full | 18/18 | 222/222 | 6/12 |
| Mixed noapp | 18/18 | 210/222 | 4/12 |
| B1 (luật) | 18/18 | 222/222 | 0/12 |

**SC3 "12 window" thực chất là 4 window của cùng một host (`sysclient0051`) lặp lại ở cả 3 seed**, vì host này luôn rơi vào TEST; không phải 12 quan sát độc lập. Số window bắt được theo seed (seed_1, seed_2, seed_3): BiLSTM full 1/0/0; BiLSTM noapp 0/1/0; Mixed full 3/0/3; Mixed noapp 0/3/1.

## 3. Kết luận

**K1 — Điểm gần 1.0 không thể quy hết cho `app_family`; có hai yếu tố cùng tồn tại.**
- Yếu tố 1 (shortcut): luật một dòng chỉ dùng `app_family` đạt F1 0.976, ngang BiLSTM full (0.969) và thấp hơn Mixed full (0.988) chỉ 0.012. Dữ liệu tách được gần như hoàn toàn bằng `app_family`. Mixed full có ROC-AUC = 1.0000 ở cả 3 seed dù checkpoint được chọn ở epoch 1, 2, 4 (model gần như chưa train): phù hợp với việc tách "dễ".
- Yếu tố 2 (beacon lặp): bỏ hẳn `app_family`, F1 vẫn còn 0.957–0.959; bắt 18/18 window SC1 và 95–96% window SC2 (210–213/222) chỉ từ timing/bytes/service/port. Beacon của chiến dịch đã thấy đủ đặc trưng để nhận ra mà không cần tên tiến trình.
- Vì vậy bỏ `app_family` chỉ giảm nhẹ và **không nhất quán giữa các seed**, xem K2.

**K2 — Ảnh hưởng của việc bỏ `app_family` (A0 so với A1) chưa được xác lập.**
- ΔF1 (full − noapp): BiLSTM +0.011 ± 0.015 (2 seed dương, 1 seed âm); Mixed +0.031 ± 0.038 (2 dương, 1 âm). Ở seed_2 chiều **ngược lại**: noapp tốt hơn full (BiLSTM 0.981 so với 0.975; Mixed 0.988 so với 0.975).
- Độ lớn chênh lệch trung bình nhỏ hơn hoặc bằng dao động giữa các seed ⇒ **không kết luận** "bỏ `app_family` làm model kém đi".
- Cộng thêm hạn chế A1 chưa hội tụ: best epoch của noapp là 8, 8, 6 (BiLSTM) và 7, 5, 8 (Mixed) trên tối đa 8, trong khi full dừng sớm (epoch 1–4). VAL PR-AUC của noapp dao động mạnh giữa các epoch. Khác biệt A0/A1 lẫn với ngân sách train.

**K3 — DL không vượt luật một dòng B1 một cách đáng kể.**
- BiLSTM full − B1: ΔF1 −0.006 ± 0.011 (seed_3 thua B1 3 window). Mixed full − B1: +0.012 ± 0.011 (hơn 3 window ở seed_1 và seed_3, hòa ở seed_2).
- Phần Mixed full hơn B1 nằm hoàn toàn ở 4 window SC3 của `sysclient0051`, và không ổn định (bắt 3/4 ở seed_1 và seed_3, **0/4 ở seed_2**).
- Cả hai cấu hình noapp có F1 trung bình thấp hơn B1 (BiLSTM −0.017, Mixed −0.019); chiều này thay đổi theo seed (seed_2: noapp cao hơn B1).

**K4 — Không kết luận "Mixed-Type tốt hơn BiLSTM".**
- Bản full: Mixed − BiLSTM ΔF1 = +0.018 ± 0.018 (2 seed dương, 1 seed hòa); bản noapp: −0.002 ± 0.010 (1 dương, 1 âm). Chênh lệch ở bản full cùng cỡ với dao động giữa các seed; ở bản noapp là 0.
- Checkpoint Mixed full được chọn rất sớm (epoch 1, 2, 4) khi VAL PR-AUC đã bão hòa, nên "thắng" của Mixed full dựa trên một model chưa train kỹ và gần như tình cờ trên 4 window.

**K5 — SC3 (host cần ngữ cảnh) là điểm yếu chung và là động lực cho fusion.**
- Network-only gần như không giải được SC3: tổng 1–6/12 window, và 0/4 ở nhiều run. Phân tích chi tiết ở phần mô tả SC3 (flow REJ tới `53.192.68.50:8080` từ `biguwcmnsucig.exe`, benign cũng có nhiều flow REJ tương tự).
- Gợi ý (giả thuyết chưa kiểm chứng): tiến trình lạ như `biguwcmnsucig.exe` không có trong từ điển TRAIN nên thành `<UNK>`; ở cả 3 seed, cả 4 window positive của `sysclient0051` đều chứa event `app_family = <UNK>`, trong khi `<UNK>` hiếm ở TRAIN (3–6 window positive, 2–3 window benign). Một model bản full có thể dùng "app lạ ⇒ đáng ngờ" như một shortcut thứ hai. Cần kiểm tra riêng nếu muốn khẳng định.

**K6 — Kết quả không ổn định ở mức train (cảnh báo phương pháp).**
- Best epoch dao động 1–8; threshold chọn trên VAL bão hòa ở đúng 1.0 trong 4/12 run (BiLSTM full seed_1, seed_2; Mixed full seed_2; Mixed noapp seed_3), làm mất các window có xác suất 0.99x.
- Số positive window VAL chênh lớn giữa các seed (39 / 168 / 88), `pos_weight` TRAIN cũng khác (371 / 515 / 412).
- Attention audit (chẩn đoán, không phải nhân quả): Mixed full dồn 0.52–0.68 attention vào `app_family` ở cả 3 seed; bản noapp chuyển sang `delta_t_log1p` và các cột bytes. Ở seed_2 attention của noapp gần như giống nhau giữa window positive và negative (0.569 so với 0.569), tức ít thông tin.

## 4. Những điều có thể và không thể nói (theo CLAUDE.md)

Có thể nói, với bằng chứng ở trên:
- Metric gần 1.0 **không** chứng minh model học hành vi APT tổng quát: luật một dòng đạt 0.976 và Mixed full chỉ hơn 0.012.
- Network-only phát hiện tốt beacon của chiến dịch đã thấy (SC1, SC2) nhưng không phát hiện được SC3 nếu thiếu ngữ cảnh host.
- Split ngẫu nhiên theo scenario **không** làm điểm rớt: kết quả gần như trùng với host split cũ, đúng dự báo STEP 09 §11.

Không thể nói:
- "Bỏ `app_family` làm giảm hiệu năng" hoặc "tăng hiệu năng": chiều thay đổi theo seed.
- "Mixed-Type tốt hơn BiLSTM": chưa vượt dao động giữa các seed.
- "Overfit": không có bằng chứng train–test gap.
- Mọi kết luận về SC3: chỉ 1 host, 4 window.

## 5. Hạn chế của thí nghiệm

1. Chỉ 3 split và 1 seed khởi tạo model; std với n = 3 chỉ mang tính mô tả, chưa có kiểm định thống kê hay bootstrap CI (TEST chỉ có 4 host positive).
2. TEST mỗi seed tập trung vào **một host SC2** (72–77 trên 82–87 window, ≈ 88–89%) cộng 4 window SC3; số window-level bị chi phối bởi host SC2 nào rơi vào TEST.
3. A1 chưa hội tụ; threshold bão hòa; VAL nhỏ và nhiễu (xem K6).
4. Chưa làm: tập hard-negative (E6), B3 oracle IP-C2, HGB thật (cần scikit-learn), đánh giá nhóm theo template (E2 ở STEP 09 §11).

## 6. Việc tiếp theo đề xuất (ưu tiên giảm dần)

1. **Đánh giá theo nhóm template/dedup** (STEP 09 §11 E2): giữ trong TEST chỉ các host có template beacon không xuất hiện ở TRAIN, hoặc báo metric sau khi gộp window trùng template. Đây là thí nghiệm trả lời trực tiếp "học hành vi hay thuộc template".
2. **Hard-negative set** (E6): FPR trên window benign có app ≠ firefox và trên 5,563 flow benign tới `53.192.68.50`.
3. **Độ nhạy cấu hình train** (làm cho cả full và noapp, áp dụng cho cả 3 seed): tăng `--epochs` lên 16; tie-break threshold sang trung điểm giữa positive thấp nhất và negative cao nhất trên VAL; thêm seed khởi tạo 43, 44 để đo dao động do khởi tạo.
4. **LOSO làm stress test phụ lục** (E5): dataset LOSO đã có trên Kaggle (3 holdout); mỗi notebook chỉ gắn một holdout (upload từng holdout thành dataset riêng).
5. **SC3 và fusion với ngữ cảnh host**: thêm nhánh host (process tree, command line) và đo lại SC3; kiểm tra giả thuyết `<UNK>` ở K5.
6. **Dữ liệu** (STEP 09B §4.4, làm sau khi các bước trên xong): kiểm tra ~47k positive Bro event bị rơi ở inner join; cân nhắc bản eCAR đã sửa của bài báo.

## 7. Câu hỏi cần thống nhất với thầy

1. Kết quả chính của nhánh Network nên là A1 (network-only) trên random split nhiều seed, còn A0 chỉ để phân tích shortcut?
2. Chấp nhận framing: "network-only phát hiện tốt beaconing của chiến dịch đã biết nhưng không phân biệt được SC3 nếu thiếu ngữ cảnh host" làm động lực cho fusion?
3. Có dùng bản eCAR đã sửa và nhãn của bài báo làm ground truth chính thức?

## 8. File

- `01_code/pipeline/10e_analyze_retrain.py`, `10f_aggregate_seeds.py`
- `02_artifacts/10e_retrain_analysis_v1/seed_{1,2,3}/analysis.json`, `aggregate/aggregate.json`
- `02_artifacts/10e_retrain_analysis_v1/STEP_10E_SEED1_ANALYSIS.md` (phân tích riêng seed_1, viết trước)
- Model: `05_models/10_random_seed{1,2,3}_v1/<run>/`
