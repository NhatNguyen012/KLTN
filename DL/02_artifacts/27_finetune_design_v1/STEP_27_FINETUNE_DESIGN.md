# STEP 27 — Thiết kế fine-tune mô hình B trên skrghosh (mở rộng từ điển, replay OpTC)

Ngày: 2026-10-22. **Chỉ là thiết kế, chưa cài đặt hay chạy gì.** **Bản cập nhật 2026-10-22:** theo yêu cầu của thầy (mô hình phải được học các scenario rồi mới test), cách chia chính đổi từ leave-one-scenario-out sang **trộn đều theo cửa sổ, 4-fold phân tầng** (mục 3); LOSO giữ làm kiểm tra phụ tùy chọn. Dựa trên số liệu đã đo ở STEP 25–26. Chưa có bằng chứng rằng fine-tune sẽ giúp ích; mục tiêu của thí nghiệm là **đo** (có/không, bao nhiêu), không phải chứng minh.

## 1. Mục tiêu và câu hỏi đo được (khớp Nội dung 5 của đề cương)
1. **Plasticity (học cái mới):** sau fine-tune, mô hình có phát hiện được chiến dịch skrghosh chưa thấy khi huấn luyện không? (F1/PR-AUC trên các cửa sổ test của fold.)
2. **Stability (không quên):** F1/PR-AUC trên OpTC TEST trước và sau fine-tune (BWT = F1_OpTC sau − F1_OpTC trước; trước: BiLSTM 0.988, Mixed-Type 0.988, STEP 24).
3. **Giá trị của mở rộng từ điển:** so với mô hình zero-shot (STEP 26) trên cùng phần dữ liệu giữ lại.
Không đặt mục tiêu "chứng minh tổng quát hóa"; xem cảnh báo mục 7.

## 2. Dữ liệu nền (đã đo)
| Scenario | Sample | Sample dương | Flow dương | Cửa sổ dương (giờ UTC) |
|---|---:|---:|---:|---|
| FIN6 | 45 | 2 | 6 | 01:45, 02:00 (liền kề → **1 đợt tấn công**) |
| APT29 | 77 | 2 | 3 | 07:15, 07:30 (liền kề → **1 đợt**) |
| menuPass | 74 | 4 | 273 (254 là `nbtscan.exe`) | 00:45+01:00 và 03:30+03:45 (**2 đợt**) |
| **Tổng** | 196 | **8** | 282 | **4 đợt độc lập** |
OpTC: TRAIN 160,210 sample (401 dương), VAL 34,361 (83 dương), TEST 34,413 (82 dương).

## 3. Cách chia train/val/test (bản chính: trộn đều theo cửa sổ, 4-fold phân tầng)
Giống quy ước đã chốt cho OpTC (split cấp cửa sổ, phân tầng theo scenario, không host-disjoint): mọi scenario đều có mặt trong train, và test là các cửa sổ khác của cùng các scenario. Vì chỉ có 8 sample dương nên **không chia 70/15/15 một lần** (test sẽ có 1–2 mẫu dương); dùng **4-fold chéo** để mỗi sample dương được test đúng một lần (out-of-fold) rồi gộp kết quả.
- **Đơn vị chia = cửa sổ (máy, 15 phút)**: các chunk của cùng một cửa sổ luôn ở cùng một fold. 181 cửa sổ, 196 sample.
- **Cửa sổ dương** (8 cửa sổ): xếp theo (scenario, thời gian) rồi gán lần lượt vào fold 0,1,2,3 → mỗi fold có đúng 2 sample dương. **Cửa sổ benign**: xáo trộn có seed (20261022) trong từng scenario rồi gán lần lượt vào các fold (phân tầng theo scenario). Phân bổ cụ thể ở `fold_assignment_mixed_4fold.csv`.
| Fold | Sample | Sample dương (scenario) | Flow dương |
|---|---:|---|---:|
| 0 | 47 | 2 (APT29, menuPass 00:45) | 18 |
| 1 | 53 | 2 (APT29, menuPass 01:00) | 256 |
| 2 | 52 | 2 (FIN6, menuPass 03:30) | 2 |
| 3 | 44 | 2 (FIN6, menuPass 03:45) | 6 |
- **Mỗi lần chạy:** TEST = 1 fold (khoảng 2 sample dương); TRAIN = 3 fold còn lại (6 sample dương, ~150 sample), trong đó ~10% cửa sổ benign ngẫu nhiên làm VAL theo dõi loss. **Không có VAL dương** nên không chọn ngưỡng/epoch theo skrghosh; siêu tham số cố định từ trước (mục 5).
- **VAL OpTC** (83 dương) chỉ để theo dõi quên; **TEST OpTC** (82 dương) tính một lần ở cuối mỗi fold/seed.
- **Chỉ số gộp:** ghép dự đoán out-of-fold của 4 fold thành một bảng 196 sample/8 dương để tính PR-AUC, ROC-AUC, recall; **đối chiếu trực tiếp với zero-shot STEP 26 trên đúng 196 sample đó** (BiLSTM F1 0.182, Mixed-Type F1 0).
- **Cái được đo:** khả năng nhận ra các mẫu thuộc **cùng chiến dịch đã thấy một phần** (giống phát biểu của OpTC), không đo chiến dịch mới. Đây là mục tiêu thầy yêu cầu; hệ quả và giới hạn ở mục 7.
- **Kiểm tra phụ (tùy chọn, rẻ vì cùng mã):** leave-one-scenario-out 3 fold (giữ lại FIN6, APT29 hoặc menuPass làm TEST) để cho thấy khoảng cách giữa "đã thấy" và "chưa thấy". Nếu thầy cho rằng LOSO chắc chắn thấp thì đây vẫn là con số minh họa, không phải chỉ số chính.

## 4. Mở rộng từ điển (chỉ nối thêm, giữ id cũ)
- **Tạo từ điển mở rộng từ TRAIN của fold**: lấy các `app_family` chưa có trong từ điển OpTC và có ≥ 5 flow trong các cửa sổ TRAIN của fold (cùng ngưỡng `min_train_frequency = 5` của OpTC), gán id nối tiếp từ 61; thêm `resp_port_class = EPHEMERAL` (OpTC không có, chiếm 2,764 flow ở skrghosh). Skrghosh có 25 tên tiến trình ngoài từ điển OpTC (phủ 75% flow), 15 tên có ≥ 5 flow trên toàn bộ dữ liệu; số token mới của từng fold sẽ tính lại khi sinh spec (tính trên cửa sổ TRAIN của fold, nên có thể ít hơn). Token ngoài từ điển mở rộng vẫn là `<UNK>` (id 0), như dữ liệu thực tế.
- **Không fit lại gì từ cửa sổ TEST của fold.** Spec mở rộng là một file mới (`preprocess_spec_ext_fold<k>.json`) = spec OpTC + các mục từ điển nối thêm; dấu vân tay sha256 mới, ghi rõ nguồn gốc. Dữ liệu OpTC giữ nguyên shards (id cũ < 61 không đổi).
- **Mô hình:** thêm hàng vào bảng embedding `app_family` (61 → 61+k) và `resp_port_class` (11 → 12); chiều embedding không đổi (BiLSTM `min(16, …)` vẫn 16 và 7; Mixed-Type `d_model = 64`). **Kiến trúc không đổi.** Hàng mới khởi tạo bằng bản sao hàng `<UNK>`. Do đó, trước khi huấn luyện, dự đoán của mô hình mở rộng trên skrghosh phải **trùng khớp từng mẫu** với kết quả zero-shot STEP 26 (kiểm tra bắt buộc, giống kiểm tra 682 mẫu ở STEP 26).
- Mã hóa lại skrghosh bằng spec mở rộng từng fold (vài giây, giống `s10_shards.py` với spec khác).

## 5. Quy trình fine-tune (tham số đặt trước, chưa thử)
Áp dụng riêng cho BiLSTM và Mixed-Type, giữ siêu tham số kiến trúc của 06e/07e.
- **Replay OpTC:** tập replay R = **toàn bộ 401 mẫu dương TRAIN OpTC + 1,600 mẫu âm TRAIN OpTC** ngẫu nhiên (seed cố định, phân tầng theo ngày), ~1.25% TRAIN OpTC. Mỗi epoch dùng toàn bộ sample skrghosh TRAIN của fold (~150) và rút ngẫu nhiên 600 mẫu từ R (150 dương, 450 âm), tức replay chiếm khoảng 4–5 lần số sample skrghosh. `pos_weight` tính trên tập trộn.
- **Giai đoạn A (3 epoch):** chỉ huấn luyện các hàng embedding mới và đầu phân loại; phần còn lại đóng băng; lr 1e-3.
- **Giai đoạn B (3 epoch):** mở khóa toàn bộ, lr nhỏ (BiLSTM 1e-4, Mixed-Type 3e-5), cùng weight decay như bản gốc.
- **Không early stopping theo skrghosh.** Lấy checkpoint cuối giai đoạn B. Theo dõi VAL OpTC để báo cáo quên.
- **Ngưỡng:** báo cả hai, không tinh chỉnh: (i) ngưỡng VAL OpTC cũ (0.9956 và 1.0, đã biết là bão hòa), (ii) 0.5. Chỉ số chính là **thứ tự điểm** (PR-AUC, ROC-AUC) và hạng của các mẫu dương.
- **Seed:** 3 seed (42, 43, 44) mỗi fold để đo độ ổn định **do khởi tạo/xáo trộn**, không đo độ ổn định do dữ liệu. Tổng 4 fold × 3 seed × 2 mô hình = 24 lần chạy rất nhỏ (thêm 18 lần nếu làm kiểm tra phụ LOSO).
- **Đối chứng:** (a) zero-shot (STEP 26, có sẵn); (b) fine-tune giữ nguyên từ điển cũ (không mở rộng) để tách giá trị của mở rộng từ điển; (c) luật đơn giản "có `powershell.exe`/`splunkd.exe`". Mục (b) là thí nghiệm thêm ngoài phạm vi các quyết định đã chốt cho OpTC, cần bạn đồng ý.

## 6. Chỉ số báo cáo
Mỗi fold và gộp out-of-fold 4 fold: TP/FP/FN/TN và PR-AUC, ROC-AUC trên TEST skrghosh; khoảng tin cậy chính xác Clopper–Pearson 95% cho recall cấp sample; F1 OpTC TEST/VAL trước và sau, BWT; trung bình và độ lệch giữa 3 seed. **Không** nêu "tốt hơn" khi hiệu số nằm trong khoảng dao động giữa các seed hoặc ≤ 1 mẫu dương.

## 7. Cảnh báo số mẫu dương ít và hệ quả của việc trộn (phải nêu khi báo cáo)
1. **Chỉ có 8 sample dương, thực chất 4 đợt tấn công độc lập** (các cửa sổ liền kề cùng đợt). Mỗi fold test chỉ có 2 sample dương; chỉ khi gộp out-of-fold mới có 8.
2. **Khoảng tin cậy rất rộng:** bắt được 8/8 chỉ cho recall ≥ 0.631 (95%); 4/4 cho ≥ 0.398; 2/2 cho ≥ 0.158; bắt 4/8 nằm trong [0.157, 0.843]. Một mẫu = 12.5 điểm recall khi gộp (50 điểm ở từng fold). Không phân biệt được hai mô hình nếu chênh vài mẫu.
3. **Rò rỉ cửa sổ liền kề là có thật, và cách chia này đặt nó ở mức cao nhất:** cả 4 đợt tấn công đều có cửa sổ kề bên nằm ở fold khác (APT29 07:15 và 07:30 ở fold 0 và 1; FIN6 01:45 và 02:00 ở fold 2 và 3; menuPass 00:45 và 01:00 ở fold 0 và 1, 03:30 và 03:45 ở fold 2 và 3). Khi cửa sổ này được test, cửa sổ kề (cùng đợt, cùng tiến trình và đích) đã nằm trong train. Vì vậy điểm số **đo khả năng nhận ra đợt tấn công đã thấy**, không đo phát hiện đợt mới. Ví dụ: menuPass 00:45 (16 flow dương) được test khi cửa sổ 01:00 (255 flow dương) ở train.
4. **93% flow dương là một token** (`nbtscan.exe`, 254/282 flow, trong cửa sổ 00:45 và 01:00 của menuPass). Fold 1 (test cửa sổ 01:00) có thể thiếu token này trong train nếu cửa sổ chứa nó nằm ở test; kết quả từng fold khác nhau nhiều vì lý do này, không phản ánh chất lượng mô hình.
5. **Nhãn có nguy cơ tuần hoàn:** nhãn do script KLTN lan theo cây tiến trình `splunkd.exe`; mô hình dùng tên tiến trình, nên "học được" có thể chỉ là học lại luật gán nhãn.
6. **Cùng một máy ảo (`192.168.1.139`) ở cả ba scenario:** hành vi benign lặp lại giữa train và test; phát biểu đúng là "nhận ra mẫu/chiến dịch đã thấy trên cùng môi trường".
7. **Không có VAL dương** nên không chọn được ngưỡng/epoch có nguyên tắc; tham số đặt từ trước, không thử lại sau khi thấy TEST (nếu buộc phải thử lại thì ghi rõ TEST đã mở lần hai).
8. **Kết quả cao ở cách chia này không phải bằng chứng khả năng tổng quát hóa.** Zero-shot (STEP 26) cho F1 0–0.18 trên cùng 196 sample; nếu fine-tune trộn đạt cao, phần lớn có thể do nhớ đợt đã thấy. Khi báo cáo cần đặt hai con số cạnh nhau và nói rõ điều kiện.
9. **AIT và dataset khác không bù được:** AIT chỉ có nhãn suy ra và không có field tiến trình (STEP 25–26), không dùng làm TRAIN fine-tune ở bước này.
10. **Quên:** F1 OpTC TEST có 82 mẫu dương, một mẫu = 1.2 điểm recall; BWT trong khoảng ±2 mẫu không phân biệt được với dao động.

## 8. Phương án khác cho vấn đề ít mẫu dương (chưa chọn, cần bạn quyết)
- **Xem đây là nghiên cứu khả thi**, báo cáo thẳng các số liệu và khoảng tin cậy (đề xuất, ít tốn nhất).
- **Thêm dữ liệu có nhiều dương hơn** (THEIA: 64,012 cạnh dương nhưng 99% từ một tiến trình; CADETS: 75,423 cạnh dương, chưa có tên tiến trình): cần tiền xử lý mới và có rủi ro riêng.
- **Cửa sổ ngắn hơn (ví dụ 5 phút) để có nhiều sample dương hơn:** làm phân phối sample khác OpTC (huấn luyện bằng cửa sổ 15 phút), nên **không đề xuất**.

## 9. Việc cần làm để cài đặt (ước lượng, chưa làm)
1. Sinh spec mở rộng và shards skrghosh theo 3 fold (vài giây mỗi fold) + tập replay R (từ shards OpTC có sẵn, vài trăm MB).
2. Viết bộ nạp trộn hai nguồn và script fine-tune (thay đổi chỉ ở nạp dữ liệu, đóng băng/mở khóa tham số, thêm hàng embedding); kiểm tra "trùng khớp zero-shot" trước khi train.
3. Chạy 18 lần: mỗi lần chỉ vài trăm sample skrghosh + ~600 replay mỗi epoch × 6 epoch; ước tính vài phút mỗi lần trên CPU, nhanh hơn trên Kaggle GPU. **Theo quy tắc dự án, train chạy trên Kaggle do bạn chạy**; nếu bạn đồng ý, mình có thể chạy cục bộ vì quy mô rất nhỏ.
