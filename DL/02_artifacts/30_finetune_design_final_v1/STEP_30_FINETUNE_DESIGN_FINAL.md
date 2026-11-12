# STEP 30 — Thiết kế fine-tune cuối (mô hình B, hai miền Windows, chia trộn 4-fold, replay OpTC)

Ngày: 2026-10-22. Thay thế và gộp STEP 27 (thiết kế skrghosh) với STEP 28–29 (THEIA, FiveDirections). **Chỉ là thiết kế, chưa cài đặt hay chạy.** Mục tiêu là đo, không phải chứng minh fine-tune sẽ tốt.

## 0. Thuật ngữ
- **Flow:** một kết nối mạng (một dòng) kèm tiến trình tạo ra nó. Mô hình thấy 5 trường: `app_family`, `image_dir_class`, `resp_port_class`, `proto`, `delta_t`.
- **Sample:** một cửa sổ 15 phút của một máy, tối đa 512 flow; nhãn sample = có ít nhất 1 flow dương.
- **Zero-shot:** dùng nguyên mô hình đã train trên OpTC để thi trên dữ liệu mới, chưa cho học thêm gì (STEP 26, 28, 29).
- **Fine-tune:** cho mô hình đã train trên OpTC học thêm một ít trên dữ liệu mới, kèm "ôn lại" một phần OpTC (replay) để không quên.
- **Fold:** một phần trong 4 phần chia đều các cửa sổ; mỗi lần chạy dùng 1 fold để thi, 3 fold để học.

## 1. Quyết định phạm vi
| Hạng mục | Quyết định | Lý do |
|---|---|---|
| Mô hình | BiLSTM và Mixed-Type bản B (đầu vào 4 category + `delta_t`), kiến trúc và đầu vào **giữ nguyên** | so sánh trước/sau sạch, dùng lại mô hình đã có |
| Miền mới | **skrghosh** và **FiveDirections** (cùng Windows với OpTC), báo cáo riêng từng bộ rồi gộp | từ điển và đường dẫn khớp OpTC (FiveDirections UNK 4.6%) |
| Không dùng | THEIA (Linux, nhãn nhiễu, 2 đợt), AIT (không có tiến trình, nhãn suy ra) | xem STEP 25, 26, 28 |
| Chia | trộn đều theo cửa sổ, 4-fold phân tầng (yêu cầu của thầy) | mọi chiến dịch đều có mặt ở train |
| Từ điển | **mở rộng (người dùng đã chốt 2026-10-22)**; không làm đối chứng "không mở rộng" | — |
| Replay | tập R từ OpTC TRAIN: 401 mẫu dương + 1,600 mẫu âm | chống quên |

### 1b. Về việc giữ nguyên đầu vào (đính chính và số liệu, 2026-10-22)
Giữ nguyên đầu vào là **lựa chọn có chủ đích**, không phải ràng buộc kỹ thuật cứng; điều đã chốt là không đổi *kiến trúc*, và việc bỏ field ở bản B được bạn duyệt. Ý "IP lạ làm hành động độc hại thì IP đó là độc" là đúng về nguyên tắc; vấn đề nằm ở **cách đưa IP vào**:
- **IP làm mã định danh (id trong bảng embedding): không khái quát được.** IP chưa từng thấy được mã hóa là `<UNK>` nên mô hình không biết gì về nó. Và trong OpTC, nhãn mạng *được định nghĩa bằng IP C2 và thời gian* (A New Hope), nên đưa IP vào là đưa luôn định nghĩa nhãn: **24,721 flow dương của OpTC chỉ đi tới 4 IP đích** (`202.6.172.98` 13,411; `132.197.158.98` 11,090+; `53.192.68.50`; cùng vài cổng khác), cả 4 đã có trong TRAIN, và **0 flow benign** đi tới hai IP C2 chính. Một mô hình có IP sẽ đạt gần điểm tuyệt đối trên OpTC chỉ bằng cách tra bảng 4 IP, rồi bỏ qua mọi thứ khác.
- **IP làm "hành vi" thì có tín hiệu, đúng như bạn nghĩ.** Mình đo thử (chưa trên OpTC): số đích khác nhau mà cùng một ứng dụng liên hệ trong cửa sổ (fan-out). Trên skrghosh AUC mức flow 0.931 (flow dương trung vị 254 đích khác nhau so với 9, do quét NetBIOS `192.0.2.x:137` của `nbtscan.exe`), trên FiveDirections 0.717 (14 so với 4). Số flow lặp cùng một đích trong cửa sổ thì ngược chiều giữa các bộ: OpTC dương là beacon lặp lại cùng đích, skrghosh dương là quét nhiều đích khác nhau (AUC 0.074, tức dương có ít lặp). Hai kiểu "bất thường về đích" ngược nhau trên cùng một đặc trưng, nên mô hình train trên OpTC không thể suy ra kiểu quét; phải học thêm ở bước fine-tune.
- **FiveDirections không hưởng lợi từ IP:** 307 flow dương đi tới 20 đích, hầu hết là máy chủ web bình thường (Google `64.233.169.103` 120 flow, `74.52.178.194` 62 flow...) vì nhãn là mức tiến trình; chỉ 9 flow tới IP tấn công trong báo cáo. Nhãn mức tiến trình khiến "IP có độc không" không phải câu trả lời cho phần lớn flow dương ở đây.
- **Cách đúng nếu muốn thêm:** đặc trưng hành vi theo đích **không dùng định danh IP** (fan-out, số lần lặp cùng đích, độ đều của khoảng cách giữa các lần, đích mới đối với máy), tính từ cửa sổ. Việc này đổi đầu vào, phải dựng lại shards OpTC từ `flows_joined.parquet` (có sẵn `resp_h`) và **train lại OpTC trên Kaggle**; chưa làm vì cần bạn đồng ý và vì phải kiểm xem đặc trưng không làm lộ nhãn OpTC (nhãn định nghĩa theo IP + thời gian).
- **Dòng lệnh:** xem mục 1c.

### 1c. Dòng lệnh (command line) trong OpTC và các bộ khác
Dòng lệnh là **toàn bộ chuỗi dùng để khởi chạy một tiến trình, gồm cả tham số**. Trích từ dữ liệu:
- **OpTC, file đang dùng (`E:\ecar-bro`, bảng eCAR-Bro, bản ghi FLOW):** trường có `bro_uid`, `dest_ip`, `dest_port`, `direction`, `image_path`, `l4protocol`, `src_ip`, `src_port`, `pid`, `ppid`, `actorID`, `principal` (ví dụ `image_path = \\?\C:\Program Files (x86)\Mozilla Firefox\firefox.exe`). **Không có `command_line` và không có `parent_image_path`.**
- **OpTC, log host thô (`E:\host-malicious\...\sysclient0201.json.gz`, eCAR), sự kiện `PROCESS`/`CREATE`:** có `properties.command_line`, `image_path`, `parent_image_path`, `user`. Ví dụ tiến trình độc (nhãn `label: 1`): `command_line = "powershell  -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAHIAUwBJAG8ATgBUAGEAYgBMAGUALg..."`, `image_path = powershell.exe`, `parent_image_path = \Device\HarddiskVolume1\Windows\system32\cmd.exe`. Một ví dụ benign: `command_line = C:\Windows\system32\cmd.exe /c "powershell -c "Get-Service lwabeat""`, cha là `python.exe`. Sự kiện FLOW trong log host thô cũng **không** có dòng lệnh; muốn gắn cho flow phải tra từ `actorID` của flow sang sự kiện tạo tiến trình (độ chính xác ánh xạ chưa đo; bài A New Hope báo khoảng 40% tiến trình bị gán sai).
- **FiveDirections:** bảng `process_node_table` cột `cmd` chính là dòng lệnh (ví dụ `powershell  -nop -ep bypass -encodedCommand KABOAGUAdwAtAE8...`), chỉ có ở ~3% tiến trình nhưng phủ gần hết tiến trình có socket.
- **skrghosh:** sự kiện `PROCESS`/`CREATE` có `command_line`, `parent_image_path`, `user`.
Hệ quả: dòng lệnh **không có trong dữ liệu train OpTC đang dùng**; để dùng phải quét log host (~6–7 giờ) và chấp nhận sai số ánh xạ. Vì vậy chưa đưa vào.

## 2. Dữ liệu và chia fold (số liệu đã đo)
| | Sample | Sample dương | Flow dương | Đợt tấn công |
|---|---:|---:|---:|---:|
| skrghosh | 196 | 8 | 282 | 4 |
| FiveDirections | 930 | 8 | 307 | 3 |
| **Gộp hai miền** | **1,126** | **16** | 589 | **7** |
Phân bổ 4-fold (cửa sổ dương gán lần lượt vào các fold, cửa sổ benign xáo trộn có seed 20261022 rồi gán lần lượt; mọi chunk của một cửa sổ cùng fold). File: `27_finetune_design_v1/fold_assignment_mixed_4fold.csv` (skrghosh) và `29_fivedirections_analysis_v1/fold_assignment_fd_mixed_4fold.csv`.
| Fold | Test: sample (dương) skrghosh + FD | Train: sample (dương) |
|---|---|---|
| 0 | 47 + 233 = 280 (2 + 2 = 4) | 846 (12) |
| 1 | 53 + 240 = 293 (4) | 833 (12) |
| 2 | 52 + 232 = 284 (4) | 842 (12) |
| 3 | 44 + 225 = 269 (4) | 857 (12) |
- Chunk cùng cửa sổ luôn chung fold; **cửa sổ kề cùng đợt luôn ở fold khác** (rò rỉ có chủ ý, hệ quả của việc trộn).
- Trong TRAIN của fold, ~10% cửa sổ benign ngẫu nhiên làm VAL chỉ để theo dõi loss. **Không có VAL dương** → không chọn ngưỡng, epoch hay siêu tham số theo dữ liệu mới.

## 3. Mở rộng từ điển (chỉ nối thêm, giữ id OpTC)
- Lấy từ cửa sổ TRAIN của từng fold (không dùng cửa sổ test): `app_family` chưa có trong từ điển OpTC và có ≥ 5 flow (toàn bộ dữ liệu: skrghosh 15 tên, FiveDirections 7 tên; mỗi fold sẽ ít hơn hoặc bằng, ước ~20 tên sau khi gộp); `resp_port_class` thêm lớp còn thiếu (ví dụ `EPHEMERAL`).
- Spec mới `preprocess_spec_ext_fold<k>.json` = spec OpTC + mục từ điển nối thêm, dấu vân tay sha256 mới; mã hóa lại shards của hai miền theo spec này. Shards OpTC không đổi (id cũ).
- Bảng embedding thêm hàng (`app_family` 61 → ~81, `resp_port_class` 11 → ~12); chiều embedding không đổi. **Hàng mới khởi tạo bằng bản sao hàng `<UNK>`** nên mô hình mở rộng ban đầu phải cho đúng dự đoán zero-shot.

## 4. Quy trình mỗi lần chạy (một fold, một seed, một mô hình)
1. **Kiểm tra bắt buộc trước khi train:** mô hình mở rộng chưa train cho xác suất **trùng từng mẫu** với zero-shot (STEP 26, 28, 29) trên mọi sample của hai miền; và trùng Kaggle trên 682 mẫu OpTC. Không qua thì dừng.
2. **Dữ liệu mỗi epoch:** toàn bộ sample TRAIN của hai miền trong fold (~840) + 600 mẫu rút ngẫu nhiên từ R (150 dương, 450 âm). `pos_weight` tính trên tập trộn.
3. **Giai đoạn A (3 epoch):** chỉ huấn luyện các hàng embedding mới và đầu phân loại; còn lại đóng băng; lr 1e-3.
4. **Giai đoạn B (3 epoch):** mở khóa toàn bộ; lr BiLSTM 1e-4, Mixed-Type 3e-5; weight decay như bản gốc. Lấy checkpoint cuối giai đoạn B (không early stopping theo dữ liệu mới).
5. **Đánh giá một lần** ở cuối: sample test của fold (cả hai miền); OpTC TEST (82 dương) và OpTC VAL (83 dương) để đo quên. Ngưỡng cố định trước: ngưỡng VAL OpTC cũ (0.9956 và 1.0) **và** 0.5; không tinh chỉnh.
6. **Số lần chạy (xem mục 8):** đề xuất **3 fold × 1 seed (42) × 2 mô hình = 6 lần**; thêm seed hoặc fold chỉ khi cần.

## 5. Chỉ số báo cáo
- **Chính:** thứ tự điểm trên dự đoán out-of-fold ghép của 4 fold (16 sample dương): PR-AUC, ROC-AUC, hạng của từng mẫu dương; recall/precision/F1 tại 2 ngưỡng cố định; **khoảng tin cậy Clopper–Pearson 95%** (bắt 16/16 chỉ cho recall ≥ 0.794; 8/16 nằm trong [0.247, 0.753]).
- **Tách riêng từng miền** (skrghosh, FiveDirections) vì dương của hai bộ khác bản chất (STEP 29).
- **Quên:** F1, recall, PR-AUC trên OpTC TEST/VAL trước và sau; BWT = F1_sau − F1_trước (trước: 0.988 và 0.988). BWT trong ±2 mẫu dương (1 mẫu = 1.2 điểm recall) không phân biệt được với dao động.
- **Đối chiếu bắt buộc đặt cạnh:** (a) zero-shot trên đúng các sample đó; (b) luật đơn giản theo token (`powershell.exe`/`splunkd.exe`/`pass_mgr.exe`/`nbtscan.exe`) để biết mô hình có hơn luật hay không; (c) mức nền ngẫu nhiên = tỉ lệ dương (skrghosh 4.1%, FiveDirections 0.9%).
- **Độ ổn định:** trung bình và độ lệch giữa 3 seed (chỉ phản ánh ngẫu nhiên khởi tạo/xáo trộn, không phản ánh dữ liệu ít).

## 6. Cái gì có thể và không thể xảy ra (giả thuyết cần kiểm, không hứa)
- **H1 (skrghosh):** dương là các token tiến trình lạ (`splunkd.exe`, `nbtscan.exe`, `pscp.exe`) → sau mở rộng từ điển mô hình có thể học được, chủ yếu bằng cách **nhớ tên**; điểm tăng không có nghĩa là học hành vi.
- **H2 (FiveDirections):** 99% flow dương là `firefox.exe` giống flow bình thường nên **đầu vào hiện tại không đủ để tách**; fine-tune khó cải thiện ngoài `powershell.exe` và `pass_mgr.exe`. Nếu kết quả vẫn thấp thì đó là giới hạn của đầu vào, không phải lỗi huấn luyện.
- **H3 (quên):** replay 600 mẫu/epoch có thể giữ F1 OpTC; nếu BWT âm hơn 2 mẫu dương, tăng replay là phương án (cần bạn đồng ý, vì là thí nghiệm thêm).
Kết quả nào cũng phải nêu cùng cảnh báo của STEP 27 mục 7: chỉ 16 sample dương, 7 đợt tấn công, rò rỉ cửa sổ kề, nhãn mức tiến trình hoặc suy ra, một máy mỗi bộ.

## 7. Sản phẩm sẽ tạo khi cài đặt (đề xuất tên)
`01_code/pipeline_v2/s14_make_ext_spec.py` (spec mở rộng và mã hóa lại shards), `s14_finetune.py` (nạp trộn hai nguồn + replay, đóng băng/mở khóa, thêm hàng embedding, kiểm tra trùng zero-shot), `s14_collect.py` (gộp out-of-fold và tính chỉ số), thư mục `02_artifacts/31_finetune_run_v1/` và báo cáo `STEP_31_*.md`.

## 8. Số lần chạy, chi phí và nơi chạy
Không bắt buộc 4 fold × 3 seed; đó chỉ là thiết kế đầy đủ nhất. Nút thắt là **số mẫu dương** chứ không phải thời gian. Các phương án (ước lượng thời gian CPU theo tốc độ suy luận đo được, huấn luyện chậm hơn ~3–4 lần; mỗi lần gồm cả BiLSTM và Mixed-Type ≈ 8 phút):
| Phương án | Số lần chạy | Mẫu dương ở test | Khoảng tin cậy 95% nếu bắt hết | Thời gian |
|---|---:|---|---|---|
| A. một lần chia (một fold, seed 42) | 2 | 4 đến 7 | recall ≥ 0.398 (4/4) đến 0.590 (7/7) | ~8–10 phút |
| 2 fold, seed 42 | 4 | 8 + 8 (mỗi mẫu test đúng một lần) | 8/8 tại từng fold ≥ 0.631; gộp 16/16 ≥ 0.794 | ~20 phút |
| **B. 3 fold, seed 42 (đề xuất)** | **6** | **7 + 5 + 4 (gộp 16)** | gộp 16/16 ≥ 0.794 | **~25 phút** |
| C. 4 fold × 3 seed | 24 | 4 mỗi fold (gộp 16) | gộp 16/16 ≥ 0.794 | ~1.5 giờ |
- **Vì sao không nên chỉ một lần chia:** một fold test chỉ có 4–7 mẫu dương, thuộc 1–3 đợt tấn công; kết quả phụ thuộc đợt nào rơi vào test. Chạy qua nhiều fold để **mọi mẫu dương đều được thi một lần** (kết quả out-of-fold), chi phí thêm chỉ ~15 phút.
- **Vì sao 1 seed là chấp nhận được:** khớp quyết định đã chốt "train một lần (seed 42)" cho OpTC. Cái giá: không đo được dao động do khởi tạo, nên không so hơn kém BiLSTM và Mixed-Type nếu chênh vài mẫu.
- Hai fold: train chỉ 563 sample/8 dương, ít dữ liệu học hơn; 3 fold cân bằng hơn (train 746–753 sample, 9–12 dương). Phân bổ: `fold_assignment_both_3fold.csv`, `fold_assignment_both_2fold.csv` (cùng quy tắc cửa sổ dương gán lần lượt, benign xáo trộn seed 20261022; 4 fold giữ như cũ).
- Theo quy tắc dự án, train chạy trên Kaggle do bạn chạy; với quy mô này mình có thể chạy cục bộ nếu bạn đồng ý.

## 9. Việc cần bạn quyết
1. Chọn phương án chạy (A, 2 fold, **B đề xuất**, hay C) và nơi chạy (CPU cục bộ hay Kaggle).
2. Có làm thí nghiệm **đặc trưng hành vi theo đích** (fan-out, lặp cùng đích, độ đều; không dùng IP làm định danh) hay không; cần dựng lại shards OpTC và train lại OpTC trên Kaggle (mục 1b).
3. Có làm kiểm tra phụ leave-one-scenario-out hay không (chỉ để minh họa).
