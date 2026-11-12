# STEP 28 — Phân tích THEIA (E3) và tiền xử lý để fine-tune mô hình B

Ngày: 2026-10-22. Mã: `01_code/pipeline_v2/s12_theia_explore.py`, `s12_theia_flows.py`, `s10_shards.py` (dùng lại), `s11_eval_subsetB.py` (nhận thêm tên bộ dữ liệu). Nguồn `E:\NEWDATASET (1)` chỉ đọc. Số liệu do mình tự đếm. Chưa train gì.

## 1. Thư mục `NEWDATASET (1)` so với bản trước
- THEIA **không đổi** (cùng tên file, kích thước và ngày: Parquet 536 MB `event_table`, CSV 9.5 GB, nhãn trong `research/.../theia_labels.csv`).
- **Mới: `DARPA-TC-E3-FIVEDIRECTIONS`** (Windows 10, E3): `Parquet/event_table` 4.2 GB, `CSV/event_table` 35 GB, bảng node và artifact THESEUS. Chưa phân tích. Vì cùng hệ điều hành với OpTC nên có thể phù hợp hơn THEIA cho mô hình hiện tại (cần kiểm tra trước khi kết luận).
- `NewDataset.md` và `research/` giữ nguyên.

## 2. THEIA có gì
Máy duy nhất `128.55.12.110`; thời gian 2018-04-03 14:02 → 2018-04-13 21:04 UTC.
| Bảng | Số dòng | Cột |
|---|---:|---|
| `event_table` | 44,408,090 | `src_node`, `dst_node` (hash), `operation`, `timestamp_rec` (ns) |
| `process_node_table` | 279,369 | `node_uuid`, `hash_id`, `path`, `cmd` (1,006 dòng thiếu path) |
| `netflow_node_table` | 186,100 | `src_addr`, `src_port`, `dst_addr`, `dst_port` (không proto, không byte, không user) |
| `file_node_table` | 1,021,955 | `path` |
- Cạnh chạm netflow: **tiến trình → netflow** 3.82M (SENDMSG 2.41M, SENDTO 0.64M, CONNECT 0.59M, WRITE_SOCKET_PARAMS 0.18M) và **netflow → tiến trình** 21.2M (RECVFROM 14.2M, READ_SOCKET_PARAMS 3.9M, RECVMSG 3.0M). Cả 186,100 netflow node đều có cạnh. 62,656 node bị nhiều tiến trình dùng chung.
- 15.7% flow không có địa chỉ đích (`dst_addr = NA` hoặc cổng 0): socket nội bộ/không phân giải được.
- Các flow chỉ thuộc **25 tiến trình/đường dẫn khác nhau**; `firefox` (`/home/admin/Downloads/firefox/firefox`) chiếm 177,413/186,100 flow (95%).

## 3. Nhãn: ba cách, chỉ một cách dùng được
Nhãn nguồn `theia_labels.csv`: 127 dòng (125 `attack`, 2 `contaminated`), **mức tiến trình** (UUID), 6 chuỗi (3.3 fail/success, 3.11 fail/success, 4.8 fail); 126/127 UUID có trong bảng tiến trình. Báo cáo Kudu (E3 Update, trong `research/.../ground_truth/`) cho **IP và giờ tấn công**: 10/4 13:41–14:55, 12/4 12:44–13:26, 13/4 14:04 (tcexec thất bại). **Giờ trong báo cáo là EDT (UTC−4)**, đã đối chiếu với dữ liệu (flow tới IP phishing `208.75.117.3` lúc 17:42 UTC, tiến trình `mail` lúc 17:17 UTC).
| Nhãn | Định nghĩa | Flow dương | Cửa sổ dương (15 phút) / 469 | Nhận xét |
|---|---|---:|---:|---|
| A | flow chạm tiến trình có nhãn REAPr | 25,303 | 189 | 24,821 flow là `firefox`; ~21.7k flow nằm ở 3–5/4 (trước tấn công) nên phần lớn là duyệt web bình thường của tiến trình sau này bị khai thác. **Không dùng.** |
| B | đích thuộc tập IP tấn công trong báo cáo | 19 | 8 | Quá ít |
| **C (chính)** | A **và** nằm trong cửa sổ tấn công theo báo cáo | **627** | **9** | Dùng làm cột `label` |
Cửa sổ tấn công UTC dùng cho C: 10/4 17:35–19:05, 12/4 16:40–17:35, 13/4 17:55–18:15 (có đệm vài phút; lựa chọn của mình, chưa kiểm độ nhạy). Thành phần nhãn C: `mail` 453 (micro APT, quét cổng 12/4 17:17–17:21), `firefox` 163, `gtcache` 4, `fluxbox` 4, còn lại vài flow.

## 4. Vấn đề cốt lõi của THEIA với mô hình mạng B
1. **`app_family` UNK 100%** (không tên nào trùng từ điển OpTC, vì OpTC là `.exe` của Windows). Zero-shot vì thế vô nghĩa; mọi chuyển giao phải qua mở rộng từ điển.
2. **`image_dir_class` mất tín hiệu:** luật OpTC là luật đường dẫn Windows nên mọi đường dẫn Linux đầy đủ đều thành `OTHER`. Muốn dùng phải thêm lớp Linux (`/tmp`, `/home`, `/var`, `/usr/bin`…) bằng cách nối thêm id mới.
3. **Không có `proto`; cổng đích thiếu ở 15.7% flow.** Với flow dương nhãn C: **604/627 (96%) không có địa chỉ đích.**
4. **Hầu hết flow dương là `firefox` giống flow benign:** trong các cửa sổ dương có 3,411 flow `firefox` âm (3% thiếu cổng) và 163 flow `firefox` dương (97.5% thiếu cổng). Tín hiệu tách được (cổng thiếu) có thể chỉ là hệ quả của cách REAPr gán nhãn theo UUID tiến trình; flow cùng dạng ở các ngày khác bị coi là âm theo nhãn C (nhãn phụ thuộc thời gian mà đặc trưng của mô hình không có), nên mâu thuẫn nội tại.
5. **Chỉ 2 đợt tấn công độc lập** (10/4 17:30–19:00 gồm 5 cửa sổ; 12/4 16:30–17:30 gồm 4 cửa sổ): 9 cửa sổ dương = 11 sample dương. Ít đợt hơn skrghosh (4 đợt).
6. **Phần "mạng" yếu:** không byte, không proto, không trạng thái kết nối. THEIA thực chất là dữ liệu provenance của máy (tiến trình, tệp, socket) hợp với nhánh Host (GraphSAGE, LightGBM) hơn là nhánh mạng.

## 5. Tiền xử lý đã làm (`data/flows_theia.parquet`, `theia/`)
- Flow = netflow node; `ts` = cạnh sớm nhất; tiến trình = tiến trình của cạnh sớm nhất; `app_family` = tên file chữ thường bỏ ` (deleted)`; `proto = NULL`; cổng đích 0 và `NA` thành NULL (`<MISSING>`). Giữ cả 3 nhãn (A, B, C) trong parquet; `label` = C.
- Mã hóa bằng đúng `preprocess_spec.json` của OpTC, đóng gói shards giống skrghosh/AIT. **700 sample, 11 sample dương (9 cửa sổ, 627 flow dương), 469 cửa sổ, PASS** (flow bảo toàn, mã hóa lại 300 flow bằng Python thuần khớp 100%). Phân bổ fold: `fold_assignment_theia_mixed_4fold.csv`.
- Trung vị 164 flow/cửa sổ, cực đại 2,743 (nhiều cửa sổ cắt thành chunk 512 flow).

## 6. Thử zero-shot mô hình B (ngưỡng VAL OpTC; `eval_zeroshot/`)
| Mô hình | TP / FP / FN / TN | F1 | PR-AUC | ROC-AUC |
|---|---|---:|---:|---:|
| BiLSTM | 11 / 664 / 0 / 25 | 0.032 | 0.019 | 0.558 |
| Mixed-Type | 0 / 0 / 11 / 689 | 0 | 0.017 | 0.518 |
BiLSTM gắn nhãn dương cho 96% mẫu âm (mẫu toàn token lạ nhận xác suất cao) nên recall 1.0 không có ý nghĩa. Mixed-Type không gắn gì. ROC-AUC ~0.5 ở cả hai: không có tín hiệu. Tái lập mã suy luận vẫn khớp Kaggle 100% (682 mẫu OpTC).

## 7. Xử lý để fine-tune (bổ sung cho STEP 27, chưa cài đặt)
- **Vai trò đề xuất:** miền Linux thứ hai, **tùy chọn**, đánh giá cùng skrghosh nhưng báo cáo **riêng**, không gộp điểm. Nhãn dùng **C**; A chỉ để báo cáo độ nhạy; B quá ít.
- **Mở rộng từ điển (chỉ nối thêm, giữ id OpTC):** `app_family` các tên Linux có ≥ 5 flow trong cửa sổ TRAIN của fold (ví dụ `firefox`, `whoopsie`, `sshd`, `python2.7`, `thunderbird`, `mail`, `bash`; số tính khi sinh spec); `image_dir_class` thêm lớp Linux (`/tmp` `/var/tmp` `/dev/shm`, `/home`, `/var`, `/etc`, `/usr/bin|sbin`, `/bin|sbin`, `/usr/lib`, đường dẫn tương đối); `resp_port_class` thêm các lớp còn thiếu (ví dụ `EPHEMERAL`). Hàng embedding mới khởi tạo bằng bản sao `<UNK>` như STEP 27.
- **Chia:** trộn đều theo cửa sổ, 4-fold phân tầng (theo ý thầy), giống skrghosh: 9 cửa sổ dương gán lần lượt vào 4 fold; mỗi fold test có 2–4 sample dương (4, 2, 2, 3). Cửa sổ kề cùng đợt luôn ở fold khác (rò rỉ có chủ ý).
- **Replay:** OpTC như STEP 27; khi fine-tune đồng thời skrghosh và THEIA, trộn thêm mẫu của miền kia để đo quên chéo.
- **Chỉ số:** như STEP 27, thêm tách riêng từng miền (Windows, Linux).

## 8. Cảnh báo (phải nêu khi báo cáo)
1. **Chỉ 11 sample dương, 2 đợt tấn công độc lập;** khoảng tin cậy rất rộng (bắt 4/4 chỉ cho recall ≥ 0.398 theo Clopper–Pearson 95%).
2. **Nhãn REAPr mức tiến trình bị nhiễm** (cả nhãn `contaminated`, các tiến trình benign trước tấn công); nhãn C dựa vào giờ trong báo cáo PDF và đệm do mình chọn, không phải nhãn từng flow của tác giả. Kết quả phụ thuộc cách chọn cửa sổ.
3. **96% flow dương không có địa chỉ đích và trông như flow `firefox` benign:** mô hình có thể chỉ học tên tiến trình hiếm (`mail`, `gtcache`, `fluxbox`) hoặc dấu hiệu "cổng thiếu", tức nhớ công cụ của kẻ tấn công trong tập này chứ không học hành vi mạng.
4. **Không có chuyển giao từ OpTC** (từ điển không giao nhau); fine-tune ở đây chủ yếu học lại từ đầu các embedding mới và đầu phân loại.
5. **Một máy, một chuỗi thời gian 10 ngày:** hành vi benign lặp lại giữa train và test của các fold; phát biểu đúng là "nhận ra đợt/công cụ đã thấy trên cùng máy".
6. Mô hình B bỏ hầu hết trường mạng nên **không khai thác được những gì THEIA có** (graph tiến trình–tệp–socket); đó là lý do THEIA hợp hơn với nhánh Host.

## 9. Đề xuất
Giữ **skrghosh làm miền fine-tune chính** cho nhánh Network DL (cùng Windows, có đủ field), coi THEIA là thử nghiệm phụ nếu thầy yêu cầu có dataset Linux; ưu tiên kiểm tra **FIVEDIRECTIONS (Windows)** trước vì cùng nền tảng với OpTC; dùng THEIA cho nhánh Host của Nguyễn (GraphSAGE/LightGBM) nơi cấu trúc provenance được tận dụng.
