# STEP 29 — DARPA TC E3 FIVEDIRECTIONS (Windows 10): phân tích, tiền xử lý và thử zero-shot mô hình B

Ngày: 2026-10-22. Mã: `01_code/pipeline_v2/s13_fd_explore.py`, `s13_fd_flows.py`, `s10_shards.py` (dùng lại), `s11_eval_subsetB.py`. Nguồn `E:\NEWDATASET (1)\DARPA-TC-E3-FIVEDIRECTIONS\Parquet` chỉ đọc. Số liệu do mình tự đếm. Chưa train gì.

## 1. Dữ liệu có gì
| Bảng | Số dòng | Cột |
|---|---:|---|
| `event_table` | 161,026,120 | `src_node`, `dst_node` (hash), `operation`, `timestamp_rec` (ns) |
| `process_node_table` | 519,493 | `node_uuid`, `hash_id`, `path` (**luôn rỗng**), `cmd` |
| `netflow_node_table` | 123,279 | `src_addr`, `src_port`, `dst_addr`, `dst_port` (không proto, không byte) |
| `file_node_table` | 733,586 | `path` |
- Thời gian 2018-04-04 13:53 → 2018-04-13 21:08 UTC; Windows 10, chủ yếu một máy `128.55.12.67` (vài máy khác chiếm vài %).
- **`cmd` là dòng lệnh**, nhưng chỉ có ở khoảng 16,000/519,493 tiến trình (97% rỗng); tuy vậy các tiến trình có socket gần như đều có `cmd`: chỉ **143/87,167 flow** thiếu tên ứng dụng. Ví dụ `"C:\Program Files\Mozilla Firefox\firefox.exe" `, `c:\windows\system32\svchost.exe -k networkservice -p -s Dnscache`, `powershell -nop -ep bypass -encodedCommand …`.
- Cạnh chạm netflow: tiến trình→netflow: SENDTO 2.81M, BIND 0.13M, CONNECT 0.09M; netflow→tiến trình: RECVFROM 5.36M, ACCEPT 0.26M. Tất cả 123,279 node có cạnh; 9,330 node bị nhiều tiến trình dùng chung.
- **36,112 netflow node chỉ có cạnh `BIND`** (socket lắng nghe/UDP chưa có đầu xa, địa chỉ rỗng, cổng 0): không phải kết nối, đã **loại** (xem mục 3). Còn lại **87,167 flow**, 854 cửa sổ 15 phút, trung vị 28 flow/cửa sổ, tối đa 3,781.
- Thành phần flow: `svchost.exe` 54,401 (62%, chủ yếu DNS tới `128.55.12.10:53`), `firefox.exe` 28,612, `tvnserver.exe` 3,533, `thunderbird.exe` 286, cổng đích thiếu chỉ 0.02%.

## 2. Nhãn và đối chiếu báo cáo Kudu
`fivedirections_labels.csv`: 50 dòng (32 UUID có trong bảng tiến trình): chuỗi 3.4 (Firefox backdoor, 11/4), 3.10 (pass-manager extension, 12/4), 4.4 (phishing + macro PowerShell, 9/4; các tiến trình `powershell.exe`, `cmd.exe` được đánh dấu `contaminated`). Nhãn mức tiến trình (UUID).
**Giờ trong báo cáo là EDT (UTC−4), đã đối chiếu với dữ liệu:** tấn công 3.4 lúc 14:08–14:40 UTC (= 10:08–10:40 EDT trong báo cáo); PowerShell lúc 19:06:38 UTC (= 15:07 EDT, flow tới `208.75.117.5` và `.6`); pass_mgr lúc 15:12 UTC (= 11:12 EDT, flow tới `135.84.161.202`). Toàn bộ 9 flow tới các IP tấn công liệt kê trong báo cáo đều là flow dương.
| Nhãn | Định nghĩa | Flow dương | Cửa sổ dương |
|---|---|---:|---:|
| label_all | tiến trình có nhãn REAPr (attack hoặc contaminated), sau khi bỏ socket chỉ BIND | 306 | – |
| label_attack | tiến trình nhãn `attack` | 304 | – |
| label_B | đích thuộc tập IP tấn công trong báo cáo | 9 | – |
| **`label` (chính)** | label_attack **hoặc** label_B (thêm 2 flow PowerShell tới C2 mà REAPr ghi là `contaminated`) | **307** | **7** |
Khác THEIA: nhãn mức tiến trình ở đây **nhất quán về thời gian** (flow dương chỉ nằm trong ngày/giờ tấn công, không có "firefox bị nhiễm" rải khắp 10 ngày). Loại socket chỉ BIND làm mất 304 flow dương mà REAPr đã gán (chúng không có đầu xa); để so sánh còn `flows_fd_candidates.parquet` giữ đủ.
Thành phần nhãn chính: `firefox.exe` 303 flow (99%), `powershell.exe` 2, `pass_mgr.exe` 2. Cửa sổ dương (UTC): 9/4 19:00 (2 flow), 11/4 14:00 (6), 14:15 (1), **14:30 (295)**, 15:45 (1), 12/4 15:00 (1), 15:15 (1) → **3 đợt tấn công độc lập** (9/4, 11/4, 12/4).

## 3. Tiền xử lý (`data/flows_fd.parquet`, `fivedirections/`)
- Flow = netflow node (không có BIND-only); `ts` = cạnh sớm nhất; tiến trình = tiến trình của cạnh sớm nhất; hostname = `fd_e3` (không tách máy).
- `image_path` = mục đầu của dòng lệnh (có hoặc không có nháy); `app_family` = tên file chữ thường, thêm `.exe` nếu chỉ ghi tên trần (`powershell`, `nslookup`); `image_dir_class` dùng luật Windows của OpTC (áp dụng được vì đây là đường dẫn Windows).
- Đầu phản hồi (quy tắc do mình đặt, chưa kiểm chứng): có CONNECT → `resp_p` = `dst_port`; có ACCEPT → `resp_p` = `src_port` (cổng dịch vụ cục bộ); còn lại → cổng nhỏ hơn trong hai cổng khác 0. `proto` = thiếu.
- Mã hóa bằng đúng `preprocess_spec.json` của OpTC. **930 sample, 8 sample dương (7 cửa sổ, 307 flow dương), PASS** (flow và flow dương bảo toàn, mã hóa lại 300 flow bằng Python thuần khớp 100%).
- **Độ phủ từ điển OpTC rất cao:** `app_family` chỉ **4.6% flow là UNK** (15 tên ngoài từ điển, 7 tên có ≥ 5 flow: `tvnserver.exe`, `thunderbird.exe`, `onedrivestandaloneupdater.exe`, `sshd.exe`, `nslookup.exe`, `system`, `lwabeat.exe`); `resp_port_class` UNK 0.7%; `image_dir_class` không UNK. Đây là bộ mới khớp nhất với mô hình B.

## 4. Thử zero-shot mô hình B (ngưỡng VAL OpTC; `eval_zeroshot/`)
| Mô hình | TP / FP / FN / TN | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|
| BiLSTM | 1 / 316 / 7 / 606 | 0.003 | 0.125 | 0.006 | 0.006 | 0.228 |
| Mixed-Type | 1 / 0 / 7 / 922 | 1.000 | 0.125 | 0.222 | 0.130 | 0.257 |
Luật "sample có `powershell.exe`" cũng cho 1/8 (F1 0.222, 0 báo nhầm). Tái lập mã suy luận vẫn khớp Kaggle 100%.
Đọc kết quả:
1. **Cả hai mô hình chỉ bắt được đúng 1 mẫu dương: cửa sổ 9/4 có `powershell.exe`** (xác suất ≈ 1.0). 7 mẫu còn lại (toàn là `firefox.exe` hoặc `pass_mgr.exe` nằm giữa nhiều flow `svchost.exe`) nhận điểm rất thấp (Mixed-Type ≈ 3e-5; BiLSTM 6e-4–6e-3).
2. **ROC-AUC dưới 0.5 ở cả hai (0.23–0.26):** mẫu dương bị chấm thấp hơn mẫu âm. Nguyên nhân hợp lý nhưng chưa kiểm chứng riêng: trong OpTC `firefox.exe` gần như luôn là benign, nên flow `firefox.exe` của tiến trình bị khai thác trông như benign; thông tin phân biệt thật sự (IP đích C2, quan hệ tiến trình) **không nằm trong đầu vào của mô hình B**.
3. **BiLSTM báo nhầm 316 mẫu âm** (FPR 34%), phần lớn là mẫu ít flow gồm token lạ hoặc ít nhiều flow DNS; Mixed-Type không báo nhầm nào.
4. Số mẫu dương quá ít (xem mục 6) nên không kết luận được hơn kém giữa hai mô hình.

## 5. So sánh với các bộ mới khác (zero-shot, cùng ngưỡng VAL OpTC)
| Bộ | Sample / dương | Đợt tấn công độc lập | `app_family` UNK | BiLSTM F1 / ROC | Mixed-Type F1 / ROC |
|---|---|---:|---:|---|---|
| skrghosh (Windows) | 196 / 8 | 4 | 74.5% | 0.182 / 0.684 | 0 / 0.847 |
| AIT (Linux, không có tiến trình) | 8,259 / 302 | – | 100% thiếu | 0.005 / 0.215 | 0 / 0.147 |
| THEIA (Linux) | 700 / 11 | 2 | 100% | 0.032 / 0.558 | 0 / 0.518 |
| **FiveDirections (Windows)** | 930 / 8 | 3 | **4.6%** | 0.006 / 0.228 | 0.222 / 0.257 |
Không bộ nào cho thấy chuyển giao zero-shot; FiveDirections là bộ có đầu vào khớp nhất (từ điển, cổng, đường dẫn) nhưng nhãn dương lại là flow của trình duyệt trông benign.

## 6. Cảnh báo
1. **Chỉ 8 sample dương, 3 đợt độc lập;** 295/307 flow dương nằm ở một cửa sổ (11/4 14:30). Bắt 1/8 nằm trong khoảng tin cậy 95% [0.003, 0.527] (Clopper–Pearson).
2. **99% flow dương là `firefox.exe` của tiến trình bị khai thác**, tức flow mạng bình thường về hình thức; nhãn là mức tiến trình, không phải nhãn từng flow. Mô hình B không dùng IP đích hay dòng lệnh nên không có cơ sở phân biệt, trừ trường hợp hiếm (`powershell.exe`, `pass_mgr.exe`).
3. Quy tắc loại BIND-only, hướng đầu phản hồi, gộp `.exe` và coi nhiều máy là một là **lựa chọn của mình, chưa kiểm độ nhạy**.
4. Giờ tấn công suy ra từ báo cáo PDF (EDT) và đã khớp với dữ liệu, nhưng nhãn dương vẫn có thể thiếu các flow khác của kẻ tấn công (REAPr chỉ gán 32/50 UUID tìm thấy trong bảng tiến trình).
5. Một chuỗi thời gian 9 ngày trên một máy: khi chia trộn theo cửa sổ, hành vi benign lặp lại giữa train và test.

## 7. Xử lý để fine-tune (bổ sung cho STEP 27, chưa cài đặt)
- **Vai trò đề xuất:** miền Windows thứ hai cùng skrghosh (cùng hệ điều hành với OpTC), gộp thành "miền Windows mới" với 16 sample dương và 7 đợt tấn công; vẫn rất ít, nên báo cáo từng bộ riêng và gộp, kèm khoảng tin cậy.
- **Chia:** trộn đều theo cửa sổ, 4-fold phân tầng (theo ý thầy), `fold_assignment_fd_mixed_4fold.csv`: mỗi fold test có 2 sample dương (3, 7, 2, 295 flow dương); cửa sổ kề cùng đợt ở fold khác (rò rỉ có chủ ý, như STEP 27).
- **Mở rộng từ điển (chỉ nối thêm):** các `app_family` ngoài từ điển có ≥ 5 flow trong cửa sổ TRAIN của fold (khoảng 7 tên); `resp_port_class` thêm lớp còn thiếu; hàng mới khởi tạo bằng `<UNK>` như STEP 27. Vì chỉ 4.6% flow là UNK nên mở rộng từ điển ở đây ít tác dụng hơn ở skrghosh.
- **Điểm yếu cần xử lý nếu muốn tách được nhãn:** đầu vào hiện không có thông tin phân biệt flow `firefox.exe` bị khai thác với flow bình thường (IP đích, dòng lệnh, quan hệ tiến trình). Thêm các trường này nghĩa là **đổi đầu vào mô hình**, trái quyết định đã chốt "không đổi kiến trúc"; chỉ nêu như hướng mở, không đề xuất làm.
- Replay OpTC, giai đoạn A/B và chỉ số như STEP 27.

## 8. Đề xuất
Xem FiveDirections như bằng chứng thứ hai (cùng skrghosh) rằng mô hình B không chuyển giao zero-shot và nhãn mức tiến trình khó học bằng đầu vào hiện tại; dùng skrghosh + FiveDirections làm hai miền fine-tune (Windows) báo cáo riêng. THEIA và AIT chỉ làm tham khảo.
