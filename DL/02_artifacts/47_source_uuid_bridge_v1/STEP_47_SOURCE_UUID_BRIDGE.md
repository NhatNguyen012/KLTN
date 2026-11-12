# STEP 47 — Cầu nối `(source_id, source_line)` → UUID sự kiện eCAR cho toàn bộ 106 file

Ngày: 2026-11-05. Mã: `01_code/pipeline_v2/s35_bridge_uuid.py`. Đầu vào: gói Nguyễn (`optc_host_ml_fusion_package`, đã giải nén trong thư mục tạm của phiên) và raw eCAR ở `E:\host-malicious`, `E:\host-begnin` (chỉ đọc, 26.8 GB gz, 106 file). Đầu ra: `bridge_scores_uuid.parquet` (103 MB), `parts/` (106 file theo nguồn), `run.log`.

## Kết quả
- **2,082,814 dòng = toàn bộ điểm VAL (833,125) và TEST (1,249,689) của LightGBM**, mỗi dòng có `event_id` (UUID, 36 ký tự), `timestamp` (EDT, có offset), `action`, `object`, `hostname_raw`, `split`, `label`, `score`, `file_host`. Không dòng nào thiếu UUID, không trùng UUID. Số dòng theo (split, label) khớp file điểm: VAL 806,252 âm / 26,873 dương; TEST 1,209,379 âm / 40,310 dương.
- Thời gian chạy 470 giây (8 tiến trình) cho 26.8 GB.
- **Kiểm tra từng file (cả 106 file đều qua, không có cảnh báo):**
  1. Số dòng đọc được của file gz **bằng đúng độ dài mask split** (ví dụ 2,285,066 = 2,285,066).
  2. **Chỉ số dòng bắt đầu từ 1** (`source_line` − 1 là chỉ số mảng mask): tại mọi dòng được chấm điểm, mã mask khớp VAL = 2 hoặc TEST = 3 (cả 2,082,814 dòng).
  3. Tên host trong bản ghi khớp tên host của file (trừ 6 dòng, xem dưới).
- 6 dòng `hostname_raw = SysClient0501` nằm trong file của máy khác (sysclient0503/04/06/10/17/24), đều `COMMAND/SHELL` nhãn 1 (lệnh từ máy tấn công ghi trong log của máy đích); ghi nhận, không phải lỗi cầu nối.

## Cách dùng
`bridge_scores_uuid.parquet` ghép được với bảng tiến trình (`proc_uuid`) hay với nhánh DL qua `event_id`/`(file_host, timestamp)`. Mã mask: 0 = không dùng, 1 = TRAIN, 2 = VAL, 3 = TEST (README của gói ghi sai 0/1/2).

## Hạn chế
- Chỉ có UUID cho các dòng **có điểm** (VAL, TEST). Không dựng cho dòng TRAIN (không có điểm).
- Nội dung bản ghi chỉ trích 4 trường (`action`, `object`, `hostname`, `timestamp`); cần thêm trường nào thì chạy lại với `source_line` đã có.
