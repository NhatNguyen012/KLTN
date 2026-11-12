# STEP 41 — Đo độ phủ ánh xạ flow → tiến trình → cha / dòng lệnh trên một máy OpTC (tracker của Nguyễn)

Ngày: 2026-10-30. Chỉ đọc E: (log host) và S1. Mã: `01_code/pipeline_v2/s24_parent_coverage.py` (dùng `HostProcessContextTracker` trong `KLTN-main.zip`, không sửa mã của Nguyễn). Không train.

## Cách đo
- Máy `sysclient0201`; replay log host eCAR **liên tục theo thời gian** 20/9 → 25/9/2019 (6 file, 1,370 MB nén, 22–23 triệu bản ghi): 2 ngày benign + 3 ngày có tấn công (+20/9 làm khởi động).
- Trước khi nạp bản ghi thời điểm `t`, trả lời mọi flow của máy trong `flows_joined.parquet` có `ts ≤ t`: tra `actor_id` trong trạng thái tracker (bằng chứng thời điểm < ts của flow; không dùng nhãn trong tracker). Chấm 61,559 flow (từ bản ghi đầu tiên trở đi).
- Cờ: `created_seen` (đã thấy `PROCESS/CREATE` của actor), `actor_found`, có dòng lệnh, có cạnh cha, nút cha có ảnh/dòng lệnh, có ông.
- Chạy lần 1 chưa có `created_seen` (lưu ở `run1_no_created_flag/`); chạy lại lần 2 thêm cờ này và thống kê theo từng actor vì nghi "tìm thấy" chỉ vì FLOW tự tạo nút. Kết quả hai lần trùng.

## Kết quả (mọi chỉ số 100%)
| Ngày UTC | nhãn | flow | created_seen | có dòng lệnh | có cạnh cha | cha có dòng lệnh |
|---|---|---:|---:|---:|---:|---:|
| 20/9 | 0 | 5,039 | 100% | 100% | 100% | 100% |
| 21/9 | 0 | 12,853 | 100% | 100% | 100% | 100% |
| 22/9 | 0 | 26,658 | 100% | 100% | 100% | 100% |
| 23/9 | 0 | 14,603 | 100% | 100% | 100% | 100% |
| 23/9 | 1 | 1,887 | 100% | 100% | 100% | 100% |
| 24/9 | 0 | 511 | 100% | 100% | 100% | 100% |
| 25/9 | 0 | 8 | 100% | 100% | 100% | 100% |

Theo actor: **53 actor** (50 benign, 3 dương); cả 53 đã thấy CREATE, có dòng lệnh và cạnh cha. Chương trình: `firefox.exe` 50 actor / 59,670 flow, `powershell.exe` 2 actor / 1,881 flow, `appidcertstorecheck.exe` 1 actor / 8 flow.
Trạng thái tracker: 0 thiếu actor, 0 thiếu cha, 0 mâu thuẫn cha, 0 hết hạn (TTL) trên các truy vấn mẫu; toàn run có 44,217 nút bị loại (TTL/dung lượng) và 40,703 sự kiện "PID reuse conflict" (chưa xem xét ý nghĩa).

## Giải thích và so với STEP 32
- STEP 32 (chỉ trong ngày 23/9): chỉ 28.2% flow khớp, 11,848 flow `firefox.exe` benign không khớp (tiến trình tạo từ ngày trước) và 100% flow dương khớp (rủi ro **rò rỉ nhãn qua độ phủ**). Replay nhiều ngày liên tục (tối thiểu 3 ngày benign trước ngày tấn công) loại bỏ khác biệt này **trên máy này**: cả benign và dương đều 100%, nên "có/không có dòng lệnh" không tương quan với nhãn ở đây.
- Ví dụ ngữ cảnh cho flow dương (từ `run_summary.json`): `powershell.exe` có `switch=-nop -sta -w -enc`, `path_role=relative`; `firefox.exe` dương có cha `explorer.exe`.

## Hạn chế (không kết luận rộng hơn dữ liệu)
1. **Một máy, 53 actor** (59.7k flow của 50 actor `firefox.exe`): độ phủ 100% chưa đại diện cho 620 máy. Máy nhiều tiến trình dài hạn (khởi động trước cửa sổ replay) sẽ thiếu; ở máy này không xảy ra.
2. **Phụ thuộc ngày khởi động**: cần replay đủ ngày trước (TTL 24 giờ tính theo `last_seen`, tiến trình còn hoạt động thì còn nút). Nếu bắt đầu đúng ngày tấn công, độ phủ thấp như STEP 32.
3. Độ chính xác của cha (đúng/sai) **chưa đo**: chỉ đo tồn tại. Bài A New Hope báo ~40% tiến trình bị gán sai theo họ; chưa đối chiếu.
4. Mới trên `firefox` và `powershell`; chưa đo cho tiến trình khác (cmd, svchost...) ở máy khác.
5. Chi phí: 552 giây cho 1,370 MB nén (~2.5 MB/s, một tiến trình, CPU-bound). Ngoại suy tuyến tính cho `host-malicious` + `host-begnin` (~914 GB nén): **~100 giờ một tiến trình, ~17 giờ nếu chạy 6 tiến trình song song** (ước lượng chưa kiểm chứng; chưa tính đọc ổ HDD và đọc 620 máy × ngày đúng cohort). Cần xin xác nhận trước khi chạy.
6. Tracker của Nguyễn bỏ FLOW khỏi tokenizer mặc định; ở đây tôi gọi trực tiếp `get_context_tokens` và đọc nút (`node.image_path`, `command_line`, `parent_edges`) cho FLOW; chưa kiểm cách dùng có đúng ý tác giả.
