# S1 — Join Bro conn với eCAR-Bro (dựng lại từ raw)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s1_join.py` (DuckDB, đọc thẳng `.gz` trên ổ E:, không ghi vào E:).

## Mục đích
Tạo **một bảng duy nhất**, 1 dòng = 1 flow mạng, kèm tiến trình (ứng dụng) đã tạo ra flow và nhãn. Đây là đầu vào duy nhất của S2, S3, S4.

## Input
| Nguồn | Vị trí | Nội dung |
|---|---|---|
| Bro conn | `E:\bro\2019-09-17 … 2019-09-25\conn.*.log.gz` (210 file, 10.4 GB nén; không dùng `conn-summary`) | 22 trường Zeek, gồm `label` (0/1, nhãn A New Hope) |
| eCAR-Bro | `E:\ecar-bro\**\ecarbro.json.gz` (156 file, 6.5 GB nén) | event FLOW có `properties.bro_uid`, `hostname`, `image_path`, `pid`, `ppid`, `actorID`, `principal`, `direction`, `l4protocol` |

## Cách làm
1. eCAR-Bro: đọc 92,097,521 bản ghi có `bro_uid`; 26,347 `uid` xuất hiện nhiều lần → giữ bản ghi sớm nhất (timestamp, rồi `id`); 0 `uid` có hostname xung đột. Còn 92,071,089 `uid` duy nhất.
2. Hostname: chữ thường, rút `sysclientNNNN` khỏi tên miền. `app_family` = tên file (chữ thường) của `image_path`.
3. Từng ngày conn: **INNER JOIN** theo `uid = bro_uid` (quyết định đã chốt; flow không có bản ghi eCAR-Bro không vào bảng), giữ 1 dòng mỗi `uid`.
4. Gộp 9 ngày, sắp theo (hostname, ts, uid), ghi một file parquet (ZSTD).
5. Thêm cột dẫn xuất: `ts_utc`, `date_utc` (UTC), `window_start_epoch = floor(ts/900)*900`.

## Output (`data/flows_joined.parquet`, 2.6 GB)
Mỗi trường được mô tả trong `schema.json` (tên, kiểu, nguồn raw, ý nghĩa, ví dụ thật, vai trò). Xem trực tiếp: `preview.csv` (140 flow: 40 tấn công mỗi scenario đủ SC1/SC2/SC3 và 100 benign) và `preview_record.json` (một flow tấn công và một flow benign, mỗi trường một giá trị). 4 cột `actor_id, pid, ppid, principal` chỉ để audit, không vào feature/shards.

## Số liệu (khớp bản cũ)
| Chỉ tiêu | Giá trị |
|---|---|
| Số flow | **92,045,755** (cũ: 92,045,755) |
| `uid` duy nhất | 92,045,755 |
| Máy | 743 |
| Flow dương (`label = 1`) | **24,721** (cũ: 24,721) |
| Flow dương theo ngày UTC | 23/9: 9,030 · 24/9: 5,527 · 25/9: 10,164 |
| `app_family` rỗng (eCAR-Bro không có `image_path`) | 33,947 flow (NULL; thành `<MISSING>` ở S3) |
| Top `app_family` | `firefox.exe` 91,841,864 · `cmd.exe` 33,434 · `conhost.exe` 32,744 · `powershell.exe` 24,503 · `ping.exe` 22,136 |
Kiểm tra tự động: `PASS` (uid duy nhất, không thiếu hostname, nhãn chỉ 0/1). Chạy thử một ngày (24/9) đã so với parquet cũ: cùng tập `uid` hai chiều, 0 dòng lệch hostname/label.

## Phần bị loại do inner join (`unmatched_flows_audit.csv`, `unmatched_counts_by_host_date.csv`)
- 4,509 flow độc hại (`label = 1`) trong Bro 17–25/9 không có bản ghi eCAR-Bro.
- Suy hostname theo IP nguồn: `sysclient0051` 317, `sysclient0351` 41, `sysclient0501` 28, vài flow ở `0005, 0010, 0203, 0618, 0955`; **4,117 flow không suy ra được máy** (máy không có flow nào ghép được để dựng bảng IP→hostname, trong đó có `dc1`).
- Bảng đếm theo (máy, ngày) cho biết kích thước nếu sau này muốn left join.

## Thời gian và tài nguyên
eCAR-Bro 384 s; mỗi ngày conn 3–34 phút (ngày 21–22/9 lâu nhất); gộp và sắp xếp 92M dòng 81 phút (bước chậm nhất); tổng khoảng 3 giờ 20 phút. Thư mục tạm `_work/` (~7 GB) xóa sau khi S5 PASS.

## Hạn chế
- Chỉ flow có eCAR-Bro; benign gần như toàn `firefox.exe` (99.78%), đặc điểm của cách thu thập eCAR-Bro.
- `pid/ppid` chỉ là số, không dùng để suy cha–con (xem phân tích OpTC).
