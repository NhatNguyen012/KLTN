# S3 — Preprocess (fit chỉ trên TRAIN)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s3_preprocess.py` (30 giây), dùng chung `v2_common.py`.

## Mục đích
Tạo **một file** `data/preprocess_spec.json` chứa toàn bộ từ điển category, thống kê numeric, trường nào dùng cho model và vì sao (thay cho 4 JSON rời của bản cũ). Đầu vào của S4.

## Input
`S1_join/data/flows_joined.parquet` ∩ các cửa sổ `split = train` của `S2_windows_split/data/windows.csv`. **Phạm vi fit: 77,281 cửa sổ, 59,902,514 flow; không dùng nhãn, VAL, TEST.**

## Cách làm (giữ như bản cũ để mô hình dùng lại được)
- Category: giá trị chữ thường (thiếu/`-`/`(empty)` → `<MISSING>` id 1; ngoài từ điển → `<UNK>` id 0); từ điển xếp theo số lần xuất hiện trong TRAIN giảm dần, id từ 2; `min_train_frequency` = 5 cho `app_family` và `service`, 1 cho còn lại. `resp_port_class`, `orig_port_class`, `*_ip_scope` dẫn xuất theo quy tắc ghi trong spec.
- Numeric: `log1p(max(x,0))` → z-score theo TRAIN (`stddev_pop`) → clip ±10; thiếu → 0.0 kèm mask; `has_missed_bytes` = `missed_bytes > 0`.
- **Quy tắc active (đổi nhỏ so với bản cũ):** category cần ≥ 2 giá trị, mỗi giá trị ≥ 5 flow TRAIN (hoặc thiếu/có giá trị đều ≥ 5 flow); numeric cần log1p std ≥ 0.01. Lý do: trong split cấp cửa sổ có đúng 1 flow `direction = inbound` (phiên RDP của `sysclient0051`, flow dương) lọt vào TRAIN và với quy tắc cũ sẽ bật cả feature `direction` thành đường tắt; với quy tắc mới feature này vẫn inactive như bản cũ.

## Output
`data/preprocess_spec.json` (phạm vi fit, từ điển, thống kê, thứ tự cột model, dấu vân tay sha256 `287b07a57dd1b118…`), `data/vocab.csv` (từ điển dạng bảng), `schema.json`, `preview.csv` (thống kê numeric), `preview_record.json` (mã hóa từng bước của một flow tấn công và một flow benign), `checks.json`.

Thứ tự cột vào model: category `['app_family', 'proto', 'service', 'conn_state', 'resp_port_class', 'image_dir_class', 'principal_class']`; numeric `['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']`; nhị phân `has_missed_bytes`; cộng `delta_t_log1p`. Gồm 5 category/7 numeric của bản cũ và thêm hai category host `image_dir_class`, `principal_class`.

## Field lấy từ host (eCAR-Bro) trong input của mô hình
| Field | Nguồn | Ý nghĩa |
|---|---|---|
| `app_family` | `image_path` | Tên tiến trình tạo ra flow (`firefox.exe`, `powershell.exe`…) |
| `image_dir_class` | `image_path` | Tiến trình chạy từ đâu: `SYSTEM32`, `PROGRAM_FILES`, `TEMP_OR_APPDATA`, `BARE_NAME`, … |
| `principal_class` | `principal` | Loại tài khoản chạy tiến trình: `DOMAIN_USER`, `SYSTEM_ACCOUNT`, `ADMINISTRATOR`, `SYSADMIN`, `NONE` |
Mọi feature còn lại là Bro conn. `pid`, `ppid`, `actor_id` vẫn chỉ là cột audit. **Lưu ý đã đo trên toàn bộ dữ liệu:** `principal_class = ADMINISTRATOR` có 13,297 flow dương và 0 flow benign (tài khoản của Red Team), nên là tín hiệu rất mạnh nhưng là đặc điểm của testbed; `image_dir_class = TEMP_OR_APPDATA` có 138 flow dương so với 69 benign (gồm tiến trình độc hại của SC3 chạy từ Temp).

| Category | Active | Số giá trị | Thiếu (TRAIN) | Top 3 (số flow) |
|---|---|---:|---:|---|
| `app_family` | có | 68 | 20,401 | firefox.exe (59,766,724), cmd.exe (24,564), conhost.exe (23,973) |
| `direction` | không | 2 | 0 | outbound (59,902,513), inbound (1) |
| `proto` | có | 2 | 0 | tcp (59,902,442), udp (72) |
| `service` | có | 4 | 238,993 | ssl (55,805,833), http (3,857,615), dns (72) |
| `conn_state` | có | 6 | 0 | sf (59,296,683), rsto (585,660), rstr (10,401) |
| `local_orig` | không | 1 | 0 | f (59,902,514) |
| `local_resp` | không | 1 | 0 | f (59,902,514) |
| `orig_ip_scope` | không | 1 | 0 | PUBLIC_IPV4 (59,902,514) |
| `resp_ip_scope` | không | 1 | 0 | PUBLIC_IPV4 (59,902,514) |
| `orig_port_class` | không | 1 | 0 | EPHEMERAL (59,902,514) |
| `resp_port_class` | có | 9 | 0 | PORT_443_HTTPS (55,997,883), PORT_80_HTTP (3,904,259), PORT_8080_HTTP_ALT (239) |
| `image_dir_class` | có | 8 | 0 | PROGRAM_FILES (59,721,422), BARE_NAME (94,170), SYSTEM32 (63,870) |
| `principal_class` | có | 5 | 0 | DOMAIN_USER (59,678,193), NONE (151,664), SYSTEM_ACCOUNT (63,318) |

| Numeric | Active | log1p mean | log1p std | Thiếu |
|---|---|---:|---:|---:|
| `duration` | có | 0.0845 | 0.4155 | 5,331 |
| `orig_bytes` | có | 6.8264 | 0.5520 | 5,331 |
| `resp_bytes` | có | 7.8961 | 1.7725 | 5,331 |
| `missed_bytes` | không | 0.0000 | 0.0023 | 0 |
| `orig_pkts` | có | 2.2374 | 0.3761 | 0 |
| `orig_ip_bytes` | có | 7.1705 | 0.3570 | 0 |
| `resp_pkts` | có | 2.5824 | 0.7926 | 0 |
| `resp_ip_bytes` | có | 8.1370 | 1.5929 | 0 |

`missed_bytes` inactive (std 0.0023 < 0.01), thay bằng cờ `has_missed_bytes`.

## Hạn chế
`app_family` có 68 giá trị khác nhau trong TRAIN, 9 giá trị hiếm (< 5 flow) bị đưa về `<UNK>`, ví dụ `notepad++.exe` (tiến trình của SC3), nên model chỉ thấy nó như `<UNK>`.
