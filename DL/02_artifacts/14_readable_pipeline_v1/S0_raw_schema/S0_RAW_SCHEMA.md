# S0 — Dữ liệu thô: eCAR (host), eCAR-Bro (cầu nối), Bro (network)

## Mục đích
Cho biết **trước khi xử lý gì**, dữ liệu gốc của DARPA OpTC có những trường nào, ý nghĩa từng trường, và một bản ghi thật trông thế nào. Mọi bước sau chỉ là biến đổi của ba nguồn này.

## Ba nguồn thô
| Nguồn | Vị trí (ổ E:) | Một dòng là gì | Dùng để |
|---|---|---|---|
| **eCAR** (host) | `E:\host-begnin\<ngày>\…` (16–22/9, benign), `E:\host-malicious\<ngày>\…` (23–25/9, có tấn công) | Một event trên máy: process tạo ra, file đọc/ghi, flow mở, registry sửa... | Nhánh host |
| **eCAR-Bro** | `E:\ecar-bro\{benign,short,evaluation}\…\ecarbro.json.gz` | Một event `FLOW` của eCAR kèm `bro_uid` | **Cầu nối** từ flow mạng sang tiến trình đã tạo ra nó (`image_path`) |
| **Bro/Zeek** | `E:\bro\<ngày>\conn.*.log.gz` (cũng có dns, http, ssl, ...) | Một kết nối mạng (5-tuple, byte, gói, trạng thái) | Nhánh network |

Khóa nối: `eCAR-Bro.properties.bro_uid = Bro conn.uid`.

## File trong thư mục này
| File | Nội dung |
|---|---|
| `fields_ecar_event.csv` | Từng trường của event eCAR: mức (top/properties), áp dụng cho object nào, kiểu, ý nghĩa, ví dụ thật |
| `fields_bro_conn.csv` | 22 trường của Bro `conn.log`: kiểu Zeek, ý nghĩa, ví dụ |
| `sample_ecar_events.json` | 9 event eCAR thật của `SysClient0618` (24/9), mỗi loại (object, action) một event |
| `sample_ecar_bro_record.json` | Một bản ghi eCAR-Bro thật (có `bro_uid`) |
| `sample_bro_conn_record.json` | Một dòng Bro `conn.log` thật, mỗi trường có tên |

## Điểm cần nhớ khi đọc
- **Hai múi giờ.** eCAR dùng giờ EDT (`-04:00`); Bro dùng epoch UTC. Cửa sổ 15 phút của hai bên trùng nhau vì 4 giờ là bội của 15 phút.
- **`object` và `action` quyết định cấu trúc `properties`**: ví dụ `PROCESS CREATE` có `command_line`, `parent_image_path`; `FLOW START` có `src_ip`, `dest_port`; `REGISTRY EDIT` có `key`, `value`, `data`.
- **Trường `label`** có trong bản corrected của host (do A New Hope gán), và trong Bro `conn.log` (cột cuối).
- eCAR **không** ghi traffic nội bộ, Bro cũng không thấy traffic nội bộ, nên di chuyển ngang (WMI, RDP) chỉ lộ qua event host.

## Đầu ra này đi đâu tiếp
- Bro `conn` + eCAR-Bro → **S1** (ghép thành bảng một dòng một flow).
- eCAR → **S6** (đặc trưng hành vi của host theo cửa sổ).
- Nhãn của hai nguồn → **S2**.

## Hạn chế
- Mô tả ý nghĩa trường eCAR do nhóm tự viết dựa trên dữ liệu quan sát được và tài liệu của bộ dữ liệu; một số thông số kỹ thuật của `THREAD` (stack, địa chỉ bắt đầu) chỉ mô tả sơ lược.
- Chưa mô tả các log Bro khác (dns, http, ssl, files...), vì pipeline hiện tại chỉ dùng `conn.log`.
