# STEP 13 — Unraveled: tải và kiểm tra nhãn (network flows đã xử lý)

Ngày: 2026-10-07. Nguồn: bucket S3 công khai `dapt2021`, thư mục `processed/network-flows/`. Đã được người dùng xác nhận tải ngày 2026-10-06.
Đã tải: 173 file CSV, 3.72 GB, vào `03_datasets/unraveled_v1/network-flows/` (script `01_code/pipeline/12_download_unraveled.py`, log `03_datasets/unraveled_v1/download_log.txt`). Không tải pcap, không tải host log.
(Liệt kê bucket có 175 mục; 2 mục là thư mục giữ chỗ, nên còn 173 file.)

## Schema
89 cột: đặc trưng NFStream/nDPI (IP, cổng, giao thức, thời gian, byte/gói, cờ TCP, thống kê gói, inter-arrival, `application_name`, `requested_server_name`, `user_agent`, `content_type`, fingerprint...) và 4 cột nhãn cuối: `Activity`, `Stage`, `DefenderResponse`, `Signature`.
File theo `net1011x…net1015x` (5 mạng con) và `netgw_F` (gateway), chia theo tuần/ngày.

## Lỗi dữ liệu và cách sửa (script `01_code/pipeline/13_clean_unraveled.py`)
Bản gốc giữ nguyên ở `03_datasets/unraveled_v1/`; bản đã sửa ở `03_datasets/unraveled_v1_clean/` (173 file, báo cáo `clean_report.json`).

Nguyên nhân: một số trường văn bản có dấu phẩy mà không được bao trong dấu nháy, nên dòng CSV bị tách thành hơn 89 trường và các cột nhãn bị lệch:
| Loại lỗi | Số dòng | Số trường/dòng | Cách sửa |
|---|---:|---:|---|
| `user_agent` chứa dấu phẩy (`... (KHTML, like Gecko) ...`) | 11,676 | 90 | ghép lại thành một trường `user_agent` |
| `client_fingerprint` của DHCP là danh sách option `1,3,6,15,...` | 1,493 | 99–107 | ghép lại thành một trường `client_fingerprint` |

Sau sửa: **6,877,157 dòng đều có đúng 89 trường, 0 dòng bị loại (quarantine)**. Mỗi dòng sửa đã kiểm `Stage` thuộc tập hợp hợp lệ.
Đính chính báo cáo trước: nhãn `Normal` và các giá trị số (`6`, `26`, `33`, `7`) **không phải nhãn thật** mà do đọc lệch cột; sau sửa `Normal` nằm đúng ở cột `Activity` (Stage = Benign).

## Phân bố nhãn sau khi sửa (6,877,157 flow)
| `Stage` | Số flow | `Activity` (số flow) | `Signature` |
|---|---:|---|---|
| Benign | 6,779,914 | Normal | None |
| Reconnaissance | 34,796 | Bruteforce 22,656; Active Scanning IP Blocks 11,450; Remote System Discovery 685; Vulnerability Scanning 5 | AA 34,111; APT 685 |
| Lateral Movement | 27,445 | Maintain Access 27,128; Remote System Discovery 317 | APT |
| Establish Foothold | 27,118 | Encrypted Channel 27,111; Hijack Execution Flow 7 | APT (7 dòng thiếu `Signature`) |
| Data Exfiltration | 7,522 | Data Transfer Size Limits 6,988; Exfiltration over C2 446; Unsecured Credentials 88 | APT |
| Cover up | 362 | Remove Traces | APT |

Ghi chú: `DefenderResponse` chỉ có hai giá trị là `Detected` (chỉ ở Reconnaissance của AA) và `Benign`; không có giá trị `Mitigated` dù bài báo mô tả. Mỗi flow chỉ có một `Stage` (multi-class, không phải multi-label). Tỷ lệ tấn công ~1.4%.

## File mẫu để gửi thầy
`02_artifacts/13_unraveled_overview_v1/unraveled_sample_flows.csv`: 21 flow (3 mẫu × 5 stage độc hại + 6 flow benign thuộc TLS, DNS, HTTP, SSH, NTP, DHCP), 25 cột chính, thêm `first_seen_utc` và mô tả stage tiếng Việt. Bản đầy đủ 89 cột: `unraveled_sample_flows_full.csv`. Chọn ngẫu nhiên có seed 42, ưu tiên khác `Activity` trong cùng stage. Mở bằng Excel được (UTF-8 có BOM).

## Việc tiếp theo (chưa làm)
- (Đã làm sạch ở bước này.) Còn lại: kiểm tra trùng lặp, tách theo tuần/host.
- Đề xuất dùng làm dataset phụ **cho nhánh network**: nhãn đa lớp theo 5 giai đoạn, kiểm tra khả năng tổng quát của BiLSTM/Mixed-Type ngoài OpTC. Không dùng cho fusion vì không có host.
- Chia theo host/IP (host-disjoint) và theo thời gian, vì tuần 1 chỉ có bình thường, tấn công APT bắt đầu tuần 2 (bài báo).
