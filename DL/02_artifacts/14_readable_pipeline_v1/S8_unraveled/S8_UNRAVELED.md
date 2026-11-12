# S8 — Unraveled: dataset phụ có nhãn giai đoạn APT (chỉ network)

## Mục đích
Có một dataset thứ hai với **nhãn đa lớp theo giai đoạn tấn công** để (1) trả lời gợi ý của thầy rằng nhãn không chỉ 0/1, (2) kiểm tra khả năng tổng quát của model network ngoài OpTC. **Không dùng cho fusion** vì không có log host có nhãn.

## Nguồn
Myneni et al., *Unraveled — A semi-synthetic dataset for Advanced Persistent Threats*, Computer Networks 227 (2023) 109688. Dữ liệu: S3 công khai `dapt2021` (thư mục `processed/network-flows/`), GitLab `asu22/unraveled` (GPLv3). Dữ liệu 6 tuần, 27 máy, ba nhóm tấn công (nghiệp dư, hacker có kỹ năng, APT).

## Đầu vào và xử lý
1. **Tải** 173 file CSV, 3.72 GB (`01_code/pipeline/12_download_unraveled.py`), về `03_datasets/unraveled_v1/`.
2. **Sửa lỗi CSV** (`01_code/pipeline/13_clean_unraveled.py`), ghi bản sạch sang `03_datasets/unraveled_v1_clean/`, bản gốc giữ nguyên:
   - 11,676 dòng có `user_agent` chứa dấu phẩy chưa được bao nháy → bị tách thành 90 trường → đã ghép lại;
   - 1,493 dòng DHCP có `client_fingerprint` là danh sách option `1,3,6,15,...` → bị tách thành 99–107 trường → đã ghép lại.
   Sau sửa **6,877,157 dòng đều có đúng 89 trường, 0 dòng bị loại**.

## Đầu ra trong thư mục này
| File | Nội dung |
|---|---|
| `fields_unraveled_flow.csv` | 89 cột: nhóm (định danh, hai chiều, chiều xuôi/ngược, ứng dụng, **NHÃN**) và ý nghĩa |
| `stage_counts_after_cleaning.csv` | Số flow theo `Stage` sau khi sửa |
| `cleaning_repairs.csv` | Số dòng đã sửa theo loại lỗi |
| `unraveled_sample_flows.csv` | **File gửi thầy:** 21 flow (3 mẫu × 5 stage độc hại, 6 flow bình thường), 25 cột chính |

## Nhãn (sau sửa)
| `Stage` | Số flow | `Activity` chính |
|---|---:|---|
| Benign | 6,779,914 | Normal |
| Reconnaissance | 34,796 | Bruteforce (22,656), Active Scanning (11,450), Remote System Discovery (685) |
| Lateral Movement | 27,445 | Maintain Access (27,128), Remote System Discovery (317) |
| Establish Foothold | 27,118 | Encrypted Channel (27,111) |
| Data Exfiltration | 7,522 | Data Transfer Size Limits (6,988), Exfiltration over C2 (446) |
| Cover up | 362 | Remove Traces |
Mỗi flow chỉ có **một** `Stage` (multi-class, không phải multi-label). `DefenderResponse` chỉ có `Detected` và `Benign` (không có `Mitigated` như bài báo mô tả).

## Hạn chế
- Dữ liệu bán tổng hợp, ~1.4% là tấn công; nhãn `Detected` chỉ ở Reconnaissance của nhóm nghiệp dư.
- Tuần 1 chỉ có hành vi bình thường; tấn công APT bắt đầu từ tuần 2. Khi chia train/test phải chia theo host hoặc thời gian.
- Tác giả báo các mô hình bất thường đạt ROC-AUC 0.32–0.67 trên bộ này (bài báo nêu hạn chế này).
- Log host của Unraveled **chưa có nhãn** (`processed/host-logs/` rỗng trong bucket) và không được tải.

## Đầu ra này đi đâu tiếp
Nếu dùng để kiểm tra BiLSTM/Mixed-Type: cần một pipeline S4/S5 riêng cho Unraveled (đặc trưng NFStream khác Bro); chưa làm.
