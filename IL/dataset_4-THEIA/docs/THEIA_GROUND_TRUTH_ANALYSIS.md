# DARPA TC Engagement 3 THEIA: Paper Audit, Ground Truth & 3-Head Design

## 1. Bằng chứng từ rà soát toàn bộ `paper-*` & Audit dữ liệu

### 1.1 Nguồn Parquet và `EDGE_REVERSED_OPS` (NDSS 2027 Theseus)
- Kết quả đối chiếu mã nguồn `paper-general/code/NDSS/theseus-main/scripts/create_parquet_files_e3.py` cho thấy `Parquet/event_table.parquet` (44,408,090 sự kiện) được chuyển đổi trực tiếp từ JSON gốc với 11 operation đảo chiều (`EDGE_REVERSED_OPS`: `EVENT_EXECUTE`, `EVENT_LSEEK`, `EVENT_MMAP`, `EVENT_OPEN`, `EVENT_ACCEPT`, `EVENT_READ`, `EVENT_RECVFROM`, `EVENT_RECVMSG`, `EVENT_READ_SOCKET_PARAMS`, `EVENT_CHECK_FILE_ATTRIBUTES`, `READ`), trong đó `src_index_id` là **Object** và `dst_index_id` là **Acting Process**.
- `CSV/event_table_preprocessed.parquet` (24,343,372 sự kiện) chỉ giữ phân vùng hậu-reboot T3 nhưng đã **xóa toàn bộ `EVENT_CLONE` (158,894 sự kiện ở T3) và `EVENT_UNLINK` (231,370 sự kiện)**, làm mất hoàn toàn quan hệ cha-con tiến trình ($E_{\text{parent}}$).
- Ngoài ra bảng Parquet gốc chưa sort hoàn toàn theo thời gian (`ts_sorted=False`). Pipeline mới đọc `Parquet/event_table.parquet` lọc trong phân vùng **T3 (`>= 2018-04-10 16:44:33 UTC`)** theo khuyến cáo của Theseus (`theia.yml`, tránh lệch phân phối T1/T2 trước khi BBN reboot máy chủ), đồng thời sort chuẩn xác theo `(timestamp_rec, event_uuid)` trước khi trích xuất ngữ cảnh $L=3$.

### 1.2 Loại bỏ toàn bộ Failed Attempts & Contaminated (`REAPr`, `Theseus`, `PIDSMaker`)
Theo khuyến cáo của **REAPr Ground Truth** (`theia_edge_labels.tar.gz`, `theia_labels.csv`, `README.md`) và **NDSS 2027 Theseus** (`configs/datasets/theia.yml`, `utils/ground_truth.py`), các chuỗi tấn công thất bại và nút nhiễm bẩn phải bị **loại hoàn toàn khỏi dataset đánh giá/huấn luyện** (không gán `1` và không để rơi vào `0`):
- **4 chuỗi `fail` bị loại**: `theia_3.3_fail_allstate`, `theia_3.3_fail_gatech_clean`, `theia_3.11_fail`, `theia_4.8_fail` (`tcexec` crash khi nạp Qt5 — lưu ý bài **MAGIC** trước đây từng gán nhầm `tcexec` là tấn công thành công do chưa có REAPr). Tổng cộng loại **1,552 cạnh REAPr fail/contaminated** + **1,907 cạnh dư âm mang artifact fail**.
- **2 cạnh `contaminated`** trên tiến trình Firefox (`3A3530B4-0200-0000-0000-000000000020`) trùng giữa `3.11_fail` và `3.11_success` bị loại hoàn toàn.
- **Unlabeled Section 4.6 Phishing Links**: Phát hiện **17 sự kiện** chưa gán nhãn trong `Parquet` kết nối tới `208.75.117.2` / `208.75.117.3` đúng khung giờ Section 4.6 (`2018-04-10 17:42 UTC`) và đã lọc sạch để không làm nhiễu tập Benign.

### 1.3 Quyết định xử lý thư viện chia sẻ `.so` / dynamic loader (`MAGIC`, `RAPiDLe`, `TFLAG`, `ATLASv2`)
- **Bằng chứng lý thuyết & thực nghiệm**:
  - **MAGIC** (Section C, Figure 10) chứng minh thực nghiệm nút `/lib64/ld-linux-x86-64.so.2` chỉ có anomaly score `0.01` (ngang nền benign, ngưỡng `3000`) vì hành vi nạp thư viện hệ thống hoàn toàn không phân biệt được giữa tiến trình sạch và tiến trình độc hại.
  - **ATLASv2** (`label_refiner.py`) chủ động loại các DLL/loader chuẩn của Windows (`ntdll.dll`, `kernel32.dll`) khỏi nhãn Attack.
  - Trên dữ liệu sạch THEIA (`3.3_success` + `3.11_success`), thư viện OS chỉ chiếm vỏn vẹn **33/66,475 cạnh** (0.05%: `/etc/ld.so.cache`, `libc-2.15.so`, `libpthread-2.15.so`, `libstdc++.so.6.0.22`, `libm-2.15.so`, `libgcc_s.so.1`), nhưng chiếm tới **6.81%** toàn cục T3 (1,050,433 sự kiện bị lọc sau các bước lọc trước), dễ gây ghi đè ngữ cảnh $E_{\text{incoming}}$ bằng tiếng ồn linker.
  - Ngược lại, **`/tmp/memtrace.so` (7 sự kiện trong `3.11_success`)** được **RAPiDLe** và **TFLAG** xác nhận là payload shared object tấn công dùng cho injection SSHD.
- **Quyết định áp dụng**: Loại bỏ có chọn lọc **thư viện chia sẻ OS & dynamic linker** (`/etc/ld.so*`, `.so` trong `/lib/`, `/lib64/`, `/usr/lib/`, `/usr/lib64/`), đồng thời **bảo toàn 100% thư viện phi chuẩn / payload kẻ tấn công** (`/tmp/memtrace.so`, `/home/.../*.so`).

---

## 2. Bảng So Sánh & Phân Bố Mẫu Sạch Cuối Cùng (580,048 Mẫu)

| Tác nhân / Hạng mục | ATLASv2 (Domain 1) | THEIA Sạch Mới (Domain 2) | Ghi chú |
| :--- | :--- | :--- | :--- |
| **Tổng sự kiện trích xuất** | 532,873 | **580,048** (từ 25.09M T3) | Sort T3, giữ `EVENT_CLONE`/`UNLINK` |
| **Benign (`0`)** | 529,220 | **513,606** (361,312 train / 50,735 val / 101,559 test) | Sạch, không dính Section 4.6 |
| **Attack (`1` - Thành công)** | 3,653 | **66,442** (47,321 train / 6,103 val / 13,018 test) | Nhiều hơn ~18 lần ATLASv2 |
| **Stage 1: Initial Compromise** | 212 (145 train) | **754** (**551** train / 57 val / 146 test) | Delivery (`141.43.176.203`, `146.153.68.151`), `pass_mgr`, payload write |
| **Stage 2: Execution & PrivEsc** | 220 (51 train) | **116** (**82** train / 13 val / 21 test) | `/dev/glx_alsa_675`, `/tmp/memtrace.so`, execute `profile`/`gtcache`/`mail` |
| **Stage 3: Discovery & Recon** | 86 (46 train) | **65,230** (**46,467** train / 6,001 val / 12,762 test) | Portscan nội bộ, `/etc/passwd`, `/etc/group`, `/proc/*/stat`, `/proc/*/maps` |
| **Stage 4: C2 & Exfiltration** | 3,135 (1,672 train) | **342** (**221** train / 32 val / 89 test) | C2 thực (`161.116.88.72:80`, `149.52.198.23:80`) |

---

## 3. Ánh Xạ Từ Vựng Liên Miền (OpTC $\rightarrow$ THEIA) & Phân Tách Chống Rò Rỉ

1. **Zero-Leakage Time-Window Split**: Thay `md5(uuid)` bằng **cửa sổ 5 giây không giao nhau** (attack) / **block 60 giây** (benign). Xác minh `0` cửa sổ và `0` UUID trùng nhau giữa `train`/`val`/`test`, đồng thời đảm bảo đủ cả 8 ô `(Scenario, Stage)` trong cả 3 tập.
2. **OpTC Base Token Alignment**: Ánh xạ operation & thuộc tính mạng (`action::*`, `object::*`, `structure::action_object=*`, `net::*`, `image_path::category=*`, `file_path::category=*`) khớp đúng **10,499 ID gốc trong `dl_vocab.json`** (~56% lưu lượng token trên THEIA tái sử dụng trực tiếp embedding pretrained từ OpTC).
3. **Train-Only Vocabulary Extension & Continual Learning Freeze**: **10,438 token THEIA mới** được fit duy nhất trên tập `train` (`[10499..20936]`). Khi fine-tune trên Kaggle, toàn bộ Transformer Blocks, `line_embedding`, `token_norm` và **các hàng embedding OpTC `[0:10499]` bị khóa nguyên vẹn**, chỉ cập nhật các hàng từ vựng THEIA mới `[10499:]`, `IL Adapter (32-dim)` và 3 đầu ra (`binary_head` 1 logit, `scenario_head` 3 classes, `stage_head` 5 classes).
