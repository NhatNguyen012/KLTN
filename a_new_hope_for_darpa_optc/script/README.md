# OpTC Parallel Host Log Labeling Script

Tài liệu hướng dẫn sử dụng script gán nhãn dữ liệu host log DARPA OpTC (Corrected Version).

---

## 1. Tổng quan & Logic xử lý

1. **Nguồn Ground Truth**:
   - Tự động tải **360,567** malicious event IDs từ file `labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz` (hoặc tập hợp các file `ground_truth_corrected*.json.gz`).
   - Lưu trữ toàn bộ ID vào In-Memory Hash Set chia sẻ giữa các worker process để đạt tốc độ tra cứu $O(1)$ với 0% IPC serialization overhead.

2. **Gán nhãn**:
   - Đối với mỗi bản ghi log dạng JSON trong file `.json.gz`:
     - Nếu `id` có trong danh sách ground truth $\rightarrow$ thêm trường `"label": 1`.
     - Nếu `id` không có trong danh sách $\rightarrow$ thêm trường `"label": 0`.
   - Giữ nguyên toàn bộ cấu trúc và các trường ban đầu (`action`, `actorID`, `hostname`, `id`, `object`, `objectID`, `pid`, `ppid`, `principal`, `properties`, `tid`, `timestamp`).

3. **Cơ chế An toàn HDD $\leftrightarrow$ SSD (Zero Data Loss)**:
   - HDD `/mnt/HDD_Data` có dung lượng trống hạn chế (~7GB), SSD `/mnt/SSD_Data` có ~771GB trống.
   - Script xử lý theo từng thư mục ngày (hoặc từng nhóm AIA):
     - **Bước 1**: Đọc file từ HDD, xử lý song song và ghi file nén `.json.gz` mới đã gán nhãn sang thư mục tạm trên SSD (`/mnt/SSD_Data/temp_label_staging/`).
     - **Bước 2**: Thực hiện kiểm tra toàn vẹn **100%** (kiểm tra định dạng gzip hợp lệ, đọc lại từng dòng, so khớp chính xác số lượng dòng trước và sau khi gán nhãn).
     - **Bước 3**: Nếu phát hiện **bất kỳ lỗi nào** $\rightarrow$ Dừng ngay lập tức, **tuyệt đối không xóa hay thay đổi file trên HDD**.
     - **Bước 4**: Chỉ khi toàn bộ thư mục đạt **100% thành công** $\rightarrow$ Xóa thư mục cũ trên HDD, di chuyển (`mv`) thư mục mới từ SSD sang HDD và gọi `os.sync()`.

---

## 2. Cài đặt & Chạy script

### Cách 1: Sử dụng file Bash wrapper (Khuyên dùng)
```bash
# Chạy đầy đủ từ đầu đến cuối cho tất cả các ngày
./script/run_labeling.sh

# Chạy thử nghiệm chế độ Dry Run (chỉ quét file, không ghi/xóa)
./script/run_labeling.sh --dry-run

# Chạy thử nghiệm gán nhãn sang SSD mà KHÔNG xóa/ghi đè HDD
./script/run_labeling.sh --skip-swap --dates 2019-09-17

# Chạy cho một hoặc nhiều ngày cụ thể
./script/run_labeling.sh --dates 2019-09-17 2019-09-18
```

### Cách 2: Gọi trực tiếp bằng Python
```bash
python3 script/label_optc_host_logs.py \
    --hdd-root /mnt/HDD_Data \
    --ssd-staging /mnt/SSD_Data/temp_label_staging \
    --gt-path labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz \
    --workers 12 \
    --compress-level 6 \
    --log-file script/labeling.log
```

---

## 3. Các tham số tùy chỉnh (CLI Arguments)

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--hdd-root` | `/mnt/HDD_Data` | Đường dẫn thư mục gốc chứa các thư mục ngày trên HDD |
| `--ssd-staging` | `/mnt/SSD_Data/temp_label_staging` | Thư mục đệm trên SSD để ghi file đã gán nhãn |
| `--gt-path` | `labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz` | Đường dẫn file hoặc thư mục ground truth corrected |
| `-w`, `--workers` | `12` (số CPU cores) | Số lượng tiến trình chạy song song |
| `-c`, `--compress-level` | `6` | Mức độ nén gzip (1: nhanh nhất, 6: cân bằng tốt nhất, 9: nén tối đa) |
| `-b`, `--batch-level` | `date` | Mức độ xử lý và swap (`date`: theo ngày, `group`: theo nhóm AIA) |
| `-d`, `--dates` | `None` (tất cả) | Danh sách các ngày cần xử lý (ví dụ: `--dates 2019-09-17 2019-09-18`) |
| `--dry-run` | `False` | Chế độ quét và in thông tin kiểm tra, không ghi/xóa dữ liệu |
| `--skip-swap` | `False` | Ghi dữ liệu đã gán nhãn sang SSD nhưng không xóa/move về HDD |
| `--log-file` | `script/labeling.log` | Đường dẫn file ghi log |

---

## 4. Kiểm thử Host (Unit Tests)

Bộ kiểm thử tự động cho host log đã được tích hợp trong `script/test_labeling.py`:
```bash
python3 script/test_labeling.py
```
Bao gồm các test case:
1. `test_01_load_ground_truth_from_repo`: Kiểm tra nạp đúng 360,567 event ID từ ground truth corrected.
2. `test_02_label_injection_accuracy`: Kiểm tra gán đúng nhãn 1 cho malicious event và nhãn 0 cho benign event.
3. `test_03_directory_batch_and_safe_swap`: Mô phỏng quy trình xử lý lô thư mục và atomic swap HDD $\leftrightarrow$ SSD.
4. `test_04_safety_abort_on_corruption`: Kiểm tra cơ chế tự ngắt an toàn khi gặp file lỗi/hỏng, đảm bảo dữ liệu HDD không bị xóa.

---

## 5. Pipeline gán nhãn dữ liệu mạng (Zeek / Bro Network Logs)

### 5.1 Tổng quan
Script `script/label_optc_network_logs.py` được thiết kế riêng cho việc gán nhãn dữ liệu mạng Zeek/Bro nằm trên SSD (`/mnt/SSD_Data/bro` $\rightarrow$ `/mnt/SSD_Data/temp_label_staging_net`).

1. **Ground Truth mạng**: Tải 29,311 connection UIDs độc hại từ `labelling/network/scenario-{1,2,3}/*.log`.
2. **Xử lý Zeek TSV**:
   - Tự động nhận diện cột `uid` hoặc `conn_uids` từ header `#fields`.
   - Cập nhật `#fields ... label` và `#types ... int`.
   - Gán `1` cho các dòng có UID độc hại và `0` cho các dòng bình thường.
3. **An toàn dữ liệu**: Ghi sang `/mnt/SSD_Data/temp_label_staging_net` và **không xóa** thư mục gốc trên SSD.

### 5.2 Cách chạy
```bash
# Sử dụng Bash wrapper:
./script/run_labeling_net.sh                      # Chạy toàn bộ 3,954 files mạng
./script/run_labeling_net.sh --dates 2019-09-25   # Chạy riêng ngày 2019-09-25
./script/run_labeling_net.sh --log-types conn     # Chỉ gán nhãn cho conn.log.gz
./script/run_labeling_net.sh --dry-run            # Quét và xem trước danh sách file

# Hoặc gọi Python trực tiếp:
python3 script/label_optc_network_logs.py \
    --bro-root /mnt/SSD_Data/bro \
    --out-root /mnt/SSD_Data/temp_label_staging_net \
    --gt-dir labelling/network \
    --workers 12
```

### 5.3 Tham số tùy chỉnh (Network CLI Arguments)
| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--bro-root` | `/mnt/SSD_Data/bro` | Đường dẫn thư mục Zeek/Bro gốc trên SSD |
| `--out-root` | `/mnt/SSD_Data/temp_label_staging_net` | Thư mục đích chứa các file đã gán nhãn |
| `--gt-dir` | `labelling/network` | Thư mục chứa các file ground truth scenario-1/2/3 |
| `--dates` | `None` (tất cả) | Danh sách ngày cần xử lý (ví dụ `--dates 2019-09-25`) |
| `--log-types` | `all` | Lọc loại log cụ thể (ví dụ `--log-types conn http ssl`) |
| `-w`, `--workers` | `12` | Số lượng tiến trình chạy song song |
| `-c`, `--compress-level` | `6` | Mức nén gzip (1-9) |
| `--dry-run` | `False` | Quét kiểm tra mà không ghi file |
| `--log-file` | `None` | Đường dẫn file ghi log chi tiết |

### 5.4 Kiểm thử tự động mạng
```bash
python3 script/test_labeling_net.py
```

