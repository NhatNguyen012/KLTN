# S4 — Đặc trưng: mỗi cột được mã hóa thế nào (chỉ học từ TRAIN)

## Mục đích
Biến các cột của flow (chữ, số) thành đầu vào số cho model. Mọi thứ cần "học" (từ điển, trung bình, độ lệch chuẩn) **chỉ tính trên TRAIN của đúng seed đó**, để TEST không rò rỉ vào bước chuẩn hóa.

## Đầu vào
Bảng flow (S1) của các host TRAIN theo split seed_K (S3).

## Cách mã hóa
**Cột phân loại** (chữ → số ID): chuẩn hóa chữ (cắt khoảng trắng, chữ thường; `-`, rỗng, `nan`... thành `<MISSING>`), rồi tra từ điển. `<UNK>` = 0 (giá trị chưa từng thấy ở TRAIN), `<MISSING>` = 1. Giá trị xuất hiện ít hơn 5 lần ở TRAIN bị gộp vào `<UNK>`.

**Cột số:** `x → ln(1 + x) → (… − mean) / std → cắt vào [−10, 10]`. Thiếu hoặc âm: điền 0 và bật cờ `_missing = 1`. `mean` và `std` là giá trị trên TRAIN (cột "log1p" đầu bảng chuẩn hóa).

**Cột nhị phân:** `has_missed_bytes = 1` nếu `missed_bytes > 0`.

**Cột thời gian:** `delta_t_log1p = ln(1 + số giây từ flow liền trước trong cùng cửa sổ)`; flow đầu cửa sổ bằng 0. Với beacon 30 giây giá trị lặp lại ≈ 3.44.

**Cột bị bỏ:** cột nào là hằng số trên TRAIN (mọi flow cùng giá trị) không mang thông tin nên không đưa vào model (ví dụ `direction`, `local_orig`, `orig_ip_scope`); `missed_bytes` bị thay bằng `has_missed_bytes` vì độ lệch chuẩn quá nhỏ.

## Đầu ra (mỗi seed có thư mục riêng `seed_1/`, `seed_2/`, `seed_3/`)
| File | Nội dung |
|---|---|
| `feature_spec.csv` | 11 cột phân loại + 8 cột số + cờ + thời gian: loại, **dùng cho model hay không và vì sao**, ý nghĩa, tên cột sau mã hóa |
| `vocab_<cột>.csv` | Từ điển giá trị → ID của từng cột phân loại (`vocab_app_family.csv` là bảng tên tiến trình → ID) |
| `numeric_normalization.csv` | Với mỗi cột số: `mean` và `std` của `ln(1+x)` trên TRAIN, ngưỡng cắt, giá trị nhỏ nhất/lớn nhất thô, tỉ lệ thiếu |

## Đầu vào của model sau bước này
5 cột phân loại (`app_family, proto, service, conn_state, resp_port_class`), 7 cột số (+ 7 cờ thiếu), 1 cờ nhị phân, 1 cột thời gian. Các cột `hostname, uid, ts, IP, label` **không** là đặc trưng.

## Điểm cần nhớ
- Từ điển khác nhau giữa các seed vì TRAIN khác nhau (ví dụ ID của một tên tiến trình có thể khác).
- Bảng chuẩn hóa chỉ là tham số để tái lập; không phải kết quả cần phân tích, vì vậy mean/std được gói vào một file duy nhất.
- File cũ `network_*.json` ở `03_datasets/.../preprocessing/` vẫn là bản mà code và notebook đọc; các CSV ở đây là bản đọc được của cùng nội dung.

## Đầu ra này đi đâu tiếp
S5: dùng từ điển và bảng chuẩn hóa này để mã hóa từng flow rồi gom thành mẫu cửa sổ.
