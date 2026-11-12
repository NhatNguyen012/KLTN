# S5 — Mẫu cửa sổ (đơn vị mà model nhìn thấy) và gói Kaggle

## Mục đích
Model **không** nhìn từng flow riêng lẻ. Nó nhận **chuỗi flow của một host trong 15 phút** (cửa sổ) và trả một xác suất "cửa sổ này có tấn công". Thư mục này cho thấy tận mắt một cửa sổ thật từ dữ liệu thô tới đầu vào số của model, và chứng minh bản đọc được khớp với shard `.npz` đã dùng để train.

## Đầu vào
- Flow đã ghép (S1), nhãn (S2), split (S3), từ điển và chuẩn hóa (S4).

## Cách dựng mẫu (STEP 10C, đã chạy)
1. Với mỗi host, gom flow theo cửa sổ 15 phút (`window_start = floor(ts/900)×900`, UTC).
2. Sắp theo thời gian (`ts`, rồi `uid`); cắt thành chunk tối đa 512 flow.
3. Mã hóa từng flow theo S4; thêm `delta_t_log1p`.
4. **Nhãn mẫu = 1 nếu chunk có ít nhất một flow độc hại.**
5. Ghi thành shard `.npz` theo ngày và tập.

## Đầu ra trong thư mục này
| File | Nội dung |
|---|---|
| `sample_windows.json` | Ba cửa sổ thật; mỗi cửa sổ có thông tin mẫu (host, giờ, nhãn, số flow) và 2 flow đầu, mỗi flow gồm `thô` và `mã_hóa` (tên trường: giá trị) |
| `window_flows_raw_vs_encoded.csv` | Toàn bộ flow của ba cửa sổ, cột thô và cột mã hóa cạnh nhau |
| `sample_manifest_head.csv` | 30 dòng đầu của `network_sample_manifest.csv` (một dòng mỗi mẫu: `sample_id, split, hostname, window_start_utc, label, event_count, shard_file, shard_sample_index`) |
| `verification_vs_npz_shard.json` | Kết quả đối chiếu bản tái tạo với mảng trong shard |

Ba cửa sổ chọn: (1) **beacon SC2 bị bắt** (`sysclient0618`, 24/9 20:00 UTC, 30 flow, label 1); (2) **cửa sổ bình thường** của cùng host (31 flow, label 0); (3) **cửa sổ SC3 khó** (`sysclient0051`, 25/9 14:45 UTC, 60 flow, label 1, model network hay bỏ sót).

## Kiểm chứng
Tái tạo mã hóa từ dữ liệu thô bằng code độc lập với bước dựng shard, rồi so với mảng trong `shards/test/...npz`:
| Cửa sổ | Số flow | `x_cat` | `x_num` (sai lệch tối đa) | cờ thiếu và `x_bin` | `delta_t` (sai lệch tối đa) |
|---|---:|---|---:|---|---:|
| beacon SC2 | 30 | giống hệt | 2.3×10⁻⁸ | giống hệt | 1.2×10⁻⁷ |
| bình thường | 31 | giống hệt | 4.3×10⁻⁷ | giống hệt | 5.3×10⁻⁸ |
| SC3 | 60 | giống hệt | 2.4×10⁻⁷ | giống hệt | 2.4×10⁻⁷ |
(Sai lệch ~10⁻⁷ là sai số làm tròn float32.)

## Gói Kaggle (không đổi so với STEP 10C)
Mỗi seed có một dataset để upload (`03_datasets/random_network_dl_v1_1_15m/seed_K_kaggle_upload`). Cấu trúc:
| Đường dẫn | Nội dung | Ai đọc |
|---|---|---|
| `shards/{train,val,test}/date=…/*.npz` | Mảng `x_cat, x_num, x_num_missing, x_bin, delta_t_log1p`, `sample_offsets`, `sample_labels`... | notebook 06b/07b/06c/07c |
| `split/network_sample_manifest.csv` | Một dòng mỗi mẫu (host, giờ, nhãn, shard, chỉ số) | notebook, script phân tích |
| `split/host_split_frozen.csv` | Host → tập | kiểm tra |
| `preprocessing/*.json` | Từ điển, mean/std, spec | notebook (dựng embedding) |
| `dataset_manifest.json`, `integrity/sha256sums.txt` | Cấu hình dựng và checksum | kiểm tra toàn vẹn |

Mỗi notebook chỉ gắn **một** dataset Kaggle. Notebook gốc 06/07 sẽ lỗi với dataset này; dùng 06b/07b/06c/07c.

## Điểm cần nhớ
- Một cửa sổ có thể gồm hàng trăm flow gần như giống hệt nhau (beacon): đó là "chữ ký" model học được.
- Mẫu SC3 có `app_family` lạ (`<UNK>`), một nguồn "shortcut" thứ hai chưa được kiểm chứng riêng.
- Muốn đọc **toàn bộ** flow đã mã hóa (không chỉ ba cửa sổ) thì cần chạy lại `14b_readable_features_and_windows.py` với danh sách cửa sổ khác; dạng đầy đủ hàng chục triệu dòng không đưa vào đây vì quá lớn.

## Đầu ra này đi đâu tiếp
Gói Kaggle → train BiLSTM/Mixed-Type → file `test_predictions.csv` (`sample_id, label, probability, prediction`) → ghép với S9.
