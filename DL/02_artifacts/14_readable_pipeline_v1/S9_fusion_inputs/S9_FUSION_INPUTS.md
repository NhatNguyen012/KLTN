# S9 — Bảng đầu vào cho fusion (host × network trên cùng cửa sổ)

## Mục đích
Một bảng duy nhất để thử mọi cách kết hợp hai nhánh: mỗi dòng là một `(hostname, cửa sổ 15 phút)` kèm điểm network, đặc trưng host và nhãn của cả hai nhánh.

## Đầu vào
- Điểm network: `test_predictions.csv` và `val_predictions.csv` của Mixed-Type bỏ `app_family`, seed_1 (`05_models/10_random_seed1_v1/mixed_v2_noapp_seed1/`), gộp theo `(hostname, window_start_epoch)` bằng giá trị lớn nhất (một cửa sổ có thể gồm nhiều chunk).
- Đặc trưng host: S6.
- Nhãn: nhãn mạng của pipeline (`y_net`) và nhãn host của A New Hope (`y_host`).

## Đầu ra
| File | Nội dung |
|---|---|
| `window_fusion_table_seed1.csv` | **36,794 dòng** (VAL và TEST của seed_1): `hostname, day, window_start_edt, window_start_epoch_utc, split, p_net, has_net, y_net, y_host, n_proc_writable, n_parent_lsass, n_cmd_susp, n_novel_pairs, s_host` |
| `fields_fusion_table.csv` | Ý nghĩa từng cột |
| `sample_fusion_rows_SC3.json` | Các cửa sổ SC3 của `sysclient0051` (10:15–11:15 EDT) để thấy cả hai nguồn cạnh nhau |

Ví dụ một dòng (`sysclient0051`, 10:30 EDT): `p_net` rỗng, `has_net = 0`, `y_net = 0`, `y_host = 1`, `n_novel_pairs = 3`, `s_host = 0.92`: network không có flow nào trong cửa sổ này, nhưng host có event độc hại.

## Cách đọc
- `p_net` rỗng: cửa sổ không có flow nào được đưa vào model network; baseline coi là 0.
- `y_net` và `y_host` **khác nhau**: nhãn mạng chỉ thấy C2; nhãn host thấy mọi event của process độc hại. Khi đánh giá phải nói rõ dùng nhãn nào.
- `s_host` là điểm luật tay, chỉ là baseline; đã thấy là quá nhiễu (xem `02_artifacts/12c_host_features_v1/STEP_12C_FUSION_BASELINE_A.md`).

## Việc đang chờ
Điểm dự đoán nhánh host của Nguyễn (LightGBM/XGBoost/RF, sau GraphSAGE): file `(hostname, thời điểm, split, prob, label)` và file split. Có file đó thì thêm cột `p_host` vào bảng này và chạy lại OR / trung bình / stacking. Nhánh host đang dùng cửa sổ 30 phút; ghép bằng cách gộp hai cửa sổ 15 phút của network (lấy xác suất lớn nhất).

## Hạn chế
- Chỉ seed_1, chỉ một biến thể model network, chỉ host có log host (69 host TEST, 78 host VAL).
- Chỉ một host SC3 (`sysclient0051`) trong TEST.
