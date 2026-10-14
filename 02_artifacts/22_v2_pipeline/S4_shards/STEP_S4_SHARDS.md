# S4 — Shards (mã hóa và đóng gói sample)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s4_shards.py` (12 phút).

## Mục đích
Mã hóa từng flow bằng `preprocess_spec.json` và đóng gói thành sample cho mô hình. Đầu vào của bước train.

## Input
`S1_join/data/flows_joined.parquet`, `S2_windows_split/data/windows.csv` (gán split), `S3_preprocess/data/preprocess_spec.json`.

## Cách làm
- Sample = các flow của một (hostname, cửa sổ 15 phút) sắp theo (`ts`, `uid`), cắt chunk mỗi 512 flow; nhãn sample = có ≥ 1 flow dương.
- Mỗi flow: 7 id category, 7 z-score numeric + 7 cờ thiếu, 1 cờ `has_missed_bytes`, `delta_t_log1p` = ln(1 + giây từ flow trước trong chunk) (flow đầu = 0), và hai chỉ số cục bộ `edge_app_local`, `edge_remote_local`.
- Các sample của mỗi split được xáo trộn có seed (20261013) rồi chia thành các file khoảng 1 triệu flow, nên mỗi file trộn nhiều máy và nhiều ngày.

## Output (4.6 GB, 86 file `.npz`)
- `shards/{train,val,test}/*.npz`: khóa và kiểu mô tả trong `shard_format.json` (giữ như bản cũ để dùng lại mã mô hình).
- `data/samples.csv`: 1 dòng = 1 sample (`sample_id, split, date, hostname, window_start_epoch, window_start_utc, chunk_index, label, event_count, positive_event_count, app_node_count, remote_node_count, shard_file, shard_sample_index`); `schema.json`, `preview.csv`.
- `decoded_preview.json`: ba sample (một mỗi scenario) với flow raw cạnh vector đã mã hóa trong shard và bản mã hóa lại bằng Python.

| Split | Sample | Sample dương | Flow | Flow dương | Số file |
|---|---:|---:|---:|---:|---:|
| train | 160,210 | 401 | 59,902,514 | 17,682 | 60 |
| val | 34,361 | 83 | 12,836,373 | 3,495 | 13 |
| test | 34,413 | 82 | 12,887,298 | 3,544 | 13 |

Kiểm tra (`checks.json`, PASS): số flow, flow dương và sample của mỗi split bằng đúng `windows.csv`; `sample_id` duy nhất; chunk tối đa 512 flow.
