# S2 — Cửa sổ và split (cấp cửa sổ, phân tầng theo scenario)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s2_windows_split.py` (4 giây).

## Mục đích
Gom flow thành cửa sổ (hostname, 15 phút) và chia 70/15/15 để **mọi scenario tấn công có mặt đủ ở TRAIN, VAL, TEST**. Đây là đầu vào của S3 (chọn cửa sổ TRAIN để fit) và S4 (gán split cho sample).

## Input
`S1_join/data/flows_joined.parquet`; `02_artifacts/11_dataset_overview_v1/hosts_625.csv` (620 máy có cả log host và log mạng, và scenario của 29 máy bị tấn công).

## Cách làm
- 620 máy, cửa sổ = `floor(ts/900)*900` (UTC); `n_chunks = ceil(n_flows/512)`; nhãn cửa sổ = có ≥ 1 flow dương.
- Tầng: tên scenario (cửa sổ dương) hoặc `benign_<ngày UTC>` (cửa sổ benign); mỗi tầng cắt 70/15/15 theo thứ tự băm sha256 của `KLTN_OPTC_WINDOW_STRATIFIED_V1|seed=1|hostname|window_start_epoch` (tái lập được).
- **Không host-disjoint** (yêu cầu của người dùng 2026-10-12, ngoại lệ so với quy tắc trong `CLAUDE.md`): 613/620 máy có cửa sổ ở cả ba split. Mọi chunk của một cửa sổ nằm cùng một split.

## Output (`data/windows.csv`, 110,402 dòng)
Trường: `hostname, window_start_epoch, window_start_utc, date_utc, scenario, n_flows, n_chunks, n_positive_flows, label, stratum, split` (mô tả trong `schema.json`; xem nhanh `preview.csv`, `preview_record.json`). Thống kê trong `split_summary.json`.

## Kết quả
| Cửa sổ dương theo scenario | train | val | test |
|---|---:|---:|---:|
| SC1 | 43 | 9 | 9 |
| SC2 | 332 | 71 | 71 |
| SC3 | 4 | 1 | 1 |

| Split | Cửa sổ | Cửa sổ dương | Flow | Flow dương | Sample (chunk) |
|---|---:|---:|---:|---:|---:|
| train | 77,281 | 379 | 59,902,514 | 17,682 | 160,210 |
| val | 16,561 | 81 | 12,836,373 | 3,495 | 34,361 |
| test | 16,560 | 81 | 12,887,298 | 3,544 | 34,413 |

Kiểm tra (`checks.json`, PASS): đúng 620 máy; bảo toàn 85,626,185 flow; mỗi scenario có mặt ở cả 3 split; tỉ lệ cửa sổ 0.70 / 0.15 / 0.15. **Đối chiếu với STEP 21A** (cùng thuật toán, cửa sổ lấy từ bảng cũ): cùng tập 110,402 cửa sổ và gán split giống hệt từng cửa sổ.

## Hạn chế
SC3 chỉ có 6 cửa sổ dương (4/1/1) nên số liệu riêng cho SC3 không có ý nghĩa thống kê. Cửa sổ TEST có "bản sao" cùng máy ở TRAIN (80/81 cửa sổ dương TEST có cửa sổ dương cùng máy ở TRAIN, theo STEP 21A), nên điểm đo khả năng nhận ra mẫu và máy đã thấy, không đo phát hiện trên máy chưa từng thấy.
