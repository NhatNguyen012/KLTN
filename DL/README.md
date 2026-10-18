# KLTN — Nhánh Network DL (pipeline v2) trên DARPA OpTC

Khóa luận "Multi-Source Context-Aware Framework for APT Detection". Repo này là phần **Network DL** (Võ Ngọc Hoàng Lâm): ghép Bro/Zeek `conn` với eCAR-Bro, rồi huấn luyện BiLSTM và Mixed-Type Self-Attention để phát hiện cửa sổ 15 phút có flow tấn công. Nhánh Host ML (LightGBM/XGBoost/RF/GraphSAGE) là của Nguyễn Nhật Nguyễn, nằm ở nhánh `main`.

Bản này là **pipeline v2, dựng lại hoàn toàn từ raw**: mỗi bước có input/output rõ ràng, file đọc được bằng Excel hoặc trình soạn thảo, và kiểm tra tự động.

## Kết quả bản cuối (TEST, ngưỡng chọn trên VAL, một seed)
| Mô hình | Precision | Recall | F1 | PR-AUC | TP / FP / FN |
|---|---:|---:|---:|---:|---|
| BiLSTM | 1.000 | 0.976 | 0.988 | 0.989 | 80 / 0 / 2 |
| Mixed-Type | 1.000 | 0.988 | 0.994 | 1.000 | 81 / 0 / 1 |

TEST có 34,413 sample, trong đó 82 sample dương (SC1 9, SC2 72, SC3 1). Hai mô hình chênh nhau đúng 1 sample nên **chưa kết luận mô hình nào tốt hơn**. Luật một dòng "sample có `powershell.exe`" đạt F1 0.994 trên cùng TEST. Chi tiết, các mẫu bị bỏ sót và giới hạn: [`02_artifacts/22_v2_pipeline/S7_results/STEP_S7_RESULTS.md`](02_artifacts/22_v2_pipeline/S7_results/STEP_S7_RESULTS.md).

## Đọc theo thứ tự
1. [`CLAUDE.md`](CLAUDE.md): bối cảnh, quyết định đã chốt, quy tắc, việc đang chờ.
2. [`00_docs/ai_agent/HANDOFF_V2_PIPELINE.md`](00_docs/ai_agent/HANDOFF_V2_PIPELINE.md): trạng thái từng bước và kết quả.
3. Báo cáo từng bước: `02_artifacts/22_v2_pipeline/S1_join … S5_validate/STEP_S?_*.md`.
4. Kế hoạch: [`STEP_22_PIPELINE_V2_PLAN.md`](02_artifacts/22_v2_pipeline/STEP_22_PIPELINE_V2_PLAN.md); thiết kế fusion (bản nháp, chưa cài đặt): [`STEP_20_FUSION_DESIGN.md`](02_artifacts/20_fusion_design_v1/STEP_20_FUSION_DESIGN.md).

## Pipeline v2
| Bước | Mã (`01_code/pipeline_v2/`) | Input → Output |
|---|---|---|
| S1 join | `s1_join.py` | Bro `conn.*.log.gz` + eCAR-Bro `ecarbro.json.gz` → `flows_joined.parquet` (92,045,755 flow, 24,721 flow dương, 743 máy); inner join theo `bro_uid = uid` |
| S2 cửa sổ và split | `s2_windows_split.py` | flow → `windows.csv` (110,402 cửa sổ, 620 máy); split cấp cửa sổ 70/15/15, phân tầng theo scenario |
| S3 preprocess | `s3_preprocess.py`, `v2_common.py` | cửa sổ TRAIN → một file `preprocess_spec.json` (từ điển, mean/std, feature active) + `vocab.csv`; **fit chỉ trên TRAIN** |
| S4 shards | `s4_shards.py` | flow + spec → `.npz` (train 160,210 / val 34,361 / test 34,413 sample) + `samples.csv` |
| S5 validate | `s5_validate.py` | kiểm tra chéo và giải mã ngược 400 sample về flow raw (0 sai) |
| S6 đóng gói | `s6_package.py`, `s6_notebooks.py`, `s6_smoke_test.py` | gói Kaggle và notebook `04_notebooks/06d…`, `07d…` |
| S7 phân tích | `s7_analyze.py`, `s7b_diagnostics.py` | kết quả theo scenario, chẩn đoán |
Mỗi thư mục bước có `schema.json` (mọi trường), `preview.csv` / `preview_record.json` (dòng thật), `checks.json`.

## Feature của mô hình
- **Từ phía host (eCAR-Bro):** `app_family` (tên tiến trình tạo flow), `image_dir_class` (tiến trình chạy từ thư mục nào), `principal_class` (loại tài khoản chạy tiến trình).
- **Từ mạng (Bro conn):** `proto`, `service`, `conn_state`, `resp_port_class`; số: `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`, cờ `has_missed_bytes`; thời gian: `delta_t_log1p`.
- Không dùng `pid`, `ppid`, `actor_id` (chỉ lưu trong bảng ghép để tra cứu). Chưa có tiến trình cha và command line.

## Quyết định và giới hạn (đọc trước khi trích số liệu)
- **Split cấp cửa sổ, không host-disjoint** (quyết định có chủ ý). 80/81 cửa sổ dương của TEST có cửa sổ dương cùng máy ở TRAIN, nên điểm đo khả năng nhận ra mẫu/máy đã thấy, không đo phát hiện trên máy mới. Kết quả với split theo máy (bản cũ, 3 seed) nằm ở lịch sử trong các handoff.
- Một lần train (seed 42), đủ feature; không ablation. TEST chỉ chấm một lần tại ngưỡng đã chọn trên VAL (ngưỡng = 1.0 do xác suất bão hòa).
- Điểm cao chủ yếu do tín hiệu đơn giản: `powershell.exe`, thư mục Temp/AppData, tài khoản Administrator (13,297 flow dương, 0 benign trong dữ liệu). 98% cửa sổ dương là beacon C2 lặp. SC3 chỉ có 6 cửa sổ dương.
- "Kết hợp host" ở đây nghĩa là **bổ sung ngữ cảnh tiến trình từ eCAR-Bro vào flow mạng**, không phải fusion với mô hình Host ML. Fusion với Host ML mới có ở mức điểm (thử nghiệm riêng); fusion mức đặc trưng mới ở thiết kế nháp.

## Chạy lại
Cần dữ liệu raw OpTC (Bro, eCAR-Bro) và Python có `duckdb`, `pandas`, `numpy`, `scipy`. Đường dẫn trong mã đang là đường dẫn tuyệt đối của máy tác giả (`D:/UIT/KLTNv2`, ổ raw `E:\`): sửa lại hằng số `ROOT`, `BRO`, `ECAR` ở đầu các script trước khi chạy. Thứ tự: `s1_join.py` (khoảng 3 giờ 20 phút) → `run_final.py` (S2 đến S5, báo cáo, đóng gói). Huấn luyện chạy trên Kaggle bằng `06d` và `07d`.

## Không có trong repo
Dữ liệu raw và bảng ghép (hàng GB), shards, gói Kaggle. Dữ liệu OpTC công khai: <https://github.com/FiveDirections/OpTC-data>; nhãn từ bài *A New Hope for DARPA OpTC* (Majorczyk, Pilastre, Dijoud, 2025).
