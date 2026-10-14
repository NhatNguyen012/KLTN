# HANDOFF — trạng thái dự án sau STEP 10 và STEP 11 (2026-10-03)

> Đọc file này sau `CLAUDE.md`. Nó thay cho trí nhớ của các phiên chat trước. Quy tắc bắt buộc vẫn là ở `CLAUDE.md` (luôn trả lời tiếng Việt; không sửa/xóa artifact cũ; split theo hostname; preprocessing chỉ fit trên TRAIN; mỗi step có report `STEP_XX_*.md`).

## 1. Người dùng và cách làm việc
- Người dùng là **Võ Ngọc Hoàng Lâm** (nhánh Network DL của KLTN APT detection trên DARPA OpTC). Bạn cùng nhóm: Nguyễn Nhật Nguyễn (nhánh Host ML).
- Phong cách mong muốn: trả lời **tiếng Việt, ngắn gọn, dễ hiểu**; thuật ngữ tiếng Anh kèm nghĩa; số liệu thật có kiểm chứng; nói rõ hạn chế; không kết luận quá mức. Báo dung lượng/thời gian và **chờ xác nhận trước job nặng**.
- Train luôn chạy trên **Kaggle** (không train local). Người dùng tự upload dataset, chạy notebook, rồi bỏ file zip kết quả vào repo (thư mục `output_kaggle/`).
- Người dùng tự ghi tiến độ vào Excel `00_docs/NhatNguyen-HoangLam-KLTN-TodoList.xlsx` (đã có sẵn nội dung 2 task retrain ở `00_docs/todo_retrain_2_tasks.xlsx`).

## 2. Đã làm (theo thứ tự)
| Step | Việc | Kết quả / file chính |
|---|---|---|
| 09, 09B | Audit leakage và phân tích nhãn | Không leakage kỹ thuật; **shortcut `app_family`** và **beacon lặp** giải thích metric ≈ 1.0 (`02_artifacts/09_leakage_audit_v1/`) |
| 10 (A) | Tuỳ chọn bỏ `app_family` ở notebook | `04_notebooks/06b_BiLSTM_Kaggle_v2.ipynb`, `07b_…v2.ipynb` (`DROP_APP_FAMILY`, `RUN_SUFFIX`), sinh bởi `10_make_noapp_notebooks.py` |
| 10a–10d | 3 split ngẫu nhiên theo scenario (seed 1,2,3), preprocessing, shards, validation | `02_artifacts/10a…10d_*`, dataset `03_datasets/random_network_dl_v1_1_15m/seed_{1,2,3}` + thư mục `seed_k_kaggle_upload` (zip để upload). Đã sửa tại chỗ 08b/08c/08d (thêm `--mode random`, mặc định giữ LOSO). Tên "loso" đã được bỏ khỏi output của mode random |
| 10E, 10F | Phân tích 12 run Kaggle (3 seed × {BiLSTM, Mixed-Type} × {có, bỏ `app_family`}) | `02_artifacts/10e_retrain_analysis_v1/STEP_10E_3SEED_CONCLUSIONS.md`; script `10e_analyze_retrain.py`, `10f_aggregate_seeds.py`; model giải nén ở `05_models/10_random_seed{k}_v1/` |
| 10G | Chuẩn bị thí nghiệm "beacon chưa từng thấy" | `02_artifacts/10g_unseen_beacon_v1/STEP_10G_UNSEEN_BEACON.md`, notebook `06c_…unseen_beacon.ipynb`, `07c_…unseen_beacon.ipynb`, dataset zip `03_datasets/loso_network_dl_v1_1_15m/holdout_scenario_{1,2}_kaggle_upload` |
| 11, 11B, 11C | Mô tả dataset OpTC; luồng đầu vào/đầu ra của pipeline; schema field | `02_artifacts/11_dataset_overview_v1/STEP_11_DATASET_OVERVIEW.md`, `STEP_11B_PIPELINE_INPUT_OUTPUT.md`, `STEP_11C_EVENT_SCHEMA.md`; schema `01_code/pipeline/network_event_schema_v1.json` (08b và 04a đọc trực tiếp; đã kiểm chứng shard byte-identical) |

## 3. Kết luận hiện tại (3 seed, TEST, trung bình)
- F1: BiLSTM có/bỏ `app_family` = **0.969 / 0.959**; Mixed-Type = **0.988 / 0.957**; luật "có powershell" = **0.976**.
- **98% positive window (530/541) là beacon C2** (SC1 mỗi ~5 giây tới `132.197.158.98:80`; SC2 mỗi ~30 giây tới `202.6.172.98:443`), nên bỏ `app_family` điểm vẫn cao. Chỉ 11 window không phải beacon (5 SC2, 6 SC3).
- **Chưa kết luận được:** Mixed-Type tốt hơn BiLSTM; bỏ `app_family` làm giảm hiệu năng (seed 2 ngược chiều); DL vượt luật 1 dòng (chỉ hơn ở 4 window của `sysclient0051`, SC3).
- **SC3** (2 host, 6 window): network-only gần như không bắt được (flow `REJ` giống noise) ⇒ động lực fusion với ngữ cảnh host (process tree, command line).
- Hạn chế đã ghi: 1 seed khởi tạo (42), TEST bị chi phối bởi 1 host SC2 (~88% window), bản bỏ `app_family` chưa hội tụ (best epoch 6–8/8), threshold bão hòa, VAL nhỏ.
- Chữ "positive window" = cửa sổ 15 phút của một host có ≥1 flow tấn công. Người dùng chưa quyết có đổi cách gọi ("window tấn công") trong Excel hay không.

## 4. Đang chờ / việc tiếp theo
1. **Chờ người dùng chạy 4 run bắt buộc trên Kaggle** (06c/07c × dataset `holdout_scenario_2` và `holdout_scenario_1`, `DROP_APP_FAMILY=True`; 4 run đối chứng `False` là tuỳ chọn). Khi có zip kết quả: giải nén vào thư mục mới `05_models/10g_unseen_*`, viết script phân tích (tái dùng `10e_analyze_retrain.py`; manifest LOSO dùng cột `loso_split`, khóa `loso_contract`), so với recall ~0.95 của split ngẫu nhiên khi bỏ `app_family`. Lưu ý scenario ≈ ngày (SC1 = 23/9, SC2 = 24–25/9).
2. Đề xuất chưa làm: đánh giá theo nhóm template/dedup; tập hard-negative (benign có app khác firefox và 5,563 flow tới `53.192.68.50`); thử `--epochs 16` và tie-break threshold cho cả full và noapp; thêm seed khởi tạo 43, 44; LOSO làm phụ lục; nhánh host cho SC3.
3. Có thể xuất bảng event đã preprocess đọc được (hướng 2 ở STEP 11C) nếu người dùng muốn.

## 5. Lưu ý kỹ thuật (đã gặp lỗi)
- Windows + Git Bash: **không dùng heredoc dài có dấu nháy, backtick hoặc `$'…'` trong lệnh Bash**; viết script bằng công cụ Write rồi chạy. Đường dẫn `/tmp` trong Bash ≠ đường dẫn Python (dùng đường dẫn Windows `C:/Users/...`).
- Ghi file bằng Python trên Windows mặc định ra CRLF; script ở repo dùng LF (`newline="\n"`).
- Notebook gốc 06/07 sẽ `KeyError` với dataset build bằng 08c (khóa `step05f_c_preprocess_fingerprint`); dùng 06b/07b/06c/07c. Mỗi notebook chỉ gắn **một** dataset Kaggle (dataset up dạng zip bị Kaggle giải nén thành thư mục lồng nhau, resolver đã xử lý).
- `D:\UIT\KLTN` (ngoài repo) chứa artifact STEP 00/02 (inventory raw, manifest host, ground truth) và bài báo trong `Papers/`. Raw data ở ổ E: (chưa gắn; chỉ gắn khi cần đọc lại file lớn).
- Thư mục `output_kaggle/` chứa 12 zip kết quả của 3 seed; chưa dọn.
