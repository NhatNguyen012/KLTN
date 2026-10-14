# CLAUDE.md — KLTN Network Deep Learning (DARPA OpTC)

Luôn trả lời bằng tiếng Việt, ngắn gọn, số liệu có kiểm chứng. Thuật ngữ tiếng Anh ghi kèm nghĩa tiếng Việt, ví dụ: data leakage (rò rỉ dữ liệu). Nói rõ hạn chế; không kết luận quá mức.

## Đọc đầu tiên (theo thứ tự)
1. `00_docs/ai_agent/HANDOFF_V2_PIPELINE.md` — **trạng thái mới nhất** (cập nhật 2026-10-13): pipeline v2 đã build lại từ raw, đã train xong, quyết định đã chốt, việc đang chờ.
2. `02_artifacts/22_v2_pipeline/S7_results/STEP_S7_RESULTS.md` — kết quả train bản cuối và cách phát biểu đúng.
3. Khi cần lịch sử: `HANDOFF_STEP10_11.md` (retrain/audit), `HANDOFF_STEP10G_17.md` (multi-label, beacon chưa từng thấy, host retrain, fusion mức điểm), `HANDOFF_FUSION_START.md` (câu hỏi mở về fusion), `02_artifacts/09_leakage_audit_v1/` (audit shortcut).

## Đề tài và hai nhánh
"Multi-Source Context-Aware Framework for APT Detection" trên DARPA OpTC. Repo này là nhánh **Network DL** (Võ Ngọc Hoàng Lâm): Bro/Zeek conn join eCAR-Bro, BiLSTM và Mixed-Type Self-Attention. Nhánh Host ML là của Nguyễn Nhật Nguyễn (LightGBM/XGBoost/RF/GraphSAGE; code gốc ở `D:\UIT\KLTN\KLTN-main\code\`).

## Trạng thái hiện tại (2026-10-13)
- **Bản cuối của nhánh Network DL = pipeline v2**: mã `01_code/pipeline_v2/`, output `02_artifacts/22_v2_pipeline/S1..S5` (+ `S7_results`), gói Kaggle `03_datasets/v2_network_dl_kaggle_upload`, notebook `04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb`, `07d_Mixed_Type_Kaggle_v2_final.ipynb`, mô hình `05_models/v2_final/`. S1–S5 và train đã xong; kết quả TEST: BiLSTM F1 0.988, Mixed-Type F1 0.994 (một seed; luật "có powershell.exe" đạt 0.994 trên cùng TEST).
- Mỗi bước v2 có input/output đọc được: `schema.json`, `preview.csv`, `preview_record.json`, `checks.json`, `STEP_S?_*.md`; preprocessing nằm trong **một** `S3_preprocess/data/preprocess_spec.json`.
- Pipeline cũ (`01_code/pipeline/` 00→17, artifact 02…21) giữ làm lịch sử và chẩn đoán; không dùng để sinh bản cuối.

## Quyết định người dùng đã chốt (2026-10-12/13) — không đề xuất lại nếu không được hỏi
- Train **một lần** (seed 42), đủ feature; **bỏ** các thí nghiệm bỏ `app_family`, beacon chưa từng thấy, nhiều seed, ablation. Bạn của người dùng giải thích điểm cao do beacon/`app_family` là bình thường.
- Split **cấp cửa sổ** (hostname, 15 phút), 70/15/15, phân tầng theo scenario (cửa sổ dương) và theo ngày (cửa sổ benign). **Không host-disjoint** — ngoại lệ có chủ ý so với quy tắc cũ. Khi nêu kết quả phải nói: điểm đo khả năng nhận ra mẫu/máy đã thấy, không đo phát hiện máy mới.
- **Inner join** eCAR-Bro; cột audit `actor_id, pid, ppid, principal` có trong bảng ghép nhưng không vào model.
- **Field host trong DL**: `app_family`, `image_dir_class`, `principal_class` (đều từ eCAR-Bro). Phát biểu đúng: "flow mạng được bổ sung ngữ cảnh tiến trình từ eCAR-Bro", **không** nói là fusion với nhánh Host ML (fusion với Host ML mới ở mức điểm, STEP 17; fusion mức đặc trưng mới ở thiết kế nháp, STEP 20).
- Người dùng cho phép tự chạy các bước và tự sửa lỗi trong phạm vi pipeline v2 ("tự động xác nhận chạy tiếp"). Với job mới ngoài phạm vi đó vẫn báo dung lượng/thời gian trước.

## Việc đang chờ / có thể làm tiếp
1. **Parent process và command line** (chưa có): cần quét log host `E:\host-*` (~6–7 giờ, như STEP 17a), tra từ `actor_id` sang event tạo tiến trình; độ chính xác ánh xạ chưa đo (bài A New Hope: ~40% tiến trình bị gán sai). Chờ người dùng quyết.
2. Fusion mức đặc trưng/gating: bản nháp ở `02_artifacts/20_fusion_design_v1/STEP_20_FUSION_DESIGN.md`; chưa cài đặt.
3. Todolist Excel của nhóm (`NhatNguyen-HoangLam-KLTN-TodoList*.xlsx`): người dùng tự cập nhật; đoạn ghi chú soạn sẵn ở `00_docs/todo_notes_lam_2026-10-12.md`.
4. Dataset thầy gợi ý đã phân tích (SAGA, Windows-APT 2025, skrghosh): `02_artifacts/19_dataset_analysis_v1/` (Word, mẫu thô, slide). Thầy cũng yêu cầu (10/10) tìm 3 dataset mới (Windows/Linux) để kiểm thử mô hình đã train: chưa làm.
5. Cập nhật báo cáo khóa luận từ `S7_results` và các `STEP_S?_*.md`.

## Quy tắc bắt buộc
- Không sửa, không xóa artifact cũ trong `02_artifacts/`, `03_datasets/`, `05_models/`. Output mới luôn ghi vào thư mục mới có số step mới. (Pipeline v2 đã tự ghi vào `22_v2_pipeline`; chạy lại S4 ghi đè `S4_shards/shards` là chủ ý, vì cùng một bản v2.)
- Mọi preprocessing (từ điển category, mean/std, quyết định active) **chỉ fit trên TRAIN** của đúng split đó. Checkpoint và ngưỡng chỉ chọn trên VAL; TEST chỉ tính chỉ số một lần.
- Không đổi kiến trúc BiLSTM/Mixed-Type. Không kết luận "overfit". Không kết luận "Mixed-Type tốt hơn BiLSTM" khi chênh lệch chưa vượt độ dao động giữa các seed (hiện chỉ 1 seed, chênh 1 sample).
- Mỗi step xong phải có report `STEP_XX_*.md` (tiếng Việt) trong thư mục artifact của step.
- Trước job nặng mới (ngoài phạm vi v2 đã được cho phép) phải báo dung lượng và thời gian ước tính và chờ xác nhận. Train luôn chạy trên **Kaggle do người dùng chạy**, không train local.
- Ổ `E:` (raw eCAR, Bro, nhãn) chỉ đọc, không ghi; chỉ cần khi sinh lại từ raw hoặc quét log host.

## Kết luận audit (đã chốt, không làm lại)
- Không có leakage kỹ thuật ở split host-disjoint cũ: vocab và mean/std fit trên TRAIN only; threshold chọn trên VAL.
- Metric ≈ 1.0 do shortcut: `app_family = powershell.exe` ⇒ 100% malicious (luật một dòng F1 0.975–0.994); 98% cửa sổ dương (530/541) là beacon C2 lặp (SC1 mỗi ~5 giây tới `132.197.158.98:80`; SC2 mỗi ~30 giây tới `202.6.172.98:443`); beacon chưa từng thấy làm recall rơi từ ~0.95 xuống ~0.03 (STEP 10H). SC3 gần như không có positive ở mạng (2 máy, 189 flow dương, 6 cửa sổ dương; flow bị từ chối `REJ` giống noise).
- Nhãn từ bài "A New Hope for DARPA OpTC": nhãn network theo IP C2 + thời gian; nhãn host theo process tree; đồng bộ qua eCAR-Bro. Scenario ≈ ngày (SC1 = 23/9, SC2 = 24–25/9, SC3 = 25/9); số máy bị tấn công SC1 17, SC2 10, SC3 2.
- `principal_class = ADMINISTRATOR` có 13,297 flow dương và 0 benign (tài khoản Red Team): tín hiệu mạnh nhưng là đặc điểm testbed.

## Cấu trúc
Xem `README.md`. `01_code/pipeline/` (cũ, 00→21a), **`01_code/pipeline_v2/`** (bản cuối), `02_artifacts/` (output từng step; v2 ở `22_v2_pipeline`), `03_datasets/`, `04_notebooks/` (notebook train Kaggle), `05_models/` (kết quả; v2 ở `v2_final`), `output_kaggle/` (zip kết quả người dùng bỏ vào), `_archive/` (code cũ, không sửa). Bảng đổi tên cũ → mới: `00_docs/RENAME_MAP.csv`.

## Ghi chú kỹ thuật
- Python: `.venv-host\Scripts\python.exe` (có duckdb, pandas, scipy, lightgbm, xgboost, sklearn, torch CPU; không có matplotlib). Python hệ thống không có các thư viện này.
- Windows + Git Bash: **không dùng heredoc dài có dấu nháy, backslash hoặc `\n` trong chuỗi**; viết script bằng công cụ Write rồi chạy (đã gặp lỗi nhiều lần). Console cp1252: `sys.stdout.reconfigure(encoding="utf-8")`. File ghi bằng Python mặc định CRLF; script ở repo dùng LF (`newline="\n"`). `-I` (isolated) bỏ thư mục script khỏi `sys.path`: không dùng `-I` khi chạy script Kaggle có import cùng thư mục.
- DuckDB: `USING SAMPLE` áp dụng **trước** `WHERE` (lọc trong subquery); `GROUP BY` 92M nhóm với nhiều `arg_min` hết RAM (tách hai pha); `strftime(to_timestamp(...))` ra giờ local, dùng `make_timestamp` để có UTC. Khi hai tiến trình DuckDB chạy song song chú ý `memory_limit`.
- Giờ: eCAR dùng EDT (UTC−4), Bro dùng epoch UTC; cửa sổ 15 phút trùng nhau giữa hai nguồn.
- Shards `.npz`: `x_cat` thứ tự theo `preprocess_spec.json → model_input_layout` (hiện 7 cột: `app_family, proto, service, conn_state, resp_port_class, image_dir_class, principal_class`); `<UNK>` = 0, `<MISSING>` = 1.
- Không chờ job nền bằng sleep dài chuỗi: dùng `run_in_background` hoặc Monitor với vòng lặp `until`.
