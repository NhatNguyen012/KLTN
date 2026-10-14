# HANDOFF — Pipeline Network DL v2 (dựng lại từ raw, cập nhật 2026-10-13 sau khi train xong)

> Đọc sau `CLAUDE.md` và các handoff cũ. Mọi quyết định dưới đây do người dùng chốt (2026-10-12/13).

## Quyết định đã chốt
- Bỏ mọi thí nghiệm bỏ `app_family`, beacon chưa từng thấy, nhiều seed, ablation. Train **một lần** (seed 42), đủ feature. Kiến trúc BiLSTM và Mixed-Type giữ nguyên.
- Split **cấp cửa sổ** (hostname, 15 phút), 70/15/15, phân tầng theo scenario (cửa sổ dương) và theo ngày (cửa sổ benign); **không host-disjoint** (ngoại lệ có chủ ý so với `CLAUDE.md`). Điểm cao hơn split theo máy là bình thường; phát biểu: đo khả năng nhận ra mẫu/máy đã thấy.
- **Inner join** eCAR-Bro (đã chốt); thêm cột audit `actor_id, pid, ppid, principal` (không vào feature/shards).
- **Feature host trong DL (bản cuối, 2026-10-13):** 3 category lấy từ eCAR-Bro (telemetry phía host): `app_family` (tên tiến trình), `image_dir_class` (tiến trình chạy từ thư mục nào), `principal_class` (loại tài khoản chạy tiến trình); còn lại là Bro conn (4 category + 8 numeric/nhị phân + delta_t). `pid/ppid/actor_id/principal/image_path` thô KHÔNG vào model. Chưa có parent process / command line (cần quét log host trên ổ E:, ước ~6-7 giờ như STEP 17a). Lưu ý: `principal_class = ADMINISTRATOR` có 13,297 flow dương và 0 benign (tài khoản Red Team).
- Mỗi bước: input/output rõ ràng, file đọc được (`schema.json`, `preview.csv`, `preview_record.json`, `checks.json`, `STEP_S?_*.md`); preprocessing gói trong **một** `preprocess_spec.json`.

## Trạng thái
| Bước | Thư mục | Kết quả |
|---|---|---|
| S1 join | `02_artifacts/22_v2_pipeline/S1_join` | PASS; 92,045,755 flow, 24,721 dương, 743 máy (khớp bản cũ) |
| S2 windows + split | `S2_windows_split` | PASS; 110,402 cửa sổ, 620 máy; khớp STEP 21A từng cửa sổ |
| S3 preprocess | `S3_preprocess` | PASS; fit chỉ TRAIN (77,281 cửa sổ); active giống bản cũ |
| S4 shards | `S4_shards` | PASS; train 160,210 / val 34,361 / test 34,413 sample |
| S5 validate | `S5_validate` | PASS; giải mã ngược 400 sample, 0 sai |
| S6 đóng gói + notebook | `03_datasets/v2_network_dl_kaggle_upload` (4.7 GB), `04_notebooks/06d_…_v2_final.ipynb`, `07d_…_v2_final.ipynb` | xong; đã chạy thử CPU vài batch cả hai mô hình (chỉ thiếu matplotlib local) |
| Train | Kaggle (người dùng đã chạy, 1 seed) | **XONG**: `output_kaggle/bilstm_v2.zip`, `mixed_v2.zip` → `05_models/v2_final/` |
| S7 phân tích | `s7_analyze.py`, `s7b_diagnostics.py` | **XONG**: `02_artifacts/22_v2_pipeline/S7_results/STEP_S7_RESULTS.md` |

## Kết quả train (TEST, ngưỡng chọn trên VAL, chi tiết ở `S7_results/STEP_S7_RESULTS.md`)
- BiLSTM: precision 1.000, recall 0.976, **F1 0.988**, PR-AUC 0.989 (TP 80, FP 0, FN 2). Mixed-Type: precision 1.000, recall 0.988, **F1 0.994**, PR-AUC 1.000 (TP 81, FP 0, FN 1). Sample TEST 34,413 (82 dương). Chênh nhau 1 sample, một seed: chưa kết luận hơn kém.
- Ngưỡng VAL của cả hai = 1.0 (xác suất bão hòa); chỉ số không phụ thuộc ngưỡng vẫn rất cao.
- Luật "có `powershell.exe`" trên cùng TEST: F1 0.994; "powershell hoặc thư mục Temp/AppData": 82/82. Không mẫu âm nào có cờ powershell/Temp/Administrator. Mô hình không vượt luật đơn giản; attention của Mixed-Type dồn vào `principal_class`, `app_family`, `image_dir_class`.
- Bỏ sót: BiLSTM 2 chunk của một cửa sổ SC2 (beacon 8 flow chìm giữa 1,800 flow firefox); Mixed-Type mẫu SC3 duy nhất ở TEST (`cKfGW.exe` từ Temp, REJ). SC3 chỉ có 1 mẫu TEST.

## Việc kế tiếp (chờ người dùng quyết)
1. Có làm **parent process / command line** không (quét log host trên ổ E:, ~6–7 giờ; độ chính xác ánh xạ chưa đo) rồi train lại, hay chốt bản hiện tại.
2. Fusion mức đặc trưng/gating (`02_artifacts/20_fusion_design_v1`) nếu thầy yêu cầu.
3. Dùng `S7_results` và các `STEP_S?_*.md` cho báo cáo khóa luận; cập nhật todolist Excel (người dùng tự làm).
4. Yêu cầu của thầy ngày 10/10: kiểm thử mô hình đã train bằng OpTC trên 3 dataset mới (Windows/Linux, không cần nhãn): chưa làm; ứng viên có flow mạng: Unraveled (đã tải), skrghosh (eCAR có FLOW ở 3/5 chiến dịch); cần ánh xạ cột sang feature của mô hình.

## Lưu ý kỹ thuật
- Chạy lại toàn bộ: `s1_join.py` → `run_s2_to_s5.py` (S2–S5 tự dừng nếu một bước không PASS) → `s6_notebooks.py` / `s6_package.py`. Mã ở `01_code/pipeline_v2/`; dùng `.venv-host`. S1 mất khoảng 3 giờ 20 phút (bước gộp và sắp xếp 81 phút), S2–S5 khoảng 15 phút, cần ổ E: gắn.
- Quy tắc active category của S3: cần ≥ 2 giá trị, mỗi giá trị ≥ 5 flow TRAIN (một flow RDP `direction = inbound` của `sysclient0051` lọt vào TRAIN sẽ bật `direction` nếu dùng quy tắc cũ).
- Gói Kaggle dùng bố cục cũ (`shards/ split/ preprocessing/ integrity/` + `dataset_manifest.json`, `build_config.json`); các file `preprocessing/network_*.json` là bản định dạng cũ **sinh từ** `preprocess_spec.json` (nguồn sự thật).
- Windows + Git Bash: không dùng heredoc dài có dấu nháy; viết script bằng Write rồi chạy. Console cp1252: `sys.stdout.reconfigure(encoding="utf-8")`.
- `pid/ppid` chỉ là số; không dùng suy cha–con. Fusion mức đặc trưng vẫn ở mức thiết kế nháp (`02_artifacts/20_fusion_design_v1`).
