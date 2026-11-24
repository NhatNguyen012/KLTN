# HANDOFF — trạng thái sau STEP 12–17 và 10H (2026-10-07)

> Đọc sau `CLAUDE.md`, `HANDOFF_STEP10_11.md`, `HANDOFF_FUSION_START.md`. Luôn trả lời tiếng Việt, ngắn gọn, số liệu kiểm chứng; báo dung lượng/thời gian và chờ xác nhận trước job nặng.

## 1. Việc đã xong (thư mục mới, không sửa artifact cũ)
| Step | Nội dung | Vị trí |
|---|---|---|
| 12A/12B | Đọc nhật ký red team OpTC, dựng nhãn **multi-label theo tactic ATT&CK** cho 788 cửa sổ (host, 15 phút) | `02_artifacts/12a_…`, `12b_multilabel_stage_v1/` (`window_labels_v1.csv`, `stage_steps_v1.csv`) |
| 12C | Đặc trưng host theo cửa sổ (quét eCAR thô, 591 file) + baseline fusion mức A (luật tay) | `02_artifacts/12c_host_features_v1/` — kết quả: **không cải thiện** so với network-only; luật tay quá nhiễu |
| 13 | Unraveled: tải `processed/network-flows` (3.72 GB), sửa lỗi CSV (13,169 dòng lệch cột), file mẫu 21 flow | `03_datasets/unraveled_v1[_clean]/`, `02_artifacts/13_unraveled_overview_v1/` |
| 14 | **Lớp đọc được** cho cả pipeline (S0–S9, mỗi bước CSV + JSON mẫu + file `.md`), đã đối chiếu với shard `.npz` | `02_artifacts/14_readable_pipeline_v1/` (`00_INDEX.md`) |
| 15 | Quy mô left join (conn.log 17–25/9 = 290M dòng, gấp 3.15 lần bảng đã ghép) + pilot suy luận SC3 | `02_artifacts/15_leftjoin_scale_v1/` — **không nên build left join** lúc này |
| 16 | Gói yêu cầu nhờ Nguyễn train lại host-disjoint | `02_artifacts/16_host_branch_request_v1/` |
| 10H | Phân tích 4 run Kaggle "beacon chưa từng thấy" | `02_artifacts/10h_unseen_beacon_analysis_v1/STEP_10H_UNSEEN_BEACON_RESULTS.md` |

## 2. Kết luận quan trọng
- Bảng join chỉ giữ flow **có eCAR-Bro**: mất 4,590 flow độc hại (DC1 4,190; SC3 `sysclient0051` mất 325/488). Benign gần như chỉ là flow Firefox (99.7–99.9%). Ngày 25/9 chỉ có 15,738 dòng đã ghép so với 23.1M dòng conn.
- 499 host cùng có flow benign tới IP kẻ tấn công SC3 (kiểm tra cập nhật notepad++): tín hiệu mạng SC3 giống benign, điểm phân biệt thật ở host (`gup.exe` → `.exe` trong Temp).
- Nhánh host của Nguyễn: dự đoán **theo event**, split theo event (random) hoặc theo thời gian (walk-forward), **không host-disjoint**; walk-forward SC3 F1 0.2. Chồng lấn TEST của hai split chỉ 8–14 host.
- **Beacon chưa từng thấy:** recall TEST ~0.025 (BiLSTM và Mixed bỏ SC2), 0.0 (Mixed bỏ SC1), 0.654 (BiLSTM bỏ SC1) so với ~0.95 ở split ngẫu nhiên ⇒ phần lớn điểm cao là thuộc template beacon.

## 3. Đang chạy / đang chờ
1. **Retrain host-disjoint (STEP 17)**, mã `01_code/pipeline/17a..17d`: `17a_host_sample_pass.py` đang quét 4,685 file eCAR (log `02_artifacts/17_host_retrain_v1/pass_log.txt`, resumable, bỏ qua file có summary). ~2,800/4,685 lúc 15:57; còn ngày 22 và 23–25/9. 26+ file `E:\host-begnin\2019-09-17` nhóm 326–375 **bị hỏng thật** (gzip -t lỗi), script giữ phần đọc được và đánh dấu `truncated`.
   Sau khi `17a` in `DONE`: `17b` (từ điển TRAIN, ma trận 30:1, LightGBM/XGBoost, ngưỡng trên VAL, TEST một lần) → `17c` (chấm 1,103 cửa sổ trong `eval_windows_seed1.csv`) → `17d` (fusion với điểm host thật). Chạy 17b/17c/17d bằng `.venv-host\Scripts\python.exe` (có scipy, lightgbm 4.6.0, xgboost-cpu 3.0.5, sklearn 1.6.1); Python hệ thống không có các thư viện này. Chưa chạy 17b/17c/17d lần nào: cần thử pilot nhỏ trước.
   Khác phương pháp gốc của Nguyễn (ghi trong báo cáo): từ điển fit trên 100% event dương + 3% event âm TRAIN; chỉ LightGBM/XGBoost (RF cần 64 GB RAM, máy có 31.7 GB); GraphSAGE **không có code trong repo**.
2. Nguyễn: train GraphSAGE trên split host-disjoint nếu cần; xác nhận cách gộp event→cửa sổ.
3. Thầy/Nguyễn: thẩm định ánh xạ bước tấn công → tactic (STEP 12B).
4. Tuỳ chọn: seed 43/44 và 4 run đối chứng `DROP_APP_FAMILY=False` cho beacon chưa từng thấy.

## 3b. Cập nhật 2026-10-08 — STEP 17 ĐÃ CHẠY XONG (đọc `02_artifacts/17_host_retrain_v1/STEP_17_HOST_RETRAIN_AND_FUSION.md`)
- 17a (quét 4,685 file, 16.5 tỷ dòng), 17b (train), 17c (chấm 1,103 cửa sổ), 17d (fusion) đều xong. **Không cần ổ E: nữa** trừ khi sinh lại mẫu/từ điển cho split mới.
- Mức event (TEST): LightGBM và XGBoost F1 0.827, precision 0.98, recall 0.715.
- Mức cửa sổ (`y_net`): chỉ network F1 0.962; chỉ host 0.975 (LightGBM, gộp `max`); OR/stacking 0.975. Cải thiện chỉ 2 cửa sổ (`sysclient0618`, SC2).
- **SC3 `sysclient0051`:** host chấm event rất cao ở 4 cửa sổ tấn công (max 0.99+, 212–668 event vượt ngưỡng) nhưng gộp `max` với ngưỡng 0.99999 (chọn trên VAL) làm mất cả 4 cửa sổ. Chưa thử cách gộp "số event vượt ngưỡng" (nếu thử sau khi đã xem TEST thì ghi rõ TEST mở lần hai). `sysclient0351` (SC3 còn lại) nằm ở TRAIN nên đây không phải thử nghiệm kịch bản chưa thấy; Nguyễn đo walk-forward SC3 F1 0.2.
- Benign trong tập cửa sổ chỉ là mẫu (2 cửa sổ mỗi host-ngày): FP/precision mức cửa sổ lạc quan.
- STEP 18: bốn dataset multi-label thầy đưa (`02_artifacts/18_dataset_candidates_v1/`): SAGA (IEEE TDSC, nhãn từng event, host) phù hợp nhất cho nhãn đa lớp host; skrghosh (eCAR, nhãn theo kịch bản); Windows-APT 2025 (nhỏ); arXiv 2606.18190 (3 nguồn, chưa có link phát hành). Chưa tải gì.
- Trả lời đã giải thích cho người dùng: fusion mức điểm (đang làm) vs mức đặc trưng; chỗ nối cấp flow đứt ở SC3 vì 325/488 flow không có eCAR-Bro.

## 4. Lưu ý kỹ thuật (đã gặp lỗi)
- Ổ E: phải gắn (đã từng bị tháo giữa chừng). Raw eCAR ở `E:\host-begnin`, `E:\host-malicious`; không ghi vào đó.
- Windows: không dùng heredoc dài có dấu `\`/nháy; viết script bằng Write rồi chạy. Console cp1252: dùng `PYTHONIOENCODING=utf-8` hoặc `sys.stdout.reconfigure(encoding="utf-8")`.
- DuckDB `USING SAMPLE` áp dụng **trước** `WHERE`: phải lọc trong subquery. `strftime(to_timestamp(ts))` ra giờ local (UTC+7): dùng `make_timestamp(...)` để có UTC. pandas `groupby.apply` bỏ cột nhóm.
- Excel khoá file đang mở (đừng ghi đè `flows_sample*.csv` khi file đang mở).
- Không chờ job nền chỉ bằng `DONE`: chờ cả `Traceback`.
- Mã nguồn Nguyễn (đã có trên máy): `D:\UIT\KLTN\KLTN-main\code\` (giống zip mới `D:\UIT\KLTNv2\KLTN-main.zip`). Tokenizer `ecar_tokenizer.py`; label ở **đuôi dòng** (`"label": 1}`), FLOW bị loại.
