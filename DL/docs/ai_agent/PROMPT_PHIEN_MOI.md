# Prompt dán vào phiên mới (cùng thư mục D:\UIT\KLTNv2) — cập nhật 2026-10-30

```text
Tôi là Võ Ngọc Hoàng Lâm (khóa luận APT detection trên DARPA OpTC, nhánh Network DL; bạn cùng nhóm Nguyễn Nhật Nguyễn làm nhánh Host ML). Làm việc trong D:\UIT\KLTNv2. Luôn trả lời tiếng Việt, ngắn gọn, số liệu kiểm chứng, nói rõ hạn chế, không kết luận quá mức; thuật ngữ tiếng Anh kèm nghĩa tiếng Việt.

Đọc theo thứ tự trước khi làm:
1. CLAUDE.md
2. 00_docs/ai_agent/HANDOFF_NEWDATASET_FINETUNE.md — đọc kỹ MỤC 0 (trạng thái mới nhất, thay các mục cũ khi mâu thuẫn): quyết định mới, STEP 33–39, hiểu biết về THEIA và ATLASv2, việc có thể làm tiếp, cảnh báo trung thực, ghi chú kỹ thuật.
3. 02_artifacts/37_new_dataset_raw_samples_v1/STEP_37_RAW_LABELS_PREPROCESS_PLAN.md (có mục ĐÍNH CHÍNH ở cuối) và 02_artifacts/36_theia_atlas_analysis_v1/STEP_36_THEIA_ATLASV2_ANALYSIS.md (có mục ĐÍNH CHÍNH ở cuối).
4. Khi cần chi tiết: 02_artifacts/39_dataset_word_v1/ (5 file Word: ATLASv2, THEIA_v2, BiLSTM, MixedType, Pipeline), 02_artifacts/38_slide_records_v1/, 02_artifacts/30_finetune_design_final_v1/STEP_30_FINETUNE_DESIGN_FINAL.md (thiết kế fine-tune), 02_artifacts/34_train_diag_v1/STEP_34_TRAIN_DIAGNOSTIC.md, 02_artifacts/22_v2_pipeline/ (pipeline v2 và S7_results).

Trạng thái tóm tắt: nhánh Network DL bản cuối là pipeline v2; bản B (4 category app_family, proto, resp_port_class, image_dir_class + delta_t) đạt F1 0.988 (BiLSTM) và 0.988 (Mixed-Type) trên OpTC TEST (TP 80/FP 0/FN 2/TN 34,331). Miền dữ liệu mới = THEIA (raw CDM18, E:\IL_DATASET\DARPA-TC-E3-THEIA\RAW) + ATLASv2 (E:\IL_DATASET\ATLASv2); đã phân tích raw, nhãn (REAPr, nằm ngoài raw), trường, mẫu nguyên văn, và đã viết tài liệu Word/slide. Chưa dựng flow/shards hay chạy mô hình cho hai bộ này. Kết quả trên dataset cũ (skrghosh + FiveDirections) chỉ để tham chiếu: fine-tune không bắt được tấn công mới; Mixed-Type chỉ bắt cửa sổ có powershell.exe; chẩn đoán TRAIN cho thấy cấu hình cũ quá ngắn (chưa chứng minh khái quát).

Quyết định đã chốt (không đề xuất lại nếu không được hỏi): train trên Kaggle do tôi chạy; 3 fold × 1 seed (42); chia trộn theo cửa sổ (yêu cầu của thầy); đầu vào giữ bản B; miền mới = THEIA + ATLASv2; MỞ RỘNG TỪ ĐIỂN NGAY TỪ ĐẦU cho cả app_family và image_dir_class (mỗi trường một từ điển riêng, id mới nối tiếp: app_family từ 61, image_dir_class từ 10; lớp thư mục Linux đề xuất SYSTEM_BIN, SYSTEM_LIB, TEMP_LINUX, VAR_LOG, HOME_USER, ETC_OPT); BỎ mọi so sánh "trước fine-tune"/zero-shot, chỉ báo ma trận nhầm lẫn (confusion matrix) TRAIN và TEST của dữ liệu mới và TEST OpTC (xem có quên không); tên chương trình THEIA lấy từ EVENT_EXECUTE (không từ Subject.path). Quy tắc không đổi: không sửa artifact cũ (output vào thư mục step mới có số tiếp theo), preprocessing chỉ fit trên TRAIN, ngưỡng không chọn theo dữ liệu mới, TEST chỉ tính một lần (nếu mở lần hai thì ghi rõ), không đổi kiến trúc, E: chỉ đọc, báo dung lượng/thời gian và chờ tôi xác nhận trước job nặng mới. Dùng .venv-host\Scripts\python.exe; viết script bằng công cụ Write (không dùng heredoc có \n hoặc \\).

Việc tiếp theo: THẦY VỪA SỬA/YÊU CẦU MỘT SỐ ĐIỀU, tôi sẽ cho bạn biết ngay sau khi bạn tóm tắt. KHÔNG tự chạy job mới (dựng flow, quét raw, train) trước khi tôi nói rõ cần làm gì.

Bắt đầu bằng việc đọc các file trên, tóm tắt 5–8 dòng những gì bạn hiểu về trạng thái hiện tại (nhớ nêu các quyết định đã chốt và những điểm còn mở), rồi hỏi tôi thầy đã sửa/yêu cầu gì.
```
