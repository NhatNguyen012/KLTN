# Prompt dán vào phiên mới (cùng thư mục D:\UIT\KLTNv2)

```text
Tôi là Võ Ngọc Hoàng Lâm (khóa luận APT detection trên DARPA OpTC, nhánh Network DL; bạn cùng nhóm là Nguyễn Nhật Nguyễn, nhánh Host ML). Hãy làm việc trong thư mục D:\UIT\KLTNv2, luôn trả lời tiếng Việt, ngắn gọn, số liệu kiểm chứng, báo dung lượng/thời gian và chờ tôi xác nhận trước mọi job nặng.

Đọc theo thứ tự trước khi làm:
1. CLAUDE.md
2. 00_docs/ai_agent/HANDOFF_STEP10_11.md, HANDOFF_FUSION_START.md, HANDOFF_STEP10G_17.md (mục 3b là trạng thái mới nhất)
3. 02_artifacts/17_host_retrain_v1/STEP_17_HOST_RETRAIN_AND_FUSION.md
4. 02_artifacts/10h_unseen_beacon_analysis_v1/STEP_10H_UNSEEN_BEACON_RESULTS.md
5. 02_artifacts/14_readable_pipeline_v1/00_INDEX.md (lớp đọc được của toàn pipeline)
6. 02_artifacts/18_dataset_candidates_v1/STEP_18_DATASET_CANDIDATES.md

Trạng thái tóm tắt: nhánh Host đã retrain theo split host-disjoint (LightGBM/XGBoost, F1 event 0.827 trên TEST); fusion mức điểm trên 1,103 cửa sổ cho cải thiện chỉ 2 cửa sổ; ở SC3 (sysclient0051) model host chấm event rất cao nhưng cách gộp event→cửa sổ bằng max làm mất 4 cửa sổ; beacon chưa từng thấy làm recall network tụt từ ~0.95 xuống ~0.03 (trừ BiLSTM bỏ SC1: 0.65).

Quy tắc không đổi: không sửa artifact cũ (output vào thư mục step mới), mọi preprocessing chỉ fit trên TRAIN, split theo hostname, ngưỡng chọn trên VAL, TEST chỉ chạy một lần (nếu buộc phải mở lần hai thì ghi rõ), không đổi kiến trúc model, không kết luận quá mức. Dùng .venv-host\Scripts\python.exe cho code cần lightgbm/xgboost/scipy. Ổ E: (raw eCAR/Bro) chỉ cần khi sinh lại mẫu hoặc quét thêm.

Việc cần làm tiếp (theo thứ tự ưu tiên, hỏi tôi trước khi chạy job nặng):
A. Fusion v2: thêm cách gộp event→cửa sổ "số event vượt ngưỡng" và "tỉ lệ vượt ngưỡng" vào danh sách chọn trên VAL (dữ liệu có sẵn trong window_scores_host.csv), chạy lại 17d, ghi rõ TEST mở lần hai, báo cả v1 và v2, tập trung SC3.
B. Thí nghiệm giữ cả hai host SC3 ngoài TRAIN (host và network) để so công bằng với walk-forward của Nguyễn (F1 0.2); cần sinh lại từ điển/mẫu cho split mới (cần ổ E:, báo ước lượng trước).
C. Tập cửa sổ benign đầy đủ hơn (hoặc trọng số lấy mẫu) để ước lượng FP thật ở mức cửa sổ; lặp seed_2, seed_3.
D. Nếu A cho thấy host bổ sung được thông tin: thử fusion mức đặc trưng/gating ở mức cửa sổ (nối vector host hoặc p_host vào biểu diễn network, source mask, missing 10/20/30%).
E. Nhãn multi-label (02_artifacts/12b_multilabel_stage_v1, S2_labels): nối vào mẫu cửa sổ và thiết kế train multi-label 5 nhóm tactic (che cửa sổ chưa có nhãn giai đoạn).
F. Dataset thầy đưa (STEP 18): nếu tôi đồng ý thì tải Windows-APT 2025 và skrghosh/apt-dataset để xem cột nhãn; hỏi tôi trước khi tải SAGA.
G. Tuỳ chọn: seed 43/44 và 4 run đối chứng DROP_APP_FAMILY=False cho beacon chưa từng thấy; nhờ Nguyễn train GraphSAGE trên split host-disjoint (gói 02_artifacts/16_host_branch_request_v1).

Việc cần tôi (người dùng) làm tay: thẩm định ánh xạ bước tấn công → tactic (STEP 12B) với thầy hoặc Nguyễn; chạy Kaggle nếu cần train thêm.

Bắt đầu bằng việc đọc các file trên và tóm tắt cho tôi ngắn gọn (5–8 dòng) những gì bạn hiểu về trạng thái hiện tại, rồi đề xuất bước đầu tiên.
```
