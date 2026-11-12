# STEP 46 — Kiểm gói `optc_host_ml_fusion_package.zip` của Nguyễn

Ngày: 2026-11-05. Gói ở `D:\UIT\KLTNv2\optc_host_ml_fusion_package.zip` (48.5 MB, 4,869 file, giải nén 67.3 MB vào thư mục tạm của phiên; không sửa gì trong repo). Chỉ đọc và tính lại số; không chạy mã của Nguyễn. Trả lời cho `00_docs/yeu_cau_gui_Nguyen_2026-11-04.md`.

## 1. Đối chiếu từng mục đã xin
| Mục | Có trong gói | Kiểm tra của tôi |
|---|---|---|
| 1 lgbm_metrics, confusion_matrix | Có (`P0_VERIFICATION_AND_METRICS`) | TEST F1 0.99632, TP 40,123 / FP 109 / FN 187 / TN 1,209,270, ngưỡng 0.87427 (chọn trên VAL). Tính lại từ điểm từng sự kiện: **khớp tuyệt đối** cho cả VAL (60 FP, 118 FN) và TEST |
| 2 điểm từng sự kiện | Có (`val_scores.parquet` 833,125 dòng, `test_scores.parquet` 1,249,689 dòng) | Cột: `source_id, source_line, split, label, score`; không trùng khóa. **Không có UUID sự kiện** (xem 2.1) |
| 3 file định danh | Có (8 file) | `experiment_identity`, `completion` (status COMPLETE, `training_run=false`), `scope` (34 host, 106 nguồn, 447,632,215 dòng/lượt), `vocab*`, hai manifest |
| 4 mask split + index | Có 106 mask `*.split.gz` + manifest; index 4,696 json | Cộng mask: 0 = 439,300,958 (không dùng), 1 = 6,248,443, 2 = 833,125, 3 = 1,249,689. Khớp đúng số TRAIN/VAL/TEST (và số dòng của hai file điểm) |
| 5 bảng tiến trình | Có (`process_table_by_host.parquet`) | 661,192 dòng, 34 host, đủ 12 cột đã xin (xem 2.3) |
| 6 độ phủ tracker | Có (`tracker_coverage_by_host.csv` 106 dòng) | Tổng: có siêu dữ liệu actor 99.7% truy vấn, có cha 79.6%; `pid_reuse_conflict_count` trung vị ~11,000/host-ngày; giải thích tái dùng PID ở `PID_REUSE_EXPLANATION.md` |
| 7 truy vấn ngữ cảnh | Có (`CONTEXT_QUERY_GUIDE.md`) | Chưa đọc kỹ |
| 8 hợp đồng DL | Có nhưng là bản thiết kế (xem 2.4) | |
| 9 adapter THEIA/ATLASv2 | Có (5 file `.py`) | Chưa đọc kỹ |
| 10 báo cáo khôi phục | Có (11 file, gồm `pipeline.md`, `MENU.md`, `field_mapping`, `parent_child_*`) | Đã thấy đủ tên file |

## 2. Điểm cần lưu ý
1. **Cầu nối `source_id` → eCAR gốc có nhưng gián tiếp, và không có UUID.** `source_id` trong file điểm khớp `sources[*].source_id` của `model_input_manifest.json` (106/106), cho đường dẫn, host, ngày. Tên file mask là một băm khác (`artifact` trong `entries` của `split_manifest.json`). Muốn UUID phải đọc raw eCAR theo `source_line` (ổ `E:\host-*` của ta có cùng tên file; chưa thử).
2. **Mã mask trong README sai.** README nói 0/1/2 = TRAIN/VAL/TEST; thực tế 1 = TRAIN, 2 = VAL, 3 = TEST, 0 = không dùng (đã đếm khớp số lượng).
3. **Bảng tiến trình là ảnh chụp trạng thái tracker, chưa đầy đủ và không có phiên bản theo thời gian.** ~11% dòng không có `parent_uuid`, `created_t`, `command_line` (tiến trình chỉ thấy là actor); tracker giới hạn 10,000 tiến trình/host nên có đẩy bớt (`evicted_count` trung bình ~8,000/host-ngày). Dùng như bảng tĩnh để ghép mọi sự kiện sẽ nhìn thấy dữ liệu về sau (`last_seen_t` lớn hơn thời điểm sự kiện) → không nhân quả. Dùng nhân quả phải phát lại log qua tracker như STEP 41.
4. **"Hợp đồng DL" là bản thiết kế, chưa được cài đặt hay kiểm chứng.** Nó liệt kê giá trị như `app_family` ∈ {system, powershell, cmd, browser, office, native, unknown}, `proto` ∈ {tcp, udp, file, ipc, reg, none}, `resp_port_class` ∈ {…, LOCAL_IPC, SYSTEM_INTERNAL}: **không khớp từ điển thật** của bản B (61/4/11/10) và không khớp fixture đi kèm (cardinalities 141/4/11/10). Ngưỡng BiLSTM 0.245 là của Run 12 IL ATLASv2 (xem STEP 45). Fixture chỉ có 3 chuỗi viết tay (`net_c2_01…`). Không có dữ liệu/shards DL chuỗi sự kiện host nào được dựng. Mục 8 mới trả lời một phần (đơn vị cửa sổ 15 phút/host, tối đa 512, 4 cột + `delta_t`, nhãn cửa sổ OR); phần "ánh xạ sự kiện FILE/REGISTRY/MODULE sang 4 trường" chưa có.
5. **Quần thể đánh giá là tập con có chọn, không phải toàn corpus.** `strategy = contextual_option_b`, chia 75/10/15 theo sự kiện; chỉ 8.33M trên 447.6M dòng được dùng; tỉ lệ dương TEST 40,310/1,249,689 = 3.2% (cao hơn nhiều so với tự nhiên ~0.03% ở flow). F1 0.9963 là mức sự kiện, chia theo sự kiện (rò rỉ cùng tiến trình), trên tập đã làm giàu dương → không so được với F1 cửa sổ của DL.
6. Lệch nhỏ: README mask nói 106 index json, thực tế 4,696; file nhãn nguồn `*.labels.gz` (~950 MB) và `ground_truth_corrected_all_evts.json.gz` không kèm (nhãn chỉ có ở cột `label` của file điểm). Mô hình `seed 1`, split `seed 2` (khớp tên thư mục seed02).

## 3. Kết luận
Gói **đủ cho phần kiểm chứng và khớp dữ liệu (mục 1–7, 9, 10)**; thiếu: UUID sự kiện (phải tự tra raw), bảng tiến trình theo thời gian, ánh xạ sự kiện host sang 4 trường DL, và dữ liệu DL chuỗi sự kiện host. Chưa đủ để chuyển DL sang chuỗi sự kiện host mà không phải tự thiết kế ánh xạ.

## 4. Bổ sung 2026-11-05: đọc adapter và báo cáo khôi phục (đọc phần đầu, chưa kiểm từng dòng mã)
- **Báo cáo 26/10 của Nguyễn nói DL giữ nguyên đơn vị mẫu hiện tại** ("Host ML dự đoán event; DL giữ sample/chunk hiện tại; provenance chỉ truy xuất context, không làm detector graph mới", `parent_child_object_context_followup_2026-10-26.md`). Điều này **khác** tài liệu testbed 29/10 (DL dùng chuỗi sự kiện host, không L3/L4) và khác "hợp đồng" trong gói 04/11. Ba tài liệu của cùng một nhóm chưa thống nhất; cần Nguyễn chốt phiên bản nào là hiện hành trước khi chuyển DL sang chuỗi sự kiện host.
- `optc_theia_atlasv2_field_mapping_2026-10-24.md`: đếm BiLSTM `06d` có **4 nguồn trực tiếp → 5 kênh** (`app_family, image_dir_class, proto, resp_port_class, delta_t_log1p`) = đúng bản B của ta; nêu rõ dataset mới không cần trùng tên cột, adapter phải tái tạo đúng ý nghĩa; field thiếu mã hóa missing không có nghĩa cho cùng tín hiệu.
- `parent_context_implementation_review_v4_2026-10-26.md`: 108 unit test đạt, các probe nhân quả/khôi phục đạt, nhưng **chưa chạy full preprocess/training và không kết luận F1 tăng**; đề xuất pilot giới hạn host/ngày dùng mask seed02.
- Adapter: `theia_adapter.py` gán nhãn bằng danh sách IOC cố định (IP, tên tệp; `firefox` nằm trong `malicious_binaries`), `cbc_adapter.py` dùng `LabelRefiner` (IP/cổng C2 + mốc thời gian): **khác nhãn REAPr của ta**; không ghép số liệu hai bên khi chưa thống nhất nhãn.
