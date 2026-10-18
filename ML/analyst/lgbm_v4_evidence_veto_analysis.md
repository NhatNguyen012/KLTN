# Kiểm định quyền phủ quyết của GraphSAGE dựa trên bằng chứng graph

Thí nghiệm này giữ nguyên LightGBM v4, GraphSAGE, graph SQLite exact-time, Host vector, split và các ngưỡng của [conditional collision](lgbm_v4_conditional_collision_kaggle_analysis.md). Nó chỉ hỏi: **trong những event high-ML collision mà conditional policy đã phủ quyết, graph có đủ bằng chứng để được phép làm vậy không?** Mã là `code/provenace_graph/model/evidence_veto_runtime.py`, notebook Kaggle là `code/kaggle/notebooks/lgbm_v4_evidence_veto.ipynb`, kết quả local riêng ở `code/output/provenace_graph/evidence_veto_v4_results/`.

## Cách kiểm định và chi phí

Runtime tái dùng kết quả conditional và cache score v4 có receipt SHA-256, xác minh hash model/graph/vocabulary/split và đối chiếu graph score với checkpoint NumPy ở từng ứng viên. Nó đọc validation trước, đánh giá năm gate định trước: có cạnh CREATE; CREATE đi vào actor gốc; CREATE và không `unresolved_relation`; CREATE đi vào actor và không `unresolved_relation`; CREATE và không `truncated`. Score veto `0,010082806...` và low-band rescue được giữ nguyên. Gate chỉ có thể **rút lại** veto high-band; middle, low và non-collision không đổi. Chọn gate cần F1 validation hơn conditional ít nhất `0,0001`, không tăng FN và giữ được ít nhất hai graph input benign khác nhau được sửa. Nếu không đạt, giữ conditional.

Chỉ có **27 event validation** và **49 event TEST** từng bị high-band veto, nên chỉ 76 ego graph cần dựng lại. Các score GraphSAGE của chúng được kiểm tra lại bằng frozen checkpoint; không suy luận lại 380.652 event. Việc đọc shard validation để tìm 27 event vẫn cần thiết nhưng không fit model. Tại ranh giới đúng bằng threshold, score cache và scorer native lệch khoảng `1e-17`; runtime coi sai khác dưới `1e-15` là hòa để tái hiện quy tắc `score >= threshold` của Kaggle. Số ứng viên validation tái lập đúng 22 FP đã sửa và 5 FN mới; TEST audit tái lập 43/6.

## Validation quyết định gì?

| Policy | TP | FP | FN | TN | F1 | Diễn giải |
|---|---:|---:|---:|---:|---:|---|
| Legacy v4 | 26.490 | 412 | 383 | 805.840 | 0,985216 | Không hỏi graph ở high ML. |
| Conditional hiện tại | 26.486 | 390 | 387 | 805.862 | 0,985544 | Sửa 22 FP, thêm 5 FN tại high band; low band cứu 1 FN. |
| Ứng viên `any_create` | 26.491 | 394 | 382 | 805.858 | 0,985565 | Cứu cả 5 FN do veto, nhưng bỏ lỡ 4 FP correction. |

`root_create` cho đúng kết quả như `any_create` trên 27 event này. Trong 22 FP mà conditional đã sửa, gate CREATE vẫn sửa 18 FP thuộc **4 graph input** và **3 source**; bốn FP còn lại quay về dự đoán dương. Các gate yêu cầu thêm `not unresolved` hoặc `not truncated` loại sạch cả 22 FP correction và chỉ đạt F1 ≈ 0,985235. Hai cờ đó quá rộng cho nhóm ứng viên này; không thể dùng chúng đơn lẻ làm tiêu chuẩn graph “đủ tin”.

Mức tăng F1 của `any_create` so với conditional chỉ **0,000021**, nhỏ hơn `0,0001` đã định trước. Vì vậy `frozen_policy.json` chọn **`conditional_unchanged`**; đây là quyết định của validation, không điều chỉnh theo TEST. Tín hiệu hữu ích là **thiếu cạnh CREATE ở actor** trùng với 5 FN do veto trên validation, nhưng đánh đổi 4 FP và số graph input độc lập ít khiến bằng chứng cải thiện tổng thể chưa rõ.

## TEST chỉ dùng để audit policy đã đóng băng

Policy được chọn giữ nguyên conditional: TP 39.728, FP 587, FN 582, TN 1.208.792, F1 0,985501. Tất cả 1.169 FP/FN và 51 prediction transition được tái xuất/reconcile vào thư mục kết quả mới. Không có GraphSAGE call mới cần thiết khi triển khai policy không đổi; 76 lần dựng graph ở đây chỉ để audit bằng chứng.

Để thấy *giới hạn của giả thuyết*, nếu áp `any_create` lên 49 ứng viên TEST trong một phép đối chứng **không được chọn**, nó sẽ cứu 6 FN, bỏ lỡ 4 FP correction, cho TP 39.734 / FP 591 / FN 576 / TN 1.208.788, F1 ≈ 0,985527. **Không được dùng con số này để đổi policy trên TEST.** Hơn nữa, chính sáu FN TEST đã giúp nêu giả thuyết thiếu lineage; đây không còn là holdout độc lập cho ý tưởng đó. Muốn khẳng định gate CREATE cải thiện thật, cần một cohort mới tách theo host/thời gian/campaign hoặc một prospective split được khóa trước.

## Diễn giải kỹ thuật

Graph có CREATE không đồng nghĩa graph đúng, và graph thiếu CREATE không đồng nghĩa event benign. Quy tắc hiện tại chỉ kiểm tra **quyền phủ quyết** của score rất thấp trong nhóm high-ML collision; nó không sửa các lỗi middle-band, không bổ sung FILE/MODULE node, không retrain và không thay graph schema. Mẫu đối chứng cho thấy sự thiếu lineage có thể làm score GraphSAGE thấp một cách không đáng tin, nhưng bằng chứng về cải thiện F1 chưa đủ lớn để tự động triển khai gate mới. Chi tiết từng event/graph input ở `validation_veto_evidence.jsonl` và `test_veto_evidence.jsonl`; mọi metric/rule ở `validation_metrics.json`, `test_metrics.json` và `frozen_policy.json`.

## Chạy nhanh trên Kaggle

Import `code/kaggle/notebooks/lgbm_v4_evidence_veto.ipynb`; gắn ba dataset chứa **đúng** các archive:

1. `code/output/host_ml_seed02/kaggle_upload/host-input.tar` (Host seed02 đã duyệt).
2. `code/output/provenace_graph/kaggle_upload_cascade_v4/provenance-cascade-bundle-v4.tar.gz` (bundle v4 exact-time).
3. `code/output/provenace_graph/kaggle_upload_evidence_veto/v4-evidence-veto-input.tar.gz` (kết quả conditional + score cache v4 được đóng gói riêng, dưới 1 MB).

Notebook ưu tiên **dataset đã giải nén** dưới `/kaggle/input` (`manifest.json` + `assets/` + `volumes/ssd` cho Host; `bundle_manifest.json` + `provenance/` cho v4 bundle; `package_manifest.json` + `previous/` + `cache/` cho input mới). Nếu không thấy layout đã giải nén, nó tìm ba archive theo đúng tên tệp, giải nén an toàn vào `/kaggle/working`, xác minh SHA-256, chạy audit và xuất `lgbm_v4_evidence_veto_results.zip`. Nó không cần LightGBM wheel/GPU vì không fit hay chấm lại 1,25 triệu event; CPU là đủ. Khi có nhiều layout hợp lệ cùng loại, notebook cố ý báo lỗi mơ hồ.
