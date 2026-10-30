# Các sửa đổi README đề xuất — chưa áp dụng

Ngày 2026-10-30. Chỉ là tài liệu review, **không sửa README thật hoặc artifact baseline**. Vị trí dòng theo snapshot đọc trong lượt này; nếu README thay đổi, tìm lại bằng trích đoạn. Số liệu bên dưới đọc từ artifacts/source hiện có, không phải kết quả chạy lại model. Các mô tả lịch sử vẫn có thể giữ trong mục riêng nếu ghi rõ version/model/split.

## 1. Số token vocabulary

- Vị trí: `ML/code/README.md:68`, cây thư mục, `vocab.json # ... 20,412 tokens nhị phân`.
- Bằng chứng: `ML/code/output/host_ml_parent_incoming_seed02/vocab.json` là token→index, 10.317 entries, IDs0..10316; SHA-256 `2e4a6239dc94f46cc05f1aff0b955e28fc271a4d5384bfcc20921ab7fdf4c913`, khớp metrics checkpoint. Không dùng số token của bản cũ để mô tả file hiện tại.
- Câu thay thế: **“vocab.json: từ điển 10.317 token→column index của artifact hiện tại; chỉ số liên tục 0–10.316. Định danh bằng SHA-256 trong metadata.”** Bỏ kích thước511KB khỏi câu nếu chưa đo lại kích thước file; không suy ra bytes từ số token.

## 2. Threshold và định danh BiLSTM subsetB

- Vị trí: `README.md:220` (T=1.0 chung), `README.md:224` (hàng BiLSTM, threshold1.000); `DL/README.md:40` (“đủ feature”, “ngưỡng=1.0”).
- Bằng chứng: `DL/05_models/bilstm_v2_subsetB/{config,threshold,metrics}.json`; checkpoint hash `1304901f46c4a559b47f1e6892fe8f558f92f19e0b77755add6dcb440755da77`. Config4 categorical, 0 numeric; seed42. Threshold **0.99560546875**, best_epoch2. TEST AP0.9888476309163509, ROC-AUC0.9996898913092129, F1=0.9876543209876543; TP80/FN2/FP0/TN34331. Chưa tái inference.
- Câu thay thế ở phần mô tả: **“BiLSTM subsetB (seed42) dùng app_family, proto, resp_port_class, image_dir_class và delta_t_log1p. Ngưỡng xác suất chọn trên VAL là 0.99560546875 theo threshold.json; TEST có82 positive chunks. Kết quả là báo cáo artifact, chưa phải bằng chứng tổng quát hóa sang host/dataset mới.”**
- Hàng BiLSTM đề xuất: threshold0.99560546875, precision1.0000, recall0.9756, F1=0.9877, AP=0.98885, ROC-AUC=0.99969, TP/FP/FN=80/0/2. Ghi rõ AP convention thay vì trộn với binned PR-AUC ML.
- Không thay threshold Mixed-Type bằng threshold BiLSTM. Tách từng model/bundle, đối chiếu metrics riêng trước sửa hàng Mixed-Type. Nếu giữ báo cáo full-feature cũ thì đánh dấu lịch sử, không mô tả là subsetB.
- Đồng bộ phần active features `DL/README.md:34–35` với scope subsetB hoặc gắn nhãn rõ là full-feature pipeline lịch sử. Các shard có cột không đồng nghĩa model subsetB sử dụng cột đó.

## 3. Undersampling, class weight và tổng TRAIN

- Vị trí: `README.md:112` (hàng TRAIN), `README.md:115` (tổng cộng), `README.md:118`, `README.md:123`; `ML/code/README.md:142` (hàng TRAIN), `ML/code/README.md:147` (undersampling30:1).
- Bằng chứng: vocab_metadata.split_counts TRAIN benign6.046.892 + malicious201.551 = **6.248.443**; lgbm_metrics.train_sampling rows6.248.110, positives201.551 → sampled negatives6.046.559, giảm333 negatives. Runtime sample_plan Bernoulli; fit_sample_model weight từ sampled counts. Receipt weight **30.000143884178197**, không phải full ratio30.001796071465783. Membership cụ thể333 mẫu chưa tái dựng.
- Câu thay thế: **“Full TRAIN frozen split gồm6.248.443 events (6.046.892 benign, 201.551 malicious). Theo training receipt, Bernoulli negative sampling giữ6.046.559 negatives và toàn bộ201.551 positives, tổng6.248.110; giảm333 negatives. Khi bật class balancing, scale_pos_weight tính trên mẫu sau sampling:6.046.559/201.551=30.000143884178197.”**
- Bảng split dùng full counts: sửa TRAIN total thành6.248.443, tổng toàn split thành**8.331.257** (=8.062.523 benign +268.734 malicious). Bảng training sample riêng dùng6.248.110, không trộn số sau sampling vào split table.
- Phần params có thể ghi≈30.00 cho dễ đọc nhưng kèm giá trị chính xác/provenance, không gọi là đúng tỷ lệ full split. Đây là undersampling rất nhẹ, không chứng minh đã cân bằng class counts.

## 4. “Gần như hoàn hảo” và “tách biệt hoàn hảo”

| Vị trí và câu cần sửa | Câu thay thế đề xuất |
|---|---|
| `README.md:140`: “F1-Score đột phá… gần như hoàn hảo” | “LightGBM đạt F1=0.9963 trên TEST của frozen random-event split seed02. Kết quả này chưa đánh giá host-disjoint, time-disjoint hoặc chuyển domain.” |
| `README.md:162`: PR-AUC0.9993 “chứng minh khả năng tách biệt hoàn hảo” | “Artifact báo PR-AUC binned≈0.9993 trên split hiện tại, với187 FN và109 FP; không phải tách biệt hoàn hảo. Cần đánh giá độc lập theo host/thời gian/engagement và báo bất định.” |
| `README.md:158`: “giải quyết triệt để điểm mù lớn nhất” | “Parent/incoming context gắn với cải thiện chỉ số trên thí nghiệm hiện tại; chưa chứng minh giải quyết mọi trường hợp process injection hoặc thiếu telemetry.” |
| `README.md:142`: “loại bỏ gần như triệt để… alert fatigue… SOC” | “Trên TEST hiện tại FPR≈0.0090% và109 FP. Tác động tới alert fatigue trong SOC chưa được đo; phụ thuộc event volume, aggregation và prior triển khai.” |
| `ML/code/README.md:146`: “Chống rò rỉ tuyệt đối (No Leakage)” | “Vocabulary chỉ fit TRAIN, không dùng VAL/TEST để chọn token. Đây là biện pháp chống vocabulary leakage; random-event split không loại trừ phụ thuộc process/host/time hoặc attack-chain overlap.” |
| `ML/code/README.md:219`: tests đảm bảo “hoạt động hoàn hảo” | “Các regression tests kiểm tra những hành vi nằm trong phạm vi assertions; không chứng minh tính đúng tuyệt đối hoặc chất lượng trên dữ liệu ngoài kiểm thử.” |

Thêm ngay sau mô tả split ở `README.md:108` và `ML/code/README.md:138`: **“Split là stratified random theo event, không host-disjoint/time-disjoint; các event cùng host/process có thể ở nhiều partitions. Chỉ số không tự chứng minh phát hiện host mới, campaign mới hoặc tương lai.”** Không thay đổi frozen split để sửa hạn chế báo cáo.

## 5. Các suy luận mạnh về subsetB cần thu hẹp

- Vị trí `README.md:242`: từ luật powershell/temp đạt điểm cao suy ra “loại bỏ… không làm giảm độ chính xác… giúp loại bỏ nhiễu thống kê mạng”.
- Câu thay thế: **“Các luật đơn giản đạt điểm cao trên TEST lịch sử, cho thấy benchmark có shortcut. Cần đối chiếu cùng sample IDs và làm ablation có kiểm soát trước khi kết luận tác động của bỏ Bro metrics. Chưa có bằng chứng từ số liệu này rằng việc bỏ metrics cải thiện tổng quát hóa hoặc loại bỏ nhiễu.”**
- Không chuyển các mẫu TEST firefox1.800 flows/REJ vào replay TRAIN. Chỉ giữ làm diagnostic held-out, tìm mẫu TRAIN tương tự theo protocol.

## Trạng thái áp dụng

Tất cả mục trên là **PROPOSED**. README root/ML/DL giữ nguyên; baseline vocab/models/metrics/split giữ nguyên. Chỉ triển khai sửa README sau một yêu cầu riêng. Không dùng việc viết câu đề xuất như bằng chứng đã chạy inference, audit corpus hoặc tests.
