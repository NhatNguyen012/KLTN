# Kiểm tra kết quả GraphSAGE v5a chỉ thêm Event node

Nguồn: `code/output/provenace_graph/kaggle_output/provenance_event_v5a_results.zip` (SHA-256 `30e5daae5e16eca84bb0c4473fb6ee49b590f5c31a6be05d80d03750aec1ba43`). ZIP có CRC hợp lệ; `config.json`, `metrics.json` và `cache_manifest.json` cùng tham chiếu manifest SHA-256 `1781a80c82e740721016ad3dd1b68c51589ee8a9f45bcf9e204f6f195449b8f4`, khớp cache v5a tại máy. File NumPy có 71 đặc trưng nút, lớp 32→16, sáu relation và 19.569 tham số hữu hạn. Checkpoint tốt nhất là epoch 28/30, được chọn theo validation AP. Không có dấu hiệu ZIP trỏ sang cache/checkpoint khác.

## Kết quả GraphSAGE độc lập

| Mẫu | Model | TP | FP | FN | TN | Precision | Recall | F1 | AP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation, 2.000 event | v5a Event | 67 | 1 | 8 | 1.924 | 0,98529 | 0,89333 | 0,93706 | 0,97157 |
| TEST, 2.000 event | GraphSAGE cũ | 49 | 4 | 7 | 1.940 | 0,92453 | 0,87500 | 0,89908 | — |
| TEST, 2.000 event | v5a Event | 50 | 4 | 6 | 1.940 | 0,92593 | 0,89286 | 0,90909 | 0,95003 |

GraphSAGE cũ dùng ngưỡng validation `0.9666019678115845`; v5a PyTorch dùng `0.9678311944007874`. Cùng 2.000 event TEST đã được kiểm chứng bằng `(source_id, source_line)` trên hai cache. V5a tăng 0,01001 điểm F1, tức 1,00 điểm phần trăm, do giảm đúng một FN, không giảm tổng FP. Mẫu chỉ có 56 malicious TEST event nên thay đổi một event đã làm F1 biến động rõ; chưa đủ chứng cứ khẳng định v5a tốt hơn tổng quát.

Ba dự đoán TEST thay đổi khi đối chiếu checkpoint cũ và v5a:

| Event (source_id rút gọn, source_line) | Nhãn | Loại Event | Cũ → v5a | Tác động |
| --- | ---: | --- | --- | --- |
| `613e6b30a7cf:2332171` | 1 | READ FILE | FN → TP | Sửa một FN |
| `92f6a358a6c7:2772146` | 0 | CREATE PROCESS | FP → TN | Sửa một FP |
| `91f59114553f:2265939` | 0 | LOAD MODULE | TN → FP | Tạo một FP mới |

Như vậy hai lỗi cũ được sửa nhưng một lỗi mới xuất hiện; số FP ròng không đổi. Các thay đổi score chịu đồng thời tác động của Event input **và** việc huấn luyện checkpoint mới, nên không thể quy kết nhân quả cho một trường action/object cụ thể chỉ từ bảng này. V5a chỉ mã hóa loại action/object, chưa mã hóa identity/path/nội dung của FILE hay MODULE.

## Sai khác ngưỡng PyTorch và NumPy

`model_numpy.npz` được suy luận bằng NumPy float64, trong khi metrics Kaggle được tính bằng PyTorch float32. Với ngưỡng PyTorch lưu trong ZIP, NumPy cho validation TP=65/FN=10 và TEST TP=49/FN=7. Hai validation event và một TEST event có cùng graph input/số điểm NumPy `0.967831151313006`, thấp hơn ngưỡng PyTorch đúng `4,31×10⁻⁸`. TEST event biên `e0a257e863a1:1942347` (malicious WRITE FILE) là TP trong PyTorch, nhưng thành FN nếu áp nguyên ngưỡng PyTorch cho NumPy.

Chọn lại ngưỡng **chỉ trên validation score NumPy** cho cùng checkpoint, theo đúng hàm chọn F1 hiện tại, cho `0.967831151313006`. Khi áp ngưỡng này, NumPy tái hiện chính xác validation 67/1/8/1.924 và TEST 50/4/6/1.940, kể cả AP. Đây là hiệu chỉnh tính nhất quán giữa hai backend, không phải tune bằng TEST. Nếu triển khai NumPy, cần lưu ngưỡng NumPy riêng hoặc xác nhận parity theo từng event; không nên dùng thẳng ngưỡng float32 trong ZIP.

## Giới hạn và bước tiếp theo

Đây là đánh giá **GraphSAGE độc lập trên sample**, không phải full TEST của LightGBM + GraphSAGE cascade (1.249.689 event). Cache nền v5a giữ cutoff đầu giây của checkpoint graph cũ; thí nghiệm này chưa giải quyết sai khác với graph exact-microsecond dùng ở cascade v4. Chưa có FP/FN full-cascade hay thời gian inference khi route thêm. Không nên thay checkpoint GraphSAGE trong cascade hiện tại chỉ dựa trên mức tăng một TP ở sample. Bước kiểm định có giá trị là chạy một đối chứng huấn luyện cùng seed/trainer nhưng không thêm Event, sau đó đánh giá v5a và đối chứng trên cùng validation và TEST bằng cùng backend; chỉ chọn policy cascade bằng validation.
