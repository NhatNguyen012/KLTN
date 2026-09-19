# Điều tra F1 và Chẩn đoán cho Host ML (XGBoost, Random Forest, LightGBM)

Các notebook `host_xgb_shards.ipynb`, `host_rf_shards.ipynb` và `host_lgbm_shards.ipynb`
đều đã được bật diagnostics mặc định. Dùng input package có vocabulary tương ứng;
không thay riêng vocab trong package. Diagnostics được nhúng trực tiếp trong notebook,
không cần upload thêm file Python lên Kaggle.

## Chạy

### Kaggle Python 3.10 / SciPy cũ

Reader trong input package cũ dùng `hashlib.file_digest` (Python 3.11+).
Notebook mới thay binding SHA256 của reader trong bộ nhớ trên Python 3.10 bằng
hash streaming tương đương, bao gồm checksum assets/shards; không sửa file input.

Setup kiểm tra phiên bản trước khi import NumPy/SciPy/XGBoost. Nếu Kaggle có
SciPy cũ hoặc thư viện không tương thích, bật Internet và chạy trong cell riêng:

```python
%pip install numpy==1.26.4 scipy==1.15.3 scikit-learn==1.6.1 joblib==1.5.1 threadpoolctl==3.6.0 lightgbm==4.6.0 xgboost==3.0.5
```

Sau đó **restart kernel/session**, rồi Run All. Không tiếp tục dùng các module
binary đã import trước khi nâng cấp. Có thể xóa/comment cell cài đặt sau khi
môi trường đã sẵn sàng. Nếu Internet bị tắt, cần wheel tương ứng được đính kèm
hoặc chọn image Kaggle có thư viện phù hợp. Không bỏ qua cảnh báo NumPy/SciPy.
NumPy 1.26.4 được chọn cho image cũ để tránh nâng sang NumPy 2 không cần thiết;
môi trường EC2 đã pin NumPy 2.2.6 trong requirements cũng được preflight chấp nhận.

Run All như trước. Các biến ở cuối setup cell:

| Biến | Mặc định | Ý nghĩa |
| --- | ---: | --- |
| `DIAGNOSTICS_ENABLED` | True | Thu báo cáo chẩn đoán |
| `DIAGNOSTIC_NEGATIVE_ROWS` | 10000 | Số negative tối đa trong mỗi probe |
| `DIAGNOSTIC_POSITIVE_ROWS` | 1000 | Số positive tối đa trong mỗi probe |
| `DIAGNOSTIC_ERROR_EXAMPLES` | 100 | Tối đa 100 FP và 100 FN mỗi split |
| `DIAGNOSTIC_MAX_NNZ` | 1000000 | Giới hạn tổng feature entries trong probe/examples của một collector |
| `LEARNING_CURVE_EVERY` | 25 | Đánh giá các mốc 1, 25, 50, … và mốc cuối |

Probe lấy mẫu ngẫu nhiên đều riêng từng lớp, seed 17, giữ cố định giữa các mốc
cây. Không lấy các shard đầu làm đại diện cả corpus. Mẫu validation được thu
ngay trong full evaluation; không đọc lại toàn bộ validation hoặc test. Mẫu TRAIN
được lấy từ các part của mẫu đã thực sự dùng fit, không quét TRAIN gốc lần nữa.

Runtime đã đổi hash: dùng OUTPUT_ROOT/SAMPLE_DIR mới nếu còn checkpoint từ phiên
bản notebook trước. Runtime từ chối trộn state cũ; không xóa hay sửa tay các hash.
Với phiên bản mới này, metrics và collector được ghi chung vào một NPZ checkpoint,
nên resume không đếm lặp/bỏ sót các shard đã publish.

## File kết quả

Trong `OUTPUT/diagnostics/` (mặc định Nguyen:
`/kaggle/working/xgb-kaggle/diagnostics/`):

- `learning_curve.json`, `.csv`: logloss, average precision, ROC AUC và F1 của
  từng prefix cây trên TRAIN/validation probe. Kèm model hash/config và input/
  sample identity. Trọng số theo lớp phục hồi tỷ lệ nhãn của split gốc.
- `learning_curve.png`: biểu đồ logloss/AP nếu có matplotlib. JSON/CSV luôn được
  xuất; nếu môi trường thiếu matplotlib, có thể cài vào đúng kernel rồi chạy lại
  evaluation cell để dựng biểu đồ từ model/checkpoint đã hoàn tất.
- `validation_threshold_curve.npz`: precision/recall/F1 và TP/FP/FN tại toàn bộ
  ngưỡng lưới 100.000 bins của **full validation**, không phải probe. Đây vẫn là
  lưới histogram, không phải tìm kiếm mọi score float khác nhau.
- `val_errors.json`, `test_errors.json`: positive có score thấp nhất và negative
  có score cao nhất bị phân loại sai ở threshold đã chọn. Mỗi ví dụ có label,
  score, threshold, feature columns/tokens, host/day, shard, `source_id`,
  `source_line` (số dòng nguồn 1-based). Tra nguồn qua `manifest.sources`.
- `val_diagnostics.json`, `test_diagnostics.json`: số dòng theo nhãn, hàng rỗng,
  số hàng probe. Test có tổng `[tp, fp, fn, tn]` theo host và theo ngày trên toàn
  split. Validation không có thống kê nhóm đầy đủ vì threshold chỉ biết sau
  lượt quét; file ghi rõ phạm vi này.
- `train-probe.json`: mẫu cố định dùng lại cho learning curve. Trường source_line
  trong file nội bộ này là offset 0-based trong shard gốc (ghi rõ line_identity),
  không được dùng như số dòng raw trong các báo cáo FP/FN.

Learning curve và ví dụ lỗi validation được ghi **trước lượt full test**, để
không phải đợi full test kết thúc mới đọc được chẩn đoán. Test diagnostics cũng
có trong checkpoint nếu phiên bị ngắt; chạy tiếp để xuất báo cáo hoàn chỉnh.

## Đọc kết quả

| Dấu hiệu | Giả thuyết cần kiểm tra tiếp |
| --- | --- |
| TRAIN tiếp tục tốt lên, validation AP giảm | Có thể overfit; thử regularization/số cây trên validation |
| Cả hai AP vẫn tăng rõ ở mốc cuối | Có thể chưa đủ rounds; thử tăng trong thí nghiệm riêng |
| AP ít đổi nhưng F1 đổi mạnh theo threshold | Nhạy với ngưỡng; xem full-validation threshold curve |
| FN tập trung ở một host/ngày | Xem các event, token và độ phủ TRAIN của nhóm đó |
| FP score rất cao ở benign hiếm | Kiểm tra negative sampling có giữ các kiểu benign tương tự |
| Có nhiều hàng rỗng ở một lớp | Kiểm tra biểu diễn/vocab/input; không quy ngay cho model |

Đây là gợi ý điều tra, không phải bộ suy luận tự động xác định nguyên nhân.
Ví dụ lỗi được chọn theo score cực đoan, **không đại diện phân phối toàn bộ lỗi**.
Probe 10.000 negatives có thể không chứa false positive cực hiếm; AP/F1 trên
probe vì vậy có thể lạc quan và dao động. Dùng full validation để quyết định,
không dùng probe làm bằng chứng duy nhất.

Logloss dùng score của model đã class-weight/undersampling, nên có thể phản ánh
calibration lệch chứ không chỉ khả năng phân biệt. F1 trên mọi mốc cây dùng cùng
threshold của model cuối; ưu tiên AP/logloss khi đọc tiến trình học. Phục hồi tỷ
lệ lớp bằng trọng số không khôi phục những kiểu negative đã bị sampling bỏ mất.

Đường học này là **đánh giá lại các prefix của ensemble đã hoàn tất**, sử dụng
[XGBoost iteration_range](https://xgboost.readthedocs.io/en/latest/prediction.html).
Không train lại, không early stopping, không tự đổi model hay hyperparameter.
Không dùng test trong learning curve hoặc chọn threshold; sau khi dùng test
để sửa thiết kế, cần held-out mới cho kết luận cuối cùng.

## Kiểm thử / regenerate

```bash
python code/kaggle/refresh_host_notebooks.py --profile kaggle --models xgb
python code/test_xgb_diagnostics.py
python code/test_host_training_runtime.py
```

Tests dùng fixture nhỏ: full-test group totals, provenance, limits, checkpoint
interruption/resume, config mismatch, prefix curves, full-validation threshold
grid và thực thi code cells của notebook. Chưa benchmark overhead trên corpus
thật hoặc GPU Kaggle. Bộ thay đổi này chỉ regenerate notebook XGB.
