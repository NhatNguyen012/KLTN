# Chạy Host ML seed02 trên Kaggle

Bản chính là `code/output/host_ml_seed02/`, tức thí nghiệm đã được giáo viên
chấp nhận. Hướng dẫn này thay thế kế hoạch EC2/100 triệu dòng của corpus cũ.
Không cần dựng lại index, split, vocabulary hoặc shard để chạy notebook.

## Dữ liệu và cấu hình đã duyệt

- 9.048 cột sparse binary; vocabulary chỉ fit trên TRAIN benign + malicious.
- TRAIN: 6.248.443 dòng; validation: 833.125; test: 1.249.689.
- Split contextual random-event 75/10/15, seed **02**.
- Notebook profile `kaggle`, seed lấy mẫu TRAIN **1**, `NEG_PER_POS = 30`.
- RF: 500 cây; XGBoost/LightGBM: 300 rounds theo notebook đã lưu.
- `MAX_MATRIX_GIB = 4`; cả ba model đánh giá toàn bộ validation/test.
- Threshold chọn bằng validation; không chọn hyperparameter từ test.

Các con số trên thuộc input đã duyệt, không phải corpus hàng tỷ dòng trong
hướng dẫn cũ. Không dùng profile `ec2-100m` để tái hiện kết quả này.

## Các bước

1. Dùng archive có sẵn:
   `code/output/host_ml_seed02/kaggle_upload/host-input.tar`.
   Giữ nguyên manifest, assets, readers và `volumes/` khi giải nén/đưa lên Kaggle.
2. Import một trong ba notebook ở `code/kaggle/notebooks/`:
   `host_rf_shards.ipynb`, `host_xgb_shards.ipynb`, `host_lgbm_shards.ipynb`.
3. Gắn input đã giải nén. Setup tìm manifest dưới `/kaggle/input`;
   nếu có nhiều manifest, đặt `OPTC_MANIFEST` tới file chính xác trước khi chạy.
4. Giữ nguyên cấu hình đã duyệt. Đặt output và sample ngoài thư mục input.
   Cả ba notebook phải dùng cùng split, vocabulary và cấu hình lấy mẫu.
5. Run All và lưu/download file `<model>_kaggle_results.zip` ở cell cuối.
   So sánh `sample_id`, `split_sha256` và `vocabulary_sha256` trong metrics.

Runtime được nhúng trong notebook. Setup kiểm tra môi trường; hướng dẫn sửa
môi trường và đọc kết quả nằm trong [XGB_DIAGNOSTICS.md](XGB_DIAGNOSTICS.md).
Các file requirements trong `code/kaggle/` là môi trường tham chiếu, không phải
bằng chứng kết quả sẽ giống tuyệt đối giữa mọi phiên bản thư viện/phần cứng.

## Checkpoint và kết quả

Model dùng `model/latest.json` cùng model slot; evaluation dùng
`validation-state.npz` và `test-state.npz`. Chạy tiếp chỉ khi input, sample,
runtime và cấu hình tương thích. Không sửa hash để ép resume. Sau di chuyển
đường dẫn, checkpoint cũ có thể không tương thích; dùng output riêng cho lần mới.

Kết quả giáo viên đã duyệt được giữ ở
`code/output/host_ml_seed02/kaggle_ouput/` (giữ chính tả thư mục gốc).
Không ghi đè kết quả đó khi thử chạy lại. Không chạy full training trên local.

## Kiểm tra local

```bash
python3 code/preprocess/verify_model_input.py \
  --manifest code/output/host_ml_seed02/model_input/manifest.json --decode
PYTHONPATH=code/preprocess:code/others:code/kaggle:code/kaggle/scripts:code/test \
  python3 -m unittest test_notebook_exports test_package_host_shards
```

Source generator ở `code/kaggle/scripts/refresh_host_notebooks.py` hỗ trợ
`--profile kaggle`. Không cần regenerate notebook chỉ vì di chuyển input;
notebook hiện tại đã được cập nhật đường dẫn local. Giữ hash runtime đã duyệt.
