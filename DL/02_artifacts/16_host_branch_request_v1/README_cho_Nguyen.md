# Yêu cầu train lại nhánh Host theo split host-disjoint (để ghép với nhánh Network)

Gửi: Nguyễn Nhật Nguyễn. Từ: Võ Ngọc Hoàng Lâm. Ngày: 2026-10-07.

## 1. Mục tiêu trong 3 câu
1. Để ghép (fusion) nhánh Host với nhánh Network, hai nhánh phải **dùng cùng một cách chia host** thành train/val/test.
2. Hiện hai bạn chia khác nhau: Network chia **theo hostname** (host nào đã vào TRAIN thì không xuất hiện ở TEST); Host chia **theo event** (random xáo trộn) hoặc **theo thời gian** (walk-forward). Vì vậy điểm của Host trên host của TEST-Network là điểm "đã thấy", không dùng được.
3. Nên Nguyễn **train lại các model host trên split theo hostname** của Lâm (file `host_split_seed1.csv`), rồi **xuất điểm dự đoán từng event** cho một danh sách cửa sổ đã chọn (`eval_windows_seed1.csv`).

Không cần đổi mô hình, siêu tham số, đặc trưng hay cách gán nhãn. Chỉ đổi **cách chia tập**.

## 2. Hình dung nhanh: khác gì so với trước

```text
TRƯỚC (Host, random split)                  BÂY GIỜ (theo hostname)
  mọi event của mọi host                      620 host
       │ xáo trộn event                          │ chia host (file host_split_seed1.csv)
       ▼                                         ▼
 TRAIN 75% │ VAL 10% │ TEST 15%          TRAIN 434 host │ VAL 93 host │ TEST 93 host
 (cùng host có ở cả 3 tập)               (mỗi host chỉ ở đúng 1 tập)
```

| Tập | Số host | Trong đó host bị tấn công | SC1 / SC2 / SC3 |
|---|---:|---:|---|
| TRAIN | 434 | 20 | 12 / 7 / 1 |
| VAL | 93 | 5 | 3 / 2 / 0 |
| TEST | 93 | 4 | 2 / 1 / 1 |

(Có 5 host chỉ có log host và 123 host chỉ có log mạng không nằm trong split này. Chỉ 78 host VAL và 69 host TEST có file log host cho ngày 23–25/9 trên ổ E:.)

## 3. Các file trong gói
| File | Nội dung |
|---|---|
| `host_split_seed1.csv` | Mỗi dòng một host: `hostname, split (train/val/test), scenario, is_attacked_host, host_group` |
| `eval_windows_seed1.csv` | 1,103 cửa sổ 15 phút cần chấm điểm: `split, hostname, day, window_start_utc, window_start_edt, window_start_epoch_utc, kind` |
| `output_template_event_predictions.csv` | Mẫu file kết quả cần nộp |
| `check_submission.py` | Script kiểm tra file kết quả trước khi gửi |

## 4. Các bước cần làm

**Bước 1. Gán event vào tập theo hostname.** Với mỗi event, lấy `hostname` (viết thường, bỏ đuôi `.systemia.com`) rồi tra `host_split_seed1.csv`. **Tuyệt đối không xáo trộn event giữa các host.**

**Bước 2. Dựng lại tập TRAIN/VAL bằng đúng cách lấy mẫu cũ, nhưng chỉ trong host của tập đó.**
- Benign: lấy mẫu theo cửa sổ 30 phút ở các ngày benign (như trước).
- Malicious: lấy toàn bộ cửa sổ bị tấn công (như trước).
- Giữ tỉ lệ benign:malicious khoảng 30:1 như trước.
- Làm riêng cho TRAIN (host TRAIN) và VAL (host VAL). Chưa động đến TEST.

**Bước 3. Dựng `vocab.json` chỉ từ TRAIN** (host TRAIN). Không dùng VAL/TEST để tạo từ điển token. Token chưa có trong TRAIN thì bỏ qua hoặc gán token lạ như cách bạn đang làm.

**Bước 4. Train các model** (LightGBM, XGBoost, Random Forest, rồi GraphSAGE 2-hop nếu muốn) với cùng siêu tham số như báo cáo trước.
- Chọn checkpoint/ngưỡng trên **VAL** (nếu cần early stopping hoặc chọn ngưỡng tối ưu F1, chỉ dùng VAL).
- Đồ thị GraphSAGE chỉ dựng từ host TRAIN.

**Bước 5. Chấm TEST đúng một lần**, theo cách lấy mẫu cũ trên host TEST. Ghi lại: số host/event mỗi tập, ngưỡng, Precision, Recall, F1, FPR, PR-AUC, ROC-AUC và confusion matrix cho từng model. Kết quả sẽ **thấp hơn** con số 0.95 trước đây; đó là bình thường (trước đó event cùng host có ở cả TRAIN và TEST), không phải lỗi.

**Bước 6. Xuất điểm từng event cho các cửa sổ cần ghép.** Với mỗi dòng trong `eval_windows_seed1.csv` (host + cửa sổ 15 phút UTC), chấm điểm **mọi event** có `timestamp` rơi vào cửa sổ đó, bằng model đã train ở Bước 4 và ngưỡng chọn ở VAL. Ghi ra CSV theo mẫu `output_template_event_predictions.csv`:

| Cột | Ý nghĩa |
|---|---|
| `hostname` | Tên host |
| `timestamp` | Thời điểm event, **giữ nguyên chuỗi gốc có múi giờ** (ví dụ `2019-09-25T10:45:12.345-04:00`) |
| `split` | `val` hoặc `test` (đúng theo `host_split_seed1.csv`) |
| `model` | `lightgbm`, `xgboost`, `rf`, hoặc `graphsage_lightgbm`... (mỗi model một dòng riêng, hoặc mỗi model một file) |
| `prob` | **Xác suất** malicious (không phải chỉ 0/1) |
| `pred` | 0/1 theo ngưỡng chọn trên VAL |
| `label` | Nhãn thật của event (nhãn provenance của bạn) |

Khối lượng ước tính: ~1,103 cửa sổ, tổng khoảng 48 triệu event (VAL ~26 triệu, TEST ~22 triệu). Nếu quá nặng, báo Lâm; phương án giảm là chỉ chấm 221 cửa sổ có event độc hại (`kind = co_event_doc_hai`, ~10 triệu event) và 1 cửa sổ benign mỗi host-ngày.

**Bước 7. Kiểm tra và gửi.**
```bash
python check_submission.py --pred event_predictions.csv
```
Script phải in `KẾT QUẢ: ĐẠT`. Gửi kèm: file dự đoán, file báo cáo số liệu ở Bước 5, và mô tả ngắn các thay đổi nếu có (nếu bạn buộc phải đổi gì khác).

## 5. Những điều không được làm
- Không xáo trộn event giữa các host; không để một host xuất hiện ở hai tập.
- Không fit vocab, scaler hay bất kỳ thống kê nào trên VAL/TEST.
- Không chọn ngưỡng, siêu tham số hay mô hình dựa trên TEST. TEST chỉ chạy một lần.
- Không đổi nhãn.

## 6. Tuỳ chọn (làm sau nếu có thời gian)
Lặp lại với `seed_2`, `seed_3` (Lâm sẽ gửi `host_split_seed2.csv`, `host_split_seed3.csv`) để xem kết quả có ổn định không.

## 7. Dùng điểm này để làm gì
Lâm sẽ gộp điểm từng event thành điểm theo `(hostname, cửa sổ 15 phút)` (ví dụ lấy xác suất lớn nhất), ghép với điểm của nhánh Network trên cùng cửa sổ, rồi thử OR / trung bình / stacking (ngưỡng và trọng số chọn trên VAL, TEST chỉ chạy một lần). Mục tiêu là kiểm tra fusion có giúp bắt các cuộc tấn công mà từng nhánh riêng bỏ sót hay không, đặc biệt SC3.
