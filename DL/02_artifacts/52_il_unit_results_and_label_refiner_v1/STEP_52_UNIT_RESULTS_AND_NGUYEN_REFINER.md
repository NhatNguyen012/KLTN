# STEP 52 — Kết quả IL đơn vị (máy, chương trình, cửa sổ) và kiểm tra LabelRefiner của Nguyễn

Ngày 2026-11-07. Nguồn: `output_kaggle/{bilstm,mixed}_il_atlas_unit_seed42.zip`; `KLTN-main.zip` (`IL/dataset_1-ATLASv2`).

## 1. F1 TEST (ngưỡng chọn trên VAL), 3 fold
| Mô hình | Fold 0 | Fold 1 | Fold 2 | TB | TB TRAIN F1 | OpTC TEST (ngưỡng gốc) |
|---|---|---|---|---|---|---|
| BiLSTM | 0.435 (10/1/25) | 0.337 (17/44/23) | 0.353 (6/1/21) | 0.375 | 0.30/0.26/0.49 | 0.981/0.981/0.981 |
| Mixed | 0.379 (11/12/24) | 0.424 (14/12/26) | 0.333 (17/58/10) | 0.379 | 0.31/0.35/0.39 | 0.988/0.988/0.994 |
Tệ hơn đơn vị cửa sổ (STEP 50: ≈ 0.51/0.56). TRAIN F1 chỉ 0.26–0.49 ⇒ mô hình không khớp được TRAIN (thiếu thông tin ở đầu vào), ROC-AUC TEST 0.76–0.83. Ngưỡng VAL vẫn dao động (BiLSTM fold 1 prob 0.19 và Mixed fold 1/2 prob 0.12–0.21 ⇒ OpTC FP 740–4,306 nếu dùng ngưỡng VAL). OpTC không bị quên. Đổi đơn vị KHÔNG cứu được vì nhãn vẫn là REAPr thô (xem mục 2).

## 2. Bạn của bạn đã xử lý firefox chưa? — Có, nhưng bên mình chưa dùng nhãn đó
- Có `code/preprocess/label_refiner.py` (LabelRefiner, 2 tầng): (1) cổng thời gian: sự kiện trước mốc tấn công đầu tiên của từng kịch bản = benign (`INITIAL_ATTACK_TIMESTAMPS`); (2) tiến trình phải nằm trong danh sách REAPr; (3) với tiến trình lưỡng dụng (firefox, winword/excel/powerpnt, explorer): flow chỉ dương nếu `remote_ip` ∈ IOC C2 (`10.193.66.115`, `192.168.223.129`) hoặc domain `ortrta.net` hoặc trùng `.seeds`; file/process-start theo danh sách IOC; (4) còn lại giữ dương. Tài liệu `analyst/preprocess.md` nêu mục tiêu "triệt tiêu 99.16% flow dương giả của Firefox".
- Mình cài lại phần netconn của luật đó trên `atlas_netconn_rows.csv` (cổng thời gian giờ UTC + IOC cho 5 tiến trình lưỡng dụng): **dương 7,761 → 51 flow**; firefox 7,696 → 10 (cổng thời gian loại 4,563, IOC loại 3,147). Khớp mô tả của bạn (>99%). 47/51 flow dương tới cổng 8080/8443/9999/8000.
- Pipeline STEP 48/51 của mình dùng `label_proc` THÔ (REAPr) nên vẫn còn 7,696 firefox "dương". Đây là lý do chính train lại vẫn không nhận ra: **không phải model/lr/đơn vị mà là nhãn khác nhau** (đã chẩn đoán ở STEP 50: firefox dương = firefox benign trên mọi đầu vào).
- Bản DL của bạn dùng nhãn tinh chỉnh (`build_network_shards.py` gọi LabelRefiner), cùng 4 category + delta_t, test chuẩn 768 mẫu chỉ 20 dương; F1 DL tốt nhất 0.7727 (Run 12 trong README), **không phải 0.9**.

## 3. "ML bạn đạt 0.9 mấy" là gì
README: LightGBM IL F1 test **0.9375**, P 100%, R 88.24% (TP 653, FN 87, FP 0) trên **79,220 sự kiện host EDR** (≈ 740 dương), nhãn theo sự kiện từ chính LabelRefiner. Khác bên mình: (a) đơn vị là sự kiện host, không phải flow/cửa sổ mạng; (b) nhãn do luật theo loại sự kiện và thực thể (tên tiến trình con, tên file, module, IOC), mà các thực thể đó rất có thể cũng là token đầu vào (`ecar_tokenizer.py`; mình chưa đối chiếu từng token ⇒ chưa kết luận có rò rỉ nhãn); (c) 87 FN vẫn còn. Nên không so trực tiếp với DL mạng.

## 4. Hạn chế của nhãn tinh chỉnh
Nhãn định nghĩa bằng IP/cổng/domain kẻ tấn công cứng và mốc giờ thủ công ⇒ với DL, cổng 8080/8443/9999/8000 (có trong `resp_port_class`) gần như là luật nhãn (47/51 dương; chỉ 29 flow âm tới các cổng đó) ⇒ điểm cao có thể phản ánh luật chứ không phải khái quát. Chỉ 51 flow/≈17 cửa sổ dương: VAL/TEST mỗi fold vài mẫu.

## 5. Việc tiếp theo (chưa chạy)
Dựng gói IL dùng nhãn tinh chỉnh (`new`) thay `label_proc`, giữ đơn vị cửa sổ hoặc chương trình, đánh giá ma trận nhầm lẫn; ghi rõ nhãn là bản tái hiện luật của Nguyễn.
