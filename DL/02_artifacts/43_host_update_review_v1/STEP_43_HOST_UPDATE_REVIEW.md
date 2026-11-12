# STEP 43 — Đọc bản cập nhật `KLTN-main.zip` (file ngày 2026-11-04) của nhánh Host

Ngày: 2026-11-04. Chỉ đọc (giải nén vào thư mục tạm, không chạy mã của Nguyễn). So với bản đã đọc ngày 30/10 bằng băm nội dung.

## 1. Khác gì so với bản 30/10
- Zip nhỏ hơn: không còn `DL/`, `Openstack/`, các báo cáo `ML/analyst/*.md` (parent_child_*, field_mapping...), `ML/MENU.md`, mã RF/XGBoost/GraphSAGE/audit (113 file bị bỏ). Chỉ còn `ML/code` (tinh gọn), `ML/analyst` (6 file), `docs/` (5 file), `AGENTS.md`.
- **Mã lõi không đổi**: 41 file giống hệt (gồm `process_context_tracker.py`, `ecar_tokenizer.py`, `run_parent_context_seed02.py`, `host_training_runtime.py`). Đổi: `ML/code/README.md` (3.4 KB → 21.9 KB), hai file test nhỏ và một cấu hình ổ đĩa.
- **Thêm**: `docs/Framework_Selection_Testbed.md` (thiết kế testbed 29/10) và bốn file mẫu `ML/analyst/{command_line_sample.json, sample_ecar.json, sample_ecarbro.json, sample_bro.csv}`.
- Thư mục `output/` (model, metrics, shards) **không có trong zip**: các con số dưới đây là lời khai của README, tôi không kiểm được.

## 2. Kết quả Host mới (theo README)
LightGBM + ngữ cảnh tiến trình cha + tương tác đến (PROCESS OPEN, THREAD REMOTE_CREATE), TEST 1,249,689 sự kiện: F1 **0.9963** (precision 0.9973, recall 0.9954; TP 40,123 / FP 109 / FN 187), so với baseline cùng split F1 0.9533 (FN 3,189). Ngưỡng 0.87427 chọn trên VAL, TEST tính một lần; vocab fit chỉ trên TRAIN (20,412 token).
Hạn chế phải nêu khi dùng:
- Chia **theo sự kiện**, ngẫu nhiên phân tầng theo (file nguồn × nhãn) 75/10/15, không theo tiến trình/máy: các sự kiện của cùng một tiến trình độc nằm ở cả TRAIN và TEST (cùng loại rò rỉ có chủ ý như chia trộn theo cửa sổ của ta). Điểm đo nhận ra mẫu đã thấy, không phải phát hiện chiến dịch mới.
- Nhãn OpTC lan theo cây tiến trình (A New Hope), nên ngữ cảnh cha–con giúp học quy ước nhãn; F1 tăng không chứng minh nhận ra hành vi nguy hiểm thật (chính báo cáo 26/10 của Nguyễn nói vậy).
- Đơn vị là sự kiện host; **không so trực tiếp** với F1 theo chunk flow của DL (0.988).
- TEST đã được xem ở các lượt trước (README baseline ghi exploratory).

## 3. Thiết kế testbed (docs/Framework_Selection_Testbed.md): điểm ảnh hưởng nhánh Network DL
- Mục "Thiết kế đích theo yêu cầu người dùng": **cả LightGBM và BiLSTM dùng host telemetry, không dùng L3/L4; loại Zeek, conn.log và process–flow correlator khỏi stack**. Tài liệu nêu rõ "hợp đồng model mới phải nói rõ DL vẫn là flow sequence hay chuyển sang host event sequence" và rằng bundle BiLSTM hiện tại (có `proto`, `resp_port_class`) chưa đáp ứng; nếu chưa thì DL "unsupported", không điền 0/UNK.
- Hệ quả: nhánh Network DL của ta (chuỗi flow, `proto`, `resp_port_class`, `delta_t`) **mâu thuẫn** với thiết kế testbed này. Cần quyết định với thầy/Nguyễn trước khi chốt "đầu vào mở rộng".
- Ghi chú khác: ATLASv2 là Windows 7 và nguồn Carbon Black; THEIA CSV cục bộ không chứng minh tương thích schema BiLSTM; adapter Linux (auditd) không tương đương 1:1 với eCAR; giữ context chỉ từ bằng chứng thời điểm trước target.

## 4. Liên hệ với STEP 40–42
Bằng chứng của ta (flow ATLASv2/THEIA của `firefox` không tách được; tín hiệu nằm ở lịch sử tiến trình, tiến trình con, kết nối tới nút gốc) ủng hộ việc đưa ngữ cảnh tiến trình vào đầu vào, nhưng **không tự quyết** DL nên là chuỗi flow hay chuỗi sự kiện host.
