# KLTN Deployment Images & Diagrams

Toàn bộ tài liệu chi tiết về kiến trúc triển khai, sơ đồ hệ thống và đối chiếu 14 khối chức năng đã được hợp nhất vào tài liệu chính:

👉 **[Xem tài liệu chi tiết tại Openstack/KLTN/README.md](../README.md)**

Thư mục này chỉ lưu trữ các tệp đồ họa và mã nguồn kết xuất sơ đồ:
- `KLTN-deployment-status.png`: Sơ đồ hiện trạng triển khai KLTN (độ phân giải cao).
- `KLTN-deployment-status.svg`: Bản vẽ vector có thể phóng to / chỉnh sửa.
- `render.py`: Script Python kết xuất sơ đồ bằng Pillow.
- `General_Architecture.png`: Sơ đồ kiến trúc tổng quát của hệ thống APT Detection.

`KLTN-deployment-status.*` là snapshot triển khai ngày 30/10/2026, không phải
bằng chứng framework source ngày 03/11/2026 đã được apply lại lên OpenStack.
Trạng thái model-gated hiện tại và các activation blocker nằm trong README chính.
Nhãn mô hình trong snapshot đã được hiệu chỉnh ngày 04/11/2026 theo phạm vi hai
nhánh LightGBM và BiLSTM; KLTN không có nhánh Provenance/GraphSAGE.
