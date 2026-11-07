# KLTN Deployment Images & Diagrams

Toàn bộ tài liệu chi tiết về kiến trúc triển khai, sơ đồ hệ thống và đối chiếu 14 khối chức năng đã được hợp nhất vào tài liệu chính:

👉 **[Xem tài liệu chi tiết tại Openstack/KLTN/README.md](../README.md)**

Thư mục này chỉ lưu trữ các tệp đồ họa và mã nguồn kết xuất sơ đồ:
- `KLTN-deployment-status.png`: Sơ đồ hiện trạng triển khai KLTN (độ phân giải cao).
- `KLTN-deployment-status.svg`: Bản vẽ vector có thể phóng to / chỉnh sửa.
- `render.py`: Script Python kết xuất sơ đồ bằng Pillow.
- `General_Architecture.png`: Sơ đồ kiến trúc tổng quát của hệ thống APT Detection.

`KLTN-deployment-status.*` là snapshot kiến trúc và hiện trạng triển khai cập nhật ngày 05/11/2026:
- Phản ánh đầy đủ 14 khối chức năng của framework đã được cài đặt mã nguồn hoàn chỉnh, vượt qua 29/29 bài test unit/contract.
- Hai mô hình `host-ml-run12-v1` (LightGBM) và `network-dl-run12-v1` (BiLSTM) đã được xác nhận golden parity và đạt Windows domain validation.
- Toàn bộ hạ tầng OpenStack Nova instances và Docker containers đã được mã hóa tự động hóa bằng Terraform và Ansible, sẵn sàng deploy live on-demand.
- Hệ thống áp dụng chính sách an toàn fail-closed: khi chưa có model hoặc domain không tương thích (như Linux/THEIA), score trả về `null` theo đúng thiết kế.
