# KLTN Deployment Images & Diagrams

Toàn bộ tài liệu chi tiết về kiến trúc triển khai, sơ đồ hệ thống và đối chiếu 14 khối chức năng đã được hợp nhất vào tài liệu chính:

👉 **[Xem tài liệu chi tiết tại Openstack/KLTN/README.md](../README.md)**

Thư mục này chỉ lưu trữ các tệp đồ họa và mã nguồn kết xuất sơ đồ:
- `General_Architecture.png`: Sơ đồ kiến trúc tổng quát của hệ thống APT Detection (thiết kế).
- `KLTN-IL3-architecture.png`: Hạ tầng IL3 **đang chạy** (14/11/2026): sensor, endpoint agent, central ingest,
  detection & fusion, SOC & response, vòng incremental learning. Vẽ lại bằng `render_il3_architecture.py` (matplotlib).
- `KLTN-deployment-status.png` / `.svg` + `render.py` (Pillow): snapshot **lịch sử** của bản pilot run-12, xem bên dưới.

Sơ đồ khối bên trong hai mô hình và confusion matrix trên TEST nằm ở `IL/figures/` (`IL/draw_il_slide_figures.py`).

`KLTN-deployment-status.*` là snapshot của bản pilot run-12 ngày 05/11/2026, đã được thay bằng triển khai IL3
(README chính, mục 1 và 9); nội dung dưới đây giữ để đối chiếu lịch sử, không còn mô tả hệ thống đang chạy:
- Phản ánh đầy đủ 14 khối chức năng của framework đã được cài đặt mã nguồn hoàn chỉnh, vượt qua 29/29 bài test unit/contract.
- Hai mô hình `host-ml-run12-v1` (LightGBM) và `network-dl-run12-v1` (BiLSTM) đã được xác nhận golden parity và đạt Windows domain validation.
- Toàn bộ hạ tầng OpenStack Nova instances và Docker containers đã được mã hóa tự động hóa bằng Terraform và Ansible, sẵn sàng deploy live on-demand.
- Hệ thống áp dụng chính sách an toàn fail-closed: khi chưa có model hoặc domain không tương thích (như Linux/THEIA), score trả về `null` theo đúng thiết kế.
