# KLTN: OpenStack Endhosts, Central Docker & MLOps Architecture

Cập nhật: **30/10/2026**.
Thư mục này chứa toàn bộ mã nguồn, cấu hình triển khai hạ tầng và runtime phục vụ mô hình của hệ thống **KLTN: Multi-Source Context-Aware Framework for APT Detection**.

> [!NOTE]
> **Hiện trạng triển khai:** Đã hoàn thiện pipeline thu thập raw telemetry phân tán (7 nguồn) và nền tảng runtime ML/DL sẵn sàng. **Chưa có hệ thống phát hiện APT hoặc vòng lặp MLOps hoạt động tự động** (các service hiện ở trạng thái chờ model bundle, weights và adapter chuẩn hóa ngữ nghĩa).

---

## 1. Sơ đồ Hiện trạng Triển khai & Đối chiếu Kiến trúc

Toàn bộ hạ tầng thử nghiệm gồm 3 máy ảo endhost và central container đều được vận hành trên máy chủ vật lý **OpenStack All-in-One (AIO)**.

![KLTN deployment status](images/KLTN-deployment-status.png)

- [Bản vẽ PNG độ phân giải cao](images/KLTN-deployment-status.png) | [Bản vẽ vector SVG](images/KLTN-deployment-status.svg)
- Mã tái tạo sơ đồ: [`images/render.py`](images/render.py) (`python3 render.py` yêu cầu Pillow và font DejaVu Sans).
- **Quy ước màu sắc trên sơ đồ:**
  - **Màu xanh lục (Green):** Chức năng đã triển khai, kiểm thử và hoạt động ổn định.
  - **Màu vàng (Yellow):** Khung runtime đã cài đặt sẵn sàng, đang chờ nạp model weights và logic inference.
  - **Màu đỏ nét đứt (Dashed Red):** Thành phần chưa được triển khai.

---

## 2. Vị trí Thực tế của các Thành phần Hạ tầng

| Máy / Node | IP nội bộ | Sensor / Forwarding | Agent / Runtime phục vụ mô hình | Lưu trữ / Trạng thái hoạt động |
|---|---|---|---|---|
| `kltn-ubuntu-1` | `172.31.250.228` | auditd, journald, Fluent Bit | `/opt/kltn-agent`: Python venv, FastAPI/Uvicorn, LightGBM 4.6.0, NumPy, SciPy; systemd user `kltn-agent` | `/var/lib/kltn-agent/inbox.sqlite`; API loopback `127.0.0.1:18081`; trạng thái: *chờ model* |
| `kltn-ubuntu-2` | `172.31.250.208` | auditd, journald, Fluent Bit | Giống Ubuntu 1, identity và trạng thái độc lập | SQLite Inbox riêng; API loopback `127.0.0.1:18081`; trạng thái: *chờ model* |
| `kltn-windows-1` | `172.31.250.236` | Sysmon, Security Audit, PowerShell Script Block Logging, Fluent Bit (native service) | `C:\KLTN\agent`: Python 3.12.10 venv, LightGBM 4.6.0, NumPy, SciPy, FastAPI/Uvicorn, WinSW 2.12.0 chạy dưới user `LocalService` | `C:\KLTN\agent\state\inbox.sqlite`; API loopback `127.0.0.1:18081`; trạng thái: *chờ model* |
| **Host vật lý** `openstack-aio` | `172.31.250.1` | Kolla OpenStack (Nova, Neutron, Libvirt); Terraform & Ansible controller | Docker Compose: **Caddy, FastAPI Ingest, NATS JetStream, PostgreSQL, Archive Worker, DL Preparation Worker** | Volumes Docker cho raw logs và JetStream queue; bảng `events`, `dl_jobs`, `serving_status`; thư mục models trống |

### Đặc tả Mạng & Giới hạn Cổng:
- **Ingress duy nhất tại lab network:** HTTPS `172.31.250.1:18443` (Caddy reverse proxy quản lý token và TLS).
- **Các cổng dịch vụ nội bộ bind Loopback host:** API Ingestion `127.0.0.1:18080`, NATS JetStream `127.0.0.1:14222`, PostgreSQL `127.0.0.1:15432`.
- **Cổng Endpoint Agent:** Bind loopback `127.0.0.1:18081` trên từng máy ảo, chỉ nhận log cục bộ từ Fluent Bit fan-out.
- **Quản trị:** SSH và WinRM được bảo vệ qua Security Group, mặc định chỉ cho phép kết nối từ IP quản trị `172.31.250.1/32`.
- **Thiết kế tài nguyên:** Endpoint không cài Docker hay PyTorch. Mô hình LightGBM chạy dạng thư viện native trong tiến trình Python của agent. Central DL chạy PyTorch trên CPU (không đòi hỏi GPU).

---

## 3. Đối chiếu 14 Khối Kiến trúc & Khoảng cách (Gap Analysis)

Bảng đối chiếu giữa kiến trúc mục tiêu tổng thể và hiện trạng triển khai trong OpenStack testbed:

| STT | Khối kiến trúc | Trước khi triển khai | Hiện trạng đã hoàn thành | Phần còn thiếu (Cần triển khai) |
|---|---|---|---|---|
| **1** | **Activities & Sensors** | Sysmon, Security, PowerShell, auditd, journald | Đã kiểm thử đầy đủ 7 luồng sự kiện từ 3 máy ảo | Chưa mở rộng socket network collection trong pilot; module-load chưa được bật |
| **2** | **Logging & Local Storage** | Bộ đệm RAM/file của Fluent Bit | **Đã bổ sung:** SQLite WAL inbox trên cả 3 VM; commit trước ACK, chống ghi trùng, giới hạn 128 MiB/50,000 events | Scheduler chọn batch theo chính sách ML; cơ chế export/replay log dài ngày |
| **3** | **Host Processing & Context** | Không có tiến trình xử lý cục bộ | **Đã bổ sung:** Python local agent nhận log qua loopback HTTP và lưu inbox | Parser chuẩn hóa ngữ nghĩa, theo dõi vòng đời process (process lifetime), ngữ cảnh cha-con (actor/parent) và trích xuất feature |
| **4** | **Host ML Detection** | Chưa có agent/runtime | **Đã bổ sung:** Runtime LightGBM 4.6.0 + NumPy/SciPy; systemd trên Linux, WinSW trên Windows | Bộ nạp model bundle, tiền xử lý từ điển vocab, tính điểm scoring và ngưỡng threshold; chưa cài runtime XGBoost/RF |
| **5** | **Log Forwarding** | Đẩy raw logs lên Central | **Đã bổ sung:** Fan-out thêm bản sao raw vào local inbox, độc lập với luồng HTTPS Central; tự động kết nối lại | Kênh score outbox đẩy cảnh báo ưu tiên và điểm phát hiện về Central |
| **6** | **Central Receive & Queue** | Caddy → FastAPI → NATS JetStream | Hoạt động ổn định với pipeline raw telemetry | Kênh riêng tiếp nhận điểm số (score receiver); kiểm soát tải/retention toàn diện |
| **7** | **Central Storage** | Bảng PostgreSQL `events` (JSONB) | **Đã bổ sung:** Bảng `dl_jobs`, `serving_status`, phân quyền role `kltn_dl` | Bảng dữ liệu đã chuẩn hóa (processed logs), kho lưu trữ Parquet dài hạn, model artifact registry |
| **8** | **Normalization & Correlation** | Chưa có | **Chưa thay đổi:** Vẫn lưu JSON raw | Parser chuyển XML Windows và Linux audit syscall thành bản ghi chuẩn; correlation theo thời gian |
| **9** | **Central DL Inference** | Chưa có runtime/worker | **Đã bổ sung:** Container PyTorch 2.7.1 CPU, worker stage tham chiếu sự kiện và heartbeat | Trình dựng sequence/chunk theo cửa sổ 15 phút, nạp trọng số mô hình DL, thực hiện suy luận chuỗi |
| **10** | **GraphSAGE / Provenance** | Nghiên cứu offline | **Chưa thay đổi** | Chưa triển khai đồ thị thực thi và dịch vụ chấm điểm đồ thị thời gian thực |
| **11** | **Context-Aware Fusion** | Chưa có | **Chưa thay đổi** | Cơ chế liên kết ML/DL theo host/thời gian, cơ chế gating, cross-attention và tính điểm nguy cơ |
| **12** | **SOC Dashboard** | CLI và SQL queries | Bổ sung CLI `serving_status.py` | Giao diện đồ họa (UI), quy trình gắn nhãn và phê duyệt cảnh báo |
| **13** | **Response & Infra Controller** | Chưa có | Terraform mới chỉ dùng để dựng hạ tầng ban đầu | Cơ chế tự động gửi lệnh cô lập máy ảo (OpenStack network quarantine) khi phát hiện tấn công |
| **14** | **MLOps / Incremental Learning** | Chưa có | Có installer lặp lại, phiên bản thư viện cố định (pins), tài liệu hướng dẫn bundle | Chưa triển khai vòng lặp MLOps: trigger drift, replay buffer, tự động huấn luyện lại và kiểm định chất lượng |

---

## 4. Phân tích Vòng lặp MLOps (Đối chiếu với Architecture)

| Khâu trong Vòng MLOps | Hiện trạng | Phần cần xây dựng |
|---|---|---|
| **Storage: Validated datasets + Model artifacts** | Mới có raw logs, staging references và thư mục model trống | Quản lý phiên bản tập dữ liệu (dataset versioning), nhãn xác minh, kiểm tra chất lượng phân vùng, metadata artifact |
| **Dashboard → Verified logs → Storage** | Chưa có | Quy trình SOC rà soát, dán nhãn sự kiện và lưu trữ tập dữ liệu chuẩn |
| **Trigger: Drift / Scheduled / Enough data** | Chưa có | Metric đo độ trôi dữ liệu (data drift), lịch định kỳ và điều kiện kích hoạt pipeline huấn luyện lại |
| **Incremental Learning Service** | Chưa có | Chính sách bộ đệm phát lại (replay buffer), điều phối huấn luyện gia tăng, checkpoint/resume |
| **Evaluation & Model Registry Service** | Chưa có | Cổng kiểm định chất lượng mô hình (acceptance gates), so sánh baseline, kiểm tra rò rỉ dữ liệu |
| **Model Deployment & Rollout** | Chưa có | Cơ chế nạp tự động, chạy thử nghiệm song song (shadow inference), giám sát và tự động rollback khi lỗi |

> [!IMPORTANT]
> **Các lưu ý cốt lõi tránh ngộ nhận:**
> - `dl_jobs` **không phải là replay buffer** của MLOps; nó chỉ chứa ID của các raw event để xếp hàng staging (giới hạn 50,000 jobs).
> - `serving_status` **không phải hệ thống đo drift**; nó chỉ báo cáo nhịp tim (heartbeat), số lượng job và tình trạng tiến trình runtime.
> - Thư mục model rỗng **không phải là Model Registry**.

---

## 5. Quy trình Từng Bước Tái Tạo Lại Hệ Thống (Recreation Runbook)

Khi bạn tiếp tục làm việc và muốn dựng lại toàn bộ trạng thái hệ thống (tạo lại 3 máy ảo, bật lại container Central, nạp cấu hình cảm biến và runtime serving), thực hiện tuần tự theo các bước chuẩn mực sau:

### Điều kiện tiên quyết:
- Chạy từ máy chủ `openstack-aio` (nơi vận hành OpenStack Kolla-Ansible).
- Đã có file xác thực `/etc/kolla/admin-openrc.sh`, Docker socket, SSH key `~/.ssh/openstack_ed25519`.
- Thư mục làm việc: `cd /mnt/SSD_Data/optc`.

---

### Bước 1: Kích hoạt lại Compute Service trên OpenStack
Compute host trước đó được đặt ở trạng thái nghỉ (`disabled`). Kích hoạt lại trước khi chạy Terraform:

```bash
cd /mnt/SSD_Data/optc
source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh
export PYTHONWARNINGS="ignore"

# Bật lại nova-compute
openstack compute service set --enable openstack-aio nova-compute
```

---

### Bước 2: Dựng lại Hạ tầng Mạng và 3 Máy ảo bằng Terraform
Lệnh này sẽ tạo lại 3 máy ảo (`kltn-ubuntu-1`, `kltn-ubuntu-2`, `kltn-windows-1`), 3 subnet riêng biệt, router, security groups và cấp phát 3 floating IPs:

```bash
cd /mnt/SSD_Data/optc/Openstack/KLTN/terraform
terraform plan -out=kltn.tfplan
terraform apply kltn.tfplan
```
*Sau khi apply thành công, bạn có thể kiểm tra danh sách máy ảo bằng lệnh `openstack server list`.*

---

### Bước 3: Khởi động lại các Central Containers
Khởi động lại 6 container kiến trúc (NATS JetStream, PostgreSQL 16, Ingest API, Worker, DL Preparation, Caddy). Dữ liệu database cũ trong Docker volumes vẫn được bảo toàn nguyên vẹn:

```bash
cd /mnt/SSD_Data/optc/Openstack/KLTN/central
docker compose --profile model-prep start
```
*(Hoặc nếu muốn khởi động mới hoàn toàn/rebuild code API: `bash /mnt/SSD_Data/optc/Openstack/KLTN/scripts/central_up.sh`)*.

---

### Bước 4: Đồng bộ Inventory, Cấu hình WinRM SAN và Tắt Sleep Windows
Sau khi máy ảo Windows khởi động (đợi khoảng 2-3 phút để QEMU Guest Agent và Sysprep hoàn tất), chạy script tự động để:
- Đọc UUID, IP từ Terraform state.
- Lấy password Windows qua QGA.
- Tự động tạo chứng thư WinRM HTTPS có IP SAN thay vì hostname.
- Tắt chế độ ngủ đông (`powercfg /hibernate off`) và cấu hình UAC remote policy:

```bash
cd /mnt/SSD_Data/optc
Openstack/KLTN/runtime/venv/bin/python Openstack/KLTN/scripts/prepare_inventory.py
python3 Openstack/KLTN/scripts/fetch_assets.py
```

---

### Bước 5: Cấu hình Sensor và Endpoint Agent bằng Ansible
Triển khai Fluent Bit, Sysmon (Windows), auditd (Linux), SQLite Inbox và service endpoint agent (`kltn-agent`):

```bash
export ANSIBLE_CONFIG="$PWD/Openstack/KLTN/ansible/ansible.cfg"
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/site.yml
```

---

### Bước 6: Kích hoạt Model Serving Runtime (Tùy chọn)
Kích hoạt framework phục vụ mô hình trên cả 3 endpoint và container central DL prep worker:

```bash
bash Openstack/KLTN/scripts/prepare_serving.sh
```

---

### Bước 7: Kiểm thử Xác nhận Toàn Trình (Verification & Smoke Test)
Xác nhận toàn bộ luồng thu thập và serving đã hoạt động ổn định:

```bash
# 1. Kiểm tra trạng thái endpoint và central
python3 Openstack/KLTN/scripts/status.py
python3 Openstack/KLTN/scripts/serving_status.py

# 2. Bắn sự kiện test (smoke marker) vào cả 3 máy ảo
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/smoke.yml -e smoke_marker=kltn-smoke-resume-001

# 3. Kiểm tra sự kiện marker xuất hiện trong PostgreSQL trung tâm
docker compose -f Openstack/KLTN/central/compose.yaml exec -T postgres \
  psql -U kltn -p 15432 -d kltn \
  -c "SELECT host_id, source, count(*) FROM events WHERE payload::text LIKE '%kltn-smoke-resume-001%' GROUP BY host_id, source;"
```

---

## 6. Kiểm thử và Xác minh Hệ thống (Validation)

Thực hiện các bước kiểm tra hoạt động của toàn bộ luồng thu thập dữ liệu:

```bash
# 1. Chạy Unit test trong môi trường Docker central
docker run --rm --network none \
  -v "$PWD/Openstack/KLTN/serving:/workspace/serving:ro" \
  -v "$PWD/Openstack/KLTN/central/app:/workspace/central/app:ro" \
  -v "$PWD/Openstack/KLTN/test:/workspace/test:ro" \
  --entrypoint python kltn-central:pilot -m unittest discover -s /workspace/test -v

# 2. Kiểm tra Ingest API, xác thực mTLS và gửi lặp
python3 Openstack/KLTN/scripts/check_ingest.py

# 3. Gửi synthetic smoke marker vào máy ảo để tạo event thật
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/smoke.yml -e smoke_marker=kltn-smoke-manual-001

# 4. Xem trạng thái dịch vụ tổng quan
python3 Openstack/KLTN/scripts/status.py
docker compose -f Openstack/KLTN/central/compose.yaml ps

# 5. Kiểm tra sự kiện marker trong cơ sở dữ liệu PostgreSQL
docker compose -f Openstack/KLTN/central/compose.yaml exec -T postgres \
  psql -U kltn -p 15432 -d kltn \
  -c "SELECT host_id, source, count(*) FROM events WHERE payload::text LIKE '%kltn-smoke-manual-001%' GROUP BY host_id, source;"
```

### Kết quả kiểm chứng thu được:
- **7 nguồn telemetry** đã được ghi nhận thành công vào PostgreSQL: `sysmon`, `security`, `powershell` (từ Windows); `audit`, `journal` (từ 2 máy Ubuntu).
- **Cơ chế chống lặp:** PostgreSQL áp dụng composite primary key loại trừ bản ghi trùng lặp; SQLite Inbox cục bộ commit thành công trước khi trả lời HTTP.
- **Giới hạn an toàn:** JetStream có trần lưu trữ 1 GiB; SQLite Inbox giới hạn 50,000 sự kiện hoặc 128 MiB raw payload để đảm bảo tài nguyên cho máy ảo.

---

## 7. Chuẩn bị Phục vụ Mô hình (Model Serving Runtime)

Hệ thống đã chuẩn bị sẵn runtime để phục vụ mô hình sau khi huấn luyện:
- Tài liệu cấu hình serving chi tiết: [serving/README.md](serving/README.md).
- Hướng dẫn vận hành và quản lý model bundle: [serving/OPERATIONS.md](serving/OPERATIONS.md).
- Trạng thái hiện tại: API suy luận trả `disabled_schema_pending` cho đến khi bundle mô hình và adapter chuẩn hóa vượt qua kiểm định tính hợp lệ.

---

## 8. Quản trị: Dừng Hệ thống (Tear Down) & Trạng thái Nghỉ (Standby)

Để giải phóng CPU/RAM máy chủ vật lý khi không sử dụng mà vẫn giữ nguyên vẹn hệ thống OpenStack nền tảng:

```bash
# 1. Dừng các Central Containers của kiến trúc (giữ nguyên dữ liệu volumes)
docker compose -f /mnt/SSD_Data/optc/Openstack/KLTN/central/compose.yaml --profile model-prep stop

# 2. Xóa 3 máy ảo và toàn bộ tài nguyên mạng Terraform (Router, Subnet, SecGroup, Floating IP)
cd /mnt/SSD_Data/optc/Openstack/KLTN/terraform
source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan

# 3. Đặt Compute Host OpenStack vào trạng thái nghỉ
openstack compute service set --disable --disable-reason "KLTN lab idle" openstack-aio nova-compute
```
*(Toàn bộ hệ thống OpenStack Kolla gốc gồm Keystone, Glance, Horizon, OVN, MariaDB, RabbitMQ vẫn tiếp tục chạy bình thường ở trạng thái không tải).*

---

## 9. Lộ trình Triển khai Tiếp theo

1. **Chuẩn hóa Schema và Adapter:** Xây dựng parser chuẩn hóa sự kiện thô (Sysmon XML, audit syscall) thành định dạng CDM/eCAR.
2. **Context Tracker Cục bộ:** Bổ sung logic theo dõi quan hệ tiến trình cha-con (actor/target/parent) và trích xuất vector đặc trưng trên endpoint agent.
3. **Triển khai Serving Endpoint:** Nạp model bundle LightGBM đã huấn luyện, thực hiện tính điểm (scoring) trực tiếp trên máy ảo.
4. **DL Chunk Builder & Ingestion:** Hoàn thiện pipeline cắt cửa sổ 15 phút tại Central, nạp trọng số BiLSTM/Mixed-Type và thực thi suy luận trên CPU container.
5. **Context-Aware Fusion & Phản ứng:** Ghép nối điểm số giữa Host và Network, đưa ra cảnh báo tổng hợp và kích hoạt cơ chế cách ly mạng tự động.
