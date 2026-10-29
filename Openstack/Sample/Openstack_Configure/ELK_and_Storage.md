# Hướng dẫn Triển khai OpenStack 2025.2 Flamingo với Kolla-Ansible trên Ubuntu 24.04 LTS

---

## Mục lục

11. [Cấu hình ELK cho ML (Elasticsearch + Kibana + Filebeat)](#11-cấu-hình-elk-cho-ml-elasticsearch--kibana--filebeat)
12. [Cấu hình Manila và CephFS (thực hiện sau khi OpenStack ổn định)](#12-cấu-hình-manila-và-cephfs-thực-hiện-sau-khi-openstack-ổn-định)
13. [Cấu hình Object Storage và Ceph RGW](#13-cấu-hình-object-storage-và-ceph-rgw)
14. [Kiến trúc mô hình triển khai (ASCII)](#14-kiến-trúc-mô-hình-triển-khai-ascii)

---

## 11. Cấu hình ELK cho ML (Elasticsearch + Kibana + Filebeat)

### 11.1 Bước 0: Tắt Central Logging Kolla - Opensearch + Fluent nếu trước đó có cấu hình (tránh trùng với ELK)

Nếu cluster đã bật OpenSearch + OpenSearch Dashboards + Fluentd theo hướng dẫn Kolla (ví dụ `enable_central_logging`, `enable_opensearch` trong `/etc/kolla/globals.yml`), cần tắt trước khi chạy Elasticsearch + Kibana trên Docker — cùng vai trò lưu trữ log và UI, và cổng **9200** / **5601** dễ xung đột với stack ELK map ra host.

#### 11.1.1 Sửa `/etc/kolla/globals.yml`

```bash
sudo nano /etc/kolla/globals.yml
```

Trong phần Central Logging, đặt (hoặc sửa) các dòng sau:

```yaml
enable_central_logging: "no"
enable_opensearch: "no"
enable_opensearch_dashboards: "no"
enable_fluentd: "no"
```

Comment hoặc xóa các dòng chỉ còn ý nghĩa khi dùng OpenSearch (tránh nhầm sau này), ví dụ:

```yaml
# opensearch_soft_retention_period_days: 30
# opensearch_hard_retention_period_days: 60
# opensearch_heap_size: "4g"
```

#### 11.1.2 Áp dụng bằng Kolla-Ansible (stable/2025.2)

Chạy trong virtualenv Kolla (ví dụ `source ~/kolla-venv/bin/activate`):

```bash
sudo rm -f /etc/kolla/haproxy/services.d/opensearch.cfg
sudo rm -f /etc/kolla/haproxy/services.d/opensearch-dashboards.cfg
docker exec -u root haproxy rm -f /etc/haproxy/services.d/opensearch.cfg
docker exec -u root haproxy rm -f /etc/haproxy/services.d/opensearch-dashboards.cfg

kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one --tags opensearch,fluentd,haproxy,prometheus
```

- Tag `opensearch`: gỡ OpenSearch và OpenSearch Dashboards (cùng role triển khai trong Kolla 2025.2).
- Tag `fluentd`: dừng collector gửi log vào OpenSearch.
- Tag `haproxy`: cập nhật HAProxy, bỏ frontend/backend trỏ tới OpenSearch/Dashboards nếu có.
- Tag `prometheus`: cập nhật Prometheus (container `prometheus_elasticsearch_exporter` gắn với OpenSearch sẽ không còn; có thể cần bỏ panel/query cũ trong Grafana nếu đã tạo).

Nếu sau lệnh trên vẫn còn container logging cũ, chạy **một lần** reconfigure đầy đủ (không `--tags`) để đồng bộ toàn stack.

#### 11.1.3 Script ghi đè cấu hình

```bash
#!/bin/bash
# Script: /usr/local/bin/fix_audit_elk.sh

echo "==== BẮT ĐẦU VÁ LỖI GHI ĐÈ KOLLA CHO ELK AUDIT ===="

# --- 1. XỬ LÝ NOVA API ---
echo "[+] Vá cấu hình Nova..."
# Ép driver = log
sudo sed -i '/^\[oslo_messaging_notifications\]$/,/^\[/{s/^driver = messagingv2$/driver = log/}' /etc/kolla/nova-api/nova.conf
# Ép use_json = true vào block [DEFAULT]
if ! grep -q "^use_json = true" /etc/kolla/nova-api/nova.conf; then
    sudo sed -i '/^\[DEFAULT\]/a use_json = true' /etc/kolla/nova-api/nova.conf
fi
# Vá block [audit]
if ! grep -q "^\[audit\]" /etc/kolla/nova-api/nova.conf; then
    echo -e '\n[audit]\nenabled = true\naudit_map_file = /var/lib/kolla/config_files/api_audit_map.conf' | sudo tee -a /etc/kolla/nova-api/nova.conf
fi

# --- 2. XỬ LÝ NEUTRON SERVER ---
echo "[+] Vá cấu hình Neutron..."
# Ép driver = log
sudo sed -i '/^\[oslo_messaging_notifications\]$/,/^\[/{s/^driver = messagingv2$/driver = log/}' /etc/kolla/neutron-server/neutron.conf
# Ép use_json = true vào block [DEFAULT]
if ! grep -q "^use_json = true" /etc/kolla/neutron-server/neutron.conf; then
    sudo sed -i '/^\[DEFAULT\]/a use_json = true' /etc/kolla/neutron-server/neutron.conf
fi
# Vá block [audit]
if ! grep -q "^\[audit\]" /etc/kolla/neutron-server/neutron.conf; then
    echo -e '\n[audit]\nenabled = true\naudit_map_file = /etc/neutron/neutron_api_audit_map.conf' | sudo tee -a /etc/kolla/neutron-server/neutron.conf
fi

# --- 3. RESTART DỊCH VỤ ---
echo "[+] Khởi động lại các container bị ảnh hưởng..."
docker restart nova_api neutron_server

echo "==== HOÀN TẤT ===="
```

#### 11.1.4 Kiểm tra cổng trước khi `docker compose up`

```bash
ss -tlnp | grep -E ':9200|:5601' || true
```

Kỳ vọng: không còn process lắng nghe **9200** và **5601** trên host (hoặc chỉ dịch vụ bạn chủ động giữ). Stack ELK trong tài liệu này dùng `localhost:9200` và `localhost:5601` — **không** dùng VIP Kolla (ví dụ `http://192.168.1.250:9200`) cho Elasticsearch mới; URL đó trong tài liệu triển khai OpenSearch cũ không còn đúng sau khi chuyển ELK.

#### 11.1.5 (Tùy chọn) Dọn file cấu hình Kolla không dùng nữa

Có thể xóa hoặc giữ lại nhưng biết là không áp dụng:

- `/etc/kolla/config/opensearch.yml`
- Thư mục `/etc/kolla/config/fluentd/` (input/filter/output tùy chỉnh)

---

### 11.2 Bước 1: Tạo không gian làm việc cho ELK Stack

Mở Terminal trên máy Host và chạy:

```bash
mkdir -p ~/elk-stack
cd ~/elk-stack
```

---

### 11.3 Bước 2: Tạo cấu hình cho Filebeat (Agent thu thập log)

Filebeat sẽ đọc log từ OpenStack (Kolla-Ansible mặc định lưu tại `/var/log/kolla/`).

#### Tạo file cấu hình:

```bash
nano filebeat.yml
```

#### Dán nội dung sau:

```yaml
filebeat.inputs:
  - type: filestream
    # ĐỔI ID ĐỂ FILEBEAT RESET TRÍ NHỚ, ĐỌC LẠI TỪ DÒNG 1
    id: openstack-audit-v4
    enabled: true
    paths:
      - /var/log/kolla/cinder/cinder-api.log
      - /var/log/kolla/keystone/keystone.log
      - /var/log/kolla/nova/*.log
      - /var/log/kolla/neutron/*.log
      - /var/log/kolla/glance/glance-api.log
processors:
  # Lớp 1: Lấy nguyên dòng log từ file (đang ở trường 'message'), bóc JSON vỏ ngoài
  # Kết quả đẩy vào mục 'openstack'
  - decode_json_fields:
      fields: ["message"]
      target: "openstack"
      overwrite_keys: true
      expand_keys: true
      add_error_key: true

  # Lớp 2: Lấy cái chuỗi string nằm trong 'openstack.message', bóc JSON lõi
  # Kết quả đẩy vào mục 'openstack.audit'
  - decode_json_fields:
      fields: ["openstack.message"]
      target: "openstack.audit"
      overwrite_keys: true
      expand_keys: true
      add_error_key: true

  # Lớp 3: Kẻ gác cổng - Lọc bỏ mọi dòng log hệ thống không có 'event_type'
  - drop_event:
      when:
        not:
          has_fields: ["openstack.audit.event_type"]

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  # Tạo không gian lưu trữ v4 mới tinh, sạch sẽ
  index: "openstack-audit-v4"

setup.datastreams.enabled: false
setup.ilm.enabled: false
setup.template.name: "openstack-audit-v4"
setup.template.pattern: "openstack-audit-v4*"
setup.template.enabled: true
setup.template.overwrite: true
setup.template.priority: 500

setup.kibana:
  host: "kibana:5601"
```

**Giải thích pipeline xử lý:**

| Bước | Mô tả                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------ |
| 1      | Phân biệt 2 format: JSON thuần (`^\s*\{`) → Glance/Cinder; Oslo text → Keystone/Nova/Neutron    |
| 2a     | Oslo format: CADF payload nằm trực tiếp trong `oslo.payload`                                      |
| 2b     | JSON format:`oslo.message` là string chứa notification envelope → decode                          |
| 2c     | Từ envelope đã decode:`oslo_notification.payload` chứa CADF → rename thành `openstack.audit` |
| 3      | Xóa temporary fields (giảm mapping conflicts)                                                        |
| 4      | Chỉ giữ event có CADF (`typeURI` hoặc `eventType`)                                             |

#### Lưu file:

```
Ctrl + O → Enter → Ctrl + X
```

---

### 11.4 Bước 3: Tạo file Docker Compose

File này dùng để chạy đồng thời 3 service:

* Elasticsearch
* Kibana
* Filebeat

#### Tạo file:

```bash
nano docker-compose.yml
```

#### Dán nội dung sau:

```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ports:
      - "127.0.0.1:9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data
    networks:
      - elk-net

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200

      - SERVER_HOST=0.0.0.0
      - I18N_LOCALE=vi
    ports:
      - "127.0.0.1:5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - elk-net

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.13.0
    container_name: filebeat
    user: root
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log/kolla:/var/log/kolla:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - elasticsearch
    networks:
      - elk-net
    command: filebeat -e -strict.perms=false

networks:
  elk-net:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.100.100.0/24
          gateway: 10.100.100.1

volumes:
  es_data:
```

#### Lưu file:

```
Ctrl + O → Enter → Ctrl + X
```

---

### 11.5 Bước 4: Khởi chạy hệ thống Logging

Chạy lệnh sau để tải image và start toàn bộ hệ thống:

```bash
docker compose up -d
```

Quá trình này có thể mất vài phút (do tải image ELK).

---

### 11.6 Bước 5: Kiểm tra hệ thống

#### Kiểm tra container:

```bash
docker ps
```

Bạn cần thấy 3 container:

* elasticsearch
* kibana
* filebeat

---

### 11.7 Bước 6: Cấu hình giao diện Kibana (Data view + Discover)

1. Mở trình duyệt: `http://localhost:5601` (trên chính máy AIO) hoặc `http://<địa-chỉ-IP-máy-AIO>:5601` từ máy khác trong LAN (nhờ `SERVER_HOST=0.0.0.0`).
2. Vào **Stack Management** → **Data views** → **Create data view**.
3. **Name:** ví dụ `openstack-audit`.
4. **Index pattern:** `openstack-audit-v10*` (khớp index trong `filebeat.yml`).
5. **Timestamp field:** chọn `@timestamp` → Save.
6. Vào **Discover**, chọn data view vừa tạo. Thêm cột / lọc theo các field CADF:
   - `openstack.audit.action` — hành động (created, read/list, deleted, ...)
   - `openstack.audit.outcome` — kết quả (success, failure)
   - `openstack.audit.initiator.name` — người thực hiện
   - `openstack.audit.target.typeURI` — loại resource
   - `openstack.audit.eventType` — loại event (activity)
   - `log.file.path` — file log nguồn (phân biệt service)
7. (Tùy chọn) **Save** search; **Dashboard** → tạo dashboard: một panel **Lens** timeline theo `@timestamp`, một panel **Top values** của `openstack.audit.action`.

---

### 11.8 Truy cập giao diện

Dùng **localhost** hoặc **IP máy chủ AIO** — đây là stack ELK Docker trên host, **không** phải VIP OpenStack (`kolla_internal_vip_address`, ví dụ `192.168.1.250`).

* Elasticsearch:  http://localhost:9200
* Kibana:  http://localhost:5601

---

### 11.9 Ghi chú

* Log OpenStack được lấy từ: `/var/log/kolla/`.
* Filebeat gửi log → Elasticsearch; index: `openstack-audit-v10*`.
* Kibana dùng để xem và visualize log.
* Nếu Kolla `reconfigure` ghi đè `driver = log`, cần sửa lại trực tiếp merged config trong `/etc/kolla/<service>/` và restart container.
* Audit middleware `keystonemiddleware.audit` cần có trong `api-paste.ini` pipeline (Nova, Neutron, Glance, Cinder) để tạo CADF event. Keystone tự sinh CADF qua `notification_format = cadf`.

---

### 11.10 Tip kiểm tra nhanh

```bash
curl http://localhost:9200
```

Nếu trả về JSON → Elasticsearch OK.

```bash
# Tạo event test
source ~/kolla-venv/bin/activate
source /etc/kolla/admin-openrc.sh
openstack network create network-test
openstack network delete network-test
```

```bash
# Kiểm tra document mới nhất
curl -X GET "localhost:9200/openstack-audit-v10/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 1,
  "sort": [ { "@timestamp": "desc" } ]
}'
```

Nếu trả về JSON có `openstack.audit.typeURI` → pipeline đã hoàn thành 100%.

```bash
# Kiểm tra phân bố document theo service
curl -s 'http://localhost:9200/openstack-audit-v10/_search' -H 'Content-Type: application/json' -d '{"size":0,"aggs":{"by_file":{"terms":{"field":"log.file.path","size":20}}}}' | python3 -m json.tool
```

Kỳ vọng: thấy document từ 5 log file (keystone, nova, neutron, glance, cinder).

## 12. Cấu hình Manila và CephFS (thực hiện sau khi OpenStack ổn định)

Phần này triển khai theo luồng: kiểm tra điều kiện ban đầu -> chuẩn bị Ceph -> tạo CephFS cho Manila -> tích hợp vào Kolla -> xác minh dịch vụ -> tạo và sử dụng share.

### 12.1 Kiểm tra Trạng thái OpenStack

```bash
# Kích hoạt môi trường
source ~/kolla-venv/bin/activate
source /etc/kolla/admin-openrc.sh

# Kiểm tra services
openstack service list
openstack compute service list
openstack volume service list
openstack network agent list

# Kiểm tra containers
docker ps --format "table {{.Names}}\t{{.Status}}" | head -20
```

### 12.2 Kiểm tra Partition Khả dụng

```bash
# Xem layout disk
lsblk

# Kiểm tra nvme1n1p3 (partition sẽ dùng cho Ceph)
sudo fdisk -l /dev/nvme1n1

# Xác nhận partition chưa được mount
mount | grep nvme1n1p3
# Nếu không có output → partition chưa sử dụng

```

### 12.3 Giai đoạn 1: Chuẩn bị Storage cho Ceph

#### 12.3.1 Sử dụng Partition nvme1n1p3

```bash
# CẢNH BÁO: Lệnh này sẽ xóa dữ liệu trên partition!
# Đảm bảo partition không chứa dữ liệu quan trọng

# Xóa filesystem/partition table cũ (nếu có)
sudo wipefs -a /dev/nvme1n1p3

# Kiểm tra lại
sudo blkid /dev/nvme1n1p3
# không nên còn TYPE/UUID của filesystem (partition đã sạch)
```

Kết quả mong đợi: partition chỉ còn `PARTUUID`, không còn `TYPE=...` của filesystem cũ.

#### 12.3.2 Cài đặt Dependencies cho Cephadm

```bash
# Cài đặt packages cần thiết
sudo apt update

# Cài đặt SSH (Nếu máy tính chưa có)
sudo apt install -y openssh-server
sudo systemctl enable --now ssh

# Cài đặt các package cần thiết
sudo apt install -y \
    podman \
    cephadm \
    ceph-common \
    python3-ceph-argparse \
    lvm2 \
    chrony

# Kiểm tra podman
podman --version

# Kiểm tra cephadm
cephadm version
sudo dpkg -s cephadm | grep Version
apt policy cephadm
sudo systemctl status chrony --no-pager
chronyc tracking
sudo cephadm check-host
```

**Lưu ý:** Cephadm sử dụng **podman** (không phải Docker) để chạy Ceph containers. Cả hai có thể cùng tồn tại.
Kết quả mong đợi: `cephadm check-host` trả về trạng thái host sẵn sàng.

---

### 12.4 Giai đoạn 2: Triển khai Ceph Single-Node với Cephadm

#### 12.4.1 Bootstrap Ceph Cluster

```bash
# Xác định IP của máy (dùng IP WiFi)

# Bootstrap cluster mới
# --single-host-defaults: Tối ưu cho single-node
# --skip-mon-network: Không cần specify network
sudo cephadm bootstrap \
    --mon-ip 192.168.1.2 \
    --single-host-defaults \
    --skip-mon-network \
    --skip-monitoring \
    --allow-fqdn-hostname \
    --cluster-network 192.168.1.0/24 \
    --output-dir /etc/ceph \
    --output-keyring /etc/ceph/ceph.client.admin.keyring \
    --output-config /etc/ceph/ceph.conf

# Pass Dashboard:
Ceph Dashboard is now available at:

	     URL: https://openstack-aio:8443/
	    User: admin
	Password: Nhatnguyen21@1
```

**Giải thích các flags:**

- `--single-host-defaults`: Giảm số replicas xuống 1 (vì chỉ có 1 node)
- Bật Ceph dashboard only (tiết kiệm RAM)
- `--skip-monitoring`: Bỏ qua Prometheus/Grafana của Ceph (đã có của OpenStack)
- `--output-*`: Xuất config files ra /etc/ceph

Kết quả mong đợi: `sudo ceph -s` chạy được, cluster ở trạng thái `HEALTH_WARN` hoặc `HEALTH_OK` (chấp nhận `WARN` tạm thời khi chưa thêm OSD/MDS).

#### 12.4.2 Xác minh Bootstrap

```bash
# Kiểm tra ceph command hoạt động
sudo ceph -s

# Kiểm tra các containers Ceph
sudo podman ps --format "table {{.Names}}\t{{.Status}}"

# Kiểm tra services
sudo ceph orch ls

sudo ceph mgr services
```

Kết quả mong đợi: có các service cốt lõi (mon, mgr) và endpoint manager hoạt động.

#### 12.4.3 Thêm OSD (Storage Device)

```bash
# Liệt kê devices khả dụng
sudo ceph orch device ls

# Chuyển phân vùng thành LVM cho Ceph
sudo pvcreate /dev/nvme1n1p3
sudo vgcreate ceph-vg /dev/nvme1n1p3
sudo lvcreate -l 100%FREE -n osd-lv ceph-vg

# Thêm OSD sử dụng partition nvme1n1p3
sudo ceph orch daemon add osd openstack-aio:/dev/ceph-vg/osd-lv
# Chờ OSD được tạo (30-60 giây)
sleep 30

# Kiểm tra OSD
sudo ceph osd tree
```

Kết quả mong đợi: `ceph osd tree` hiển thị OSD `up/in`.

#### 12.4.4 Cấu hình cho Single-Node

```bash
# Đặt số replicas mặc định = 1 (vì chỉ có 1 OSD)
sudo ceph config set global mon_allow_pool_size_one true
sudo ceph config set global osd_pool_default_size 1
sudo ceph config set global osd_pool_default_min_size 1

# Tắt cảnh báo single-point-of-failure
sudo ceph config set global mon_warn_on_pool_no_redundancy false

# Yêu cầu daemon MGR đang Active hiện tại nhường quyền cho con Standby
sudo ceph mgr fail

# Kiểm tra cluster health
sudo ceph -s
```

Kết quả mong đợi: không còn cảnh báo pool size liên quan single-node.

#### 12.4.5 Xác minh Ceph Cluster Healthy

```bash
# Kiểm tra tổng quan
sudo ceph -s

# Kiểm tra OSDs
sudo ceph osd status

# Kiểm tra capacity
sudo ceph df

```

Kết quả mong đợi: dung lượng OSD đã được nhận, cluster sẵn sàng tạo CephFS.

### 12.5 Giai đoạn 3: Cấu hình CephFS

#### 12.5.1 Tạo CephFS Filesystem

```bash
# Tạo CephFS volume mới
# Lệnh này tự động tạo:
# - MDS daemon
# - Data pool: cephfs.manila_data.data
# - Metadata pool: cephfs.manila_data.meta
sudo ceph fs volume create manila_data

# Chờ MDS daemon khởi động (30-60 giây)
sleep 45

# Kiểm tra CephFS
sudo ceph fs ls
```

Kết quả mong đợi: thấy filesystem `manila_data`.

#### 12.5.2 Xác minh MDS (Metadata Server)

```bash
# Kiểm tra MDS status
sudo ceph mds stat

# Kiểm tra chi tiết
sudo ceph fs status manila_data
```

Kết quả mong đợi: có ít nhất 1 MDS `active`.

#### 12.5.3 Cấu hình Pools cho Manila

```bash
# Liệt kê pools đã tạo
sudo ceph osd pool ls detail

# Đặt application cho pools (nếu chưa có)
sudo ceph osd pool application enable cephfs.manila_data.data cephfs
sudo ceph osd pool application enable cephfs.manila_data.meta cephfs

# Kiểm tra
sudo ceph osd pool application get cephfs.manila_data.data
```

Kết quả mong đợi: application của 2 pool là `cephfs`.

---

### 12.6 Giai đoạn 4: Tạo User và Keyring cho Manila

#### 12.6.1 Tạo Ceph User cho Manila

```bash
# Tạo user client.manila với quyền cần thiết cho CephFS
sudo ceph auth get-or-create client.manila \
    mon 'allow r' \
    osd 'allow rw pool=cephfs.manila_data.data' \
    mds 'allow *' \
    -o /etc/ceph/ceph.client.manila.keyring

# Kiểm tra keyring đã tạo
sudo cat /etc/ceph/ceph.client.manila.keyring

```

Kết quả mong đợi: có section `[client.manila]` và `key = ...`.

#### 12.6.2 Xác minh User

```bash
# Liệt kê auth
sudo ceph auth get client.manila

# Test quyền truy cập
sudo ceph --name client.manila --keyring /etc/ceph/ceph.client.manila.keyring health

```

Kết quả mong đợi: lệnh trả về health của cluster, không lỗi auth.

#### 12.6.3 Export Config cho OpenStack

```bash
# Tạo thư mục để export
mkdir -p ~/ceph-export

# Copy ceph.conf (xóa comments và dòng trống)
sudo grep -v '^\s*#' /etc/ceph/ceph.conf | grep -v '^\s*$' > ~/ceph-export/ceph.conf

# Copy keyring
sudo cp /etc/ceph/ceph.client.manila.keyring ~/ceph-export/

# Đặt quyền
chmod 644 ~/ceph-export/ceph.conf
sudo chown $USER:$USER ~/ceph-export/ceph.client.manila.keyring
chmod 640 ~/ceph-export/ceph.client.manila.keyring

# Xem nội dung
cat ~/ceph-export/ceph.conf

```

Kết quả mong đợi: `~/ceph-export` có đủ `ceph.conf` và `ceph.client.manila.keyring`.

### 12.7 Giai đoạn 5: Tích hợp Ceph vào cấu hình Kolla Manila

#### 12.7.1 Tạo Thư mục Cấu hình Manila

```bash
# Tạo thư mục cho Manila config
sudo mkdir -p /etc/kolla/config/manila
sudo mkdir -p /etc/kolla/config/manila/manila-share

# Đổi ownership
sudo chown -R $USER:$USER /etc/kolla/config/manila
```

#### 12.7.2 Copy Ceph Config và Keyring

```bash
# Copy ceph.conf vào Manila config
# QUAN TRỌNG: File không được có TAB ở đầu dòng!
sudo cp ~/ceph-export/ceph.conf /etc/kolla/config/manila/ceph.conf

# Copy keyring vào cả 2 vị trí (manila root và manila-share)
sudo cp ~/ceph-export/ceph.client.manila.keyring /etc/kolla/config/manila/
sudo cp ~/ceph-export/ceph.client.manila.keyring /etc/kolla/config/manila/manila-share/

# Đặt quyền đúng
sudo chown -R $USER:$USER /etc/kolla/config/manila
sudo chmod 644 /etc/kolla/config/manila/ceph.conf
sudo chmod 640 /etc/kolla/config/manila/ceph.client.manila.keyring
sudo chmod 640 /etc/kolla/config/manila/manila-share/ceph.client.manila.keyring

# Xác minh cấu trúc thư mục
tree /etc/kolla/config/manila/
```

Kết quả mong đợi: có `ceph.conf`, `ceph.client.manila.keyring` và thư mục `manila-share/`.

#### 12.7.3 Kiểm tra Nội dung Config Files

```bash
# Kiểm tra ceph.conf KHÔNG có tab
cat -A /etc/kolla/config/manila/ceph.conf | head -10
# Output không nên có ^I (ký hiệu tab)

# Kiểm tra keyring
cat -A /etc/kolla/config/manila/ceph.client.manila.keyring
# Output không nên có ^I (ký hiệu tab)

# Nếu có ký tự ^I
# Xóa khoảng trắng đầu dòng trong ceph.conf
sudo sed -i 's/^[ \t]*//' /etc/kolla/config/manila/ceph.conf

# Xóa khoảng trắng đầu dòng trong keyring Manila
sudo sed -i 's/^[ \t]*//' /etc/kolla/config/manila/ceph.client.manila.keyring

# Xóa khoảng trắng đầu dòng trong keyring Manila-share
sudo sed -i 's/^[ \t]*//' /etc/kolla/config/manila/manila-share/ceph.client.manila.keyring

```

Kết quả mong đợi: các file không có ký tự tab đầu dòng (`^I`).

#### 12.7.4 Cấu hình Manila Backend Nâng cao

Tạo custom `manila-share.conf` cho backend CephFS native:

```bash
# Tạo custom manila-share config
cat > /etc/kolla/config/manila/manila-share.conf << 'EOF'
[cephfsnative1]
# Driver cho CephFS Native
driver_handles_share_servers = False
share_backend_name = CEPHFS
share_driver = manila.share.drivers.cephfs.driver.CephFSDriver

# Ceph config
cephfs_conf_path = /etc/ceph/ceph.conf
cephfs_auth_id = manila
cephfs_cluster_name = ceph
cephfs_filesystem_name = manila_data

# Protocol
cephfs_protocol_helper_type = CEPHFS
EOF
```

### 12.8 Giai đoạn 6: Triển khai Manila trên Kolla

#### 12.8.1 Chạy Prechecks

```bash
# Kích hoạt môi trường Kolla
source ~/kolla-venv/bin/activate

# Chạy prechecks
kolla-ansible prechecks -i /etc/kolla/ansible/inventory/all-in-one 
```

**Nếu có lỗi:** Đọc kỹ error message và sửa trước khi tiếp tục.

#### 12.8.2 Pull Images Mới

```bash
# Pull Manila container images
kolla-ansible pull -i /etc/kolla/ansible/inventory/all-in-one
```

#### 12.8.3 Deploy/Reconfigure

```bash
# Reconfigure để thêm Manila service
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one

# Thời gian: 10-20 phút
```

Kết quả mong đợi: playbook kết thúc thành công, container Manila được cập nhật.

#### 12.8.4 Post-Deploy

```bash
# Chạy post-deploy để cập nhật openrc files
kolla-ansible post-deploy -i /etc/kolla/ansible/inventory/all-in-one
```

Kết quả mong đợi: có thể source lại `admin-openrc.sh` và gọi OpenStack CLI bình thường.

---

### 12.9 Giai đoạn 7: Xác minh Manila backend sau reconfigure

#### 12.9.1 Kiểm tra Manila Service List

```bash
# Source credentials
source /etc/kolla/admin-openrc.sh

# Cài đặt Manila client
pip install python-manilaclient

# Kiểm tra Manila services
openstack share service list
```

Kết quả mong đợi: service `manila-scheduler` và `manila-share` ở trạng thái `up`.

#### 12.9.2 Kiểm tra Manila Pools

```bash
# Liệt kê storage pools
openstack share pool list

# Chi tiết pool
openstack share pool list --detail

```

Kết quả mong đợi: pool backend CephFS hiển thị và `driver_handles_share_servers=False`.

---

### 12.10 Giai đoạn 8: Sử dụng Manila Share

#### 12.10.1 Tạo Share Type

```bash
# Source credentials
source /etc/kolla/admin-openrc.sh

# Tạo share type cho CephFS
openstack share type create cephfs_type false

# Đặt extra specs để map với backend
openstack share type set cephfs_type --extra-specs share_backend_name=CEPHFS

# Kiểm tra share types
openstack share type list
```

#### 12.10.2 Tạo Manila Share

```bash
# Tạo share 10GB với protocol CEPHFS
openstack share create \
  --name my-first-share \
  --share-type cephfs_type \
  CEPHFS 10

# Theo dõi trạng thái
openstack share show my-first-share
```

Kết quả mong đợi: share chuyển sang trạng thái `available`.

#### 12.10.3 Cấu hình Access

```bash
# CephFS Native, Ceph không quản lý bảo mật bằng IP mà bằng Cephx (Keyring/Mật khẩu). Khi chạy lệnh này, Manila sẽ tự động tạo ra một user mới trong Ceph và cấp quyền cho user đó truy cập đúng vào thư mục 10GB vừa tạo.
openstack share access create my-first-share cephx test-client

# Kiểm tra access rules
openstack share access list my-first-share

```

Kết quả mong đợi: access rule về trạng thái `active` và có thông tin secret để mount.

#### 12.10.4 Lấy Export Location

```bash
# Lấy thông tin export
openstack share export location list my-first-share
# Output sẽ có dạng:
# 192.168.1.2:6789:/volumes/_nogroup/<uuid>
```

#### 12.10.5 Mount Share trong VM

Để mount CephFS share trong VM, thực hiện lần lượt các bước sau.

##### 12.10.5.1 Cài đặt Ceph client trong VM

```bash
# Trong VM (Ubuntu)
sudo apt update
sudo apt install -y ceph-common
```

##### 12.10.5.2 Copy `ceph.conf` và secret vào VM

```bash
# Tạo thư mục ceph config
sudo mkdir -p /etc/ceph

# Copy ceph.conf (từ export location)
# Nội dung tối thiểu:
sudo tee /etc/ceph/ceph.conf << EOF
[global]
mon_host = 192.168.1.2
EOF

# Copy hoặc tạo keyring cho manila client
echo "AQC1l8NpIHh0GhAA5c0YYGzqSGYpwOVrG9ICYQ==" | sudo tee /etc/ceph/test-client.secret
```

##### 12.10.5.3 Mount CephFS

```bash
# Tạo mount point
sudo mkdir -p /mnt/cephfs-share

# Mount sử dụng kernel driver
sudo mount -t ceph \
    192.168.1.2:6789:/volumes/_nogroup/3a2ea581-a261-43e4-9d69-d6197917546e/899d72ca-0152-4978-84c7-b0a85ec72796 \
    /mnt/cephfs-share \
    -o name=test-client,secretfile=/etc/ceph/ceph.client.manila.keyring

# Kiểm tra mount
df -h

```

Kết quả mong đợi: `df -h` hiển thị mount CephFS tại `/mnt/cephfs-share`.

#### 12.10.6 Test Read/Write

```bash
# Trong VM, sau khi mount
cd /mnt/cephfs-share

# Tạo file test
sudo echo "Hello from Manila CephFS Share!" > test.txt

# Đọc file
cat test.txt

# Kiểm tra dung lượng
df -h 
```

#### 12.10.7 Cấu hình tự động Mount khi Reboot

```bash
# Mở fstab
sudo nano /etc/fstab
# --> Thêm đường dẫn
192.168.1.2:6789:/volumes/_nogroup/3a2ea581-a261-43e4-9d69-d6197917546e/899d72ca-0152-4978-84c7-b0a85ec72796 /mnt/cephfs-share ceph name=test-client,secretfile=/etc/ceph/test-client.secret,_netdev,noatime 0 0

# Xác minh cấu hình đã hoàn thành
# Tháo ổ đĩa ra
sudo umount /mnt/cephfs-share

# Yêu cầu hệ thống mount lại tất cả các ổ đĩa khai báo trong fstab
sudo mount -a

# Kiểm tra lại
df -h | grep ceph

# --> Nếu lệnh df -h vẫn hiện ổ đĩa 10GB, cấu hình của bạn đã hoạt động
```

---



### 12.11 Triển khai Manila với Share Servers (Generic Backend) trên hệ thống hiện tại

Mục này hướng dẫn bổ sung backend Generic (with share servers) vào hệ thống đã có Manila CephFS (without share servers).
Kết quả cuối cùng: Manila có thể tạo NFS share thông qua service VM.

#### 12.11.1 Bước 1: Chuẩn bị biến và kiểm tra network

```bash
source ~/kolla-venv/bin/activate
source /etc/kolla/admin-openrc.sh

openstack network list
openstack subnet list
```

Xác định trước các giá trị sẽ dùng:
- `<EXTERNAL_NET_ID>`: network external (ví dụ `public-net`).
- `<TENANT_NET_ID>`: network private của tenant dùng cho share.
- `<TENANT_SUBNET_ID>`: subnet private tương ứng.

Kết quả mong đợi: xác định được đủ 3 ID trên trước khi cấu hình backend Generic.

#### 12.11.2 Bước 2: Bật Generic backend trong Kolla

##### 12.11.2.1 Bật cờ backend trong `globals.yml`

```bash
sudo nano /etc/kolla/globals.yml
```

Đảm bảo có dòng:

```yaml
enable_manila_backend_generic: "yes"
```

##### 12.11.2.2 Cập nhật `manila-share.conf`

```bash
sudo nano /etc/kolla/config/manila/manila-share.conf
```

Giữ nguyên backend CephFS hiện có, thêm section Generic bên dưới:

```ini
[generic]
share_backend_name = GENERIC
share_driver = manila.share.drivers.generic.GenericShareDriver
driver_handles_share_servers = True
service_instance_flavor_id = 100
service_image_name = manila-service-image
service_instance_user = manila
service_instance_password = manila
service_instance_network_helper = neutron
service_instance_floating_ip = True
service_instance_external_network_id = <EXTERNAL_NET_ID>
```

Kết quả mong đợi: file `manila-share.conf` có đồng thời backend CephFS và backend Generic.

#### 12.11.3 Bước 3: Tạo image và flavor cho service VM

```bash
wget https://tarballs.opendev.org/openstack/manila-image-elements/images/manila-service-image-master.qcow2

openstack image create "manila-service-image" \
  --file manila-service-image-master.qcow2 \
  --disk-format qcow2 \
  --container-format bare \
  --public

openstack flavor create manila-service-flavor \
  --id 100 \
  --ram 2048 \
  --disk 0 \
  --vcpus 1
```

Kết quả mong đợi: image `manila-service-image` và flavor ID `100` tồn tại.

#### 12.11.4 Bước 4: Áp dụng cấu hình Manila

```bash
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one --tags manila

openstack share service list
```

Kết quả mong đợi: dịch vụ Manila `up`, backend Generic được nạp thành công.

#### 12.11.5 Bước 5: Tạo Share Network và Share Type cho Generic

##### 12.11.5.1 Đảm bảo tenant subnet có router ra external network

```bash
openstack router create manila-router
openstack router set manila-router --external-gateway <EXTERNAL_NET_ID>
openstack router add subnet manila-router <TENANT_SUBNET_ID>
openstack router show manila-router
```

##### 12.11.5.2 Tạo share network map vào tenant network

```bash
openstack share network create \
  --name generic-tenant-share-net \
  --neutron-net-id <TENANT_NET_ID> \
  --neutron-subnet-id <TENANT_SUBNET_ID>

openstack share network list
```

##### 12.11.5.3 Tạo share type cho Generic backend

```bash
openstack share type create generic_share_type True
openstack share type set generic_share_type --extra-specs share_backend_name=GENERIC
openstack share type list
```

Kết quả mong đợi: có `generic-tenant-share-net` và `generic_share_type` với `driver_handles_share_servers=True`.

#### 12.11.6 Bước 6: Tạo NFS share và mount từ VM client

##### 12.11.6.1 Tạo share

```bash
openstack share create NFS 1 \
  --name my-share-with-server \
  --share-network generic-tenant-share-net \
  --share-type generic_share_type

watch -n 5 openstack share list
```

Chờ đến khi trạng thái share là `available`.

##### 12.11.6.2 Lấy export location và cấp quyền truy cập

```bash
openstack share export location list my-share-with-server
openstack share access create my-share-with-server ip <CLIENT_IP_ADDRESS>
openstack share access list my-share-with-server
```

##### 12.11.6.3 Mở security group cho NFS (nếu cần)

```bash
openstack security group rule create --protocol tcp --dst-port 111 manila-service
openstack security group rule create --protocol udp --dst-port 111 manila-service
openstack security group rule create --protocol tcp --dst-port 2049 manila-service
openstack security group rule create --protocol udp --dst-port 2049 manila-service
```

##### 12.11.6.4 Mount trên VM client

```bash
sudo apt update
sudo apt install -y nfs-common
sudo nano /etc/fstab

# Ghi vào file /etc/fstab 
10.254.0.26:/shares/share-54a611a3-23f6-4fd4-bcaa-080558328827 /mnt/test-nfs nfs defaults,_netdev,noatime,nofail 0 0

# Lưu file Ctrl+O, Enter, Ctrl+X và chạy:
sudo systemctl daemon-reload
sudo mount -a
df -h
```

Kết quả mong đợi: mount thành công, ghi/đọc file được trong `/mnt/test-nfs`.

#### 12.11.7 Chú ý và lỗi thường gặp

- Share Generic phải map vào tenant network (`<TENANT_NET_ID>/<TENANT_SUBNET_ID>`), không map vào `manila_service_network`.
- Router phải gắn đúng tenant subnet đang dùng để tạo share network.
- Access rule nên mở theo đúng IP VM client (`<CLIENT_IP_ADDRESS>`), không nên mở rộng mặc định nếu không cần.
- Nếu mount timeout, kiểm tra security group của service VM đã mở TCP/UDP `111` và `2049` chưa.


## 13. Cấu hình Object Storage và Ceph RGW

### 13.1 Khởi tạo dịch vụ RGW

```
cat <<EOF > ~/rgw_spec.yaml
service_type: rgw
service_id: default
placement:
  hosts:
    - openstack-aio
spec:
  rgw_frontend_port: 7480
EOF

# Triển khai RGW thông qua cephadm
sudo ceph orch apply -i ~/rgw_spec.yaml

# Chờ 1-2 phút, kiểm tra xem RGW đã lên và port 7480 đã LISTEN chưa:
sudo ceph orch ls | grep rgw
ss -lntup | grep 7480
```

### 13.2 Liên kết RGW với OpenStack Keystone

```
# 
grep keystone_admin_password /etc/kolla/passwords.yml

# Set cấu hình xác thực qua Keystone cho RGW
sudo ceph config set client.rgw rgw_keystone_api_version 3
sudo ceph config set client.rgw rgw_keystone_url http://192.168.1.250:5000
sudo ceph config set client.rgw rgw_keystone_admin_user admin
sudo ceph config set client.rgw rgw_keystone_admin_password <MẬT_KHẨU_ADMIN>
sudo ceph config set client.rgw rgw_keystone_admin_project admin
sudo ceph config set client.rgw rgw_keystone_admin_domain default
sudo ceph config set client.rgw rgw_keystone_accepted_roles "admin, member"
sudo ceph config set client.rgw rgw_keystone_accepted_admin_roles admin
sudo ceph config set client.rgw rgw_s3_auth_use_keystone true
sudo ceph config set client.rgw rgw_swift_account_in_url true
sudo ceph config set client.rgw rgw_swift_versioning_enabled true

# Khởi động lại RGW để nhận cấu hình mới
sudo ceph orch restart rgw.default
```

### 13.3 Đăng ký RGW (như là Swift) vào OpenStack

```
# Kích hoạt biến môi trường admin của OpenStack
source /etc/kolla/admin-openrc.sh

# Tạo service Swift
openstack service create --name swift --description "Ceph RGW Object Storage" object-store

# Đăng ký các Endpoints (Sử dụng IP 192.168.1.2 và port 7480)
openstack endpoint create --region RegionOne object-store public http://192.168.1.2:7480/swift/v1/AUTH_%\(project_id\)s
openstack endpoint create --region RegionOne object-store internal http://192.168.1.2:7480/swift/v1/AUTH_%\(project_id\)s
openstack endpoint create --region RegionOne object-store admin http://192.168.1.2:7480/swift/v1/AUTH_%\(project_id\)s
```

### 13.4 Kiểm tra kết quả

```
# Tạo một container (giống bucket trong S3)
openstack container create test-container

# Tạo 1 file txt và upload lên
echo "Hello Ceph RGW on Port 7480" > test.txt
openstack object create test-container test.txt

# Kiểm tra list object
openstack object list test-container
openstack object show test-container test.txt
```

---

## 14. Kiến trúc mô hình triển khai (ASCII)

Hai sơ đồ dưới đây mô tả **toàn bộ hệ thống** triển khai trên máy AIO (Ubuntu 24.04, single-NIC laptop). Danh sách container được lấy từ `docker ps` thực tế (Kolla + ELK) và kiến trúc Ceph theo tài liệu (cephadm/podman).

---

### 14.1 Mô hình toàn cục (OpenStack + ELK + Ceph)

```
+====================================================================================================+
|  HOST: openstack-aio   Ubuntu 24.04 LTS  /  Kernel 6.17                                           |
|  wlp0s20f3 (WiFi DHCP 192.168.1.2)   VIP = 192.168.1.250 (keepalived)                             |
|                                                                                                    |
|  ┌── DOCKER ENGINE (Kolla-Ansible + ELK Docker Compose) ─────────────────────────────────────────┐ |
|  │                                                                                               │ |
|  │  ╔═══ PROXY / HA ══════╗  ╔═══ DB / MQ ════════════════════╗  ╔══ INFRA ══════════════════╗   │ |
|  │  ║ haproxy             ║  ║ mariadb                        ║  ║ cron                     ║   │ |
|  │  ║ keepalived           ║  ║ proxysql                       ║  ║ kolla_toolbox            ║   │ |
|  │  ║                      ║  ║ rabbitmq                       ║  ║ local-registry (:4000)   ║   │ |
|  │  ║                      ║  ║ memcached                      ║  ║                          ║   │ |
|  │  ╚══════════════════════╝  ╚════════════════════════════════╝  ╚══════════════════════════╝   │ |
|  │                                                                                               │ |
|  │  ╔═══ IDENTITY ════════╗  ╔═══ COMPUTE (Nova) ═════════════╗  ╔══ IMAGE ═════════════════╗   │ |
|  │  ║ keystone            ║  ║ nova_api          nova_metadata║  ║ glance_api               ║   │ |
|  │  ║ keystone_fernet     ║  ║ nova_scheduler    nova_conductor║  ║                          ║   │ |
|  │  ║ keystone_ssh        ║  ║ nova_compute      nova_ssh     ║  ║                          ║   │ |
|  │  ║                      ║  ║ nova_novncproxy   nova_libvirt ║  ║                          ║   │ |
|  │  ╚══════════════════════╝  ║ placement_api                  ║  ╚══════════════════════════╝   │ |
|  │                             ╚═══════════════════════════════╝                                  │ |
|  │                                                                                               │ |
|  │  ╔═══ NETWORK (Neutron + OVN) ═════════════════════════════════════════════════════════════╗   │ |
|  │  ║ neutron_server              neutron_rpc_server          neutron_periodic_worker         ║   │ |
|  │  ║ neutron_ovn_metadata_agent  neutron_ovn_maintenance_worker                             ║   │ |
|  │  ║ ovn_northd   ovn_nb_db   ovn_sb_db   ovn_sb_db_relay_1   ovn_controller               ║   │ |
|  │  ║ openvswitch_db             openvswitch_vswitchd                                        ║   │ |
|  │  ╚════════════════════════════════════════════════════════════════════════════════════════╝   │ |
|  │                                                                                               │ |
|  │  ╔═══ STORAGE (Cinder LVM) ╗  ╔═══ SHARED FS (Manila) ════╗  ╔══ DASHBOARD ═════════════╗   │ |
|  │  ║ cinder_api               ║  ║ manila_api                ║  ║ horizon                  ║   │ |
|  │  ║ cinder_scheduler         ║  ║ manila_scheduler          ║  ║                          ║   │ |
|  │  ║ cinder_volume            ║  ║ manila_share              ║  ║                          ║   │ |
|  │  ║ cinder_backup            ║  ║ manila_data               ║  ║                          ║   │ |
|  │  ║ iscsid  tgtd  multipathd ║  ╚═══════════════════════════╝  ╚══════════════════════════╝   │ |
|  │  ╚═════════════════════════╝                                                                  │ |
|  │                                                                                               │ |
|  │  ╔═══ ORCHESTRATION ════╗  								   │ |
|  │  ║ heat_api             ║ 									   │ |
|  │  ║ heat_api_cfn         ║ 									   │ |
|  │  ║ heat_engine          ║ 									   │ |
|  │  ╚══════════════════════╝  								   │ |
|  │  ╔═══ ELK STACK (Docker Compose, ~/elk-stack) ═══════════════════════════════════════════╗   │ |
|  │  ║ elasticsearch  (localhost:9200)   ◄── filebeat (đọc /var/log/kolla/*)                  ║   │ |
|  │  ║ kibana         (0.0.0.0:5601)     ◄── query elasticsearch                             ║   │ |
|  │  ║ filebeat       (CADF JSON logs)   ──► index: openstack-audit-v4                        ║   │ |
|  │  ╚════════════════════════════════════════════════════════════════════════════════════════╝   │ |
|  │                                                                                               │ |
|  └───────────────────────────────────────────────────────────────────────────────────────────────┘ |
|                                                                                                    |
|  ┌── NETWORK DATAPATH ───────────────────────────────────────────────────────────────────────────┐ |
|  │  wlp0s20f3 ─── management 192.168.1.0/24 ─── VIP .250 (HAProxy)                              │ |
|  │       │                                                                                       │ |
|  │       │ iptables MASQUERADE                                                                   │ |
|  │       │                                                                                       │ |
|  │  br-exnat (172.10.10.1/24) ──► veth-ext ◄──► veth-peer ──► OVS br-ex (Neutron)               │ |
|  │                                                  │                                            │ |
|  │                                    provider net 172.10.10.0/24  floating .200-.250             │ |
|  └───────────────────────────────────────────────────────────────────────────────────────────────┘ |
|                                                                                                    |
|  ┌── CEPH CLUSTER (cephadm / Podman, external) ─────────────────────────────────────────────────┐ |
|  │  ceph-mon     (monitor)         192.168.1.2:3300,6789                                         │ |
|  │  ceph-mgr     (manager + dashboard :8443)                                                     │ |
|  │  ceph-osd.0   (/dev/nvme1n1p3, LVM)                                                          │ |
|  │  ceph-mds     (MDS cho CephFS manila_data)                                                    │ |
|  │  ceph-rgw     (Rados Gateway :7480, Swift-compatible, nếu bật)                                │ |
|  │  Pools: cephfs.manila_data.data / .meta    User: client.manila (keyring → Kolla Manila)       │ |
|  └───────────────────────────────────────────────────────────────────────────────────────────────┘ |
+====================================================================================================+
```

**Chú giải:**

| Ký hiệu            | Ý nghĩa                                                                                     |
| -------------------- | --------------------------------------------------------------------------------------------- |
| `╔══╗`         | Nhóm container cùng chức năng                                                             |
| Docker Engine        | Tất cả container Kolla + ELK chạy trên Docker                                             |
| Ceph (Podman)        | Container Ceph quản lý bởi cephadm, chạy trên Podman riêng                              |
| VIP .250             | `kolla_internal_vip_address`, keepalived + HAProxy                                          |
| br-exnat             | Linux bridge + NAT cho provider network, script tự tạo                                      |
| veth-ext / veth-peer | Virtual Ethernet pair kết nối br-exnat ↔ OVS br-ex                                         |
| ELK Stack            | Chạy bằng `docker compose` riêng tại `~/elk-stack`, đọc log từ `/var/log/kolla/` |

---

### 14.2 Log flow chi tiết khi chạy `openstack server create`

Sơ đồ dưới đây mô tả luồng xử lý nghiệp vụ (mũi tên `──►`) và luồng ghi log CADF/audit (mũi tên `- - ►`) khi chạy lệnh:

```
openstack server create --flavor m1.tiny --image CirrOS \
  --network net-A --security-group allow-all-ssh-ping \
  --property purpose=audit_test_expansion test_expansion_vm
```

```
  CLI / Horizon / SDK
        │
        │  POST /v2.1/servers
        ▼
  ┌─ haproxy (VIP :8774) ─┐
  │  proxy → nova_api      │
  └────────┬───────────────┘
           │
           ▼
  ┌─ nova_api ───────────────────────────────────────────────────────────────┐
  │  1. Xác thực token ──────────────────► keystone (port 5000)             │
  │     keystone_fernet giải mã token      │                                │
  │     keystone_ssh (nếu multi-node sync) │                                │
  │     ◄──────────────────────────────────┘                                │
  │  2. Kiểm tra quota/flavor ───────────► placement_api                    │
  │     ◄── trả resource provider ─────────┘                                │
  │  3. Validate image ──────────────────► glance_api                       │
  │     ◄── image metadata ─────────────────┘                               │
  │  4. Validate network + SG ───────────► neutron_server                   │
  │     neutron_server ──► neutron_rpc_server (plugin RPC)                  │
  │     neutron_server ──► mariadb (network/subnet/SG lookup)               │
  │     ◄── network info ────────────────────┘                              │
  │  5. Ghi build request vào DB ────────► mariadb (nova cell DB)           │
  │  6. Gửi message build ──────────────► rabbitmq (queue: scheduler)       │
  │  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - │
  │  LOG: nova_api ghi CADF event (action=create, target=compute/server)    │
  │       → /var/log/kolla/nova/nova-api.log (driver=log, use_json=true)    │
  └─────────────────────────────────────────────────────────────────────────┘
           │ RabbitMQ
           ▼
  ┌─ nova_scheduler ─────────────────────────────────────────────────────────┐
  │  7. Nhận message từ queue scheduler                                      │
  │  8. Query placement_api → danh sách host phù hợp                        │
  │  9. Áp filter + weigher → chọn host (localhost trong AIO)                │
  │ 10. Gửi message build ──────────────► rabbitmq (queue: compute.host)     │
  │  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  │
  │  LOG: nova_scheduler ghi scheduling decision log                         │
  │       → /var/log/kolla/nova/nova-scheduler.log                           │
  └──────────────────────────────────────────────────────────────────────────┘
           │ RabbitMQ
           ▼
  ┌─ nova_conductor ─────────────────────────────────────────────────────────┐
  │ 11. Trung gian DB: cập nhật instance state trong mariadb                 │
  │     (nova_compute không truy cập DB trực tiếp)                           │
  │  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  │
  │  LOG: → /var/log/kolla/nova/nova-conductor.log                           │
  └──────────────────────────────────────────────────────────────────────────┘
           │ RabbitMQ
           ▼
  ┌─ nova_compute ───────────────────────────────────────────────────────────┐
  │ 12. Nhận message build instance                                          │
  │ 13. Download image qua ──────────────► glance_api                        │
  │ 14. Tạo port/VIF ───────────────────► neutron_server                     │
  │     neutron_server ──► neutron_rpc_server (tạo port)                     │
  │     neutron_server ──► neutron_ovn_metadata_agent (metadata)             │
  │     neutron_server ──► rabbitmq ──► ovn_northd (logical flow)            │
  │     ovn_northd ──► ovn_nb_db / ovn_sb_db (cập nhật topology)            │
  │     ovn_sb_db_relay_1 (relay cho multi-node, AIO vẫn chạy)              │
  │     ovn_controller ──► openvswitch_vswitchd (tạo OVS port thực)         │
  │                        openvswitch_db (lưu OVS config)                   │
  │     neutron_periodic_worker (dọn port/router cũ, chạy nền)              │
  │     neutron_ovn_maintenance_worker (đồng bộ OVN ↔ Neutron, chạy nền)   │
  │ 15. Áp security group rules ──► ovn_controller (ACL trong OVN)          │
  │ 16. Tạo volume boot (nếu BFV) ──► cinder_api                            │
  │     cinder_api ──► cinder_scheduler (chọn backend)                       │
  │     cinder_scheduler ──► cinder_volume (tạo LV trên cinder-volumes VG)  │
  │     cinder_backup (standby, dùng khi backup volume)                      │
  │     iscsid + tgtd + multipathd (iSCSI attach LV → VM)                   │
  │ 17. Gọi nova_libvirt ──► libvirtd (KVM/QEMU)                            │
  │     nova_ssh (live-migration giữa nodes, AIO ít dùng)                    │
  │ 18. Console proxy ──────────────────► nova_novncproxy (:6080)            │
  │ 19. Cập nhật state ────────────────► nova_conductor ──► mariadb          │
  │ 20. Gửi notification ─────────────► rabbitmq                             │
  │  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  │
  │  LOG: nova_compute ghi CADF event (action=create, outcome=success)       │
  │       → /var/log/kolla/nova/nova-compute.log                             │
  │  LOG: neutron_server ghi CADF event (action=create port)                 │
  │       → /var/log/kolla/neutron/neutron-server.log                        │
  │  LOG: glance_api ghi CADF event (action=read image)                      │
  │       → /var/log/kolla/glance/glance-api.log                             │
  │  LOG: cinder_api ghi CADF event (action=create volume, nếu BFV)         │
  │       → /var/log/kolla/cinder/cinder-api.log                             │
  └──────────────────────────────────────────────────────────────────────────┘
           │
           │  Tất cả LOG files nằm trong /var/log/kolla/
           ▼
  ┌─ ELK PIPELINE (Docker Compose) ─────────────────────────────────────────┐
  │                                                                          │
  │  filebeat ── đọc /var/log/kolla/{keystone,nova,neutron,glance,cinder}/   │
  │     │  decode_json_fields (lớp 1: JSON vỏ ngoài)                        │
  │     │  decode_json_fields (lớp 2: oslo.message → openstack.audit)        │
  │     │  drop_event (lọc: chỉ giữ dòng có event_type / CADF)              │
  │     ▼                                                                    │
  │  elasticsearch (localhost:9200)                                           │
  │     │  index: openstack-audit-v4                                         │
  │     ▼                                                                    │
  │  kibana (0.0.0.0:5601)                                                   │
  │     Data view: openstack-audit  →  Discover / Dashboard                  │
  │     Fields: openstack.audit.action, .outcome, .initiator.name,           │
  │             .target.typeURI, .eventType, log.file.path                    │
  └──────────────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─ MANILA + CEPH (không trực tiếp trong flow create, trừ khi share) ──────┐
  │  manila_api → manila_scheduler → manila_share (CephFS native driver)     │
  │  manila_data (data service helper)                                       │
  │     ──► Ceph cluster (Podman): ceph-mon, ceph-mgr, ceph-osd.0, ceph-mds│
  │         CephFS: manila_data  /  pools: .data + .meta                     │
  │         ceph-rgw (:7480, Swift API, nếu bật)                             │
  │  horizon (dashboard web :80, truy cập tất cả service qua HAProxy)       │
  │  heat_api / heat_api_cfn / heat_engine (orchestration / stack)           │
  └──────────────────────────────────────────────────────────────────────────┘
```

**Chú giải:**

| Ký hiệu                              | Ý nghĩa                                                        |
| -------------------------------------- | ---------------------------------------------------------------- |
| `──►`                             | Luồng xử lý nghiệp vụ (request/response hoặc RPC)          |
| `- - ►`                             | Luồng ghi log CADF/audit vào file                              |
| `LOG:`                               | Điểm phát sinh audit event, ghi JSON vào `/var/log/kolla/` |
| Số thứ tự 1-20                      | Trình tự xử lý khi tạo VM                                   |
| Container*in nghiêng* trong mô tả | Chạy nền, không trực tiếp trong flow nhưng liên quan      |

**Bảng tổng hợp container theo nhóm (runtime `docker ps` + Ceph):**

| Nhóm                   | Container                                                                                                                                                                                                                          | Số lượng     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| Proxy/HA                | haproxy, keepalived                                                                                                                                                                                                                | 2               |
| DB/MQ/Cache             | mariadb, proxysql, rabbitmq, memcached                                                                                                                                                                                             | 4               |
| Identity                | keystone, keystone_fernet, keystone_ssh                                                                                                                                                                                            | 3               |
| Compute                 | nova_api, nova_scheduler, nova_conductor, nova_compute, nova_metadata, nova_novncproxy, nova_ssh, nova_libvirt, placement_api                                                                                                      | 9               |
| Network                 | neutron_server, neutron_rpc_server, neutron_periodic_worker, neutron_ovn_metadata_agent, neutron_ovn_maintenance_worker, ovn_northd, ovn_nb_db, ovn_sb_db, ovn_sb_db_relay_1, ovn_controller, openvswitch_db, openvswitch_vswitchd | 12              |
| Block Storage           | cinder_api, cinder_scheduler, cinder_volume, cinder_backup, iscsid, tgtd, multipathd                                                                                                                                               | 7               |
| Image                   | glance_api                                                                                                                                                                                                                         | 1               |
| Shared FS               | manila_api, manila_scheduler, manila_share, manila_data                                                                                                                                                                            | 4               |
| Dashboard               | horizon                                                                                                                                                                                                                            | 1               |
| Orchestration           | heat_api, heat_api_cfn, heat_engine                                                                                                                                                                                                | 3               |
| ELK                     | elasticsearch, kibana, filebeat                                                                                                                                                                                                    | 3               |
| Infra                   | cron, kolla_toolbox, local-registry                                                                                                                                                                                                | 3               |
| **Ceph (Podman)** | ceph-mon, ceph-mgr, ceph-osd.0, ceph-mds, ceph-rgw (tùy chọn)                                                                                                                                                                    | 4-5             |
| **Tổng**         |                                                                                                                                                                                                                                    | **75-76** |

> Ghi chú: Địa chỉ IP (`192.168.1.2`, VIP `.250`), tên thiết bị (`wlp0s20f3`, `veth-peer`), partition (`/dev/nvme1n1p3`) là theo môi trường thực tế trong tài liệu. Khi đổi môi trường, thay các giá trị tương ứng.
