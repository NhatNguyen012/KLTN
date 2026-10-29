# Triển khai Manila với Share Servers (Generic Backend) trên hệ thống hiện tại

Do hệ thống OpenStack 2025.2 của bạn đã được triển khai và cấu hình sẵn Manila ở chế độ **Without Share Servers** (sử dụng CephFS backend), tài liệu này sẽ tập trung vào các bước bổ sung để cấu hình thêm chế độ **With Share Servers** (sử dụng Generic Backend). Ở chế độ này, Manila sẽ tự động gọi Nova tạo máy ảo (VM) làm file server và xuất (export) NFS share vào một Private Network.

## Các mục sai đã được chỉnh lại (quan trọng)

1. Sai share network khi tạo share Generic:

- Trước đó dùng `manila-service-share-net` (map vào `manila_service_network` / subnet `4f8266a4-4a81-49c5-ac0b-6ff7fe524b48`) nên từng phát sinh lỗi tạo Share Server.
- Cấu hình đã chạy ổn là `generic-tenant-share-net` map vào tenant network `private-net-2` (`84a867d2-c90c-462a-961f-21a590e092be`) và subnet `47293959-2a42-4712-8957-430262fa96db`.

2. Sai subnet khi gắn router:

```bash
openstack router remove subnet manila-router 4f8266a4-4a81-49c5-ac0b-6ff7fe524b48
openstack router add subnet manila-router 47293959-2a42-4712-8957-430262fa96db
```

3. Phần hướng dẫn access rule chưa khớp thực tế:

- Access rule nên mở theo đúng IP VM client thực tế (ví dụ đã test thành công: `10.2.0.250`).
- Nếu test không Mount NFS được do timeout, đảm bảo rule `mở full protocol như UDP/TCP cho port 111, 2049, allow All Traffic`.

```bash
openstack security group rule create --protocol tcp --dst-port 111:111 --remote-ip 0.0.0.0/0 manila-service
openstack security group rule create --protocol udp --dst-port 111:111 --remote-ip 0.0.0.0/0 manila-service
openstack security group rule create --protocol tcp --dst-port 2049:2049 --remote-ip 0.0.0.0/0 manila-service
openstack security group rule create --protocol udp --dst-port 2049:2049 --remote-ip 0.0.0.0/0 manila-service
```

---

## Bước 1: Kích hoạt thêm Generic Backend trong Kolla-Ansible

### 1. Bổ sung cấu hình vào `globals.yml`

Do `enable_manila: "yes"` đã có sẵn, bạn chỉ cần bật thêm Generic backend:

```bash
sudo nano /etc/kolla/globals.yml
```

Thêm dòng sau (hoặc sửa nếu đã có):

```yaml
enable_manila_backend_generic: "yes"
```

Kiểm tra Network, Subnet

```bash
(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack network list
+--------------------------------------+------------------------+--------------------------------------+
| ID                                   | Name                   | Subnets                              |
+--------------------------------------+------------------------+--------------------------------------+
| 28a429e7-ea84-4425-a12a-b5a4778a2f6a | net-B                  | 36c8c44d-117c-4dfe-b445-a62c4933a5df |
| 4d0ccbd7-2a04-4ef2-8581-90be68664c6c | private-net            | 42e3cd15-dfef-4124-bca9-7af4679331ff |
| 7f4277c5-d031-4635-a7fd-d8cc9b87dda2 | public-net             | 128d4118-686e-4805-bd89-51c50594686b |
| 84a867d2-c90c-462a-961f-21a590e092be | private-net-2          | 47293959-2a42-4712-8957-430262fa96db |
| a98c42f9-4d86-4ca3-883f-1a83f7e1e0c8 | net-A                  | e2a6f1c0-27d2-4c29-94f7-7d1969d45c2d |
| e9916547-c8e8-4597-bf10-a25926adcd3c | k8s-lab-4              | ce15be1d-955d-4f70-bb11-54a33561a885 |
+--------------------------------------+------------------------+--------------------------------------+
(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack subnet list
+--------------------------------------+-----------------------------------------+--------------------------------------+----------------+
| ID                                   | Name                                    | Network                              | Subnet         |
+--------------------------------------+-----------------------------------------+--------------------------------------+----------------+
| 128d4118-686e-4805-bd89-51c50594686b | public-subnet                           | 7f4277c5-d031-4635-a7fd-d8cc9b87dda2 | 172.10.10.0/24 |
| 36c8c44d-117c-4dfe-b445-a62c4933a5df | subnet-B                                | 28a429e7-ea84-4425-a12a-b5a4778a2f6a | 10.3.0.0/24    |
| 42e3cd15-dfef-4124-bca9-7af4679331ff | private-subnet                          | 4d0ccbd7-2a04-4ef2-8581-90be68664c6c | 10.0.0.0/24    |
| 47293959-2a42-4712-8957-430262fa96db | private-subnet-2                        | 84a867d2-c90c-462a-961f-21a590e092be | 10.2.0.0/24    |
| ce15be1d-955d-4f70-bb11-54a33561a885 | k8s-lab-4-wdakws6hwxqv-                 | e9916547-c8e8-4597-bf10-a25926adcd3c | 10.0.0.0/24    |
|                                      | network-y6x3f2koouwq-private_subnet-    |                                      |                |
|                                      | ugksjrsbtsj7                            |                                      |                |
| e2a6f1c0-27d2-4c29-94f7-7d1969d45c2d | subnet-A                                | a98c42f9-4d86-4ca3-883f-1a83f7e1e0c8 | 10.1.0.0/24    |
+--------------------------------------+-----------------------------------------+--------------------------------------+----------------+


```

### 2. Cập nhật file cấu hình `manila-share.conf`

Do Manila đã được cấu hình với CephFS, cấu hình custom nằm tại thư mục `/etc/kolla/config/manila/`. Bạn cần thêm phần `[generic]` vào file `manila-share.conf`.

```bash
sudo nano /etc/kolla/config/manila/manila-share.conf
```

Đảm bảo file có nội dung sau (giữ nguyên config của CephFS backend cũ, thêm section này vào dưới cùng):

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
service_instance_external_network_id = 7f4277c5-d031-4635-a7fd-d8cc9b87dda2

```

---

## Bước 2: Chuẩn bị OS Image và Flavor cho Share Server

Manila ở chế độ này cần tạo máy ảo để làm Share Server, vì vậy phải có Image chuyên dụng và Flavor.

### 1. Kích hoạt môi trường quản trị

```bash
source /home/nhatnguyen/kolla-venv/bin/activate
source /etc/kolla/admin-openrc.sh
```

### 2. Tải và cấu hình Image

```bash
wget https://tarballs.opendev.org/openstack/manila-image-elements/images/manila-service-image-master.qcow2

openstack image create "manila-service-image" \
  --file manila-service-image-master.qcow2 \
  --disk-format qcow2 --container-format bare \
  --public
```

### 3. Tạo Flavor cho máy ảo Manila (ID = 100)

Tạo flavor với ID=100 khớp với khai báo `service_instance_flavor_id`:

```bash
openstack flavor create manila-service-flavor \
  --id 100 \
  --ram 2048 \
  --disk 0 \
  --vcpus 1
```

---

## Bước 3: Reconfigure Dịch vụ Manila

Thay vì deploy từ đầu, tiến hành cấu hình lại (reconfigure) để áp dụng các config mới cho backend Generic:

```bash
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one --tags manila
```

Đợi lệnh hoàn tất. Cả 2 backend (CephFS cũ và Generic mới) giờ đây sẽ cùng hoạt động.
Bạn có thể xác nhận log:

```bash
docker restart manila_share
sudo tail -f /var/log/kolla/manila/manila-share.log # Ở terminal khác
openstack share service list
```

---

## Bước 4: Tạo Share Network và Share Type cho Generic

Ở chế độ *With Share Servers*, share type cung cấp thuộc tính `driver_handles_share_servers=True` và phải chỉ định rõ Tenant Network.

### 1. Lấy thông tin Network của user/tenant

```bash
openstack network list
openstack subnet list

(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack network list
+--------------------------------------+------------------------+--------------------------------------+
| ID                                   | Name                   | Subnets                              |
+--------------------------------------+------------------------+--------------------------------------+
| 01e54f0c-b46f-4bfb-b4fb-d476f4464f83 | manila_service_network |                                      |
| 28a429e7-ea84-4425-a12a-b5a4778a2f6a | net-B                  | 36c8c44d-117c-4dfe-b445-a62c4933a5df |
| 4d0ccbd7-2a04-4ef2-8581-90be68664c6c | private-net            | 42e3cd15-dfef-4124-bca9-7af4679331ff |
| 7f4277c5-d031-4635-a7fd-d8cc9b87dda2 | public-net             | 128d4118-686e-4805-bd89-51c50594686b |
| 84a867d2-c90c-462a-961f-21a590e092be | private-net-2          | 47293959-2a42-4712-8957-430262fa96db |
| a98c42f9-4d86-4ca3-883f-1a83f7e1e0c8 | net-A                  | e2a6f1c0-27d2-4c29-94f7-7d1969d45c2d |
| e9916547-c8e8-4597-bf10-a25926adcd3c | k8s-lab-4              | ce15be1d-955d-4f70-bb11-54a33561a885 |
+--------------------------------------+------------------------+--------------------------------------+
(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack subnet list
+--------------------------------------+-----------------------------------------+--------------------------------------+----------------+
| ID                                   | Name                                    | Network                              | Subnet         |
+--------------------------------------+-----------------------------------------+--------------------------------------+----------------+
| 128d4118-686e-4805-bd89-51c50594686b | public-subnet                           | 7f4277c5-d031-4635-a7fd-d8cc9b87dda2 | 172.10.10.0/24 |
| 36c8c44d-117c-4dfe-b445-a62c4933a5df | subnet-B                                | 28a429e7-ea84-4425-a12a-b5a4778a2f6a | 10.3.0.0/24    |
| 42e3cd15-dfef-4124-bca9-7af4679331ff | private-subnet                          | 4d0ccbd7-2a04-4ef2-8581-90be68664c6c | 10.0.0.0/24    |
| 47293959-2a42-4712-8957-430262fa96db | private-subnet-2                        | 84a867d2-c90c-462a-961f-21a590e092be | 10.2.0.0/24    |
| 4f8266a4-4a81-49c5-ac0b-6ff7fe524b48 |                                         | 01e54f0c-b46f-4bfb-b4fb-d476f4464f83 | 10.254.0.0/28  |
| ce15be1d-955d-4f70-bb11-54a33561a885 | k8s-lab-4-wdakws6hwxqv-                 | e9916547-c8e8-4597-bf10-a25926adcd3c | 10.0.0.0/24    |
|                                      | network-y6x3f2koouwq-private_subnet-    |                                      |                |
|                                      | ugksjrsbtsj7                            |                                      |                |
| e2a6f1c0-27d2-4c29-94f7-7d1969d45c2d | subnet-A                                | a98c42f9-4d86-4ca3-883f-1a83f7e1e0c8 | 10.1.0.0/24    |
+--------------------------------------+-----------------------------------------+--------------------------------------+----------------+

```

Ghi nhớ `<NETWORK_ID>` và `<SUBNET_ID>` của một private network.

### 2. Tạo Router và Giao tiếp Mạng (Bắt buộc cho OVN/Helper)

Để Floating IP (Neutron Helper) hoạt động và điều hướng traffic cho service VM, bạn phải chắc chắn Private Network đã có Router.

```bash
# 1. Tạo router
openstack router create manila-router

# 2. Gắn External network làm gateway
openstack router set manila-router --external-gateway public-net

# 3. Gắn subnet của private network (share-subnet) vào router
openstack router add subnet manila-router <SUBNET_ID>

(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack router add subnet manila-router 47293959-2a42-4712-8957-430262fa96db
(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack router show manila-router
+---------------------------+-------------------------------------------------------------------------------------------------------------------+
| Field                     | Value                                                                                                             |
+---------------------------+-------------------------------------------------------------------------------------------------------------------+
| admin_state_up            | UP                                                                                                                |
| availability_zone_hints   |                                                                                                                   |
| availability_zones        |                                                                                                                   |
| created_at                | 2026-04-19T00:24:49Z                                                                                              |
| description               |                                                                                                                   |
| enable_default_route_bfd  | False                                                                                                             |
| enable_default_route_ecmp | False                                                                                                             |
| enable_ndp_proxy          | None                                                                                                              |
| external_gateway_info     | {"network_id": "7f4277c5-d031-4635-a7fd-d8cc9b87dda2", "external_fixed_ips": [{"subnet_id":                       |
|                           | "128d4118-686e-4805-bd89-51c50594686b", "ip_address": "172.10.10.206"}], "enable_snat": true}                     |
| external_gateways         | [{'network_id': '7f4277c5-d031-4635-a7fd-d8cc9b87dda2', 'external_fixed_ips': [{'ip_address': '172.10.10.206',    |
|                           | 'subnet_id': '128d4118-686e-4805-bd89-51c50594686b'}]}]                                                           |
| flavor_id                 | None                                                                                                              |
| ha                        | True                                                                                                              |
| id                        | d3293b33-2c9b-49d0-be7a-6af3b506733c                                                                              |
| interfaces_info           | [{"port_id": "b30a3a2a-054e-4a5d-9174-30e0eb0455ab", "ip_address": "10.2.0.1", "subnet_id":                       |
|                           | "47293959-2a42-4712-8957-430262fa96db"}]                                                                          |
| name                      | manila-router                                                                                                     |
| project_id                | 68b8a1d761f648a0a6b13c32d27dfb38                                                                                  |
| revision_number           | 9                                                                                                                 |
| routes                    |                                                                                                                   |
| status                    | ACTIVE                                                                                                            |
| tags                      |                                                                                                                   |
| updated_at                | 2026-04-19T04:29:21Z                                                                                              |
+---------------------------+-------------------------------------------------------------------------------------------------------------------+
```

Lưu ý: Dòng lệnh cũ từng dùng `4f8266a4-4a81-49c5-ac0b-6ff7fe524b48` ở bước này là không đúng với luồng triển khai đã chạy thành công.

### 3. Tạo Share Network

Manila dùng Share Network để biết sẽ gán máy ảo Share Server vào đâu:

```bash
openstack share network create \
  --name generic-tenant-share-net \
  --neutron-net-id 84a867d2-c90c-462a-961f-21a590e092be \
  --neutron-subnet-id 47293959-2a42-4712-8957-430262fa96db

(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack share network list
+--------------------------------------+--------------------------+
| ID                                   | Name                     |
+--------------------------------------+--------------------------+
| 7f3d05ab-1f30-4be1-8cbf-9ed7bfe46d8c | generic-tenant-share-net |
| ecadd935-e801-4989-a464-9168ece803a3 | manila-service-share-net |
+--------------------------------------+--------------------------+
(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack share network show 7f3d05ab-1f30-4be1-8cbf-9ed7bfe46d8c
+-----------------------------------+----------------------------------------------------------+
| Field                             | Value                                                    |
+-----------------------------------+----------------------------------------------------------+
| id                                | 7f3d05ab-1f30-4be1-8cbf-9ed7bfe46d8c                     |
| name                              | generic-tenant-share-net                                 |
| project_id                        | 68b8a1d761f648a0a6b13c32d27dfb38                         |
| created_at                        | 2026-04-19T04:54:32.159099                               |
| updated_at                        | None                                                     |
| description                       | None                                                     |
| status                            | active                                                   |
| security_service_update_support   | False                                                    |
| network_allocation_update_support | False                                                    |
| share_network_subnets             |                                                          |
|                                   | id = ca0fa9a5-b8d8-4b1f-a1a3-7d3d010ec47f                |
|                                   | neutron_net_id = 84a867d2-c90c-462a-961f-21a590e092be    |
|                                   | neutron_subnet_id = 47293959-2a42-4712-8957-430262fa96db |
| security_services                 |                                                          |
+-----------------------------------+----------------------------------------------------------+
```

Lưu ý: `manila-service-share-net` vẫn có thể tồn tại trong hệ thống, nhưng không dùng cho bước tạo share Generic ở luồng này.

### 4. Tạo Share Type mới

Tạo một Type dành riêng cho Generic Backend (yêu cầu tạo Share Server):

```bash
openstack share type create generic_share_type True
openstack share type set generic_share_type --extra-specs share_backend_name=GENERIC

(kolla-venv) nhatnguyen@openstack-aio:/etc/kolla/ansible/inventory$ openstack share type list
+-------------------------+--------------------+------------+------------+-------------------------+-------------------------+-------------+
| ID                      | Name               | Visibility | Is Default | Required Extra Specs    | Optional Extra Specs    | Description |
+-------------------------+--------------------+------------+------------+-------------------------+-------------------------+-------------+
| d5918e7f-8cba-4c3f-     | cephfs_type        | public     | False      | driver_handles_share_se | share_backend_name :    | None        |
| 80d4-3dff6f68cc6a       |                    |            |            | rvers : False           | CEPHFS                  |             |
| 92e2b9d4-99bf-4dcb-     | generic_share_type | public     | False      | driver_handles_share_se | share_backend_name :    | None        |
| b385-c2f2a49fb986       |                    |            |            | rvers : True            | GENERIC                 |             |
+-------------------------+--------------------+------------+------------+-------------------------+-------------------------+-------------+
```

---

## Bước 5: Cấp phát NFS Share và Sử dụng

### 1. Khởi tạo Share

```bash
openstack share create NFS 1 \
  --name my-share-with-server \
  --share-network generic-tenant-share-net \
  --share-type generic_share_type
```

Chờ quá trình chạy:

```bash
watch -n 5 openstack share list
# Status chuyển từ "creating" -> "available"
```

### 2. Lấy đường dẫn Export (Export Location)

```bash
openstack share export location list my-share-with-server
```

*(Copy đường dẫn export có dạng `10.x.x.x:/shares/share-xxxx`)*

### 3. Cho phép truy cập IP và Mở Port Security Group

Mở quyền mount cho IP máy ảo Client (ví dụ đã test thành công: `10.2.0.250`):

```bash
openstack share access create my-share-with-server ip <CLIENT_IP_ADDRESS>

# Nếu cần mở thêm rule NFS, thao tác trên security group của service instance
# (thường là 'manila-service', không nên mặc định dùng 'default')
openstack security group rule create --protocol tcp --dst-port 2049 manila-service
openstack security group rule create --protocol udp --dst-port 2049 manila-service
```

### 4. Mount thư mục Share vào máy Client

Đăng nhập vào máy Client bằng SSH và mount:

```bash
sudo apt update && sudo apt install nfs-common -y
mkdir -p ~/shared_files
sudo mount -t nfs -v <EXPORT_LOCATION_IP>:/shares/share-<ID> ~/shared_files
df -h | grep shared_files
```

# Ví dụ test thực tế đã thành công trên VM client 10.2.0.154

```bash
# Lấy Export path
openstack share show c7b608d0-dc4c-4f44-8122-1368df181179 -c path -f value
# VD: 10.254.0.26:/shares/share-54a611a3-23f6-4fd4-bcaa-080558328827

# Trên VM client:
sudo mkdir -p /mnt/test-nfs
sudo mount -t nfs 10.254.0.26:/shares/share-54a611a3-23f6-4fd4-bcaa-080558328827 /mnt/test-nfs
df -h | grep nfs
# -> 10.254.0.26:/shares/share-54a611a3-23f6-4fd4-bcaa-080558328827  974M     0  907M   0% /mnt/test-nfs

sudo touch /mnt/test-nfs/test_file.txt
ls -l /mnt/test-nfs/
# -> -rw-r--r-- 1 root root     0 Apr 28 14:55 test_file.txt
```
