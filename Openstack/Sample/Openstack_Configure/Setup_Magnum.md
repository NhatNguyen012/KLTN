# Triển khai Magnum + Barbican (Container Infrastructure + Key Manager) — OpenStack 2025.2, Kolla-Ansible

## Bối cảnh

Tài liệu này bổ sung dịch vụ **Magnum** và **Barbican** cho hệ thống đã mô tả trong [Newest_Openstack_Config.md](./Newest_Openstack_Config.md):

- **OpenStack:** 2025.2 Flamingo
- **Triển khai:** Kolla-Ansible `stable/2025.2`, All-in-One, Ubuntu 24.04
- **Mạng:** OVN, provider network `public-net` (172.10.10.0/24), WiFi + `br-exnat` + NAT
- **Đã bật sẵn:** Heat (`enable_heat: "yes"`) — **bắt buộc** để Magnum điều phối stack cụm qua Orchestration

**Tham khảo chính thức:**

- [Magnum Installation Guide (PDF)](https://docs.openstack.org/magnum/latest/doc-magnum.pdf)
- [Barbican Installation / User Guide (PDF](https://docs.openstack.org/barbican/latest/doc-barbican.pdf)

Magnum gồm **magnum-api** (REST) và **magnum-conductor** (làm việc với Heat, Nova, Neutron, Glance, Cinder…). **Barbican** (Key Manager) được Magnum khuyến nghị để lưu chứng chỉ TLS cho API Kubernetes (`cert_manager_type = barbican` trong [doc-magnum.pdf](https://docs.openstack.org/magnum/latest/doc-magnum.pdf) mục *certificates*). Trên Kolla-Ansible, database, Keystone, RabbitMQ, HAProxy và container image được quản lý tự động; phần thủ công chủ yếu là **bật role** (Magnum + Barbican), **kéo image**, **reconfigure**, rồi **ảnh Glance + ClusterTemplate + Cluster**.

---

## 1. Kiến trúc và phụ thuộc (rút gọn theo tài liệu Magnum)

| Thành phần            | Vai trò với Magnum                                                                                                                                                                                                                                                                    |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Keystone**      | Xác thực API; trust/domain cho tài khoản cụm (theo mô hình Magnum)                                                                                                                                                                                                               |
| **Glance**        | Ảnh nút Kubernetes (Fedora CoreOS / Ubuntu tùy driver) với metadata `os_distro` đúng                                                                                                                                                                                            |
| **Nova**          | Máy ảo master/worker                                                                                                                                                                                                                                                                  |
| **Neutron (OVN)** | Mạng cụm, floating IP (nếu bật)                                                                                                                                                                                                                                                     |
| **Cinder**        | Ổ cho container runtime / etcd tùy template (`docker-volume-size`, `volume-driver`)                                                                                                                                                                                               |
| **Heat**          | Tạo/cập nhật/xóa tài nguyên cụm qua template                                                                                                                                                                                                                                     |
| **Barbican**      | Lưu chứng chỉ TLS cho cụm; Magnum dùng **barbican** làm `cert_manager_type` khi dịch vụ được bật (khuyến nghị theo tài liệu Magnum). Nếu tắt Barbican, Kolla đặt **x509keypair** (chứng chỉ trong DB Magnum) — chỉ nên dùng cho lab tối giản |

**Lưu ý môi trường laptop (32 GB RAM):** mỗi cụm Kubernetes tiêu tốn nhiều RAM/CPU; nên bắt đầu với **1 master + 0–1 worker**, flavor nhỏ, và chỉ bật Magnum khi đã ổn định các dịch vụ khác.

---

## 2. Điều kiện tiên quyết

1. OpenStack đã deploy theo [Newest_Openstack_Config.md](./Newest_Openstack_Config.md), `openstack service list` có **heat** và các dịch vụ lõi.
2. Đã có **external network** `public-net` và subnet (gateway 172.10.10.1, pool floating như tài liệu gốc).
3. **Cinder** và **Glance** hoạt động (upload image, tạo volume).
4. Virtualenv Kolla đã kích hoạt: `source ~/kolla-venv/bin/activate`.
5. (Khuyến nghị) Local registry `192.168.1.2:4000` — sau khi bật Magnum và Barbican cần **pull/push** thêm image container tương ứng (magnum-*, barbican-*) như quy trình mirror trong [Newest_Openstack_Config.md](./Newest_Openstack_Config.md) §9.4.1.
6. **Không có Octavia** trong `openstack service list`: với cụm Kubernetes một master, **bắt buộc** tạo ClusterTemplate với **`--no-master-lb`** (hoặc đảm bảo không bật master LB). Nếu không, template Heat của Magnum sẽ cố tạo Load Balancer qua Octavia và stack sẽ lỗi (xem §3.4 và §8).

---

## 3. Cấu hình Kolla-Ansible

### 3.1 Bật Magnum và Barbican trong `globals.yml`

Mở `/etc/kolla/globals.yml` và **bật** cả hai (trong [Newest_Openstack_Config.md](./Newest_Openstack_Config.md) Magnum đang comment, Barbican đang `no`):

```yaml
# Container Infrastructure + chứng chỉ TLS qua Key Manager
enable_magnum: "yes"
enable_barbican: "yes"
```

**Giữ nguyên** (đã đúng cho Magnum):

```yaml
enable_heat: "yes"
```

Với Kolla-Ansible 2025.2, khi `enable_barbican: "yes"`, template `magnum.conf` của role Magnum đặt **`cert_manager_type = barbican`** trong section `[certificates]` (đúng hướng dẫn cài đặt Magnum trong [doc-magnum.pdf](https://docs.openstack.org/magnum/latest/doc-magnum.pdf)). Chi tiết vận hành và chính sách secret xem [doc-barbican.pdf](https://docs.openstack.org/barbican/latest/doc-barbican.pdf).

**Mặc định Kolla** cho Barbican (simple crypto plugin, không HSM) thường đủ cho lab; tinh chỉnh sâu (PKCS11, v.v.) nằm ngoài phạm vi tài liệu này — tham chiếu PDF Barbican.

### 3.2 (Tùy chọn) Ghi đè `globals.yml` cho trust cụm

Trong Kolla `stable/2025.2`, mặc định `enable_cluster_user_trust: False`. Nếu sau này bạn cần luồng trust đầy đủ cho user cụm (theo hướng dẫn nâng cao trong tài liệu Magnum), có thể thêm vào `globals.yml` (sau khi đọc kỳ hạn chế bảo mật):

```yaml
enable_cluster_user_trust: True
```

Chỉ bật khi có lý do cụ thể; mặc định để `False` vẫn tạo được nhiều cụm lab.

### 3.3 (Tùy chọn) File cấu hình Magnum / Barbican tùy chỉnh

Chỉ thêm khi cần lệch khỏi mặc định Kolla:

```bash
sudo mkdir -p /etc/kolla/config/magnum
sudo nano /etc/kolla/config/magnum/magnum.conf
```

Ví dụ (minh họa — thường **không cần** vì Kolla đã set `trustee_keystone_interface = public` để các nút cụm gọi Keystone qua endpoint public):

```ini
[DEFAULT]
# debug = true
```

Barbican: chỉ tạo file trong `/etc/kolla/config/barbican/` nếu bạn đọc [doc-barbican.pdf](./Openstack_Whitepaper/doc-barbican.pdf) và cần plugin hoặc policy tùy chỉnh.

Sau mọi thay đổi file trong `/etc/kolla/config/`, luôn chạy `reconfigure` (mục 4).

### 3.4 Octavia (chưa triển khai) và Load Balancer cho master API

Tài liệu Magnum ghi nhận **LBaaS / Octavia** cho **API control plane** khi dùng load balancer phía trước các master. Trên môi trường **không có** dịch vụ Octavia (`openstack service list` không có loại `load-balancer`), Heat stack của cụm Kubernetes **không được** yêu cầu tạo Octavia load balancer.

- Sau khi tạo: `openstack coe cluster template show <tên-template>` — kiểm tra trường tương ứng master LB là **disabled** / **False** (tùy phiên bản client).

Khi sau này triển khai **Octavia** đầy đủ, có thể tạo template mới với master LB bật cho HA multi-master (phạm vi ngoài tài liệu này).

---

## 4. Triển khai và cập nhật dịch vụ

### 4.1 Prechecks và pull image

```bash
source ~/kolla-venv/bin/activate

# Đảm bảo veth-peer tồn tại (theo Newest_Openstack_Config.md §4.3)
ip link show veth-peer || {
  sudo ip link add veth-ext type veth peer name veth-peer
  sudo ip link set veth-ext up
  sudo ip link set veth-peer up
}

kolla-ansible prechecks -i /etc/kolla/ansible/inventory/all-in-one
kolla-ansible pull -i /etc/kolla/ansible/inventory/all-in-one
```

### 4.1.1 Retag và push image Magnum / Barbican vào local registry

Khi `globals.yml` dùng **`docker_registry: "192.168.1.2:4000"`** (như [Newest_Openstack_Config.md](./Newest_Openstack_Config.md) §9.4.1), sau `kolla-ansible pull` các image nằm trên host với prefix `quay.io/openstack.kolla/...`. Cần **tag lại** sang registry nội bộ rồi **push** — cùng mô hình với đoạn mirror trong tài liệu gốc (mục *Lần đầu duy nhất*, quanh dòng 1334–1367).

**Bước A — Pull từ Quay (nếu registry local chưa có sẵn layer):** tạm comment trong `/etc/kolla/globals.yml`:

```yaml
# docker_registry: "192.168.1.2:4000"
# docker_pull_policy: "missing"
```

Sau đó:

```bash
source ~/kolla-venv/bin/activate
kolla-ansible pull -i /etc/kolla/ansible/inventory/all-in-one
```

**Bước B — Chỉ mirror các image Magnum và Barbican** (khớp `openstack_release` **2025.2**; đổi biến nếu bạn dùng tag khác):

```bash
LOCAL_REG="192.168.1.2:4000"
RELEASE_TAG="2025.2"

docker images --format '{{.Repository}}:{{.Tag}}' \
| grep "^quay.io/openstack.kolla/.*:${RELEASE_TAG}$" \
| grep -E 'magnum|barbican' \
| while read -r image; do
  image_name=$(echo "$image" | sed 's|^quay.io/||')
  new_image="${LOCAL_REG}/${image_name}"
  echo "Dang xu ly: $new_image"
  docker tag "$image" "$new_image"
  docker push "$new_image"
done
```

**Kiểm tra nhanh** (trên host hoặc `curl` catalog registry):

```bash
docker images | grep -E 'magnum|barbican' | grep 192.168.1.2
# hoặc
curl -s "http://${LOCAL_REG}/v2/_catalog" | jq
```

**Bước C — Bật lại** `docker_registry` và `docker_pull_policy: "missing"` trong `globals.yml`.

**Bước D — Áp dụng cấu hình** để container kéo image từ local (giống tài liệu gốc):

```bash
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one
```

> **Ghi chú:** Nếu bạn đã chạy vòng lặp mirror **toàn bộ** image `quay.io/openstack.kolla/.*:2025.2` trong [Newest_Openstack_Config.md](./Newest_Openstack_Config.md) §9.4.1 thì Magnum/Barbican đã nằm trong registry; khi đó chỉ cần `pull` + `reconfigure` sau khi bật `enable_magnum` / `enable_barbican`, không bắt buộc lặp Bước B.

### 4.2 Reconfigure (cụm đã chạy) hoặc deploy (lần đầu)

**Hệ đã deploy OpenStack:** thêm Barbican rồi Magnum (thứ tự gợi ý: Barbican trước để endpoint và DB sẵn sàng; gộp tag một lần cũng được):

```bash
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one \
  --tags barbican,magnum,haproxy,keystone
```

Nếu Ansible báo lỗi thiếu database hoặc user cho Barbican/Magnum trên cloud **đã deploy từ trước**, chạy **một lần** triển khai role đầy đủ (tạo DB/bootstrap) rồi mới `reconfigure` tùy tag:

```bash
kolla-ansible deploy -i /etc/kolla/ansible/inventory/all-in-one --tags barbican
kolla-ansible deploy -i /etc/kolla/ansible/inventory/all-in-one --tags magnum
```

Hoặc một lần `kolla-ansible deploy` / `reconfigure` **không** `--tags` để tránh bỏ sót bước MariaDB/RabbitMQ liên quan (chậm hơn nhưng an toàn).

Nếu muốn an toàn hơn (áp dụng toàn bộ cấu hình):

```bash
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one
```

**Lần đầu cài toàn stack** (chưa có OpenStack): dùng `kolla-ansible deploy` như tài liệu gốc; Magnum sẽ được đưa vào cùng lần deploy nếu `enable_magnum: "yes"` trước khi deploy.

### 4.3 Post-deploy và kiểm tra nhanh

```bash
kolla-ansible post-deploy -i /etc/kolla/ansible/inventory/all-in-one
source /etc/kolla/admin-openrc.sh

openstack service list | grep -iE 'magnum|barbican|key-manager'
openstack endpoint list --service container-infra
openstack endpoint list --service key-manager

docker ps --format '{{.Names}}\t{{.Status}}' | grep -iE 'magnum|barbican'
```

Kiểm tra trạng thái nội bộ (theo CLI Guide trong PDF):

```bash
docker exec magnum_api magnum-status upgrade check
```

Xem log khi lỗi:

```bash
sudo tail -n 200 /var/log/kolla/magnum/magnum-api.log
sudo tail -n 200 /var/log/kolla/magnum/magnum-conductor.log
```

---

## 5. Cài đặt client và xác minh API

```bash
pip install python-magnumclient
# hoặc dùng openstack cli nếu plugin coe đã có trong bản client của bạn
openstack coe cluster template list
openstack coe cluster list
```

---

## 6. Chuẩn bị tài nguyên OpenStack cho cụm

### 6.1 Keypair

```bash
openstack keypair create --public-key ~/.ssh/openstack_key.pub mykey
```

### 6.2 Flavor

Flavor đủ RAM/disk cho ảnh Kubernetes (ví dụ tối thiểu lab):

```bash
openstack flavor create --ram 8192 --disk 40 --vcpus 4 m1.magnum-medium
```

Điều chỉnh theo ảnh thực tế bạn dùng.

### 6.3 Xác nhận external network

```bash
openstack network show public-net
openstack subnet list --network public-net
```

Tên mạng ngoài truyền vào `ClusterTemplate` phải khớp (thường `public-net`).

---

## 7. Ảnh Glance tương thích Magnum / Kubernetes

Magnum yêu cầu ảnh có **metadata** phù hợp driver COE (thường `os_distro`). Chi tiết bảng ảnh và phiên bản Kubernetes nằm trong [doc-magnum.pdf](https://docs.openstack.org/magnum/latest/doc-magnum.pdf) phần *Kubernetes → Images*.

**Ví dụ** (Fedora CoreOS — phổ biến trong tài liệu Magnum; cần tải file `.qcow2` đúng phiên bản hỗ trợ bởi bản Magnum 2025.2 của bạn từ kho ảnh OpenStack/Magnum upstream):

```bash
cd /etc/kolla/ansible/inventory

wget https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/38.20230806.3.0/x86_64/fedora-coreos-38.20230806.3.0-openstack.x86_64.qcow2.xz

unxz fedora-coreos-38.20230806.3.0-openstack.x86_64.qcow2.xz

openstack image create k8s-fedora-magnum-38 \
  --disk-format qcow2 \
  --container-format bare \
  --file fedora-coreos-38.20230806.3.0-openstack.x86_64.qcow2 \
  --property os_distro=fedora-coreos \
  --property os_version=38 \
  --property container_format=bare \
  --public
```

**Lưu ý Kolla 2025.2:** template `magnum.conf` của Kolla có thể vô hiệu hóa một số driver Cluster API mặc định nếu không cấu hình kubeconfig nâng cao. Với lab, thường dùng **driver Kubernetes cổ điển (Heat)** và ảnh được Magnum hỗ trợ rõ ràng cho release đó. Nếu `cluster template create` báo lỗi driver, kiểm tra log `magnum-conductor` và tài liệu release Magnum 2025.2.

---

## 8. Tạo ClusterTemplate và Cluster (ví dụ)

Điều chỉnh tên image, flavor, keypair và nhãn mạng cho khớp môi trường bạn (mạng ngoài trong lab của bạn là **`public-net`** / subnet `172.10.10.0/24`).

```bash
source /etc/kolla/admin-openrc.sh

openstack coe cluster template create k8s-template-aio-v6 \
  --image k8s-fedora-magnum-38 \
  --master-flavor m1.magnum-master \
  --flavor m1.magnum-master \
  --external-network public-net \
  --dns-nameserver 8.8.8.8 \
  --keypair mykey \
  --network-driver calico \
  --volume-driver cinder \
  --floating-ip-enabled \
  --coe kubernetes \
  --labels kube_tag=v1.28.9-rancher1,\
container_runtime=containerd,\
cgroup_driver=cgroupfs,\
cloud_provider_enabled=true,\
cinder_csi_enabled=true,\
cloud_provider_tag=v1.27.3,\
cinder_csi_plugin_tag=v1.27.3,\
k8s_keystone_auth_tag=v1.27.3,\
magnum_auto_healer_tag=v1.27.3,\
octavia_ingress_controller_tag=v1.27.3,\
calico_tag=v3.26.4,\
calico_mtu=1400,\
containerd_version=1.6.31,\
containerd_tarball_sha256=75afb9b9674ff509ae670ef3ab944ffcdece8ea9f7d92c42307693efa7b6109d

openstack coe cluster template show k8s-template-aio-v6

# Lưu ý tương thích CLI:
# Một số bản python-openstackclient không hỗ trợ cờ "--no-master-lb".
# Với các bản này, KHÔNG truyền cờ đó khi create; sau đó kiểm tra:
# openstack coe cluster template show k8s-template-aio-v6 -c master_lb_enabled -f value
# Kỳ vọng cho môi trường không Octavia: False.

openstack coe cluster create k8s-aio-v6 \
  --cluster-template k8s-template-aio-v6 \
  --master-count 1 \
  --node-count 1

Theo dõi:

```bash
openstack coe cluster show k8s-aio-v6
openstack stack list
```

Khi trạng thái `CREATE_COMPLETE`, lấy cấu hình (tùy phiên bản client):

```bash
openstack coe cluster config <Cluster ID> --dir ~/k8s-config
export KUBECONFIG=~/k8s-config/config
kubectl get nodes -o wide
kubectl get pods -A -o wide
watch -n 10 'kubectl get pods -A | grep -Ei "c	rash|error|backoff|pending|fail"'
while true; do kubectl get pods -A | grep -Ei "crash|error|backoff|pending|fail"; echo ""; sleep 10; done >> /mnt/shared_data/NT524/temp1.md

```

---

## 10. Xử lý sự cố thường gặp

| Hiện tượng                               | Hướng xử lý                                                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Prechecks lỗi interface                    | Đảm bảo `veth-peer` UP trước khi chạy Ansible (§4.1).                                                                                                                                               |
| Cụm kẹt `CREATE_IN_PROGRESS`            | `openstack stack show <stack>`; log `heat-engine`, `magnum-conductor`.                                                                                                                                 |
| Heat/Octavia/LB khi tạo cụm               | Cloud**không có Octavia**: tạo lại ClusterTemplate với **`--no-master-lb`**, không dùng `--master-lb-enabled` (§3.4, §8).                                                           |
| Nút không pull image / không ra Internet | Kiểm tra router, SNAT, DNS, security group; laptop: NAT `172.10.10.0/24` → WiFi.                                                                                                                         |
| Lỗi TLS / kubeconfig / Barbican            | Xác nhận `enable_barbican: "yes"` và endpoint **key-manager**; log `barbican-api`; xem *TLS* / *certificates* trong [doc-magnum.pdf](https://docs.openstack.org/magnum/latest/doc-magnum.pdf). |
| Thiếu image trên local registry           | Chạy lại `kolla-ansible pull` và mirror tag magnum + barbican về `192.168.1.2:4000`.                                                                                                                 |

---

## 11. Tóm tắt checklist

- [ ] `enable_magnum: "yes"` và **`enable_barbican: "yes"`** trong `/etc/kolla/globals.yml`; `enable_heat: "yes"`.
- [ ] `prechecks` → `pull` (magnum + barbican) → `reconfigure --tags barbican,magnum,haproxy,keystone` (hoặc full `reconfigure` / `deploy`).
- [ ] `post-deploy`, kiểm tra endpoint **`container-infra`** và **`key-manager`**, container `magnum_*` và `barbican_*`.
- [ ] Cài `python-magnumclient`, upload ảnh Glance đúng `os_distro`.
- [ ] Tạo flavor, keypair; **ClusterTemplate có `--no-master-lb`** nếu không có Octavia; tạo Cluster; kiểm tra Heat stack và `kubectl`.
- [ ] (Tùy chọn) `enable_cluster_user_trust`; Octavia chỉ khi cần master LB / HA.

---

## 12. Tài liệu tham khảo

- [https://docs.openstack.org/magnum/latest/doc-magnum.pdf](https://docs.openstack.org/magnum/latest/doc-magnum.pdf) — Magnum (Installation, User Guide, Admin, CADF, certificates).
- [https://docs.openstack.org/barbican/latest/doc-barbican.pdf](https://docs.openstack.org/barbican/latest/doc-barbican.pdf) — Barbican (cài đặt, vận hành, policy).
- [Newest_Openstack_Config.md](./Newest_Openstack_Config.md) — Triển khai nền Kolla 2025.2, mạng, Heat, ELK.
- Mã nguồn: [openstack/magnum](https://opendev.org/openstack/magnum), [openstack/barbican](https://opendev.org/openstack/barbican); client: [python-magnumclient](https://opendev.org/openstack/python-magnumclient).
