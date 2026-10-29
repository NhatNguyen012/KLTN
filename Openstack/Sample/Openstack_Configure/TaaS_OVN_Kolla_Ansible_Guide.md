# Hướng dẫn TaaS với OVN trên OpenStack 2026.1 và Ubuntu 24.04.4 LTS

Tài liệu này cấu hình **Tap Mirror** của Tap-as-a-Service (TaaS) cho mô hình
Kolla-Ansible All-in-One trong
[`OpenStack_2026.1_Ubuntu_24.04.md`](OpenStack_2026.1_Ubuntu_24.04.md):

- Host: Ubuntu 24.04.4 LTS (Noble Numbat).
- OpenStack/Kolla-Ansible: 2026.1 Gazpacho.
- Neutron: ML2/OVN.
- Container engine: Docker.
- Inventory: `/etc/kolla/inventory/all-in-one`.
- External network mẫu: `public-net`, `172.31.250.0/24`.
- Tenant network mẫu: `private-net`, `10.20.0.0/24`.

> **Phạm vi:** OVN hỗ trợ API **Tap Mirror** để gửi bản sao traffic ra một
> tunnel GRE hoặc ERSPAN v1. Cặp API TaaS kiểu cũ là **Tap Service + Tap Flow**
> không được OVN backend hỗ trợ. Các lệnh `tap service create` và
> `tap flow create` chỉ phù hợp với backend ML2/OVS.

---

## Mục lục

1. [Cơ chế và các điểm cần sửa trong Kolla 2026.1](#1-cơ-chế-và-các-điểm-cần-sửa-trong-kolla-20261)
2. [Kiểm tra trước khi thay đổi](#2-kiểm-tra-trước-khi-thay-đổi)
3. [Bật và cấu hình TaaS cho OVN](#3-bật-và-cấu-hình-taas-cho-ovn)
4. [Reconfigure Neutron](#4-reconfigure-neutron)
5. [Xác minh control plane](#5-xác-minh-control-plane)
6. [Tạo hai VM để kiểm thử Tap Mirror](#6-tạo-hai-vm-để-kiểm-thử-tap-mirror)
7. [Bắt gói và chứng minh mirror hoạt động](#7-bắt-gói-và-chứng-minh-mirror-hoạt-động)
8. [Dọn tài nguyên kiểm thử](#8-dọn-tài-nguyên-kiểm-thử)
9. [Xử lý lỗi](#9-xử-lý-lỗi)
10. [Rollback](#10-rollback)
11. [Kết quả kiểm thử thực tế](#11-kết-quả-kiểm-thử-thực-tế)
12. [Tài liệu tham chiếu](#12-tài-liệu-tham-chiếu)

---

## 1. Cơ chế và các điểm cần sửa trong Kolla 2026.1

### 1.1 Tap Mirror trên OVN

Tap Mirror gắn vào logical switch port của VM nguồn. OVN tạo mirror với các thuộc tính sau trong Northbound DB:

| Thuộc tính | Ý nghĩa                                   |
| ------------ | ------------------------------------------- |
| `filter`   | `from-lport`, `to-lport` hoặc `both` |
| `type`     | `gre` hoặc `erspan`                    |
| `index`    | Tunnel ID do người dùng chọn            |
| `sink`     | IP ở đầu nhận tunnel                    |

Traffic được đóng gói tại chassis đang giữ port nguồn. Vì `sink` là endpoint underlay, host compute phải có route tới địa chỉ đó. Trong lab một NIC của tài liệu chính, floating IP của VM monitor thuộc `172.31.250.0/24`; host có route trực tiếp qua `br-exnat`, nên có thể dùng floating IP đó làm `--remote-ip`.

Không dùng fixed IP `10.20.0.x` làm `--remote-ip`: đó là địa chỉ overlay của tenant network và không phải endpoint underlay mà chassis có thể gửi tunnel trực tiếp tới.

### 1.2 Hai mặc định của Kolla 2026.1 chưa đủ cho OVN

Khi đặt `enable_neutron_taas: true`, role Neutron của Kolla-Ansible 2026.1:

1. thêm plugin `taas`, nhưng không thêm plugin `tapmirror` vào    `service_plugins`;
2. sinh provider mặc định là `TaasRpcDriver`, dành cho agent ML2/OVS, thay vì `TaasOvnDriver`.

Vì vậy cấu hình OVN cần đồng thời:

```ini
service_plugins = ovn-router,taas,tapmirror
```

và:

```ini
service_provider = TAAS:TAAS:neutron_taas.services.taas.service_drivers.ovn.taas_ovn.TaasOvnDriver:default
```

### 1.3 Vì sao provider phải có trong `/etc/kolla/config/neutron.conf`

Kolla 2026.1 chạy Neutron API, RPC server, periodic worker và OVN maintenance worker trong các container riêng. File tùy chỉnh chung `/etc/kolla/config/neutron.conf` được merge vào `neutron.conf` của tất cả các container này.

Ngược lại, `neutron_taas.conf` do role Kolla sinh chỉ được copy vào `neutron_server` (và vào Open vSwitch agent nếu backend đó được dùng). Nếu chỉ sửa `/etc/kolla/config/neutron/neutron_taas.conf`, các worker vẫn có thể nạp plugin `taas` nhưng không tìm thấy default provider, rồi restart loop.

Do đó tài liệu đặt `[service_providers]` trong file cấu hình dùng chung. Một override riêng cho `neutron_taas.conf` cũng được tạo để file chuyên biệt của `neutron_server` không còn ghi driver RPC sai với kiến trúc thực tế.

### 1.4 Thay đổi hướng mirror trong 2026.1

OpenStack 2026.1 có extension `tap-mirror-both-direction`. Cú pháp đúng là một dictionary `HƯỚNG=TUNNEL_ID`:

```console
--directions BOTH=101
```

`--directions BOTH` không hợp lệ vì thiếu tunnel ID; đây không phải lỗi parser của CLI. Nếu cloud không quảng bá extension mới, dùng hai mục riêng:

```console
--directions IN=101 --directions OUT=102
```

`IN` là traffic `to-lport` (đi vào VM), `OUT` là `from-lport` (đi ra từ VM). Tunnel ID phải chưa được Tap Mirror khác sử dụng trong project.

---

## 2. Kiểm tra trước khi thay đổi

### 2.1 Kích hoạt môi trường CLI

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
export OS_CLIENT_CONFIG_FILE=/etc/kolla/clouds.yaml
export OS_CLOUD=kolla-admin
export INVENTORY=/etc/kolla/inventory/all-in-one

openstack token issue
kolla-ansible --version
```

Nếu đã copy `/etc/kolla/clouds.yaml` vào `$HOME/.config/openstack/clouds.yaml`, không cần đặt `OS_CLIENT_CONFIG_FILE`.

### 2.2 Xác nhận đúng release, OVN và network

```bash
lsb_release -ds

grep -E \
  '^(openstack_release|kolla_base_distro_version|neutron_plugin_agent):' \
  /etc/kolla/globals.yml

sudo docker exec ovn_nb_db ovn-nbctl --version

openstack network show public-net
openstack network show private-net
ip route get 172.31.250.210
```

Kết quả yêu cầu:

- OS là `Ubuntu 24.04.4 LTS`.
- `openstack_release: "2026.1"`.
- `kolla_base_distro_version: "noble"`.
- `neutron_plugin_agent: "ovn"`.
- OVN tối thiểu 22.12; image Kolla 2026.1 mới hơn mức này.
- Host có route tới floating-IP pool qua `br-exnat`.

### 2.3 Xác nhận core services đang ổn định

```bash
openstack compute service list
openstack network agent list
openstack hypervisor list

sudo docker ps --format 'table {{.Names}}\t{{.Status}}' |
  grep -E 'neutron|ovn|openvswitch'
```

Không tiếp tục nếu core service đang lỗi từ trước; nếu không sẽ khó phân biệt lỗi nền với lỗi do TaaS.

### 2.4 Sao lưu cấu hình hiện tại

```bash
BACKUP_TAG="$(date +%Y%m%d-%H%M%S)"

sudo cp -a /etc/kolla/globals.yml \
  "/etc/kolla/globals.yml.before-taas-$BACKUP_TAG"

if [[ -f /etc/kolla/config/neutron.conf ]]; then
  sudo cp -a /etc/kolla/config/neutron.conf \
    "/etc/kolla/config/neutron.conf.before-taas-$BACKUP_TAG"
fi

if [[ -f /etc/kolla/config/neutron/neutron_taas.conf ]]; then
  sudo cp -a /etc/kolla/config/neutron/neutron_taas.conf \
    "/etc/kolla/config/neutron/neutron_taas.conf.before-taas-$BACKUP_TAG"
fi
```

---

## 3. Bật và cấu hình TaaS cho OVN

### 3.1 Bật TaaS trong `globals.yml`

Thêm vào `/etc/kolla/globals.yml`:

```yaml
# Tap-as-a-Service; phần override bên dưới chọn OVN Tap Mirror driver.
enable_neutron_taas: true
```

Kiểm tra chỉ có một khai báo hiệu lực:

```bash
grep -n '^enable_neutron_taas:' /etc/kolla/globals.yml
```

### 3.2 Tạo shared override cho mọi Neutron worker

Tạo hoặc chỉnh `/etc/kolla/config/neutron.conf`:

```ini
[DEFAULT]
# Bộ plugin đúng với globals.yml của tài liệu AIO.
# Nếu deployment đã bật thêm service plugin, phải giữ chúng trong danh sách.
service_plugins = ovn-router,taas,tapmirror

[service_providers]
# Đặt provider trong neutron.conf chung để API/RPC/periodic/maintenance worker đều thấy cùng một OVN driver.
service_provider = TAAS:TAAS:neutron_taas.services.taas.service_drivers.ovn.taas_ovn.TaasOvnDriver:default
```

> **Quan trọng:** đường dẫn ở đây là `/etc/kolla/config/neutron.conf`, không
> phải `/etc/kolla/config/neutron/neutron.conf`.

Danh sách ví dụ trên khớp deployment trong tài liệu chính. Nếu đang dùng thêm QoS, trunk, logging, port forwarding, FWaaS hoặc plugin khác, xem danh sách hiện tại rồi thêm `taas,tapmirror`, không xóa plugin cũ:

```bash
sudo grep '^service_plugins' /etc/kolla/neutron-server/neutron.conf
```

Không đặt `clear_config = true` trong section `[DEFAULT]` của `neutron.conf`; làm vậy có thể xóa các giá trị Neutron quan trọng do Kolla sinh.

### 3.3 Ghi đè provider trong file riêng của TaaS

Tạo thư mục và file `/etc/kolla/config/neutron/neutron_taas.conf`:

```bash
sudo install -d -m 0750 /etc/kolla/config/neutron
sudoedit /etc/kolla/config/neutron/neutron_taas.conf
```

Nội dung:

```ini
[service_providers]
# Directive của merge_configs: xóa provider TaasRpcDriver trong template Kolla.
clear_config = true
service_provider = TAAS:TAAS:neutron_taas.services.taas.service_drivers.ovn.taas_ovn.TaasOvnDriver:default
```

Không thêm:

```ini
[taas]
driver = ovn
```

Option `[taas] driver` là đường dẫn Python của agent-side driver dành cho ML2/OVS. OVN Tap Mirror được chọn bởi `service_provider` ở trên; chuỗi rút gọn `ovn` không phải giá trị hợp lệ của option agent driver.

### 3.4 Kiểm tra file trước khi reconfigure

```bash
grep -nE '^(enable_neutron_taas|neutron_plugin_agent):' \
  /etc/kolla/globals.yml

sudo sed -n '/^\[DEFAULT\]/,/^\[/p' /etc/kolla/config/neutron.conf
sudo sed -n '/^\[service_providers\]/,/^\[/p' \
  /etc/kolla/config/neutron.conf
sudo cat /etc/kolla/config/neutron/neutron_taas.conf
```

Không để block `[service_providers]` khác khai báo thêm default provider cho `TAAS`; Neutron sẽ từ chối khởi động nếu có nhiều provider mặc định.

---

## 4. Reconfigure Neutron

`reconfigure` của Kolla 2026.1 cũng chạy bootstrap Neutron, vì vậy migration của subproject `tap-as-a-service` sẽ được áp dụng khi service vừa được bật.

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
export INVENTORY=/etc/kolla/inventory/all-in-one

kolla-ansible prechecks -i "$INVENTORY" -t neutron
kolla-ansible reconfigure -i "$INVENTORY" -t neutron
```

Không chạy `neutron-db-manage` thủ công trước. Chỉ chạy thủ công khi đã xác định bootstrap container thất bại và log nêu rõ migration nào chưa được áp dụng.

---

## 5. Xác minh control plane

### 5.1 Container và log

```bash
for container in \
  neutron_server \
  neutron_rpc_server \
  neutron_periodic_worker \
  neutron_ovn_maintenance_worker
do
  sudo docker inspect \
    --format '{{.Name}} restart={{.RestartCount}} status={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' \
    "$container"
done

sudo grep -R -nE \
  'DefaultServiceProviderNotFound|Multiple default providers|Traceback|ERROR' \
  /var/log/kolla/neutron | tail -n 100
```

Các container phải là `running`; `neutron_server` phải `healthy`; restart count không được tiếp tục tăng.

### 5.2 Cấu hình đã render trong mọi worker

```bash
for container in \
  neutron_server \
  neutron_rpc_server \
  neutron_periodic_worker \
  neutron_ovn_maintenance_worker
do
  echo "[$container]"
  sudo docker exec "$container" \
    grep -E '^(service_plugins|service_provider)\s*=' \
    /etc/neutron/neutron.conf
done

sudo docker exec neutron_server \
  grep -E '^service_provider\s*=' /etc/neutron/neutron_taas.conf
```

Mọi `neutron.conf` phải có:

```text
service_plugins = ovn-router,taas,tapmirror
service_provider = TAAS:TAAS:...TaasOvnDriver:default
```

File `neutron_taas.conf` trong API container cũng phải trỏ đến `TaasOvnDriver`, không còn `TaasRpcDriver`.

### 5.3 Extension API

Cài phần mở rộng CLI cùng constraints của release trên deployment host:

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
python -m pip install \
  tap-as-a-service \
  -c https://releases.openstack.org/constraints/upper/2026.1
```

Nạp credentials và kiểm tra:

```bash
export OS_CLIENT_CONFIG_FILE=/etc/kolla/clouds.yaml
export OS_CLOUD=kolla-admin

openstack extension list --network -f value -c Alias -c Name |
  grep -E '(^| )(taas|taas-vlan-filter|tap-mirror|tap-mirror-both-direction)( |$)'

openstack tap mirror create --help
openstack tap mirror list
```

OpenStack 2026.1 phải quảng bá bốn alias:

```text
taas
taas-vlan-filter
tap-mirror
tap-mirror-both-direction
```

Nếu `tap-mirror` thiếu, kiểm tra `tapmirror` trong `service_plugins`. Nếu tất cả alias TaaS đều thiếu, kiểm tra migration và việc nạp plugin `taas`.

---

## 6. Tạo hai VM để kiểm thử Tap Mirror

Phần này dùng hai Ubuntu VM, mỗi VM chỉ cần **một port** trên `private-net`:

- `taas-source`: phát ICMP để tạo traffic cần mirror.
- `taas-monitor`: nhận tunnel GRE qua floating IP và chạy `tcpdump`.

Không cần thêm NIC `ens4` và không cần tự gán fixed IP trong guest. Neutron, DHCP và cloud-init cấu hình NIC chính; floating IP được OVN NAT tới chính port đó.

### 6.1 Chuẩn bị image, flavor và keypair

Tái sử dụng các tài nguyên của tài liệu chính nếu chúng đã tồn tại:

```bash
openstack image show Ubuntu-24.04
openstack flavor show m1.small
openstack keypair show lab-key
```

Nếu image chưa có, làm theo Mục 9.4 của tài liệu chính. Nếu keypair chưa có:

```bash
install -d -m 0700 "$HOME/.ssh"

if [[ ! -f "$HOME/.ssh/openstack_ed25519" ]]; then
  ssh-keygen -t ed25519 \
    -f "$HOME/.ssh/openstack_ed25519" \
    -C openstack-aio \
    -N ''
fi

openstack keypair create \
  --public-key "$HOME/.ssh/openstack_ed25519.pub" \
  lab-key
```

### 6.2 Security groups

```bash
openstack security group create taas-source-sg \
  --description 'TaaS test source: SSH and ICMP'

openstack security group rule create taas-source-sg \
  --ingress --ethertype IPv4 --protocol tcp --dst-port 22 \
  --remote-ip 172.31.250.1/32

openstack security group rule create taas-source-sg \
  --ingress --ethertype IPv4 --protocol icmp \
  --remote-ip 0.0.0.0/0

openstack security group create taas-monitor-sg \
  --description 'TaaS test monitor: SSH, ICMP and GRE'

openstack security group rule create taas-monitor-sg \
  --ingress --ethertype IPv4 --protocol tcp --dst-port 22 \
  --remote-ip 172.31.250.1/32

openstack security group rule create taas-monitor-sg \
  --ingress --ethertype IPv4 --protocol icmp \
  --remote-ip 0.0.0.0/0

openstack security group rule create taas-monitor-sg \
  --ingress --ethertype IPv4 --protocol 47 \
  --remote-ip 0.0.0.0/0
```

Protocol IP số 47 là GRE; đây không phải TCP/UDP port 47. Trong production, giới hạn `--remote-ip` theo địa chỉ underlay của compute nodes.

### 6.3 Tạo port và VM

Tạo file `taas-monitor-user-data.yaml` để cài `tcpdump`:

```yaml
#cloud-config
package_update: true
packages:
  - tcpdump
```

Tạo port rõ tên để không phải đoán port nào thuộc VM:

```bash
openstack port create taas-source-port \
  --network private-net \
  --security-group taas-source-sg

openstack port create taas-monitor-port \
  --network private-net \
  --security-group taas-monitor-sg
```

Boot đúng hai VM:

```bash
openstack server create taas-source \
  --flavor m1.small \
  --image Ubuntu-24.04 \
  --key-name lab-key \
  --port taas-source-port

openstack server create taas-monitor \
  --flavor m1.small \
  --image Ubuntu-24.04 \
  --key-name lab-key \
  --port taas-monitor-port \
  --user-data taas-monitor-user-data.yaml

for attempt in $(seq 1 120); do
  SOURCE_STATUS="$(openstack server show taas-source -f value -c status)"
  MONITOR_STATUS="$(openstack server show taas-monitor -f value -c status)"

  printf 'source=%s monitor=%s\n' "$SOURCE_STATUS" "$MONITOR_STATUS"

  if [[ "$SOURCE_STATUS" == ACTIVE && "$MONITOR_STATUS" == ACTIVE ]]; then
    break
  fi

  if [[ "$SOURCE_STATUS" == ERROR || "$MONITOR_STATUS" == ERROR ]]; then
    echo 'Có VM chuyển sang ERROR' >&2
    exit 1
  fi

  sleep 5
done

[[ "$SOURCE_STATUS" == ACTIVE && "$MONITOR_STATUS" == ACTIVE ]]
openstack server list
```

### 6.4 Gán floating IP

```bash
SOURCE_FIP="$(
  openstack floating ip create public-net \
    --port taas-source-port -f value -c floating_ip_address
)"

MONITOR_FIP="$(
  openstack floating ip create public-net \
    --port taas-monitor-port -f value -c floating_ip_address
)"

printf 'SOURCE_FIP=%s\nMONITOR_FIP=%s\n' "$SOURCE_FIP" "$MONITOR_FIP"
```

Đợi cloud-init hoàn tất:

```bash
SSH_OPTS=(
  -i "$HOME/.ssh/openstack_ed25519"
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=10
)

ssh "${SSH_OPTS[@]}" "ubuntu@$SOURCE_FIP" \
  'cloud-init status --wait'

ssh "${SSH_OPTS[@]}" "ubuntu@$MONITOR_FIP" \
  'cloud-init status --wait && command -v tcpdump'
```

### 6.5 Tạo Tap Mirror

Lấy port UUID và kiểm tra tunnel ID chưa được dùng:

```bash
SOURCE_PORT_ID="$(openstack port show taas-source-port -f value -c id)"

openstack tap mirror list
```

Tạo mirror hai chiều bằng extension mới của 2026.1:

```bash
openstack tap mirror create \
  --name taas-gre-both \
  --description 'OVN 2026.1 two-VM GRE verification' \
  --port "$SOURCE_PORT_ID" \
  --directions BOTH=101 \
  --remote-ip "$MONITOR_FIP" \
  --mirror-type gre
```

Kiểm tra API và OVN Northbound DB:

```bash
openstack tap mirror show taas-gre-both

sudo docker exec ovn_nb_db ovn-nbctl \
  --columns=name,filter,type,index,sink list Mirror

sudo docker exec ovn_nb_db ovn-nbctl \
  get Logical_Switch_Port "$SOURCE_PORT_ID" mirror
```

Kết quả mong đợi là một row `Mirror` có:

```text
filter : both
type   : gre
index  : 101
sink   : <MONITOR_FIP>
```

Tap Mirror API không có trường `status`; không chờ `ACTIVE`. Hai bằng chứng cần dùng là row/attachment trong OVN NB DB và packet GRE thực tế tại VM monitor.

---

## 7. Bắt gói và chứng minh mirror hoạt động

### 7.1 Bắt GRE trên VM monitor

Tìm NIC mang default route thay vì giả định luôn là `ens3`:

```bash
MONITOR_IF="$(
  ssh "${SSH_OPTS[@]}" "ubuntu@$MONITOR_FIP" \
    "ip -4 route show default | awk '{print \$5; exit}'"
)"

echo "$MONITOR_IF"
```

Bắt đầu capture ở background:

```bash
ssh "${SSH_OPTS[@]}" "ubuntu@$MONITOR_FIP" \
  "sudo timeout 12 tcpdump -ni '$MONITOR_IF' -vv 'ip proto 47'" \
  > /tmp/taas-gre-capture.txt 2>&1 &

CAPTURE_PID=$!
sleep 3
```

### 7.2 Tạo traffic trên VM source

```bash
ssh "${SSH_OPTS[@]}" "ubuntu@$SOURCE_FIP" \
  'ping -c 4 1.1.1.1'

wait "$CAPTURE_PID" || true
grep -B1 -A2 'proto ICMP' /tmp/taas-gre-capture.txt
tail -n 4 /tmp/taas-gre-capture.txt
```

Kết quả đạt khi:

- ping của `taas-source` có reply;
- `tcpdump` trên `taas-monitor` bắt được packet `GREv0`;
- tunnel key/index hiển thị tương ứng `101` (`0x65`) nếu phiên bản `tcpdump`
  giải mã trường này;
- row `Mirror` vẫn gắn với logical switch port nguồn.

Để quan sát cả traffic gốc và tunnel trên host trong lúc chẩn đoán:

```bash
sudo tcpdump -ni any -vv \
  "host $MONITOR_FIP and ip proto 47"
```

### 7.3 Diễn giải hướng

Với `BOTH=101`, cả echo request đi ra và echo reply đi vào port nguồn đều được mirror vào cùng tunnel. Nếu dùng hai hướng riêng, OVN tạo hai row Mirror:

```bash
openstack tap mirror create \
  --name taas-gre-in-out \
  --port "$SOURCE_PORT_ID" \
  --directions IN=101 \
  --directions OUT=102 \
  --remote-ip "$MONITOR_FIP" \
  --mirror-type gre
```

Chỉ dùng ví dụ thay thế này sau khi xóa `taas-gre-both`, vì tunnel ID 101 đang được mirror đầu tiên sử dụng.

---

## 8. Dọn tài nguyên kiểm thử

Xóa mirror trước port nguồn để driver có thể detach sạch khỏi OVN:

```bash
openstack tap mirror delete taas-gre-both

openstack server delete --wait taas-source taas-monitor

openstack floating ip delete "$SOURCE_FIP" "$MONITOR_FIP"

openstack port delete taas-source-port taas-monitor-port

openstack security group delete taas-source-sg taas-monitor-sg
```

Giữ lại image, flavor và keypair vì chúng được dùng chung với tài liệu triển
khai chính. Xác nhận không còn mirror hoặc VM test:

```bash
openstack tap mirror list
openstack server list

sudo docker exec ovn_nb_db ovn-nbctl list Mirror
```

---

## 9. Xử lý lỗi

### 9.1 Neutron worker restart loop

Triệu chứng thường gặp:

```text
DefaultServiceProviderNotFound
Service type TAAS does not have a default service provider
```

Kiểm tra provider có trong **main config của từng worker**:

```bash
for container in \
  neutron_server neutron_rpc_server neutron_periodic_worker \
  neutron_ovn_maintenance_worker
do
  sudo docker exec "$container" \
    grep -nA2 '^\[service_providers\]' /etc/neutron/neutron.conf
done
```

Nếu chỉ `neutron_server` có `/etc/neutron/neutron_taas.conf`, đó chưa phải cấu
hình đủ. Đặt provider trong `/etc/kolla/config/neutron.conf` rồi reconfigure.

### 9.2 API trả về 404 cho `/taas/tap_mirrors`

```bash
sudo docker exec neutron_server \
  grep '^service_plugins' /etc/neutron/neutron.conf

openstack extension list --network -f value -c Alias |
  grep -E 'taas|tap-mirror'
```

Danh sách phải chứa cả `taas` và `tapmirror`. `enable_neutron_taas` tự thêm
`taas`, nhưng Kolla 2026.1 không tự thêm `tapmirror`.

### 9.3 CLI không có nhóm lệnh `tap mirror`

Đây là lỗi ở deployment host, không phải Neutron API:

```bash
python -m pip show tap-as-a-service python-openstackclient openstacksdk
python -m pip install \
  tap-as-a-service \
  -c https://releases.openstack.org/constraints/upper/2026.1
```

Mở shell mới hoặc chạy lại `hash -r`, sau đó kiểm tra
`openstack tap mirror create --help`.

### 9.4 `BOTH` bị từ chối

```bash
openstack extension list --network -f value -c Alias |
  grep tap-mirror-both-direction
```

Nếu alias thiếu, dùng `IN=<id>` và `OUT=<id>` riêng. Nếu alias có nhưng CLI help chỉ ghi `IN`/`OUT`, vẫn thử đúng cú pháp `--directions BOTH=101`: client 17.0.0 dùng parser dictionary và server 2026.1 mới là phía xác thực key `BOTH`.

### 9.5 Có row Mirror nhưng VM monitor không thấy GRE

Kiểm tra theo thứ tự:

```bash
# 1. Route underlay từ host tới sink
ip route get "$MONITOR_FIP"

# 2. Floating IP gắn đúng monitor port
openstack floating ip list --port taas-monitor-port

# 3. Security group có IPv4 protocol 47 ingress
openstack security group rule list taas-monitor-sg

# 4. Mirror gắn đúng logical switch port nguồn
sudo docker exec ovn_nb_db ovn-nbctl \
  get Logical_Switch_Port "$SOURCE_PORT_ID" mirror

# 5. Bắt ở host để tách lỗi tunnel generation khỏi lỗi delivery vào guest
sudo tcpdump -ni any -vv "host $MONITOR_FIP and ip proto 47"
```

Không thêm IP thủ công lên một NIC phụ trong guest. Với bài test này monitor chỉ có một port; fixed IP, default route và floating-IP NAT đã đủ.

### 9.6 DB có mirror nhưng sai sink hoặc direction

Thông số `port_id`, `directions`, `remote_ip` và `mirror_type` không được API
cho sửa sau khi tạo. Xóa và tạo lại mirror:

```bash
openstack tap mirror delete taas-gre-both
# Chạy lại lệnh create với thông số đúng.
```

### 9.7 Xem log đúng container

```bash
sudo tail -n 200 /var/log/kolla/neutron/neutron-server.log
sudo tail -n 200 /var/log/kolla/neutron/neutron-rpc-server.log
sudo tail -n 200 /var/log/kolla/neutron/neutron-periodic-workers.log
sudo tail -n 200 /var/log/kolla/ovn/ovn-controller.log

sudo docker logs --tail 200 neutron_server
sudo docker logs --tail 200 neutron_periodic_worker
```

Tên file log có thể thay đổi theo patch level; dùng lệnh sau để liệt kê:

```bash
sudo find /var/log/kolla/neutron /var/log/kolla/ovn \
  -maxdepth 1 -type f -printf '%p\n' | sort
```

---

## 10. Rollback

Trong maintenance window:

1. xóa mọi Tap Mirror;
2. đặt `enable_neutron_taas: false` hoặc xóa dòng đã thêm;
3. khôi phục `/etc/kolla/config/neutron.conf` từ backup, hoặc xóa riêng
   `taas,tapmirror` và block `[service_providers]` đã thêm;
4. khôi phục/xóa override `neutron_taas.conf`;
5. reconfigure Neutron.

```bash
openstack tap mirror list -f value -c ID |
  xargs -r openstack tap mirror delete

kolla-ansible reconfigure \
  -i /etc/kolla/inventory/all-in-one \
  -t neutron

kolla-ansible check -i /etc/kolla/inventory/all-in-one
```

Không cần xóa bảng migration TaaS khỏi Neutron database khi tắt plugin; giữ schema giúp việc bật lại hoặc nâng cấp an toàn hơn.

---

## 11. Kết quả kiểm thử thực tế

Quy trình trong tài liệu đã được chạy end-to-end ngày **2026-09-03** trên
deployment đi kèm repository này.

| Hạng mục              | Kết quả quan sát                                                           |
| ----------------------- | ----------------------------------------------------------------------------- |
| Host OS                 | Ubuntu 24.04.4 LTS                                                            |
| Kolla-Ansible           | 22.1.1.dev6, branch`stable/2026.1`                                          |
| Image container         | `2026.1-ubuntu-noble`                                                       |
| OVN / OVS library       | OVN 26.03.0 / Open vSwitch 3.7.1                                              |
| Tap-as-a-Service        | 17.0.0                                                                        |
| Neutron workers         | API, RPC, periodic, maintenance và metadata đều healthy; restart count 0   |
| `kolla-ansible check` | `ok=42`, `changed=0`, `failed=0`                                        |
| API extensions          | `taas`, `taas-vlan-filter`, `tap-mirror`, `tap-mirror-both-direction` |
| VM nguồn               | `10.20.0.102`, floating IP `172.31.250.239`                               |
| VM monitor              | `10.20.0.168`, floating IP `172.31.250.249`                               |
| Source port             | `0f3523da-a0ec-4b60-aeb5-5cb3e3f726ba`                                      |
| Tap Mirror              | `b8f3790c-0f72-42ae-8675-21a24b9c274b`, `BOTH=101`, GRE                   |

OVN Northbound DB đã tạo và gắn row sau vào logical switch port nguồn:

```text
filter : both
index  : 101
name   : tm_both_b8f379
sink   : "172.31.250.249"
type   : gre
```

VM nguồn ping `1.1.1.1` bốn lần, nhận đủ bốn reply và không mất packet. Trên
`ens3` của VM monitor, `tcpdump` bắt được cả hai chiều của ICMP bên trong GRE:

```text
172.31.250.1 > 10.20.0.168: GREv0, key=0x65
10.20.0.102 > 1.1.1.1: ICMP echo request

172.31.250.1 > 10.20.0.168: GREv0, key=0x65
1.1.1.1 > 10.20.0.102: ICMP echo reply
```

`0x65` là giá trị hexadecimal của tunnel ID 101. Điều này xác nhận đồng thời API, OVN NB DB, attachment vào source port, GRE delivery qua floating IP và mirror hai chiều đều hoạt động.

Sau phép thử, mirror, hai VM, hai floating IP, hai port và hai security group test đã được xóa. Image `Ubuntu-24.04`, flavor và keypair `lab-key` được giữ lại để tái sử dụng. Cấu hình TaaS/OVN vẫn đang bật.

---

## 12. Tài liệu tham chiếu

1. [OpenStack 2026.1 documentation](https://docs.openstack.org/2026.1/)
2. [Kolla-Ansible 2026.1 quick start](https://docs.openstack.org/kolla-ansible/2026.1/user/quickstart.html)
3. [Kolla-Ansible: advanced configuration overrides](https://docs.openstack.org/kolla-ansible/2026.1/admin/advanced-configuration.html)
4. [Tap-as-a-Service 2025.1 release note: OVN Tap Mirror support and OVN 22.12 minimum](https://docs.openstack.org/releasenotes/tap-as-a-service/2025.1.html)
5. [OpenStack Networking API: Tap Mirrors](https://docs.openstack.org/api-ref/network/v2/index.html#tap-mirrors)
6. [OpenStackClient TaaS commands](https://docs.openstack.org/python-openstackclient/latest/cli/command-objects/network/v2/taas/index.html)
7. [Neutron advanced network API feature matrix](https://docs.openstack.org/neutron/2026.1/admin/api-feature-matrix.html)
8. [neutron-lib 2026.1: `tap-mirror-both-direction`](https://docs.openstack.org/releasenotes/neutron-lib/2026.1.html)
9. [Tap-as-a-Service source, stable/2026.1](https://opendev.org/openstack/tap-as-a-service/src/branch/stable/2026.1)
10. [Kolla-Ansible source, stable/2026.1](https://opendev.org/openstack/kolla-ansible/src/branch/stable/2026.1)
