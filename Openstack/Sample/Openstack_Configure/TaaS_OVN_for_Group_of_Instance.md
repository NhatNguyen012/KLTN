# TaaS/OVN cho một nhóm instance trên OpenStack 2026.1

Tài liệu này mô tả cách giám sát một **nhóm instance** bằng OVN Tap Mirror trên
Ubuntu 24.04.4 LTS và OpenStack 2026.1. Phần cài đặt và cấu hình TaaS nền tảng
nằm trong
[`TaaS_OVN_Kolla_Ansible_Guide.md`](TaaS_OVN_Kolla_Ansible_Guide.md); tài liệu
này chỉ tập trung vào mô hình nhiều workload port, một hoặc nhiều sensor và
vòng lặp reconciliation.

Kết luận đã được kiểm chứng trên deployment Kolla-Ansible AIO hiện tại:

```text
Neutron port tag
       │
       ▼
Mirror Controller (một active writer)
       │
       ├── một Tap Mirror cho mỗi workload port
       ├── một GRE key riêng cho mỗi mirror
       └── kiểm tra API + OVN + packet thực tế
       │
       ▼
Network Sensor VM / sensor shard
```

OVN TaaS không cung cấp resource kiểu “mirror instance group”. Tap Mirror gắn
với một Neutron port, tương ứng một OVN Logical Switch Port. Vì vậy port tag
định nghĩa membership, còn controller riêng chuyển desired state đó thành các
Tap Mirror.

---

## Mục lục

1. [Kết quả thẩm định kỹ thuật](#1-kết-quả-thẩm-định-kỹ-thuật)
2. [Kiến trúc đúng cho group](#2-kiến-trúc-đúng-cho-group)
3. [Điều kiện trước khi thử](#3-điều-kiện-trước-khi-thử)
4. [Quy tắc membership và tunnel ID](#4-quy-tắc-membership-và-tunnel-id)
5. [PoC: hai workload dùng chung một sensor](#5-poc-hai-workload-dùng-chung-một-sensor)
6. [Xác minh control plane và data plane](#6-xác-minh-control-plane-và-data-plane)
7. [Thử thay đổi membership](#7-thử-thay-đổi-membership)
8. [Thiết kế Mirror Controller](#8-thiết-kế-mirror-controller)
9. [Trùng packet east-west và correlation](#9-trùng-packet-east-west-và-correlation)
10. [MTU, monitoring network và bảo mật](#10-mtu-monitoring-network-và-bảo-mật)
11. [Scale và nhiều sensor](#11-scale-và-nhiều-sensor)
12. [Dọn tài nguyên PoC](#12-dọn-tài-nguyên-poc)
13. [Kết quả kiểm thử thực tế](#13-kết-quả-kiểm-thử-thực-tế)
14. [Quan hệ với Stable/Menu.md](#14-quan-hệ-với-stablemenumd)
15. [Tài liệu tham chiếu](#15-tài-liệu-tham-chiếu)

---

## 1. Kết quả thẩm định kỹ thuật

Các ý chính trong `temp.md` là đúng, nhưng cần các giới hạn sau:

| Nhận định | Kết luận |
| --- | --- |
| Mirror từng port thay vì chỉ bắt ở gateway | Đúng; thấy traffic đi vào/ra workload port, gồm east-west và north-south của port đó |
| Dùng Neutron port tag làm group | Đúng; đây là desired-state metadata, không phải resource TaaS native |
| Nhiều source dùng chung một sensor IP | Đúng; mỗi mirror vẫn cần tunnel ID riêng |
| Dùng GRE key để map packet về instance | Đúng; phải lưu thêm project, network, port, server và khoảng thời gian hiệu lực |
| Tự thêm/xóa mirror khi membership đổi | Đúng; cần một controller reconciliation, persistent state và single writer |
| Một Floating IP làm sink trong AIO | Đúng cho functional PoC, nhưng không bảo đảm full-size packet nếu đường sensor thiếu MTU headroom |
| Một sensor luôn đủ cho group nhỏ | Không thể kết luận chỉ từ số VM; phải đo bandwidth, packet/s, burst, CPU và packet loss |

Ba điểm không được bỏ qua:

1. `openstack tap mirror create` trả về thành công chưa đủ chứng minh OVN đã
   lập trình dataplane. Tap Mirror không có trường `status`.
2. Nếu hai đầu của cùng một flow đều thuộc group và đều dùng `BOTH`, một packet
   east-west xuất hiện dưới key của cả hai port.
3. Tap Mirror API chỉ chọn port, hướng, tunnel ID, remote IP và tunnel type. Alias
   `taas-vlan-filter` thuộc mô hình Tap Flow cũ; nó không cung cấp five-tuple
   filter cho Tap Mirror.

Không dùng Nova Server Group để thay cho monitoring group. Nova Server Group
điều khiển affinity/anti-affinity khi schedule VM, không biểu diễn port nào cần
mirror. Một VM nhiều NIC chỉ được giám sát trên các port đã gắn tag.

---

## 2. Kiến trúc đúng cho group

```text
                         OpenStack API
                              ▲
                              │
                       Mirror Controller
                 discover / allocate / reconcile
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
        workload-A       workload-B       workload-C
        Neutron port     Neutron port     Neutron port
        tag=apt-monitor  tag=apt-monitor  tag=apt-monitor
        GRE key 201      GRE key 202      GRE key 203
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                    routable monitoring path
                              ▼
                       Network Sensor VM
                   tcpdump / Zeek / Suricata
                              │
                   events + key/port mapping
                              ▼
                 correlation / feature / model
```

Gateway-only capture nhìn rõ north-south traffic nhưng có thể không thấy
lateral movement giữa hai VM cùng logical switch. Mirror workload port cho
phép quan sát traffic đi vào và đi ra port đó. Tuy nhiên không nên diễn giải
nó thành bằng chứng rằng mọi packet bị drop ở mọi stage của OVN hoặc security
group đều chắc chắn được thu; phải thử riêng denied traffic nếu use case cần
khẳng định này.

Một Tap Mirror có đúng một `remote_ip`. Có hai chiến lược nhiều sensor:

- **sharding:** mỗi source port đi tới một sensor; tiết kiệm bandwidth;
- **replication:** một source port có nhiều Tap Mirror đi tới nhiều sensor;
  mỗi mirror cần key riêng và làm tăng traffic mirror tương ứng.

Không sửa OVN Northbound DB trực tiếp để gắn một row Mirror vào nhiều port.
Làm như vậy bỏ qua Neutron database, policy và cleanup lifecycle.

---

## 3. Điều kiện trước khi thử

### 3.1 Xác nhận cloud đang sẵn sàng

Các lệnh START trong [`../Stable/Menu.md`](../Stable/Menu.md) đã quản lý động
tất cả Kolla container unit. Nếu OpenStack đang chạy, chỉ cần kiểm tra:

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh

openstack token issue

sudo docker ps -a \
  --format '{{.Names}}\t{{.Status}}' |
  grep -E 'Exited|Restarting|unhealthy' || echo 'Không có container lỗi'
```

Không chạy lại `kolla-ansible reconfigure` chỉ để thêm một instance vào
monitoring group.

### 3.2 Xác nhận TaaS và port tags

```bash
openstack extension list --network -f value -c Alias |
  grep -E '^(standard-attr-tag|taas|tap-mirror|tap-mirror-both-direction)$'

openstack tap mirror list
openstack port list --tags apt-monitor

sudo docker exec neutron_server \
  grep '^service_plugins' /etc/neutron/neutron.conf
```

Deployment này phải quảng bá ít nhất `taas`, `tap-mirror`,
`tap-mirror-both-direction` và extension tag. Main Neutron config phải chứa
`ovn-router,taas,tapmirror` và provider phải là `TaasOvnDriver` như tài liệu
cấu hình nền tảng.

### 3.3 Resource dùng trong PoC

```bash
openstack image show Ubuntu-24.04
openstack flavor show m1.small
openstack keypair show lab-key
openstack network show private-net
openstack network show public-net
```

PoC dưới đây tạo ba VM: hai workload và một sensor. Nó dùng Floating IP làm
sink để phù hợp AIO hiện tại. Mục 10 giải thích vì sao production cần một
monitoring provider network riêng.

---

## 4. Quy tắc membership và tunnel ID

### 4.1 Điều kiện để một port được reconcile

Tag một workload port:

```bash
openstack port set --tag apt-monitor <PORT_ID>
```

Một port chỉ đủ điều kiện khi đồng thời thỏa:

```text
tag contains apt-monitor
device_owner == compute:nova
status == ACTIVE
binding_host_id is not empty
port_id != sensor port ID
OVN Logical_Switch_Port exists
```

Truy vấn candidate rồi kiểm tra binding:

```bash
mapfile -t CANDIDATE_PORTS < <(
  openstack port list \
    --tags apt-monitor \
    --device-owner compute:nova \
    --status ACTIVE \
    -f value -c ID |
  sort
)

for port_id in "${CANDIDATE_PORTS[@]}"; do
  openstack port show "$port_id" \
    -f value -c status -c device_owner -c binding_host_id

  sudo docker exec ovn_nb_db \
    ovn-nbctl --if-exists get Logical_Switch_Port "$port_id" _uuid
done
```

Port có tag nhưng còn `DOWN`, chưa có `device_owner` hoặc chưa bind host không
được tạo mirror. Đây là trường hợp bình thường khi port được tạo trước VM.

### 4.2 Tunnel ID

Mỗi direction của mỗi Tap Mirror phải dùng một tunnel ID chưa bị mirror khác
sử dụng trong phạm vi API mà controller quản lý. API hiện tại trả HTTP 409 nếu
phát hiện conflict, nhưng controller vẫn phải:

- chạy một active writer cho mỗi allocation domain;
- giữ persistent mapping `port_id -> tunnel_id`;
- bắt và retry HTTP 409;
- dành một range riêng, ví dụ `10000-19999`, không cấp ID ngẫu nhiên mù;
- không tái sử dụng ID ngay nếu telemetry lịch sử còn dùng mapping cũ.

Nếu một sensor nhận traffic từ nhiều project, key phải unique tại chính sensor,
không chỉ unique trong từng project. GRE packet không mang OpenStack project ID.

---

## 5. PoC: hai workload dùng chung một sensor

### 5.1 Tạo security group

```bash
openstack security group create taas-group-workload-sg \
  --description 'Group TaaS verification workloads'

openstack security group rule create taas-group-workload-sg \
  --ingress --ethertype IPv4 --protocol tcp --dst-port 22 \
  --remote-ip 172.31.250.1/32

openstack security group rule create taas-group-workload-sg \
  --ingress --ethertype IPv4 --protocol icmp --remote-ip 0.0.0.0/0

openstack security group create taas-group-sensor-sg \
  --description 'Group TaaS verification sensor'

openstack security group rule create taas-group-sensor-sg \
  --ingress --ethertype IPv4 --protocol tcp --dst-port 22 \
  --remote-ip 172.31.250.1/32

openstack security group rule create taas-group-sensor-sg \
  --ingress --ethertype IPv4 --protocol icmp --remote-ip 0.0.0.0/0

openstack security group rule create taas-group-sensor-sg \
  --ingress --ethertype IPv4 --protocol 47 --remote-ip 0.0.0.0/0
```

Protocol IP 47 là GRE, không phải TCP/UDP port 47. Rule mở từ `0.0.0.0/0` chỉ
phù hợp PoC. Production phải giới hạn theo địa chỉ egress thực của compute
chassis trên monitoring network.

### 5.2 Tạo port và VM

Chỉ hai source port mang tag; sensor port tuyệt đối không mang tag group:

```bash
openstack port create \
  --network private-net \
  --security-group taas-group-workload-sg \
  --tag apt-monitor \
  taas-group-source-a-port

openstack port create \
  --network private-net \
  --security-group taas-group-workload-sg \
  --tag apt-monitor \
  taas-group-source-b-port

openstack port create \
  --network private-net \
  --security-group taas-group-sensor-sg \
  taas-group-sensor-port
```

Tạo cloud-init cho sensor:

```bash
tee /tmp/taas-group-sensor-user-data.yaml >/dev/null <<'EOF'
#cloud-config
package_update: true
packages:
  - tcpdump
EOF
```

Boot ba VM:

```bash
openstack server create taas-group-source-a \
  --flavor m1.small --image Ubuntu-24.04 --key-name lab-key \
  --port taas-group-source-a-port

openstack server create taas-group-source-b \
  --flavor m1.small --image Ubuntu-24.04 --key-name lab-key \
  --port taas-group-source-b-port

openstack server create taas-group-sensor \
  --flavor m1.small --image Ubuntu-24.04 --key-name lab-key \
  --port taas-group-sensor-port \
  --user-data /tmp/taas-group-sensor-user-data.yaml

for attempt in $(seq 1 120); do
  ACTIVE_COUNT="$({
    openstack server list --name '^taas-group-' -f value -c Status |
      grep -c '^ACTIVE$'
  } || true)"

  [[ "$ACTIVE_COUNT" -eq 3 ]] && break

  openstack server list --name '^taas-group-'
  sleep 5
done

[[ "$ACTIVE_COUNT" -eq 3 ]]
```

### 5.3 Cấp Floating IP cho functional test

```bash
SOURCE_A_FIP="$(
  openstack floating ip create public-net \
    --port taas-group-source-a-port -f value -c floating_ip_address
)"

SOURCE_B_FIP="$(
  openstack floating ip create public-net \
    --port taas-group-source-b-port -f value -c floating_ip_address
)"

SENSOR_FIP="$(
  openstack floating ip create public-net \
    --port taas-group-sensor-port -f value -c floating_ip_address
)"

printf 'SOURCE_A_FIP=%s\nSOURCE_B_FIP=%s\nSENSOR_FIP=%s\n' \
  "$SOURCE_A_FIP" "$SOURCE_B_FIP" "$SENSOR_FIP"
```

Xác nhận cloud-init:

```bash
SSH_OPTS=(
  -i "$HOME/.ssh/openstack_ed25519"
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=10
)

ssh "${SSH_OPTS[@]}" "ubuntu@$SENSOR_FIP" \
  'cloud-init status --wait && command -v tcpdump'
```

### 5.4 Discover group và tạo hai mirror

```bash
PORT_A_ID="$(
  openstack port show taas-group-source-a-port -f value -c id
)"
PORT_B_ID="$(
  openstack port show taas-group-source-b-port -f value -c id
)"
SENSOR_PORT_ID="$(
  openstack port show taas-group-sensor-port -f value -c id
)"

openstack port list \
  --tags apt-monitor \
  --device-owner compute:nova \
  --status ACTIVE \
  -f table -c ID -c Name -c Status -c Tags

MIRROR_A_ID="$(
  openstack tap mirror create \
    --name "tm-apt-$PORT_A_ID" \
    --description 'managed-by=taas-group-controller;group=apt-monitor' \
    --port "$PORT_A_ID" \
    --directions BOTH=201 \
    --remote-ip "$SENSOR_FIP" \
    --mirror-type gre \
    -f value -c id
)"

MIRROR_B_ID="$(
  openstack tap mirror create \
    --name "tm-apt-$PORT_B_ID" \
    --description 'managed-by=taas-group-controller;group=apt-monitor' \
    --port "$PORT_B_ID" \
    --directions BOTH=202 \
    --remote-ip "$SENSOR_FIP" \
    --mirror-type gre \
    -f value -c id
)"

printf 'MIRROR_A_ID=%s\nMIRROR_B_ID=%s\n' \
  "$MIRROR_A_ID" "$MIRROR_B_ID"
```

Tên giúp operator đọc log, nhưng tên Tap Mirror không phải khóa ownership đáng
tin cậy và không được giả định unique. Controller phải lưu UUID trả về từ API.

---

## 6. Xác minh control plane và data plane

### 6.1 API layer

```bash
openstack tap mirror list -f table

openstack tap mirror list -f json |
  jq -r '.[] | [.ID, .Name, .Port, .Directions, ."Remote IP"] | @tsv'
```

Phải có đúng một object controller-owned cho mỗi desired port, đúng key, sink
và type. Không dùng số object API làm bằng chứng duy nhất rằng mirror healthy.

### 6.2 OVN layer

```bash
sudo docker exec ovn_nb_db ovn-nbctl \
  --columns=_uuid,name,filter,type,index,sink list Mirror

for port_id in "$PORT_A_ID" "$PORT_B_ID"; do
  printf '%s: ' "$port_id"
  sudo docker exec ovn_nb_db \
    ovn-nbctl get Logical_Switch_Port "$port_id" mirror
done
```

Kết quả mong đợi:

```text
port A -> Mirror(filter=both, index=201, sink=<SENSOR_FIP>)
port B -> Mirror(filter=both, index=202, sink=<SENSOR_FIP>)
```

API object tồn tại nhưng thiếu OVN row hoặc thiếu attachment phải được đánh dấu
`DEGRADED`. Sau grace period, controller nên xóa/recreate object của chính nó
và phát cảnh báo. Việc này đặc biệt quan trọng vì Tap Mirror API không có
`status`.

### 6.3 Packet layer

Lấy NIC default-route của sensor:

```bash
MONITOR_IF="$(
  ssh "${SSH_OPTS[@]}" "ubuntu@$SENSOR_FIP" \
    'ip -4 route show default' |
  awk '{print $5; exit}'
)"

SOURCE_B_FIXED="$(
  openstack port show taas-group-source-b-port -f json |
    jq -r '.fixed_ips[0].ip_address'
)"
```

Bắt GRE ở background:

```bash
ssh "${SSH_OPTS[@]}" "ubuntu@$SENSOR_FIP" \
  "sudo timeout 18 tcpdump -U -ni '$MONITOR_IF' \
     -w /tmp/taas-group.pcap 'ip proto 47'" &

CAPTURE_PID=$!
sleep 3

ssh "${SSH_OPTS[@]}" "ubuntu@$SOURCE_A_FIP" \
  'ping -c 3 -s 111 1.1.1.1'

ssh "${SSH_OPTS[@]}" "ubuntu@$SOURCE_B_FIP" \
  'ping -c 3 -s 222 1.0.0.1'

ssh "${SSH_OPTS[@]}" "ubuntu@$SOURCE_A_FIP" \
  "ping -c 3 -s 333 '$SOURCE_B_FIXED'"

wait "$CAPTURE_PID" || true

ssh "${SSH_OPTS[@]}" "ubuntu@$SENSOR_FIP" \
  'sudo tcpdump -nn -vv -r /tmp/taas-group.pcap' |
  grep -E 'GREv0|ICMP echo'
```

Phải thấy cả `key=0xc9` (201) và `key=0xca` (202), cùng inner ICMP của hai
source. Đừng chỉ kiểm tra packet GRE; xác nhận inner source/destination và hai
hướng mong đợi.

---

## 7. Thử thay đổi membership

### 7.1 Xóa port B khỏi desired state

```bash
openstack port unset --tag apt-monitor "$PORT_B_ID"

openstack port list \
  --tags apt-monitor \
  --device-owner compute:nova \
  --status ACTIVE \
  -f value -c ID
```

Trong một controller thật, chỉ xóa mirror có UUID trong persistent ownership
database. PoC đã lưu UUID lúc tạo nên xóa trực tiếp bằng ID đó:

```bash
openstack tap mirror delete "$MIRROR_B_ID"

sudo docker exec ovn_nb_db \
  ovn-nbctl get Logical_Switch_Port "$PORT_B_ID" mirror
```

Attachment của B phải là `[]`; mirror A phải còn nguyên.

### 7.2 Thêm lại port B

```bash
openstack port set --tag apt-monitor "$PORT_B_ID"

MIRROR_B_ID="$(
  openstack tap mirror create \
    --name "tm-apt-$PORT_B_ID" \
    --description 'managed-by=taas-group-controller;group=apt-monitor' \
    --port "$PORT_B_ID" \
    --directions BOTH=202 \
    --remote-ip "$SENSOR_FIP" \
    --mirror-type gre \
    -f value -c id
)"
```

Controller dùng lại key 202 vì persistent mapping của B vẫn còn hiệu lực.

### 7.3 Xác nhận conflict được chặn

Thử dùng lại key của B cho A phải trả HTTP 409:

```bash
openstack tap mirror create \
  --name tm-conflict-test \
  --port "$PORT_A_ID" \
  --directions BOTH=202 \
  --remote-ip "$SENSOR_FIP" \
  --mirror-type gre
```

Kết quả mong đợi:

```text
ConflictException: 409 ... Tap Mirror with tunnel_id 202 already exists
```

Không dựa hoàn toàn vào check này để chống race: quá trình “scan ID rồi insert”
không thay thế single-writer allocation và persistent database.

---

## 8. Thiết kế Mirror Controller

### 8.1 Desired, API và actual state

Controller phải phân biệt bốn lớp:

```text
Desired state  = eligible ports có group tag
API state      = Tap Mirror objects do controller sở hữu
OVN state      = Mirror rows + LSP attachments
Observed state = GRE keys sensor vừa nhìn thấy
```

Một reconciliation cycle an toàn:

1. lấy distributed lock hoặc xác nhận mình là active leader;
2. list tagged ports và lọc các điều kiện ở Mục 4;
3. đọc persistent allocation/ownership database;
4. list Tap Mirror API objects;
5. tạo mirror còn thiếu bằng key đã cấp;
6. với immutable field sai, tạo replacement có kiểm soát rồi xóa object cũ;
7. xóa object chỉ khi UUID thuộc controller và port không còn desired;
8. operator-side verifier so sánh API với OVN row/LSP attachment;
9. sensor heartbeat báo key nào có/không có traffic trong cửa sổ quan sát;
10. xuất mapping versioned cho correlation pipeline.

`port_id`, `directions`, `remote_ip` và `mirror_type` không sửa được qua API;
chỉ `name` và `description` update được. Thay đổi sink, type hoặc key phải
replace mirror.

### 8.2 Persistent state tối thiểu

```text
controller_id
group_id
project_id
network_id
port_id
server_id
fixed_ips
mac_address
tunnel_id
direction
sensor_id
sensor_remote_ip
tap_mirror_id
generation
valid_from
valid_until
last_api_check
last_ovn_check
last_packet_seen
health
```

Không join telemetry chỉ bằng fixed IP vì nhiều tenant có thể dùng cùng CIDR.
Không tái sử dụng key mà không đóng `valid_until` của mapping cũ.

### 8.3 Ownership và quyền

Khuyến nghị metadata dễ đọc:

```text
name        = mc-<group>-<port-short-id>
description = managed-by=<controller-id>;group=<group>;port=<uuid>;generation=<n>
```

Nhưng source of truth vẫn là controller database chứa Tap Mirror UUID. Tên
không bảo đảm unique và description có thể bị sửa. Controller không bao giờ
xóa mirror chỉ vì nó có cùng prefix.

Dùng application credential/service account có quyền tối thiểu trong project.
Giới hạn ai được gắn monitoring tag và ai được chọn `remote_ip`, vì mirror tới
sink tùy ý có thể trở thành đường rò dữ liệu.

### 8.4 Failure handling

- HTTP 409: cấp key khác hoặc retry mapping đã biết sau khi refresh state.
- Port chưa bind: backoff, không tạo mirror.
- API object thiếu OVN row: `DEGRADED`, retry có giới hạn rồi replace.
- Sink không route được: giữ control-plane state nhưng cảnh báo data-plane down.
- Neutron tạm unavailable: exponential backoff, không xóa hàng loạt desired
  state từ một lần list lỗi.
- Controller mất database: dừng mutation; không suy đoán ownership từ name rồi
  xóa resource.

Ở quy mô rất lớn cần theo dõi thêm rủi ro implementation hiện tại sinh tên OVN
Mirror từ sáu ký tự đầu UUID của Tap Mirror. OVN yêu cầu tên row unique, nên
collision dù hiếm có thể trở nên đáng kể khi có hàng nghìn mirror. Luôn kiểm tra
OVN actual state và cân nhắc upstream fix trước khi mở rộng tới quy mô đó.

---

## 9. Trùng packet east-west và correlation

Giả sử A và B đều dùng `BOTH`:

```text
A -> B request
  ├── key A: OUT khỏi port A
  └── key B: IN vào port B

B -> A reply
  ├── key B: OUT khỏi port B
  └── key A: IN vào port A
```

Đây không phải lỗi; hai observation biểu diễn góc nhìn của hai endpoint. Nhưng
nếu pipeline đếm connection/byte mà không de-duplicate, feature sẽ bị nhân đôi.

Chọn một trong ba policy:

- giữ cả hai observation để phục vụ endpoint-context và đánh dấu `vantage_port`;
- de-duplicate theo flow/packet fingerprint, time window và direction;
- chỉ mirror `OUT` cho một experiment chấp nhận mất full inbound payload.

Broadcast/multicast có thể tạo amplification lớn hơn. Capacity planning phải
dùng cả Mbps, packets/s, packet size distribution và tỷ lệ duplicate.

Mapping gửi tới correlation nên chứa:

```text
GRE key -> project -> network -> port -> server -> IP/MAC
        -> sensor -> direction -> valid_from/valid_until
```

Host telemetry và network telemetry phải đồng bộ clock, tốt nhất bằng chrony,
và giữ timestamp precision phù hợp với cửa sổ correlation.

---

## 10. MTU, monitoring network và bảo mật

### 10.1 Floating IP chỉ là functional path trong AIO

Tap Mirror `remote_ip` là endpoint underlay/routable từ compute chassis. Fixed
IP overlay của sensor không tự động là một endpoint phù hợp. Trong AIO này,
Floating IP hoạt động vì host có route tới `public-net` và OVN NAT packet về
sensor port.

Tuy nhiên sensor đang ở cùng `private-net` MTU 1442. GRE/IPv4 có key trong phép
đo thực tế cần thêm 42 byte so với inner L3 packet:

```text
20 byte outer IPv4 + 8 byte GRE/key + 14 byte inner Ethernet = 42 byte
```

Kết quả đo:

```text
inner L3 1400 -> GRE outer 1442 -> sensor nhận được
inner L3 1401 -> GRE outer 1443 -> sensor không nhận được
inner L3 1442 -> workload ping thành công, mirror không tới sensor
```

Vì vậy small-packet test thành công không chứng minh full-fidelity capture.

Kiểm tra gần MTU:

```bash
PRIVATE_MTU="$(
  openstack network show private-net -f value -c mtu
)"

# ICMP payload = IP packet size - 20 byte IPv4 - 8 byte ICMP.
PING_PAYLOAD=$((PRIVATE_MTU - 28))

ssh "${SSH_OPTS[@]}" "ubuntu@$SOURCE_A_FIP" \
  "ping -M do -c 3 -s '$PING_PAYLOAD' '$SOURCE_B_FIXED'"
```

Chạy đồng thời packet capture ở sensor và xác nhận packet lớn thực sự xuất
hiện, không chỉ xác nhận ping nguồn thành công.

### 10.2 Thiết kế production

Ưu tiên provider network monitoring riêng:

```text
Compute-1 ─┐
Compute-2 ─┼── isolated monitoring provider network ── Sensor
Compute-N ─┘
```

Yêu cầu:

- mọi chassis có workload được monitor đều route tới sensor sink;
- monitoring-path MTU lớn hơn workload inner L3 MTU cộng toàn bộ encapsulation
  overhead;
- với workload MTU 1442, GRE/IPv4 measurement trên cần ít nhất 1484;
- với tenant MTU 1500, dùng jumbo MTU và đo lại thay vì giả định;
- ERSPAN, IPv6 outer hoặc VLAN có overhead khác, phải test riêng;
- kiểm tra packet loss, NIC drops và capture drops dưới load.

### 10.3 Security

GRE không cung cấp encryption hay authentication. Production cần:

- VLAN/provider network monitoring cô lập;
- protocol 47 ingress chỉ từ compute egress addresses;
- egress ACL/routing chỉ tới approved sensors;
- encryption ở lớp transport khác nếu đi qua network không tin cậy;
- RBAC cho controller credential, PCAP, Zeek logs và key mapping;
- retention policy vì packet capture có thể chứa credential và dữ liệu nhạy cảm.

---

## 11. Scale và nhiều sensor

Không đặt ngưỡng chỉ theo số instance. Một sensor phù hợp hay không phụ thuộc:

```text
mirrored throughput
packets per second
burst rate
average/small-packet distribution
east-west duplication
GRE/ERSPAN overhead
sensor vCPU/RAM/NIC
Zeek/Suricata rules and packet loss
PCAP write throughput
```

Sharding khuyến nghị trong multi-node:

```text
Compute/rack A workloads -> Sensor A
Compute/rack B workloads -> Sensor B
Compute/rack C workloads -> Sensor C
                         -> normalized events/features -> central fusion
```

Controller cần lưu `sensor_id` trong allocation và có một allocation domain
key riêng cho mỗi sensor. Khi chuyển một port sang sensor khác, tạo generation
mới và giữ lịch sử thời gian của mapping.

Replication tới hai sensor tạo hai Tap Mirror cho cùng source port, hai key và
xấp xỉ gấp đôi mirrored bandwidth. Không mô tả replication như một thay đổi
đơn giản của `remote_ip` vì field này immutable và mỗi mirror chỉ có một sink.

---

## 12. Dọn tài nguyên PoC

Xóa mirror trước source port để OVN detach sạch. Chạy trong cùng shell đã lưu
`MIRROR_A_ID`/`MIRROR_B_ID`; nếu đổi shell, lấy lại đúng UUID từ output Mục 6
và kiểm tra bằng `openstack tap mirror show` trước khi xóa:

```bash
[[ -n "${MIRROR_A_ID:-}" && -n "${MIRROR_B_ID:-}" ]]
openstack tap mirror delete "$MIRROR_A_ID" "$MIRROR_B_ID"

openstack server delete --wait \
  taas-group-source-a taas-group-source-b taas-group-sensor

for port_name in \
  taas-group-source-a-port \
  taas-group-source-b-port \
  taas-group-sensor-port
do
  mapfile -t FIP_IDS < <(
    openstack floating ip list --port "$port_name" -f value -c ID
  )

  if (( ${#FIP_IDS[@]} )); then
    openstack floating ip delete "${FIP_IDS[@]}"
  fi
done

openstack port delete \
  taas-group-source-a-port \
  taas-group-source-b-port \
  taas-group-sensor-port

openstack security group delete \
  taas-group-workload-sg taas-group-sensor-sg
```

Hậu kiểm:

```bash
openstack tap mirror list -f value -c Name |
  grep '^tm-apt-' || true
openstack server list --all-projects -f value -c Name |
  grep '^taas-group-' || true
openstack port list -f value -c Name |
  grep '^taas-group-' || true

sudo docker exec ovn_nb_db \
  ovn-nbctl --columns=name,index,sink list Mirror
```

Không dùng prefix/name cleanup trên production. Cleanup tự động chỉ được xóa
UUID nằm trong controller ownership database.

---

## 13. Kết quả kiểm thử thực tế

Quy trình được chạy ngày **2026-09-07** trên OpenStack 2026.1 AIO hiện tại.

| Thành phần | Giá trị |
| --- | --- |
| Host | Ubuntu 24.04.4 LTS |
| TaaS / OVN / OVS | 17.0.0 / 26.03.0 / 3.7.1 |
| Source A | server `8a916d55-e182-493c-8d44-3750ad4a62f0`, port `f8a5d965-ccdd-457f-aa71-489eef8c514f`, `10.20.0.170`, FIP `172.31.250.218`, key 202 |
| Source B | server `3eeadeb2-bac1-4446-98f7-0e6969805392`, port `0e8e9f23-2dfc-499a-99f4-d4d665b56f3e`, `10.20.0.109`, FIP `172.31.250.243`, key 201 |
| Sensor | server `c4c57e77-4e34-4540-a774-fe503680b1ea`, port `e9bd1ae6-967d-4a7d-a2f7-fa4fa903e092`, `10.20.0.160`, FIP/sink `172.31.250.204` |

Key của A/B trong bảng là allocation của lần chạy thực tế; thứ tự khác ví dụ
ở Mục 5 nhưng không thay đổi nguyên tắc mỗi source port dùng một key riêng.

Các kết quả đạt:

- port tag query trả đúng hai workload port và không trả sensor;
- hai Tap Mirror cùng sink được tạo với key 201/202;
- OVN NB có hai row `filter=both`, đúng index/sink và gắn đúng hai LSP;
- source A ping `1.1.1.1`, source B ping `1.0.0.1`, mỗi phép thử 3/3 reply;
- sensor thấy cả `key=0xc9` và `key=0xca` cùng inner ICMP hai chiều;
- A ping B 3/3 và cùng east-west packet xuất hiện dưới key của cả A và B;
- dùng lại key 201 bị API từ chối bằng HTTP 409;
- bỏ tag B, reconcile xóa đúng mirror B và OVN attachment trở thành `[]`;
- thêm lại tag B, mirror/key 201 được tạo lại và OVN attachment phục hồi;
- một tagged port chưa bind làm tổng tagged port tăng từ 2 lên 3 nhưng query
  `device_owner=compute:nova,status=ACTIVE` vẫn chỉ trả hai eligible port;
- private network MTU là 1442: GRE mirror nhận tới inner L3 1400/outer 1442,
  nhưng không nhận inner L3 1401 trở lên dù workload ping vẫn thành công;
- `tcpdump` báo 0 packet dropped trong functional fan-in capture.

Sau kiểm thử, hai mirror, ba VM, ba floating IP, ba port, hai security group và
unbound test port đã được xóa. OVN Mirror table và mọi resource có prefix
`taas-group-` đều trống. Image, flavor, keypair và cấu hình TaaS nền tảng được
giữ nguyên.

---

## 14. Quan hệ với Stable/Menu.md

Chỉ bật TaaS không yêu cầu sửa [`../Stable/Menu.md`](../Stable/Menu.md). TaaS
chạy trong các Neutron process hiện có, còn Menu đã start/stop động toàn bộ
Kolla container unit.

Khi Mirror Controller trở thành một systemd service/container thật, lúc đó mới
cập nhật Menu:

1. START controller sau `openstack token issue` và extension checks;
2. controller phải retry/backoff khi Neutron chưa ready;
3. hiển thị last successful reconcile, leader state và degraded mirror count;
4. STOP controller trước khi dừng Kolla units để nó không hiểu API outage là
   desired state rỗng rồi thực hiện cleanup sai.

Hiện tại host chưa cài custom Mirror Controller, nên không thay đổi Menu.

---

## 15. Tài liệu tham chiếu

1. [OpenStack Networking API: Tap Mirrors](https://docs.openstack.org/api-ref/network/v2/index.html#tap-mirrors)
2. [OpenStackClient 2026.1: port tags](https://docs.openstack.org/python-openstackclient/2026.1/cli/command-objects/port.html)
3. [OpenStackClient: TaaS commands](https://docs.openstack.org/python-openstackclient/latest/cli/command-objects/network/v2/taas/index.html)
4. [TaaS 2025.1 release notes: OVN Tap Mirror support](https://docs.openstack.org/releasenotes/tap-as-a-service/2025.1.html)
5. [Tap-as-a-Service stable/2026.1 source](https://opendev.org/openstack/tap-as-a-service/src/branch/stable/2026.1)
6. [OVN Northbound database Mirror table](https://www.ovn.org/support/dist-docs/ovn-nb.5.html)
7. [OVN `ovn-nbctl` mirror commands](https://www.ovn.org/support/dist-docs/ovn-nbctl.8.html)
