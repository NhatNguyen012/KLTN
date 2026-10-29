# Hướng dẫn Triển khai OpenStack 2025.2 Flamingo với Kolla-Ansible trên Ubuntu 24.04 LTS

## 📋 Mục lục

1. [Tổng quan Kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Yêu cầu Phần cứng và Phần mềm](#2-yêu-cầu-phần-cứng-và-phần-mềm)
3. [Chuẩn bị Hệ điều hành Ubuntu 24.04](#3-chuẩn-bị-hệ-điều-hành-ubuntu-2404)
4. [Cấu hình Mạng cho Laptop (Single-NIC WiFi + veth Bridge)](#4-cấu-hình-mạng-cho-laptop-single-nic-wifi--veth-bridge)
5. [Cài đặt Docker và Dependencies](#5-cài-đặt-docker-và-dependencies)
6. [Cài đặt Kolla-Ansible](#6-cài-đặt-kolla-ansible)
7. [Cấu hình Kolla-Ansible](#7-cấu-hình-kolla-ansible)
8. [Cấu hình CADF Audit Logging (Bắt buộc cho Đề tài 10)](#8-cấu-hình-cadf-audit-logging-bắt-buộc-cho-đề-tài-10)
9. [Triển khai OpenStack](#9-triển-khai-openstack)
10. [Thiết lập Bridge/NAT và Mạng OpenStack](#10-thiết-lập-bridgenat-và-mạng-openstack)
11. [Cấu hình ELK cho ML (Elasticsearch + Kibana + Filebeat)](#11-cấu-hình-elk-cho-ml-elasticsearch--kibana--filebeat)
12. [Cấu hình Manila và CephFS (thực hiện sau khi OpenStack ổn định)](#12-cấu-hình-manila-và-cephfs-thực-hiện-sau-khi-openstack-ổn-định)
13. [Cấu hình Object Storage và Ceph RGW](#13-cấu-hình-object-storage-và-ceph-rgw)
14. [Kiến trúc mô hình triển khai (ASCII)](#14-kiến-trúc-mô-hình-triển-khai-ascii)

---

## 1. Tổng quan Kiến trúc

### 1.1 Mô tả Đề tài 10

Đề tài này xây dựng hệ thống **Anomaly Detection** dựa trên ML/DL để phát hiện:

- **Brute-force IAM:** Nhiều lần đăng nhập thất bại → thành công bất thường
- **Lateral Movement:** VM/user truy cập tuần tự qua nhiều hosts/services
- **Credential Misuse:** API calls từ IP/geo bất thường
- **Privilege Escalation:** Chuỗi API calls kết thúc với thay đổi quyền

### 1.2 Các thành phần chính

| Thành phần            | Mô tả              | Vai trò trong Đề tài 10                                        |
| ----------------------- | -------------------- | ------------------------------------------------------------------ |
| **Keystone**      | Identity Service     | Nguồn logs authentication chính                                  |
| **Nova**          | Compute Service      | Logs instance actions                                              |
| **Neutron**       | Networking Service   | Logs network events, port changes                                  |
| **Glance**        | Image Service        | Logs image access                                                  |
| **Cinder**        | Block Storage        | Logs storage operations                                            |
| **Elasticsearch** | Log Storage & Search | Lưu trữ và query logs cho ML                                    |
| **Filebeat**      | Log Collector        | Thu thập logs từ `/var/log/kolla/` và gửi vào Elasticsearch |

---

## 2. Yêu cầu Phần cứng và Phần mềm

### 2.1 Phần cứng thực tế (Laptop All-in-One)

> **Lưu ý:** Hệ thống này triển khai trên laptop cá nhân, chỉ có 1 NIC WiFi.
> Mạng external cho OpenStack sẽ được mô phỏng bằng **veth pair + Linux bridge + NAT** (xem Mục 4).

```
┌───────────────────────────────────────────────────────────────────────┐
│                    THÔNG TIN PHẦN CỨNG THỰC TẾ                        │
├─────────────────┬─────────────────────────────────────────────────────┤
│ Model           │ G5 GD                                               │
│ CPU             │ 11th Gen Intel i5-11400H (6 cores / 12 threads)     │
│ RAM             │ 32 GB DDR4                                          │
│ Storage (OS)    │ /dev/nvme1n1p6 — 300 GB (Ubuntu 24.04)              │
│ Storage (Cinder)│ /dev/nvme0n1p2 — 50 GB  (Cinder LVM volumes)        │
│ Storage (Ceph)  │ /dev/nvme0n1p3 — 150 GB  (Ceph)                     │
│ Network         │ wlp0s20f3 — WiFi (card duy nhất)                    │
│ GPU             │ NVIDIA GeForce RTX 3050 Mobile (không dùng cho ML)  │
│ Kernel          │ 6.17.0-14-generic                                   │
└─────────────────┴─────────────────────────────────────────────────────┘
```

### 2.2 Kiến trúc mạng Laptop (Single-NIC)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Laptop (Ubuntu 24.04)                                                   │
│                                                                          │
│  wlp0s20f3 (WiFi DHCP) ◄── Management + Internet                         │
│       │                                                                  │
│       │  iptables MASQUERADE                                             │
│       │                                                                  │
│  br-exnat (172.10.10.1/24)   ◄── Linux Bridge, gateway cho external net  │
│       │                                                                  │
│  veth-ext ◄────────────► veth-peer                                       │
│  (in br-exnat)            (in OVS br-ex)                                 │
│                              │                                           │
│                         OVN / Neutron                                    │
│                              │                                           │
│                    Provider Network 172.10.10.0/24                       │
│                    Floating IPs: 172.10.10.200 – 172.10.10.250           │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Yêu cầu Phần mềm

- **OS:** Ubuntu 24.04 LTS (Noble Numbat)
- **Python:** 3.12+ (đi kèm Ubuntu 24.04)
- **Docker:** 24.0+
- **Ansible:** 2.18 - 2.19
- **Kolla-Ansible:** stable/2025.2

---

## 3. Chuẩn bị Hệ điều hành Ubuntu 24.04

### 3.1 Cập nhật Hệ thống

```bash
# Cập nhật package list và upgrade tất cả packages
sudo apt update && sudo apt upgrade -y
```

**Giải thích:**

- `apt update`: Cập nhật danh sách packages từ repositories
- `apt upgrade -y`: Nâng cấp tất cả packages đã cài đặt, `-y` tự động xác nhận

### 3.2 Cấu hình Hostname

```bash
# Đặt hostname cho node (thay 'openstack-aio' bằng tên mong muốn)
sudo hostnamectl set-hostname openstack-aio

# Thêm hostname vào /etc/hosts
echo "192.168.1.2 openstack-aio" | sudo tee -a /etc/hosts
```

**Giải thích:**

- `hostnamectl set-hostname`: Thiết lập hostname hệ thống
- Thêm vào `/etc/hosts` để đảm bảo DNS resolution nội bộ hoạt động

### 3.3 Tắt các dịch vụ không cần thiết

```bash
# Tắt và disable UFW firewall (OpenStack tự quản lý firewall rules)
sudo systemctl stop ufw
sudo systemctl disable ufw

# Tắt swap (quan trọng cho hiệu năng containers)
sudo swapoff -a
sudo sed -i '/swap/d' /etc/fstab
```

**Giải thích:**

- **UFW:** OpenStack sử dụng iptables/nftables riêng, UFW có thể gây xung đột
- **Swap:** Containers hoạt động hiệu quả hơn khi không có swap

### 3.4 Cấu hình Kernel Parameters

```bash
# Tạo file cấu hình sysctl cho OpenStack
sudo tee /etc/sysctl.d/99-openstack.conf << 'EOF'
# Enable IP forwarding (cần cho routing giữa các networks)
net.ipv4.ip_forward = 1

# Tăng số lượng file descriptors
fs.file-max = 2097152

# Cấu hình network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Cho phép bridge filtering
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

# Load bridge module và áp dụng cấu hình
sudo modprobe br_netfilter
echo "br_netfilter" | sudo tee /etc/modules-load.d/br_netfilter.conf
sudo sysctl -p /etc/sysctl.d/99-openstack.conf
```

**Giải thích:**

- `ip_forward`: Cho phép Linux route packets giữa các network interfaces
- `br_netfilter`: Module cho phép iptables xử lý traffic qua bridges
- Các buffer settings tối ưu hóa network throughput

---

## 4. Cấu hình Mạng cho Laptop (Single-NIC WiFi + veth Bridge)

> **⚠️ ĐẶC THÙ LAPTOP:** Laptop chỉ có 1 card WiFi (`wlp0s20f3`), không có cổng Ethernet rời.
> OpenStack cần 2 interfaces (Management + External). Ta sẽ dùng **veth pair + Linux bridge + NAT**
> để mô phỏng interface external qua WiFi.

### 4.1 Kiến trúc Mạng Single-NIC

```
                    Internet
                       │
                  WiFi Router
                       │
               ┌───────┴────────┐
               │  wlp0s20f3     │  ◄── Management interface (DHCP)
               │  (e.g. 192.168.│      Kolla API, SSH, web dashboards
               │    1.x/24)     │
               └───────┬────────┘
                       │
              iptables MASQUERADE (NAT)
                       │
               ┌───────┴────────┐
               │  br-exnat      │  ◄── Linux bridge, gateway 172.10.10.1/24
               │  172.10.10.1   │
               └───────┬────────┘
                       │
           ┌───────────┴─────────────────┐
           │  veth-ext ◄────► veth-peer  │  ◄── veth pair (L2 cable ảo)
           │ (in br-exnat)  (in br-ex)   │
           └─────────────────────────────┘
                       │
               ┌───────┴────────┐
               │  OVS br-ex     │  ◄── OVN external bridge
               │  (Neutron)     │      Provider net 172.10.10.0/24
               └────────────────┘
```

**Tóm tắt vai trò:**

| Thành phần                  | Vai trò                                                  |
| ----------------------------- | --------------------------------------------------------- |
| `wlp0s20f3`                 | Management + Internet (DHCP từ WiFi router)              |
| `br-exnat`                  | Linux bridge, gateway cho external network 172.10.10.0/24 |
| `veth-ext` ↔ `veth-peer` | Cáp ảo L2 nối br-exnat với OVS br-ex                  |
| NAT (iptables)                | MASQUERADE traffic từ 172.10.10.0/24 ra WiFi             |

### 4.2 Giữ nguyên Netplan (WiFi DHCP)

Laptop đang dùng NetworkManager qua WiFi DHCP — **không cần thay đổi Netplan**.

```bash
# Kiểm tra Netplan hiện tại (giữ nguyên)
cat /etc/netplan/01-network-manager-all.yaml
# Output: renderer: NetworkManager

# Xác nhận WiFi có IP
ip addr show wlp0s20f3
# → phải thấy inet 192.168.x.x/24 (hoặc dải IP WiFi router cấp)

#Cố định IP của máy (Ưu tiên thực hiện khi ở Wìfi tại nhà hoặc nơi thường trú) để tránh việc IP sau này bị thay đổi dẫn đến các service bị crash
nmcli connection show --active
# Bạn sẽ thấy một dòng có TYPE = wifi và DEVICE = wlp0s20f3. Cột NAME chính là giá trị cần lấy (thường là tên mạng Wi-Fi của bạn) ví dụ NAME = MyWiFi

sudo nmcli connection modify "MyWiFi" ipv4.addresses <192.168.x.x/24> ipv4.gateway <192.168.x.x> ipv4.dns "8.8.8.8 1.1.1.1" ipv4.method manual
# Thuộc tính ipv4.method manual ngắt hành vi gọi DHCP client, trong khi các tham số còn lại gán cứng IP và Gateway vào profile.

sudo nmcli connection up "MyWiFi"
```

> **Lưu ý:** Bạn nên cố định IP WiFi trên router (DHCP reservation) để VIP luôn hợp lệ.
> Hoặc đặt VIP là một IP chưa dùng trong subnet WiFi.

### 4.3 Tạo veth Pair TRƯỚC KHI Deploy

Kolla-Ansible cần `neutron_external_interface` tồn tại khi chạy prechecks.
Ta tạo veth pair **trước** để prechecks/deploy thành công:

```bash
# Tạo veth pair (L2 virtual cable)
sudo ip link add veth-ext type veth peer name veth-peer
sudo ip link set veth-ext up
sudo ip link set veth-peer up

# Kiểm tra
ip link show veth-ext
ip link show veth-peer
# → Cả hai phải ở trạng thái UP
```

**Giải thích:**

- `veth-ext` sẽ được gắn vào Linux bridge `br-exnat` (sau deploy)
- `veth-peer` sẽ được Kolla thêm vào OVS `br-ex` (trong quá trình deploy)
- Tạo trước để `prechecks` không báo lỗi "interface not found"

### 4.4 Script Thiết lập Bridge + NAT (Chạy sau Deploy)

Sau khi Kolla deploy xong, ta cần tạo Linux bridge `br-exnat` và NAT rules.
Script này cũng đảm bảo veth-peer nằm trong OVS br-ex:

```bash
# Tạo script setup bridge + NAT
sudo tee /usr/local/bin/setup-openstack-bridge.sh << 'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail

main() {
  # ===== Biến cấu hình =====
  local LB="br-exnat"              # Linux bridge name
  local VETH_EXT="veth-ext"        # Đầu gắn vào br-exnat
  local VETH_PEER="veth-peer"      # Đầu gắn vào OVS br-ex
  local UPLINK="wlp0s20f3"         # WiFi interface
  local EXT_NET="172.10.10.0/24"   # External network CIDR
  local EXT_GW="172.10.10.1"       # Gateway trên br-exnat
  local OVS_CONT="openvswitch_vswitchd"  # Tên container OVS
  local OVS_BR="br-ex"             # OVS bridge name
  local RETRIES=60
  local SLEEP=2

  log(){ echo "[$(date +'%F %T')] $*"; }

  log "[+] Thiết lập Host bridge + NAT ($LB ↔ $UPLINK)"

  # 1) Tạo Linux bridge làm L3 gateway
  if ! ip link show "$LB" >/dev/null 2>&1; then
    log "[create] $LB"
    ip link add name "$LB" type bridge
  fi
  ip addr show dev "$LB" | grep -q " $EXT_GW/" || ip addr add "${EXT_GW}/24" dev "$LB" || true
  ip link set "$LB" up

  # 2) Tạo lại veth pair (đảm bảo trạng thái sạch)
  ip link del "$VETH_EXT" 2>/dev/null || true
  ip link del "$VETH_PEER" 2>/dev/null || true
  ip link add "$VETH_EXT" type veth peer name "$VETH_PEER"
  ip link set "$VETH_EXT" master "$LB"
  ip link set "$VETH_EXT" up
  ip link set "$VETH_PEER" up

  # 3) Bật IP forwarding
  sysctl -q -w net.ipv4.ip_forward=1 >/dev/null

  # 4) Tắt reverse path filtering (strict → loose)
  for IF in all default "$UPLINK" "$LB"; do
    echo 2 > "/proc/sys/net/ipv4/conf/$IF/rp_filter" || true
  done

  # 5) Thiết lập NAT + FORWARD rules
  # Xóa rules cũ (nếu có)
  iptables -t nat -D POSTROUTING -s "$EXT_NET" -o "$UPLINK" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "$LB" -o "$UPLINK" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$UPLINK" -o "$LB" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

  # Thêm rules mới
  iptables -t nat -A POSTROUTING -s "$EXT_NET" -o "$UPLINK" -j MASQUERADE
  iptables -A FORWARD -i "$LB" -o "$UPLINK" -j ACCEPT
  iptables -A FORWARD -i "$UPLINK" -o "$LB" -m state --state ESTABLISHED,RELATED -j ACCEPT

  # 6) Gắn veth-peer vào OVS br-ex (chờ container sẵn sàng)
  log "[+] Chờ OVS container '$OVS_CONT' và bridge '$OVS_BR' sẵn sàng..."
  local ATTEMPT=1
  while (( ATTEMPT <= RETRIES )); do
    if docker ps --format '{{.Names}}' | grep -Fxq "${OVS_CONT}"; then
      if docker exec -u 0 "${OVS_CONT}" ovs-vsctl --may-exist add-port "${OVS_BR}" "${VETH_PEER}"; then
        local OFPORT
        OFPORT=$(docker exec -u 0 "${OVS_CONT}" ovs-vsctl get Interface "${VETH_PEER}" ofport 2>/dev/null || echo "-1")
        if [[ "$OFPORT" != "-1" && -n "$OFPORT" ]]; then
          log "[ok] ${VETH_PEER} → ${OVS_BR} (ofport=${OFPORT})"
          break
        fi
      fi
    fi
    log "[wait] Thử lại ${ATTEMPT}/${RETRIES}; đợi ${SLEEP}s..."
    sleep "${SLEEP}"
    ((ATTEMPT++))
  done

  if (( ATTEMPT > RETRIES )); then
    log "[FAIL] Không thể gắn ${VETH_PEER} vào ${OVS_BR}. Kiểm tra container/bridge."
    exit 1
  fi

  log "[DONE] $LB=$EXT_GW ; NAT→$UPLINK ; $VETH_EXT↔$VETH_PEER→$OVS_BR"
}

main "$@"
SCRIPT_EOF

sudo chmod +x /usr/local/bin/setup-openstack-bridge.sh
```

**Giải thích chi tiết:**

| Bước | Hành động             | Lý do                                 |
| ------ | ------------------------ | -------------------------------------- |
| 1      | Tạo `br-exnat` bridge | Gateway L3 cho external network        |
| 2      | Tạo veth pair           | Cáp ảo L2 nối bridge với OVS       |
| 3      | `ip_forward=1`         | Cho phép routing giữa interfaces     |
| 4      | `rp_filter=2`          | Tránh kernel drop packets qua bridge  |
| 5      | iptables NAT             | MASQUERADE 172.10.10.0/24 → WiFi      |
| 6      | Gắn veth-peer vào OVS  | Kết nối vào Neutron external bridge |

### 4.5 Tạo Systemd Service (Tự động sau mỗi lần khởi động)

```bash
# Tạo systemd service để tự động chạy bridge setup khi boot
sudo tee /etc/systemd/system/openstack-bridge.service << 'EOF'
[Unit]
Description=OpenStack External Bridge + NAT Setup (Single-NIC Laptop)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/setup-openstack-bridge.sh
ExecStop=/sbin/ip link del br-exnat 2>/dev/null || true

[Install]
WantedBy=multi-user.target docker.service
EOF

sudo systemctl daemon-reload
sudo systemctl enable openstack-bridge.service
```

**Giải thích:**

- Service chạy **sau Docker** khởi động (vì cần OVS container)
- `RemainAfterExit=yes`: Giữ trạng thái "active" sau khi script hoàn tất
- `enable`: Tự động chạy sau khi docker khởi chạy

### 4.6 Kiểm tra Mạng

```bash
# Kiểm tra WiFi (Management)
ip addr show wlp0s20f3     # Phải có IP từ DHCP
ping -c 2 8.8.8.8          # Internet hoạt động
# Kiểm tra veth pair (sau khi tạo ở bước 4.3)
ip link show veth-ext       # state UP
ip link show veth-peer      # state UP
# Sau khi deploy + chạy bridge script (bước 4.4):
ip addr show br-exnat       # 172.10.10.1/24
bridge link show            # veth-ext → br-exnat

```

---

## 5. Cài đặt Docker và Dependencies

### 5.1 Cài đặt Dependencies Hệ thống

```bash
# Cài đặt các packages cần thiết cho Kolla-Ansible
sudo apt install -y \
    python3-dev \
    python3-venv \
    python3-pip \
    libffi-dev \
    gcc \
    libssl-dev \
    build-essential \
    git \
    curl \
    wget \
    jq \
    libdbus-1-dev \
    libglib2.0-dev
```

**Giải thích các packages:**

| Package          | Mục đích                                |
| ---------------- | ------------------------------------------ |
| `python3-dev`  | Header files Python cho compile extensions |
| `python3-venv` | Tạo virtual environments                  |
| `libffi-dev`   | Foreign Function Interface library         |
| `gcc`          | GNU C Compiler cho compile modules         |
| `libssl-dev`   | OpenSSL development files                  |
| `git`          | Clone repositories                         |
| `jq`           | Parse JSON output trong scripts            |

### 5.2 Cài đặt Docker

```bash
# Phương pháp 1: Cài đặt từ Ubuntu repository (đơn giản)
sudo apt install -y docker.io containerd

# HOẶC Phương pháp 2: Cài đặt từ Docker official repository (khuyến nghị cho production)
# Thêm Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Thêm Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list

# Cài đặt Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

### 5.3 Cấu hình Docker

```bash
# Thêm user hiện tại vào group docker
sudo usermod -aG docker $USER

# Tạo Docker daemon configuration
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json << 'EOF'
{
    "bridge": "none",
    "ip-forward": false,
    "iptables": false,
    "log-opts": {
        "max-file": "5",
        "max-size": "50m"
    },
  "insecure-registries": ["192.168.1.2:4000", "localhost:4000"]
}
EOF

# Khởi động và enable Docker
sudo systemctl daemon-reload
sudo systemctl enable docker
sudo systemctl start docker

# QUAN TRỌNG: Logout và login lại để group membership có hiệu lực
# HOẶC chạy lệnh sau để apply ngay trong session hiện tại:
newgrp docker

# Khởi tạo Local Registry nội bộ (chạy 1 lần)
sudo mkdir -p /opt/registry/data
docker run -d --name local-registry --restart=always \
  -p 4000:5000 \
  -v /opt/registry/data:/var/lib/registry \
  registry:2

# Kiểm tra registry đã hoạt động
curl -s http://192.168.1.2:4000/v2/_catalog
```

**Giải thích cấu hình Docker:**

- `insecure-registries`: Cho phép Docker pull/push qua HTTP tới local registry (không TLS)
- `bridge: none`, `ip-forward: false`, `iptables: false`: Tránh xung đột vì networking do OpenStack/OVN quản lý
- Volume `/opt/registry/data`: Giữ image bền vững qua reboot/recreate container registry

### 5.4 Kiểm tra Docker

```bash
# Kiểm tra Docker version
docker --version

# Kiểm tra Docker hoạt động
docker run hello-world

# Kiểm tra Docker info
docker info
```

---

## 6. Cài đặt Kolla-Ansible

### 6.1 Tạo Python Virtual Environment

```bash
# Tạo thư mục cho kolla
mkdir -p ~/kolla
cd ~/kolla

# Tạo virtual environment
python3 -m venv ~/kolla-venv

# Kích hoạt virtual environment
source ~/kolla-venv/bin/activate

# Nâng cấp pip
pip install -U pip setuptools wheel
```

**Giải thích:**

- **Virtual Environment:** Cô lập các Python packages của Kolla, tránh xung đột với system packages
- Mọi lệnh sau này cần chạy trong virtual environment này

### 6.2 Cài đặt Ansible Core

```bash
# Cài đặt Ansible phiên bản tương thích với Kolla-Ansible 2025.2
pip install "ansible-core>=2.18,<2.20"

# Kiểm tra phiên bản
ansible --version
```

**Giải thích:**

- OpenStack 2025.2 Flamingo yêu cầu Ansible Core 2.18-2.19

### 6.3 Cài đặt Kolla-Ansible

```bash
# Cài đặt Kolla-Ansible từ OpenStack Git (stable/2025.2)
pip install git+https://opendev.org/openstack/kolla-ansible@stable/2025.2

# Cài đặt dependencies của Kolla-Ansible
kolla-ansible install-deps

# Cài đặt Ansible Galaxy collections
ansible-galaxy collection install --force -r ~/kolla-venv/share/kolla-ansible/requirements.yml
```

**Giải thích:**

- `stable/2025.2`: Branch ổn định cho phiên bản Flamingo
- `install-deps`: Cài đặt các Python packages phụ thuộc
- Ansible Galaxy collections: Các modules Ansible cần thiết

### 6.4 Thiết lập Cấu hình Directory

```bash
# Tạo thư mục cấu hình Kolla
sudo mkdir -p /etc/kolla/config

# Đổi ownership cho user hiện tại
sudo chown -R $USER:$USER /etc/kolla

# Copy cấu hình mẫu
cp -r ~/kolla-venv/share/kolla-ansible/etc_examples/kolla/* /etc/kolla/

# Copy inventory file cho All-in-One
cp ~/kolla-venv/share/kolla-ansible/ansible/inventory/all-in-one /etc/kolla/ansible/inventory/

# Tạo thư mục cho cấu hình custom
mkdir -p /etc/kolla/config/nova
mkdir -p /etc/kolla/config/neutron
mkdir -p /etc/kolla/config/cinder
mkdir -p /etc/kolla/config/grafana/dashboards
```

---

## 7. Cấu hình Kolla-Ansible

### 7.1 Tạo Passwords

```bash
# Tạo tất cả passwords ngẫu nhiên
kolla-genpwd

# Kiểm tra file passwords
head -30 /etc/kolla/passwords.yml

# (Tùy chọn) Đặt password custom cho Keystone admin
# Mở file và sửa keystone_admin_password
nano /etc/kolla/passwords.yml
```

**Giải thích:**

- `kolla-genpwd`: Tự động tạo passwords mạnh cho tất cả services
- Passwords được lưu trong `/etc/kolla/passwords.yml`
- Nên backup file này an toàn

### 7.2 Cấu hình globals.yml

```bash
# Mở file cấu hình chính
nano /etc/kolla/globals.yml
```

**Nội dung cấu hình chi tiết:**

```yaml
# ============================================================
# /etc/kolla/globals.yml
# Cấu hình Kolla-Ansible cho Đề tài 10: ML Log Anomaly Detection
# OpenStack Version: 2025.2 Flamingo
# ============================================================

# ------------------------------------------
# PHẦN 1: CẤU HÌNH CƠ BẢN
# ------------------------------------------

# Workaround cho lỗi Ansible đã biết
workaround_ansible_issue_8743: yes

# Base distribution cho containers
# "ubuntu" sử dụng Ubuntu 24.04 làm base image
kolla_base_distro: "ubuntu"

# Phiên bản OpenStack
# "2025.2" là Flamingo - phiên bản SLURP mới nhất
openstack_release: "2025.2"

# VIP cho High Availability (HAProxy)
# QUAN TRỌNG: Chọn IP chưa sử dụng TRONG CÙNG SUBNET WiFi.
# Ví dụ: Nếu WiFi cấp IP 192.168.1.x/24 → chọn IP chưa dùng trong dải đó.
# Nên đặt DHCP reservation trên router WiFi cho IP này.
kolla_internal_vip_address: "192.168.1.150"

# (Tùy chọn) External VIP nếu có network riêng cho public access
# kolla_external_vip_address: "10.0.0.150"

docker_registry: "192.168.1.2:4000"
docker_pull_policy: "missing"

# ------------------------------------------
# PHẦN 2: CẤU HÌNH MẠNG (LAPTOP SINGLE-NIC)
# ------------------------------------------

# Management interface = WiFi (card mạng duy nhất trên laptop)
network_interface: "wlp0s20f3"

# External interface = veth-peer (đầu veth pair gắn vào OVS br-ex)
# Phải tạo veth pair TRƯỚC khi chạy deploy (xem Mục 4.3)
neutron_external_interface: "veth-peer"

# Plugin agent cho Neutron (BẮT BUỘC dùng OVN từ 2025.1)
# OVN thay thế OpenvSwitch agent, tích hợp tốt hơn với containers
neutron_plugin_agent: "ovn"

# Kích hoạt provider networks
enable_neutron_provider_networks: "yes"

# ------------------------------------------
# PHẦN 3: CORE SERVICES
# ------------------------------------------

# Compute service
enable_nova: "yes"

# Block storage service
enable_cinder: "yes"
# Backend cho Cinder: sử dụng LVM
enable_cinder_backend_lvm: "yes"
cinder_lvm_type: "thin"

# Image service
enable_glance: "yes"

# Identity service
enable_keystone: "yes"

# Dashboard
enable_horizon: "yes"

# ------------------------------------------
# PHẦN 4: CENTRAL LOGGING KOLLA (TẮT ĐỂ DÙNG ELK NGOÀI)
# ------------------------------------------

# Tắt Central Logging của Kolla để tránh trùng vai trò/cổng với ELK Docker
# ELK (Elasticsearch + Kibana + Filebeat) sẽ được dựng ở Mục 11
enable_central_logging: "no"
enable_opensearch: "no"
enable_opensearch_dashboards: "no"
enable_fluentd: "no"

# Các tham số dưới đây chỉ dùng khi bật OpenSearch của Kolla, giữ comment để tham khảo
# opensearch_soft_retention_period_days: 30
# opensearch_hard_retention_period_days: 60
# opensearch_heap_size: "4g"
# ------------------------------------------
# PHẦN 5: MONITORING VÀ METRICS
# ------------------------------------------

# Prometheus thu thập metrics
enable_prometheus: "yes"

# Grafana visualization
enable_grafana: "yes"

# Ceilometer thu thập metrics tài nguyên
enable_ceilometer: "yes"

# Gnocchi time-series database
enable_gnocchi: "yes"

# Enabling Aodh for alarming
enable_aodh: "yes"

# ------------------------------------------
# PHẦN 6: NETWORKING ADVANCED
# ------------------------------------------

# OVN components
enable_ovn: "yes"

# Metadata agent cho VMs
enable_neutron_metadata_agent: "yes"

# DVR (Distributed Virtual Router) - tối ưu network traffic
enable_neutron_dvr: "no"  # Đặt "no" cho AIO deployment

# ------------------------------------------
# PHẦN 7: CẤU HÌNH LVM CHO CINDER
# ------------------------------------------

# iSCSI để attach volumes vào VMs
enable_iscsid: "yes"

# Multipathd cho high availability storage paths
enable_multipathd: "yes"

# Tên Volume Group cho Cinder (phải tạo trước)
cinder_volume_group: "cinder-volumes"

# ------------------------------------------
# PHẦN 8: MANILA + CEPHFS
# ------------------------------------------

# Bật Manila service
enable_manila: "yes"

# Tắt generic driver (sử dụng VM làm share server)
enable_manila_backend_generic: "no"

# Bật CephFS Native driver (kết nối trực tiếp từ client)
enable_manila_backend_cephfs_native: "yes"

# Ceph user cho Manila (phải khớp với user đã tạo trong Ceph)
ceph_manila_user: "manila"

# Tên CephFS filesystem (phải khớp với filesystem đã tạo)
manila_cephfs_filesystem_name: "manila_data"

# ------------------------------------------
# PHẦN 9: TÙY CHỌN BỔ SUNG
# ------------------------------------------

# Nova console access
nova_console: "novnc"

# Enable Magnum nếu muốn triển khai Kubernetes
# enable_magnum: "yes"

# Enable Heat cho orchestration
enable_heat: "yes"

# Disable services không cần thiết cho mô hình hiện tại
enable_designate: "no"
enable_barbican: "no"

# Ceph External Configuration, Uncomment nếu muốn tích hợp Ceph cho Glance/Cinder
# enable_ceph: "no"  # Không dùng Kolla để deploy Ceph
# glance_backend_ceph: "no"  # Giữ Glance dùng local storage
# cinder_backend_ceph: "no"  # Giữ Cinder dùng LVM
```

### 7.3 Cấu hình Inventory cho All-in-One

```bash
# Mở file inventory
nano /etc/kolla/ansible/inventory/all-in-one
```

Với All-in-One deployment, file inventory mặc định đã được cấu hình đúng. Kiểm tra các nhóm hosts:

```ini
# /etc/kolla/ansible/inventory/all-in-one
# Tất cả services chạy trên localhost

[control]
localhost

[network]
localhost

[compute]
localhost

[monitoring]
localhost

[storage]
localhost

[deployment]
localhost

# Đảm bảo các groups này được định nghĩa cho OVN
[ovn-controller]
localhost

[ovn-nb-db]
localhost

[ovn-sb-db]
localhost

[ovn-northd]
localhost
```

## 8. Cấu hình CADF Audit Logging (Bắt buộc cho Đề tài 10)

> **Quan trọng:** Các bước dưới đây cấu hình CADF audit để log được ghi chuẩn JSON/CADF vào `/var/log/kolla/`, phục vụ pipeline Filebeat -> Elasticsearch ở Mục 11.

### 8.1 Keystone

Keystone dùng `notification_format = cadf` (không cần audit middleware trong paste).

```bash
sudo nano /etc/kolla/config/keystone/keystone.conf
```

```ini
[DEFAULT]
use_json = true
use_syslog = true
syslog_log_facility = LOG_USER
use_stderr = false
log_file = /var/log/kolla/keystone/keystone.log
notification_format = cadf
debug = false

[audit]
enabled = true

[oslo_messaging_notifications]
driver = log
```

---

### 8.2 Nova

#### Bước 1: User override config

```bash
sudo nano /etc/kolla/config/nova/nova.conf
```

```ini
[DEFAULT]
use_json = true
use_stderr = false
log_file = /var/log/kolla/nova/nova-api.log
debug = false

[oslo_messaging_notifications]
driver = log

[audit]
enabled = true
audit_map_file = /var/lib/kolla/config_files/api_audit_map.conf
```

#### Bước 2: Tạo api-paste.ini với audit middleware

```bash
sudo nano /etc/kolla/config/nova/api-paste.ini
```

Thêm `audit` vào pipeline keystone (sau `keystonecontext`, trước app):

```ini
[composite:openstack_compute_api_v21]
use = call:nova.api.auth:pipeline_factory_v21
keystone = cors http_proxy_to_wsgi compute_req_id faultwrap request_log sizelimit osprofiler authtoken keystonecontext audit osapi_compute_app_v21

[composite:openstack_compute_api_v21_legacy_v2_compatible]
use = call:nova.api.auth:pipeline_factory_v21
keystone = cors http_proxy_to_wsgi compute_req_id faultwrap request_log sizelimit osprofiler authtoken keystonecontext audit legacy_v2_compatible osapi_compute_app_v21

[filter:audit]
paste.filter_factory = keystonemiddleware.audit:filter_factory
audit_map_file = /var/lib/kolla/config_files/api_audit_map.conf
```

> **Lưu ý:** Copy file `api-paste.ini` gốc từ container (`docker cp nova_api:/etc/nova/api-paste.ini .`), thêm `audit` filter definition và chèn `audit` vào pipeline, rồi lưu vào `/etc/kolla/config/nova/api-paste.ini`.

#### Bước 3: Sửa trực tiếp merged config (vì Kolla template ghi đè `driver`)

Sau `kolla-ansible reconfigure`, kiểm tra trong container:

```bash
docker exec nova_api grep -A3 '\[oslo_messaging_notifications\]' /etc/nova/nova.conf
```

Nếu vẫn thấy `driver = messagingv2`, cần sửa trực tiếp:

```bash
# Sửa driver trong file merged config
sudo sed -i '/^\[oslo_messaging_notifications\]$/,/^\[/{s/^driver = messagingv2$/driver = log/}' /etc/kolla/nova-api/nova.conf

# Thêm [audit] section nếu chưa có
echo '
[audit]
enabled = true
audit_map_file = /var/lib/kolla/config_files/api_audit_map.conf' | sudo tee -a /etc/kolla/nova-api/nova.conf
```

#### Bước 4: Cập nhật config.json thêm api-paste.ini

```bash
# Copy api-paste.ini đã sửa vào thư mục Kolla
sudo cp /etc/kolla/config/nova/api-paste.ini /etc/kolla/nova-api/api-paste.ini
```

Sửa `/etc/kolla/nova-api/config.json` — thêm block copy `api-paste.ini`:

```json
{
    "command": "uwsgi /etc/nova/nova-api-uwsgi.ini",
    "config_files": [
        {
            "source": "/var/lib/kolla/config_files/nova.conf",
            "dest": "/etc/nova/nova.conf",
            "owner": "nova",
            "perm": "0600"
        },
        {
            "source": "/var/lib/kolla/config_files/nova-api-uwsgi.ini",
            "dest": "/etc/nova/nova-api-uwsgi.ini",
            "owner": "nova",
            "perm": "0600"
        },
        {
            "source": "/var/lib/kolla/config_files/api-paste.ini",
            "dest": "/etc/nova/api-paste.ini",
            "owner": "nova",
            "perm": "0600"
        }
    ],
    "permissions": [
        {
            "path": "/var/log/kolla/nova",
            "owner": "nova:nova",
            "recurse": true
        }
    ]
}
```

```bash
docker restart nova_api
```

---

### 8.3 Neutron

#### Bước 1: User override config

```bash
sudo nano /etc/kolla/config/neutron/neutron.conf
```

```ini
[DEFAULT]
use_json = true
use_stderr = false
log_file = /var/log/kolla/neutron/neutron-server.log
debug = false

[oslo_messaging_notifications]
driver = log

[audit]
enabled = true
audit_map_file = /etc/neutron/neutron_api_audit_map.conf
```

#### Bước 2: Tạo api-paste.ini với audit middleware

Copy gốc từ container rồi thêm audit:

```bash
docker cp neutron_server:/etc/neutron/api-paste.ini /tmp/neutron-api-paste.ini
```

Thêm `audit` vào pipeline keystone (sau `keystonecontext`, trước `extensions`):

```ini
[composite:neutronapi_v2_0]
use = call:neutron.auth:pipeline_factory
keystone = cors http_proxy_to_wsgi request_id catch_errors osprofiler authtoken keystonecontext audit extensions neutronapiapp_v2_0

[filter:audit]
paste.filter_factory = keystonemiddleware.audit:filter_factory
audit_map_file = /etc/neutron/neutron_api_audit_map.conf
```

#### Bước 3: Sửa trực tiếp merged config

```bash
sudo sed -i '/^\[oslo_messaging_notifications\]$/,/^\[/{s/^driver = messagingv2$/driver = log/}' /etc/kolla/neutron-server/neutron.conf

echo '
[audit]
enabled = true
audit_map_file = /etc/neutron/neutron_api_audit_map.conf' | sudo tee -a /etc/kolla/neutron-server/neutron.conf
```

#### Bước 4: Cập nhật config.json

Copy `api-paste.ini` vào `/etc/kolla/neutron-server/` và sửa `config.json` thêm:

```json
{
    "source": "/var/lib/kolla/config_files/api-paste.ini",
    "dest": "/etc/neutron/api-paste.ini",
    "owner": "neutron",
    "perm": "0600"
}
```

```bash
docker restart neutron_server
```

---

### 8.4 Glance

#### Bước 1: User override config

```bash
sudo nano /etc/kolla/config/glance/glance-api.conf
```

```ini
[DEFAULT]
use_json = true
use_stderr = false
log_file = /var/log/kolla/glance/glance-api.log
debug = false

[oslo_messaging_notifications]
driver = log

[audit]
enabled = true
audit_map_file = /var/lib/kolla/venv/etc/pycadf/glance_api_audit_map.conf
```

#### Bước 2: Tạo api-paste.ini với audit middleware

Copy gốc từ container rồi thêm audit filter vào pipeline keystone:

```bash
docker cp glance_api:/etc/glance/glance-api-paste.ini /tmp/glance-api-paste.ini
```

Thêm `audit` vào các pipeline keystone (sau `context`, trước `rootapp` hoặc `cache`):

```ini
keystone = cors http_proxy_to_wsgi versionnegotiation osprofiler authtoken context audit rootapp
keystone+caching = cors http_proxy_to_wsgi versionnegotiation osprofiler authtoken context audit cache rootapp
keystone+cachemanagement = cors http_proxy_to_wsgi versionnegotiation osprofiler authtoken context audit cache cachemanage rootapp

[filter:audit]
paste.filter_factory = keystonemiddleware.audit:filter_factory
audit_map_file = /var/lib/kolla/venv/etc/pycadf/glance_api_audit_map.conf
```

#### Bước 3: Cập nhật config.json

Copy `glance-api-paste.ini` vào `/etc/kolla/glance-api/` và sửa `config.json` thêm:

```json
{
    "source": "/var/lib/kolla/config_files/glance-api-paste.ini",
    "dest": "/etc/glance/glance-api-paste.ini",
    "owner": "glance",
    "perm": "0600"
}
```

```bash
docker restart glance_api
```

---

### 8.5 Cinder

Chỉnh riêng **cinder-api** (không dùng `cinder.conf` chung) để tránh ép mọi container Cinder (scheduler, volume…) dùng chung một `log_file`.

#### Bước 1: User override config

```bash
sudo nano /etc/kolla/config/cinder/cinder-api.conf
```

```ini
[DEFAULT]
use_json = true
use_stderr = false
log_file = /var/log/kolla/cinder/cinder-api.log
debug = false

[oslo_messaging_notifications]
driver = log

[audit]
enabled = true
audit_map_file = /var/lib/kolla/venv/etc/pycadf/cinder_api_audit_map.conf
```

#### Bước 2: Tạo api-paste.ini với audit middleware

```bash
docker cp cinder_api:/etc/cinder/api-paste.ini /tmp/cinder-api-paste.ini
```

Thêm `audit` vào pipeline keystone (sau `keystonecontext`, trước `apiv3`):

```ini
keystone = request_id cors http_proxy_to_wsgi faultwrap sizelimit osprofiler authtoken keystonecontext audit apiv3

[filter:audit]
paste.filter_factory = keystonemiddleware.audit:filter_factory
audit_map_file = /var/lib/kolla/venv/etc/pycadf/cinder_api_audit_map.conf
```

#### Bước 3: Cập nhật config.json

Copy `api-paste.ini` vào `/etc/kolla/cinder-api/` và sửa `config.json` thêm:

```json
{
    "source": "/var/lib/kolla/config_files/api-paste.ini",
    "dest": "/etc/cinder/api-paste.ini",
    "owner": "cinder",
    "perm": "0600"
}
```

```bash
docker restart cinder_api
```

---

### 8.6 Reconfigure Kolla và xác nhận

```bash
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one --tags keystone,nova,neutron,glance,cinder
```

> **Quan trọng:** Sau `reconfigure`, Kolla template **có thể ghi đè** `driver = log` thành `messagingv2` cho Nova/Neutron. Luôn kiểm tra bằng `docker exec <container> grep driver /etc/<service>/<service>.conf` và sửa lại theo Bước 3 của từng service nếu cần, rồi `docker restart <container>`.

#### Xác nhận config đúng trong container

```bash
# Keystone
docker exec keystone grep -E 'notification_format|driver' /etc/keystone/keystone.conf

# Nova
docker exec nova_api grep -A3 '\[oslo_messaging_notifications\]' /etc/nova/nova.conf
docker exec nova_api grep -i 'audit' /etc/nova/api-paste.ini

# Neutron
docker exec neutron_server grep -A3 '\[oslo_messaging_notifications\]' /etc/neutron/neutron.conf
docker exec neutron_server grep -i 'audit' /etc/neutron/api-paste.ini

# Glance
docker exec glance_api grep -A3 '\[oslo_messaging_notifications\]' /etc/glance/glance-api.conf
docker exec glance_api grep -i 'audit' /etc/glance/glance-api-paste.ini

# Cinder
docker exec cinder_api grep -A3 '\[oslo_messaging_notifications\]' /etc/cinder/cinder.conf
docker exec cinder_api grep -i 'audit' /etc/cinder/api-paste.ini
```

Kỳ vọng cho mỗi service: `driver = log` + `audit` filter trong pipeline. **Nếu không có sau khi reconfigure, hãy xem mục 11.1.3** --> Script ghi đè

> **Lưu ý:** Sau khi tắt Fluentd ở Bước 0, OpenStack vẫn ghi log JSON/CADF vào file trong `/var/log/kolla/`; Filebeat đọc trực tiếp các file này.

---

## 9. Triển khai OpenStack

### 9.1 Chuẩn bị LVM cho Cinder

```bash
# Xác định disk cho Cinder
# Liệt kê các disks
lsblk

# CẢNH BÁO: Dữ liệu trên partition này sẽ bị xóa!
# Xóa filesystem cũ nếu có
sudo wipefs -a /dev/nvme0n1p2

# Tạo Physical Volume
sudo pvcreate /dev/nvme0n1p2

# Tạo Volume Group
sudo vgcreate cinder-volumes /dev/nvme0n1p2

# Kiểm tra
sudo vgs cinder-volumes
sudo lvs cinder-volumes
sudo pvs /dev/nvme0n1p2
```

**Giải thích:**

- **PV (Physical Volume):** Đánh dấu disk cho LVM sử dụng
- **VG (Volume Group):** Nhóm các PV lại

### 9.2 Chạy Bootstrap Servers

```bash
# Đảm bảo đang trong virtual environment
source ~/kolla-venv/bin/activate
cd /etc/kolla/ansible/inventory/

# Đảm bảo veth-peer đã tồn tại (tạo ở Mục 4.3)
ip link show veth-peer || sudo ip link add veth-ext type veth peer name veth-peer && sudo ip link set veth-ext up && sudo ip link set veth-peer up

# Bootstrap: Cài đặt Docker và dependencies trên tất cả nodes
pip install docker
pip install dbus-python
kolla-ansible bootstrap-servers -i all-in-one
```

**Giải thích:**

- Cài đặt Docker nếu chưa có
- Cấu hình Docker daemon
- Cài đặt các packages cần thiết trên target hosts
- Thời gian: ~5-10 phút

### 9.3 Chạy Prechecks

```bash
# Kiểm tra tất cả điều kiện trước khi deploy
kolla-ansible prechecks -i all-in-one
```

**Giải thích:**

- Kiểm tra network connectivity
- Kiểm tra ports không bị conflict
- Validate cấu hình
- **Nếu có lỗi:** Đọc kỹ error message và sửa trước khi tiếp tục

### 9.4 Pull Container Images theo 2 tình huống

#### 9.4.1 Lần đầu duy nhất (registry chưa có image): pull từ Internet rồi mirror vào local

```bash
# Bước A: Tạm thời pull từ registry gốc
# Mở /etc/kolla/globals.yml và comment 2 dòng sau nếu đang bật:
# docker_registry: "192.168.1.2:4000"
# docker_pull_policy: "missing"

kolla-ansible pull -i /etc/kolla/ansible/inventory/all-in-one

# Bước B: Mirror toàn bộ image OpenStack 2025.2 sang local registry
LOCAL_REG="192.168.1.2:4000"
docker images --format '{{.Repository}}:{{.Tag}}' \
| grep '^quay.io/openstack.kolla/.*:.*2025.2' \
| while read -r image; do
  image_name=$(echo "$image" | sed 's|^quay.io/||')
  new_image="${LOCAL_REG}/${image_name}"
  echo "Dang xu ly: $new_image"
  docker tag "$image" "$new_image"
  docker push "$new_image"
done

# Bước C: Bật lại local registry trong globals.yml
# docker_registry: "192.168.1.2:4000"
# docker_pull_policy: "missing"

# Bước D: Áp dụng cấu hình để container dùng image từ local
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one
```

**Giải thích:**

- Chỉ làm quy trình này 1 lần cho mỗi release (ví dụ 2025.2)
- Sau bước mirror, local registry đã có đầy đủ image để triển khai không phụ thuộc Internet

#### 9.4.2 Các lần redeploy sau: pull trực tiếp từ local

```bash
# Đảm bảo globals.yml đang có:
# docker_registry: "192.168.1.2:4000"
# docker_pull_policy: "missing"

kolla-ansible pull -i all-in-one
```

**Giải thích:**

- Kolla sẽ pull trực tiếp từ local registry 192.168.1.2:4000
- Nhanh hơn và ổn định hơn khi mạng Internet chậm/không ổn định

#### 9.4.3 Kiểm tra nhanh trước khi deploy

```bash
# Kiểm tra local registry còn giữ image
curl -s http://192.168.1.2:4000/v2/_catalog | jq

# Kiểm tra tag của một image mẫu
curl -s http://192.168.1.2:4000/v2/openstack.kolla/keystone/tags/list | jq
```

### 9.5 Deploy OpenStack

```bash
# TRIỂN KHAI CHÍNH
pip install "bcrypt<4.0.0"
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
kolla-ansible deploy -i all-in-one
```

**Giải thích:**

- Khởi động tất cả containers
- Cấu hình services
- Thiết lập databases
- Thời gian: ~20-40 phút

**Theo dõi tiến trình:**

```bash
# Trong terminal khác, watch containers
watch -n 2 'docker ps --format "table {{.Names}}\t{{.Status}}"'
```

### 9.6 Post-Deployment

```bash
# Tạo file môi trường admin
kolla-ansible post-deploy -i all-in-one

# Cài đặt OpenStack CLI client
pip install python-openstackclient python-neutronclient python-novaclient

# Source credentials
source /etc/kolla/admin-openrc.sh

# Kiểm tra kết nối
openstack token issue
openstack service list
```

---

## 10. Thiết lập Bridge/NAT và Mạng OpenStack

### 10.1 Chạy Script Bridge + NAT

Sau khi Kolla deploy thành công, chạy script bridge đã tạo ở Mục 4.4:

```bash
# Chạy script thiết lập bridge + NAT
sudo /usr/local/bin/setup-openstack-bridge.sh

# Kiểm tra kết quả
ip addr show br-exnat              # Phải có 172.10.10.1/24
bridge link show                    # veth-ext gắn vào br-exnat

# Kiểm tra veth-peer trong OVS br-ex
docker exec openvswitch_vswitchd ovs-vsctl show | grep -A2 veth-peer

# Kiểm tra NAT rules
sudo iptables -t nat -L POSTROUTING -n | grep 172.10.10
sudo iptables -L FORWARD -n | grep -E 'br-exnat|wlp0s20f3'
```

### 10.2 Tạo Mạng Provider (External)

```bash
# Source credentials
source /etc/kolla/admin-openrc.sh

# Tạo external network (provider network)
# Sử dụng dải 172.10.10.0/24 qua bridge br-exnat
openstack network create public-net \
  --external \
  --provider-physical-network physnet1 \
  --provider-network-type flat \
  --share

# Tạo subnet cho external network
# Gateway 172.10.10.1 là IP của br-exnat bridge
openstack subnet create public-subnet \
  --network public-net \
  --subnet-range 172.10.10.0/24 \
  --gateway 172.10.10.1 \
  --allocation-pool start=172.10.10.200,end=172.10.10.250 \
  --dns-nameserver 8.8.8.8 \
  --no-dhcp
```

**Giải thích:**

- `172.10.10.0/24`: Dải mạng external sử dụng qua br-exnat bridge
- `gateway 172.10.10.1`: IP của br-exnat = gateway cho VMs ra internet qua NAT
- `allocation-pool`: Dải Floating IPs cho VMs (172.10.10.200 – 250)
- Traffic đi: VM → OVN → br-ex → veth-peer → veth-ext → br-exnat → NAT → wlp0s20f3 → Internet

### 10.3 Tạo Mạng Private (Tenant)

```bash
# Tạo private network cho VMs
openstack network create private-net

# Tạo subnet cho private network
openstack subnet create private-subnet \
  --network private-net \
  --subnet-range 10.0.0.0/24 \
  --gateway 10.0.0.1 \
  --allocation-pool start=10.0.0.100,end=10.0.0.200 \
  --dns-nameserver 8.8.8.8
```

### 10.4 Tạo Router và Kết nối Networks

```bash
# Tạo router
openstack router create main-router

# Đặt external gateway cho router
openstack router set main-router --external-gateway public-net

# Thêm private subnet vào router
openstack router add subnet main-router private-subnet

# Kiểm tra router
openstack router show main-router
```

**Giải thích:**

- Router kết nối private network với external network
- VMs trong private-net có thể truy cập Internet qua router
- Floating IPs được allocate từ public-net

### 10.5 Tạo Security Group

```bash
# Tạo security group mới
openstack security group create allow-all-ssh-ping \
  --description "Allow SSH and ICMP"

# Cho phép SSH (port 22)
openstack security group rule create \
  --protocol tcp \
  --dst-port 22 \
  --ingress \
  allow-all-ssh-ping

# Cho phép ICMP (ping)
openstack security group rule create \
  --protocol icmp \
  --ingress \
  allow-all-ssh-ping

# Cho phép tất cả outbound traffic
openstack security group rule create \
  --protocol tcp \
  --egress \
  allow-all-ssh-ping

openstack security group rule create \
  --protocol udp \
  --egress \
  allow-all-ssh-ping

openstack security group rule create \
  --protocol icmp \
  --egress \
  allow-all-ssh-ping
```

### 10.6 Tạo Flavor và Upload Image

```bash
# Tạo flavor nhỏ cho testing
openstack flavor create m1.tiny \
  --ram 512 \
  --disk 1 \
  --vcpus 1

openstack flavor create m1.small \
  --ram 2048 \
  --disk 10 \
  --vcpus 1

openstack flavor create m1.medium \
  --ram 4096 \
  --disk 20 \
  --vcpus 2

# Download Ubuntu cloud image
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -O ubuntu-24.04.img

# Upload image
openstack image create "Ubuntu-24.04" \
  --file ubuntu-24.04.img \
  --disk-format qcow2 \
  --container-format bare \
  --public

# Download CirrOS cho testing nhanh
wget http://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img

openstack image create "CirrOS" \
  --file cirros-0.6.2-x86_64-disk.img \
  --disk-format qcow2 \
  --container-format bare \
  --public
```

### 10.7 Tạo SSH Keypair

```bash
# Generate SSH key nếu chưa có
ssh-keygen -t ed25519 -f ~/.ssh/openstack_key -N ""

# Upload public key
openstack keypair create --public-key ~/.ssh/openstack_key.pub mykey

# Liệt kê keypairs
openstack keypair list
```

### 10.8 Launch VM để Test

```bash
# Khởi tạo VM
openstack server create test-vm \
  --flavor m1.small \
  --image "Ubuntu-24.04" \
  --network private-net \
  --security-group allow-all-ssh-ping \
  --key-name mykey

# Kiểm tra trạng thái
openstack server list

# Allocate floating IP
openstack floating ip create public-net

# Associate floating IP với VM (thay IP bằng output từ lệnh trên)
openstack server add floating ip test-vm <FLOATING_IP>

# SSH vào VM
ssh -i ~/.ssh/openstack_key ubuntu@<FLOATING_IP>
```

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

Kỳ vọng: không còn process lắng nghe **9200** và **5601** trên host (hoặc chỉ dịch vụ bạn chủ động giữ). Stack ELK trong tài liệu này dùng `localhost:9200` và `localhost:5601` — **không** dùng VIP Kolla (ví dụ `http://192.168.1.150:9200`) cho Elasticsearch mới; URL đó trong tài liệu triển khai OpenSearch cũ không còn đúng sau khi chuyển ELK.

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

Dùng **localhost** hoặc **IP máy chủ AIO** — đây là stack ELK Docker trên host, **không** phải VIP OpenStack (`kolla_internal_vip_address`, ví dụ `192.168.1.150`).

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

(kolla-venv) nhatnguyen@openstack-aio:~$ sudo wipefs -a /dev/nvme1n1p3
(kolla-venv) nhatnguyen@openstack-aio:~$ sudo blkid /dev/nvme1n1p3
/dev/nvme1n1p3: PARTUUID="e238881d-c9df-49c7-a0bd-6d26847a1b7d"
```

#### 12.3.2 Cài đặt Dependencies cho Cephadm

```bash
# Cài đặt packages cần thiết
sudo apt update

# Cài đặt SSH (Nếu máy tính chưa có)
sudo apt update
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

Get:29 http://vn.archive.ubuntu.com/ubuntu noble-updates/universe amd64 cephadm amd64 19.2.3-0ubuntu0.24.04.3 [136 kB]


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

#### 12.4.2 Xác minh Bootstrap

```bash
# Kiểm tra ceph command hoạt động
sudo ceph -s

# Kiểm tra các containers Ceph
sudo podman ps --format "table {{.Names}}\t{{.Status}}"

# Kiểm tra services
sudo ceph orch ls

sudo ceph mgr services

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

#### 12.4.5 Xác minh Ceph Cluster Healthy

```bash
# Kiểm tra tổng quan
sudo ceph -s

# Kiểm tra OSDs
sudo ceph osd status

# Kiểm tra capacity
sudo ceph df

```

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

#### 12.5.2 Xác minh MDS (Metadata Server)

```bash
# Kiểm tra MDS status
sudo ceph mds stat

# Kiểm tra chi tiết
sudo ceph fs status manila_data
```

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

#### 12.6.2 Xác minh User

```bash
# Liệt kê auth
sudo ceph auth get client.manila

# Test quyền truy cập
sudo ceph --name client.manila --keyring /etc/ceph/ceph.client.manila.keyring health

```

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

nhatnguyen@openstack-aio:~$ cat -A /etc/kolla/config/manila/ceph.conf | head -5
[global]$
fsid = 6aa1408c-27f5-11f1-917a-d4939003b88e$
mon_host = [v2:192.168.1.2:3300/0,v1:192.168.1.2:6789/0]$
nhatnguyen@openstack-aio:~$ cat -A /etc/kolla/config/manila/ceph.client.manila.keyring 
[client.manila]$
key = AQCIWcNpY42VEBAAsgrXUTGFV4sGFQ7H41E8Gw==$
nhatnguyen@openstack-aio:~$ cat -A /etc/kolla/config/manila/manila-share/ceph.client.manila.keyring 
[client.manila]$
key = AQCIWcNpY42VEBAAsgrXUTGFV4sGFQ7H41E8Gw==$

```

#### 12.7.4 Cấu hình Manila Backend Nâng cao

Custom thêm manila-share config:

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

### 12.8 Giai đoạn 6: Triển khai và Kiểm tra

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

#### 12.8.4 Post-Deploy

```bash
# Chạy post-deploy để cập nhật openrc files
kolla-ansible post-deploy -i /etc/kolla/ansible/inventory/all-in-one
```

---

### 12.9 Giai đoạn 6: Xác minh Manila backend sau reconfigure

#### 12.9.1 Kiểm tra Manila Service List

```bash
# Source credentials
source /etc/kolla/admin-openrc.sh

# Cài đặt Manila client
pip install python-manilaclient

# Kiểm tra Manila services
openstack share service list
```

#### 12.9.2 Kiểm tra Manila Pools

```bash
# Liệt kê storage pools
openstack share pool list

# Chi tiết pool
openstack share pool list --detail

```

---

### 12.10 Giai đoạn 7: Sử dụng Manila Share

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

#### 12.10.3 Cấu hình Access

```bash
# CephFS Native, Ceph không quản lý bảo mật bằng IP mà bằng Cephx (Keyring/Mật khẩu). Khi chạy lệnh này, Manila sẽ tự động tạo ra một user mới trong Ceph và cấp quyền cho user đó truy cập đúng vào thư mục 10GB vừa tạo.
openstack share access create my-first-share cephx test-client

(kolla-venv) nhatnguyen@openstack-aio:~$ openstack share access create my-first-share cephx test-client
+--------------+--------------------------------------+
| Field        | Value                                |
+--------------+--------------------------------------+
| id           | a2847dc0-edca-44c3-bd1c-f2ca3c33cdd8 |
| share_id     | 8830275b-ba6a-4217-a5ca-1687be28924d |
| access_level | rw                                   |
| access_to    | test-client                          |
| access_type  | cephx                                |
| state        | queued_to_apply                      |
| access_key   | None                                 |
| created_at   | 2026-03-25T08:07:17.243881           |
| updated_at   | None                                 |
| properties   |                                      |
+--------------+--------------------------------------+

# Kiểm tra access rules
openstack share access list my-first-share

```

#### 12.10.4 Lấy Export Location

```bash
# Lấy thông tin export
openstack share export location list my-first-share
# Output sẽ có dạng:
# 192.168.1.2:6789:/volumes/_nogroup/<uuid>
```

#### 12.10.5 Mount Share trong VM

Để mount CephFS share trong VM, cần:

**1. Cài đặt Ceph client trong VM:**

```bash
# Trong VM (Ubuntu)
sudo apt update
sudo apt install -y ceph-common
```

**2. Copy ceph.conf và keyring vào VM:**

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

**3. Mount CephFS:**

```bash
# Tạo mount point
sudo mkdir -p /mnt/cephfs-share

# Mount sử dụng kernel driver
sudo mount -t ceph \
    192.168.1.2:6789:/volumes/_nogroup/3a2ea581-a261-43e4-9d69-d6197917546e/899d72ca-0152-4978-84c7-b0a85ec72796 \
    /mnt/cephfs-share \
    -o name=test-client,secretfile=/etc/ceph/ceph.client.manila.keyring

ubuntu@test-vm:~$ sudo mount -t ceph     192.168.1.2:6789:/volumes/_nogroup/3a2ea581-a261-43e4-9d69-d6197917546e/899d72ca-0152-4978-84c7-b0a85ec72796     /mnt/cephfs-share     -o name=test-client,secretfile=/etc/ceph/test-client.secret
2026-03-25T08:26:17.175+0000 752f1ac93040 -1 auth: unable to find a keyring on /etc/ceph/ceph.client.test-client.keyring,/etc/ceph/ceph.keyring,/etc/ceph/keyring,/etc/ceph/keyring.bin: (2) No such file or directory

# Kiểm tra mount
df -h

ubuntu@test-vm:~$ df -h
Filesystem                                                                                                    Size  Used Avail Use% Mounted on
tmpfs                                                                                                         197M  1.1M  196M   1% /run
/dev/vda1                                                                                                     8.7G  2.1G  6.6G  25% /
tmpfs                                                                                                         984M     0  984M   0% /dev/shm
tmpfs                                                                                                         5.0M     0  5.0M   0% /run/lock
/dev/vda16                                                                                                    881M   64M  756M   8% /boot
/dev/vda15                                                                                                    105M  6.2M   99M   6% /boot/efi
tmpfs                                                                                                         197M   12K  197M   1% /run/user/1000
192.168.1.2:6789:/volumes/_nogroup/3a2ea581-a261-43e4-9d69-d6197917546e/899d72ca-0152-4978-84c7-b0a85ec72796   10G     0   10G   0% /mnt/cephfs-share

```

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
sudo ceph config set client.rgw rgw_keystone_url http://192.168.1.150:5000
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
|  wlp0s20f3 (WiFi DHCP 192.168.1.2)   VIP = 192.168.1.150 (keepalived)                             |
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
|  │  ╔═══ ORCHESTRATION ═══╗  ╔═══ METERING / ALARM ══════════════════════════════════════════╗   │ |
|  │  ║ heat_api             ║  ║ ceilometer_central    ceilometer_compute                     ║   │ |
|  │  ║ heat_api_cfn         ║  ║ ceilometer_notification                                      ║   │ |
|  │  ║ heat_engine          ║  ║ gnocchi_api           gnocchi_metricd                        ║   │ |
|  │  ╚══════════════════════╝  ║ aodh_api  aodh_evaluator  aodh_listener  aodh_notifier      ║   │ |
|  │                             ╚═════════════════════════════════════════════════════════════╝   │ |
|  │                                                                                               │ |
|  │  ╔═══ MONITORING (Prometheus + Grafana) ══════════════════════════════════════════════════╗   │ |
|  │  ║ prometheus_server          prometheus_alertmanager       prometheus_node_exporter       ║   │ |
|  │  ║ prometheus_cadvisor        prometheus_libvirt_exporter   prometheus_blackbox_exporter   ║   │ |
|  │  ║ prometheus_openstack_exporter   prometheus_memcached_exporter                          ║   │ |
|  │  ║ prometheus_mysqld_exporter      grafana                                                ║   │ |
|  │  ╚════════════════════════════════════════════════════════════════════════════════════════╝   │ |
|  │                                                                                               │ |
|  │  ╔═══ ELK STACK (Docker Compose, ~/elk-stack) ═══════════════════════════════════════════╗   │ |
|  │  ║ elasticsearch  (localhost:9200)   ◄── filebeat (đọc /var/log/kolla/*)                  ║   │ |
|  │  ║ kibana         (0.0.0.0:5601)     ◄── query elasticsearch                             ║   │ |
|  │  ║ filebeat       (CADF JSON logs)   ──► index: openstack-audit-v4                        ║   │ |
|  │  ╚════════════════════════════════════════════════════════════════════════════════════════╝   │ |
|  │                                                                                               │ |
|  └───────────────────────────────────────────────────────────────────────────────────────────────┘ |
|                                                                                                    |
|  ┌── NETWORK DATAPATH ───────────────────────────────────────────────────────────────────────────┐ |
|  │  wlp0s20f3 ─── management 192.168.1.0/24 ─── VIP .150 (HAProxy)                              │ |
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
| VIP .150             | `kolla_internal_vip_address`, keepalived + HAProxy                                          |
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
  ┌─ MONITORING (chạy song song, không trực tiếp trong flow create) ────────┐
  │  prometheus_server        ◄── scrape metrics từ:                         │
  │    prometheus_node_exporter        (host CPU/RAM/disk/net)               │
  │    prometheus_cadvisor             (container metrics)                    │
  │    prometheus_libvirt_exporter     (VM metrics qua libvirt)              │
  │    prometheus_openstack_exporter   (OpenStack API metrics)               │
  │    prometheus_memcached_exporter   (memcached stats)                     │
  │    prometheus_mysqld_exporter      (MariaDB stats)                       │
  │    prometheus_blackbox_exporter    (endpoint probe)                       │
  │  prometheus_alertmanager  (alert rules → email/webhook)                  │
  │  grafana                  (dashboard visualization :3000)                │
  │                                                                          │
  │  ceilometer_notification ◄── rabbitmq (OpenStack notifications)          │
  │  ceilometer_central      (polling metrics từ API)                        │
  │  ceilometer_compute      (polling metrics từ hypervisor)                 │
  │     ──► gnocchi_api / gnocchi_metricd (time-series DB)                   │
  │  aodh_api / aodh_evaluator / aodh_listener / aodh_notifier (alarming)   │
  └──────────────────────────────────────────────────────────────────────────┘
           │
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

| Nhóm                   | Container                                                                                                                                                                                                                                               | Số lượng     |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| Proxy/HA                | haproxy, keepalived                                                                                                                                                                                                                                     | 2               |
| DB/MQ/Cache             | mariadb, proxysql, rabbitmq, memcached                                                                                                                                                                                                                  | 4               |
| Identity                | keystone, keystone_fernet, keystone_ssh                                                                                                                                                                                                                 | 3               |
| Compute                 | nova_api, nova_scheduler, nova_conductor, nova_compute, nova_metadata, nova_novncproxy, nova_ssh, nova_libvirt, placement_api                                                                                                                           | 9               |
| Network                 | neutron_server, neutron_rpc_server, neutron_periodic_worker, neutron_ovn_metadata_agent, neutron_ovn_maintenance_worker, ovn_northd, ovn_nb_db, ovn_sb_db, ovn_sb_db_relay_1, ovn_controller, openvswitch_db, openvswitch_vswitchd                      | 12              |
| Block Storage           | cinder_api, cinder_scheduler, cinder_volume, cinder_backup, iscsid, tgtd, multipathd                                                                                                                                                                    | 7               |
| Image                   | glance_api                                                                                                                                                                                                                                              | 1               |
| Shared FS               | manila_api, manila_scheduler, manila_share, manila_data                                                                                                                                                                                                 | 4               |
| Dashboard               | horizon                                                                                                                                                                                                                                                 | 1               |
| Orchestration           | heat_api, heat_api_cfn, heat_engine                                                                                                                                                                                                                     | 3               |
| Metering/Alarm          | ceilometer_central, ceilometer_compute, ceilometer_notification, gnocchi_api, gnocchi_metricd, aodh_api, aodh_evaluator, aodh_listener, aodh_notifier                                                                                                   | 9               |
| Monitoring              | prometheus_server, prometheus_alertmanager, prometheus_node_exporter, prometheus_cadvisor, prometheus_libvirt_exporter, prometheus_blackbox_exporter, prometheus_openstack_exporter, prometheus_memcached_exporter, prometheus_mysqld_exporter, grafana | 10              |
| ELK                     | elasticsearch, kibana, filebeat                                                                                                                                                                                                                         | 3               |
| Infra                   | cron, kolla_toolbox, local-registry                                                                                                                                                                                                                     | 3               |
| **Ceph (Podman)** | ceph-mon, ceph-mgr, ceph-osd.0, ceph-mds, ceph-rgw (tùy chọn)                                                                                                                                                                                         | 4-5             |
| **Tổng**         |                                                                                                                                                                                                                                                         | **75-76** |

> Ghi chú: Địa chỉ IP (`192.168.1.2`, VIP `.150`), tên thiết bị (`wlp0s20f3`, `veth-peer`), partition (`/dev/nvme1n1p3`) là theo môi trường thực tế trong tài liệu. Khi đổi môi trường, thay các giá trị tương ứng.
