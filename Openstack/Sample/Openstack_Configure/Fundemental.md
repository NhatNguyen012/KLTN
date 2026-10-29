# Hướng dẫn Triển khai OpenStack 2025.2 Flamingo với Kolla-Ansible trên Ubuntu 24.04 LTS

---

## Mục lục

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
enable_prometheus: "no"

# Grafana visualization
enable_grafana: "no"

# Ceilometer thu thập metrics tài nguyên
enable_ceilometer: "no"

# Gnocchi time-series database
enable_gnocchi: "no"

# Enabling Aodh for alarming
enable_aodh: "no"

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
> Ghi chú: Địa chỉ IP (`192.168.1.2`, VIP `.150`), tên thiết bị (`wlp0s20f3`, `veth-peer`), partition (`/dev/nvme1n1p3`) là theo môi trường thực tế trong tài liệu. Khi đổi môi trường, thay các giá trị tương ứng.
