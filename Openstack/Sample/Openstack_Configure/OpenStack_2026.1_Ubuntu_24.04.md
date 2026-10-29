# Hướng dẫn triển khai OpenStack 2026.1 Gazpacho với Kolla-Ansible trên Ubuntu 24.04 LTS

---

> **Trạng thái tương thích — đọc trước khi cài đặt**
>
> **Ubuntu 24.04 LTS Noble Numbat là host OS được Kolla-Ansible 2026.1 hỗ trợ chính thức.**
> Host và container đều dùng nền Ubuntu Noble; image Kolla có tag `2026.1-ubuntu-noble.`
> Mô hình mục tiêu là **All-in-One (AIO)** trên laptop/máy trạm chỉ có một NIC Wi-Fi. Mạng external được mô phỏng bằng Linux bridge, veth pair và NAT.
> **Lưu ý: Nên thay đổi IP, VIP, block ổ đĩa, tên card mạng Wifi của tài liệu thành của bản thân trước khi chạy, để tránh bị cấu hình sai đối với người mới**

---

## Mục lục

0. [Phạm vi, giới hạn và bộ giá trị mẫu](#0-phạm-vi-giới-hạn-và-bộ-giá-trị-mẫu)
1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Yêu cầu phần cứng và kiểm tra trước khi cài](#2-yêu-cầu-phần-cứng-và-kiểm-tra-trước-khi-cài)
3. [Chuẩn bị Ubuntu 24.04](#3-chuẩn-bị-ubuntu-2404)
4. [Chuẩn bị mạng external cho máy một NIC](#4-chuẩn-bị-mạng-external-cho-máy-một-nic)
5. [Cài Kolla-Ansible 2026.1](#5-cài-kolla-ansible-20261)
6. [Cấu hình Kolla-Ansible](#6-cấu-hình-kolla-ansible)
7. [Bootstrap, kiểm tra và triển khai OpenStack](#7-bootstrap-kiểm-tra-và-triển-khai-openstack)
8. [Tạo mạng OpenStack](#8-tạo-mạng-openstack)
9. [Image, flavor, keypair và máy ảo kiểm thử](#9-image-flavor-keypair-và-máy-ảo-kiểm-thử)
10. [Kiểm tra toàn hệ thống](#10-kiểm-tra-toàn-hệ-thống)
11. [Xử lý lỗi thường gặp](#11-xử-lý-lỗi-thường-gặp)
12. [Vận hành, cập nhật và sao lưu](#12-vận-hành-cập-nhật-và-sao-lưu)
13. [Tài liệu chính thức tham chiếu](#13-tài-liệu-chính-thức-tham-chiếu)

---

## 0. Phạm vi, giới hạn và bộ giá trị mẫu

### 0.1 Phạm vi

Hướng dẫn triển khai các thành phần cơ bản sau:

| Thành phần                 | Vai trò                                             |
| ---------------------------- | ---------------------------------------------------- |
| Keystone                     | Identity, project, user, token và service catalog   |
| Glance                       | Lưu trữ image máy ảo                             |
| Nova + Placement             | Lập lịch và chạy máy ảo KVM/QEMU               |
| Neutron + OVN                | Mạng tenant, router, security group và floating IP |
| Horizon                      | Giao diện web                                       |
| Heat                         | Orchestration                                        |
| MariaDB, RabbitMQ, Memcached | Database, message queue và cache nội bộ           |
| HAProxy + Keepalived         | API VIP trên mạng management                       |

### 0.2 Giới hạn của mô hình

- Một node duy nhất nên không có high availability thực sự.
- Wi-Fi vừa làm management vừa làm đường ra Internet.
- External network là mạng riêng giả lập và được NAT qua host, không phải provider network nối trực tiếp vào switch vật lý.
- Ubuntu 24.04 là host được hỗ trợ, nhưng cách dùng một Wi-Fi NIC và provider  network giả lập trong guide là thiết kế riêng cho lab.
- VIP trên Wi-Fi có thể chỉ truy cập ổn định từ chính host nếu access point  hoặc driver Wi-Fi không chuyển gratuitous ARP như mạng Ethernet thông thường.

### 0.3 Phiên bản sử dụng

| Thành phần              | Phiên bản/giá trị                  |
| ------------------------- | -------------------------------------- |
| Host OS                   | Ubuntu 24.04 LTS Noble Numbat          |
| Python host               | 3.12.x                                 |
| Ansible Core              | `>=2.20,<2.21`                       |
| Kolla-Ansible             | branch`stable/2026.1`, package 22.x  |
| OpenStack                 | 2026.1 Gazpacho                        |
| Kolla base distro         | Ubuntu                                 |
| Kolla base distro version | Noble                                  |
| Kolla image tag           | `2026.1-ubuntu-noble`                |
| Neutron mechanism         | OVN                                    |
| Container engine          | Docker CE do Kolla bootstrap quản lý |

Kolla-Ansible 2026.1 khai báo `ansible-core>=2.19,!=2.19.0,<2.21`. Ubuntu 24.04 dùng Python 3.12, tương thích với cả nhánh 2.19 và 2.20; tài liệu dùng nhánh 2.20 để mỗi lần cài mới chọn cùng một dòng phiên bản được Kolla 2026.1 hỗ trợ.

### 0.4 Bộ giá trị mẫu

Mọi lệnh trong tài liệu dùng bộ giá trị sau. Hãy thay chúng theo máy thực tế:

| Giá trị                 | Mẫu trong tài liệu       | Cách xác định                      |
| ------------------------- | --------------------------- | -------------------------------------- |
| Hostname                  | `openstack-aio`           | Tự chọn                              |
| NIC management            | `wlp0s20f3`               | `ip -br link`                        |
| IP management cố định  | `192.168.2.10`            | `ip -4 -br addr`                     |
| Prefix management         | `/24`                     | `ip -4 route`                        |
| Gateway Wi-Fi             | `192.168.2.1`             | `ip route show default`              |
| Kolla internal VIP        | `192.168.2.250`           | IP trống cùng subnet management      |
| Linux external bridge     | `br-exnat`                | Giữ nguyên hoặc tự chọn           |
| Hai đầu veth            | `veth-ext`, `veth-peer` | Giữ nguyên hoặc tự chọn           |
| External CIDR             | `172.31.250.0/24`         | Dải RFC1918 không trùng mạng khác |
| External gateway          | `172.31.250.1`            | IP của`br-exnat`                    |
| Floating-IP pool          | `.200` đến `.250`     | Nằm trong external CIDR               |
| Private CIDR              | `10.20.0.0/24`            | Không trùng mạng host/VPN           |
| Local registry tùy chọn | `192.168.2.10:4000`       | Dùng IP management của host          |

### 0.5 Tìm nhanh thông số máy

```console
# Tên và trạng thái interface
ip -br link

# Địa chỉ IPv4 hiện tại
ip -4 -br address

# Default route, gateway và interface đi Internet
ip -4 route show default

# DNS và trạng thái NetworkManager
resolvectl status
nmcli connection show --active

# Disk/partition, filesystem và mountpoint
lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL

# CPU, RAM và ảo hóa
lscpu
free -h
test -e /dev/kvm && echo "/dev/kvm: OK" || echo "/dev/kvm: KHONG CO"

# Ví dụ:
nguyen@nguyen-G5-GD:~$ ip -br link
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
enp3s0           DOWN           d4:93:90:03:b8:8e <NO-CARRIER,BROADCAST,MULTICAST,UP> 
wlp0s20f3        UP             f8:b5:4d:91:7b:0c <BROADCAST,MULTICAST,UP,LOWER_UP> 
docker0          DOWN           5e:36:43:62:c2:d0 <NO-CARRIER,BROADCAST,MULTICAST,UP> 
nguyen@nguyen-G5-GD:~$ ip -4 -br address
lo               UNKNOWN        127.0.0.1/8 
wlp0s20f3        UP             192.168.2.10/24 
docker0          DOWN           172.17.0.1/16 
nguyen@nguyen-G5-GD:~$ ip -4 route show default
default via 192.168.2.1 dev wlp0s20f3 proto dhcp src 192.168.2.10 metric 600 
nguyen@nguyen-G5-GD:~$ resolvectl status
Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (enp3s0)
    Current Scopes: none
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 3 (wlp0s20f3)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.2.1
       DNS Servers: 192.168.2.1 fd00:db80::1
        DNS Domain: lan

Link 4 (docker0)
    Current Scopes: none
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
nguyen@nguyen-G5-GD:~$ nmcli connection show --active
NAME        UUID                                  TYPE      DEVICE  
Quang Minh  8bc0f8bb-4b90-4a10-a60c-69db1516715a  wifi      wlp0s20f3 
lo          287b0c4e-a374-446e-a0f4-3ddce70d20da  loopback  lo  
docker0     7386659e-9e6c-4cfc-96a8-f24eae1b95a7  bridge    docker0   
nguyen@nguyen-G5-GD:~$ lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
NAME        PATH             SIZE TYPE FSTYPE MOUNTPOINTS   MODEL
sda         /dev/sda       931.5G disk                      TOSHIBA MQ04ABF100
└─sda1      /dev/sda1      931.5G part ext4   /mnt/HDD_Data 
nvme1n1     /dev/nvme1n1   931.5G disk                      CT1000P310SSD8
└─nvme1n1p1 /dev/nvme1n1p1 931.5G part ext4   /mnt/SSD_Data 
nvme0n1     /dev/nvme0n1   476.9G disk                      SSSTC CA6-8D512
├─nvme0n1p1 /dev/nvme0n1p1     1G part vfat   /boot/efi   
└─nvme0n1p2 /dev/nvme0n1p2 475.9G part ext4   /   
nguyen@nguyen-G5-GD:~$ lscpu
Architecture:                x86_64
  CPU op-mode(s):            32-bit, 64-bit
  Address sizes:             39 bits physical, 48 bits virtual
  Byte Order:                Little Endian
CPU(s):                      12
  On-line CPU(s) list:       0-11
Vendor ID:                   GenuineIntel
  Model name:                11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz
    CPU family:              6
    Model:                   141
    Thread(s) per core:      2
    Core(s) per socket:      6
    Socket(s):               1
    Stepping:                1
    CPU(s) scaling MHz:      63%
    CPU max MHz:             4500.0000
    CPU min MHz:             800.0000
    BogoMIPS:                5376.00
    Flags:                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx
                              fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs 
                             bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64
                              monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe po
                             pcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb 
                             cat_l2 cdp_l2 ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsg
                             sbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdt_a avx512f avx512dq rdseed adx smap avx
                             512ifma clflushopt clwb intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 x
                             saves split_lock_detect user_shstk dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp
                             _epp hwp_pkg_req vnmi avx512vbmi umip pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnn
                             i avx512_bitalg avx512_vpopcntdq rdpid movdiri movdir64b fsrm avx512_vp2intersect md_clear i
                             bt flush_l1d arch_capabilities
Virtualization features:   
  Virtualization:            VT-x
Caches (sum of all):   
  L1d:                       288 KiB (6 instances)
  L1i:                       192 KiB (6 instances)
  L2:                        7.5 MiB (6 instances)
  L3:                        12 MiB (1 instance)
NUMA:              
  NUMA node(s):              1
  NUMA node0 CPU(s):         0-11
Vulnerabilities:   
  Gather data sampling:      Vulnerable
  Ghostwrite:                Not affected
  Indirect target selection: Mitigation; Aligned branch/return thunks
  Itlb multihit:             Not affected
  L1tf:                      Not affected
  Mds:                       Not affected
  Meltdown:                  Not affected
  Mmio stale data:           Not affected
  Old microcode:             Not affected
  Reg file data sampling:    Not affected
  Retbleed:                  Not affected
  Spec rstack overflow:      Not affected
  Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:                Mitigation; Enhanced / Automatic IBRS; IBPB conditional; PBRSB-eIBRS SW sequence; BHI SW loo
                             p, KVM SW loop
  Srbds:                     Not affected
  Tsa:                       Not affected
  Tsx async abort:           Not affected
  Vmscape:                   Not affected
nguyen@nguyen-G5-GD:~$ free -h
               total        used        free      shared  buff/cache   available
Mem:            31Gi       6.4Gi        22Gi       1.7Gi       4.5Gi        24Gi
Swap:          8.0Gi          0B       8.0Gi
nguyen@nguyen-G5-GD:~$ test -e /dev/kvm && echo "/dev/kvm: OK" || echo "/dev/kvm: KHONG CO"
/dev/kvm: OK
```

---

## 1. Tổng quan kiến trúc

### 1.1 Kiến trúc logic All-in-One

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Ubuntu 24.04 host: openstack-aio                                    │
│                                                                     │
│  ┌────────────────── OpenStack control plane ────────────────────┐  │
│  │ HAProxy/Keepalived VIP 192.168.2.250                          │  │
│  │ Keystone │ Glance │ Nova │ Neutron │ Horizon │ Heat │          │
│  │ MariaDB  │ RabbitMQ │ Memcached │ OVN databases              │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────── Compute ────────────────────────────────┐  │
│  │ nova-compute + libvirt/KVM                                    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  wlp0s20f3: management + Internet                                  │
│  br-exnat ↔ veth-ext === veth-peer ↔ OVS br-ex ↔ OVN              │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Kiến trúc mạng một NIC

```text
                                  Internet
                                      │
                                Wi-Fi router
                                      │
                         wlp0s20f3 (192.168.2.10/24)
                           Management/API + Internet
                                      │
                   host nft-compatible iptables MASQUERADE
                                      │
                       br-exnat (172.31.250.1/24)
                                      │
                         veth-ext === veth-peer
                                           │
                                      OVS br-ex
                                           │
                                           OVN
                  ┌────────────────────────┴───────────────────────┐
                  │                                                │
      public-net 172.31.250.0/24                     private-net 10.20.0.0/24
      FIP .200-.250                                  VM fixed IP
                  │                                                │
                  └────────────── main-router ─────────────────────┘
```

Luồng outbound:

```text
VM
→ private-net
→ OVN logical router
→ public-net/router external IP
→ OVS br-ex
→ veth-peer/veth-ext
→ br-exnat
→ host MASQUERADE
→ wlp0s20f3
→ Internet
```

Luồng SSH từ host vào floating IP:

```text
Host 172.31.250.1
→ br-exnat
→ veth pair
→ OVS br-ex
→ OVN DNAT floating IP
→ VM private IP:22
```

### 1.3 Tách vai trò các địa chỉ IP

| Địa chỉ             | Chủ thể            | Mục đích                               |
| ---------------------- | -------------------- | ----------------------------------------- |
| `192.168.2.10`       | `wlp0s20f3`        | SSH host, registry tùy chọn, management |
| `192.168.2.250`      | Keepalived/Kolla VIP | Endpoint API và Horizon                  |
| `172.31.250.1`       | `br-exnat`         | Gateway ngoài cho Neutron                |
| `172.31.250.200-250` | Neutron              | Router external IP và floating IP        |
| `10.20.0.1`          | OVN router           | Gateway private subnet                    |
| `10.20.0.100-200`    | Neutron DHCP         | Fixed IP của VM                          |

VIP không được:

- Trùng IP management.
- Nằm trong DHCP pool đang có khả năng cấp cho thiết bị khác.
- Đang được một máy khác sử dụng.
- Nằm khác subnet với `network_interface`.

---

## 2. Yêu cầu phần cứng và kiểm tra trước khi cài

### 2.1 Phần cứng

Kolla quick start ghi mức tối thiểu 8 GB RAM, 40 GB disk và hai network
interfaces. Với AIO có Horizon, Heat và một vài VM, nên dùng:

| Tài nguyên | Tối thiểu để thử   | Khuyến nghị cho guide này |
| ------------ | ----------------------- | ---------------------------- |
| CPU          | 4 core có VT-x/AMD-V   | 6 core/12 thread trở lên   |
| RAM          | 16 GB                   | 32 GB trở lên              |
| Disk host    | 80 GB trống            | 150 GB trở lên             |
| NIC          | 1 NIC + veth mô phỏng | 1 Wi-Fi ổn định           |
| Ảo hóa     | QEMU software           | KVM qua`/dev/kvm`          |

Ví dụ máy tương đương tài liệu gốc:

```text
CPU       : Intel Core i5-11400H, 6 core / 12 thread
RAM       : 32 GB
OS disk   : khoảng 300 GB
Network   : wlp0s20f3, Wi-Fi
```

### 2.2 Kiểm tra Ubuntu và Python

```bash
cat /etc/os-release
python3 --version
uname -r
```

Kỳ vọng:

```text
VERSION_ID="24.04"
VERSION_CODENAME=noble
Python 3.12.x

# Ví dụ:
nguyen@nguyen-G5-GD:~$ cat /etc/os-release
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
nguyen@nguyen-G5-GD:~$ python3 --version
Python 3.12.3
nguyen@nguyen-G5-GD:~$ uname -r
7.0.0-30-generic
```

### 2.3 Kiểm tra KVM

```console
lscpu | grep -E 'Virtualization|Model name'
lsmod | grep -E '^kvm'
ls -l /dev/kvm

# Ví dụ:
nguyen@nguyen-G5-GD:~$ lscpu | grep -E 'Virtualization|Model name'
Model name:                              11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz
Virtualization:                          VT-x
nguyen@nguyen-G5-GD:~$ lsmod | grep -E '^kvm'
kvm_intel             540672  0
kvm                  1507328  1 kvm_intel

sudo apt update
sudo apt install -y cpu-checker libvirt-clients

kvm-ok
sudo virt-host-validate qemu

# Ví dụ:
nguyen@nguyen-G5-GD:~$ kvm-ok
INFO: /dev/kvm exists
KVM acceleration can be used
nguyen@nguyen-G5-GD:~$ sudo virt-host-validate qemu
  QEMU: Checking for hardware virtualization                                 : PASS
  QEMU: Checking if device /dev/kvm exists                                   : PASS
  QEMU: Checking if device /dev/kvm is accessible                            : PASS
  QEMU: Checking if device /dev/cpu/0/msr exists                             : PASS
  QEMU: Checking if device /dev/vhost-net exists                             : PASS
  QEMU: Checking if device /dev/net/tun exists                               : PASS
  QEMU: Checking for cgroup 'cpu' controller support                         : PASS
  QEMU: Checking for cgroup 'cpuacct' controller support                     : PASS
  QEMU: Checking for cgroup 'cpuset' controller support                      : PASS
  QEMU: Checking for cgroup 'memory' controller support                      : PASS
  QEMU: Checking for cgroup 'devices' controller support                     : PASS
  QEMU: Checking for cgroup 'blkio' controller support                       : PASS
  QEMU: Checking for device assignment IOMMU support                         : PASS
  QEMU: Checking if IOMMU is enabled by kernel                               : PASS
  QEMU: Checking for secure guest support                                    : WARN (Unknown if this platform has Secure Guest support)
```

Nếu không có `/dev/kvm`:

1. Bật Intel VT-x hoặc AMD-V/SVM trong BIOS/UEFI.
2. Nếu Ubuntu 24.04 đang chạy trong VM, bật nested virtualization.
3. Nếu không thể bật KVM, dùng `nova_compute_virt_type: "qemu"` ở Mục 6; hiệu năng sẽ thấp hơn đáng kể.

### 2.4 Kiểm tra RAM, disk và port

```bash
free -h
df -hT /
lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL

sudo ss -lntup | grep -E ':(80|443|3306|5000|5672|6080|8774|8776|9292|9696)\b' || true

# Ví dụ:
nguyen@nguyen-G5-GD:~$ free -h
               total        used        free      shared  buff/cache   available
Mem:            31Gi       6.6Gi        21Gi       2.0Gi       5.2Gi        24Gi
Swap:          8.0Gi          0B       8.0Gi
nguyen@nguyen-G5-GD:~$ df -hT /
Filesystem     Type  Size  Used Avail Use% Mounted on
/dev/nvme0n1p2 ext4  468G   33G  412G   8% /
nguyen@nguyen-G5-GD:~$ lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
NAME        PATH             SIZE TYPE FSTYPE MOUNTPOINTS   MODEL
sda         /dev/sda       931.5G disk                      TOSHIBA MQ04ABF100
└─sda1      /dev/sda1      931.5G part ext4   /mnt/HDD_Data 
nvme1n1     /dev/nvme1n1   931.5G disk                      CT1000P310SSD8
└─nvme1n1p1 /dev/nvme1n1p1 931.5G part ext4   /mnt/SSD_Data 
nvme0n1     /dev/nvme0n1   476.9G disk                      SSSTC CA6-8D512
├─nvme0n1p1 /dev/nvme0n1p1     1G part vfat   /boot/efi   
└─nvme0n1p2 /dev/nvme0n1p2 475.9G part ext4   /
nguyen@nguyen-G5-GD:~$ sudo ss -lntup | grep -E ':(80|443|3306|5000|5672|6080|8774|8776|9292|9696)\b' || true
nguyen@nguyen-G5-GD:~$
```

Port 80/443 có thể đang bị Apache, Nginx hoặc reverse proxy khác chiếm. Dừng hoặc đổi cấu hình dịch vụ đó trước khi deploy.

### 2.5 Script kiểm tra chỉ đọc

```bash
sudo tee /usr/local/sbin/openstack-aio-preflight <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

MGMT_IF="${1:-wlp0s20f3}"
FAILED=0

ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILED=1; }

source /etc/os-release
if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
    ok "Host là Ubuntu 24.04 (${VERSION_CODENAME:-unknown})"
else
    fail "Guide yêu cầu Ubuntu 24.04; tìm thấy ${PRETTY_NAME:-unknown}"
fi

if ip link show "$MGMT_IF" >/dev/null 2>&1; then
    ok "Có management interface $MGMT_IF"
else
    fail "Không tìm thấy management interface $MGMT_IF"
fi

if ip -4 address show dev "$MGMT_IF" | grep -q 'inet '; then
    ok "$MGMT_IF có IPv4"
else
    fail "$MGMT_IF chưa có IPv4"
fi

if ip -4 route show default | grep -q "dev $MGMT_IF"; then
    ok "Default route đi qua $MGMT_IF"
else
    warn "Default route không đi qua $MGMT_IF"
fi

MEM_GIB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
if (( MEM_GIB >= 16 )); then
    ok "RAM khoảng ${MEM_GIB} GiB"
else
    warn "RAM chỉ khoảng ${MEM_GIB} GiB; AIO có thể thiếu bộ nhớ"
fi

if [[ -e /dev/kvm ]]; then
    ok "Có /dev/kvm"
else
    warn "Không có /dev/kvm; phải dùng QEMU hoặc bật virtualization"
fi

if systemctl is-active --quiet systemd-timesyncd || \
   systemctl is-active --quiet chrony; then
    ok "Có dịch vụ đồng bộ thời gian đang chạy"
else
    warn "Chưa thấy systemd-timesyncd hoặc chrony active"
fi

if (( FAILED != 0 )); then
    printf '\nPreflight FAILED. Không tiếp tục cho đến khi sửa lỗi.\n'
    exit 1
fi

printf '\nPreflight hoàn tất. Các WARN vẫn cần được đánh giá.\n'
SCRIPT

sudo chmod 0755 /usr/local/sbin/openstack-aio-preflight
sudo /usr/local/sbin/openstack-aio-preflight wlp0s20f3
```

Script trên không thay đổi disk hoặc cấu hình hệ thống.

---

## 3. Chuẩn bị Ubuntu 24.04

### 3.1 Cập nhật hệ thống

```bash
sudo apt update
sudo apt full-upgrade -y

if [[ -f /var/run/reboot-required ]]; then
    cat /var/run/reboot-required
    cat /var/run/reboot-required.pkgs 2>/dev/null || true
fi
```

Nếu kernel, systemd hoặc thư viện nền vừa được cập nhật:

```bash
sudo reboot
```

Sau khi đăng nhập lại:

```bash
uname -r
systemctl --failed
```

Không tiếp tục nếu hệ thống đang có unit quan trọng ở trạng thái failed.

### 3.2 Đặt hostname

```bash
sudo hostnamectl set-hostname openstack-aio
hostnamectl
```

Kiểm tra `/etc/hosts`:

```bash
getent hosts openstack-aio || true
sudoedit /etc/hosts
```

Đảm bảo có một dòng tương ứng với IP management thực tế:

```text
192.168.2.10 openstack-aio
```

Không thêm lặp nhiều dòng cho cùng hostname. Kiểm tra lại:

```bash
getent hosts openstack-aio
ping -c 2 openstack-aio
```

### 3.3 Cố định IP management

Ưu tiên tạo **DHCP reservation trên Wi-Fi router** cho MAC của
`wlp0s20f3`. Cách này ít rủi ro mất kết nối hơn việc đặt static IP trực tiếp
trên laptop.

Lấy MAC:

```bash
cat /sys/class/net/wlp0s20f3/address
```

Nếu bắt buộc cấu hình static bằng NetworkManager:

```bash
nmcli -f NAME,TYPE,DEVICE connection show --active

# Ví dụ profile là MyWiFi
sudo nmcli connection modify "MyWiFi" \
  ipv4.method manual \
  ipv4.addresses "192.168.2.10/24" \
  ipv4.gateway "192.168.2.1" \
  ipv4.dns "1.1.1.1 8.8.8.8"

sudo nmcli connection up "MyWiFi"
```

> Chạy thay đổi này tại console vật lý. Nếu IP/gateway sai, SSH hiện tại sẽ bị ngắt.

Xác nhận:

```bash
ip -4 address show dev wlp0s20f3
ip -4 route
ping -c 3 1.1.1.1
getent hosts docs.openstack.org
```

### 3.4 Chọn và kiểm tra VIP

VIP phải trống và nằm cùng subnet với IP management:

```bash
sudo apt install -y arping

# Không có reply là kết quả mong muốn
sudo arping -D -I wlp0s20f3 -c 3 192.168.2.250
```

Đồng thời loại VIP khỏi DHCP pool. Không cấu hình VIP thành IP management và không để DHCP lease địa chỉ này cho một thiết bị. Sau này Keepalived sẽ gán VIP; không gán cố định trước deploy.

Nếu cần truy cập Horizon/API từ **một máy khác trong LAN**, nên kiểm tra sớm việc driver/AP Wi-Fi có chuyển traffic cho secondary IP. Chỉ chạy sau khi `arping -D` xác nhận VIP trống:

```bash
VIP_TEST="192.168.2.250"
VIP_TEST_CIDR="${VIP_TEST}/24"

cleanup_vip_test() {
    sudo ip address delete "$VIP_TEST_CIDR" dev wlp0s20f3 2>/dev/null || true
}
trap cleanup_vip_test EXIT

sudo ip address add "$VIP_TEST_CIDR" dev wlp0s20f3
sudo arping -U -I wlp0s20f3 -c 3 "$VIP_TEST" || true
ip -4 address show dev wlp0s20f3

read -r -p "Từ máy khác trong LAN, ping ${VIP_TEST}; nhấn Enter sau khi thử: "

cleanup_vip_test
trap - EXIT
```

Nếu máy khác không thấy VIP nhưng host tự ping được, Wi-Fi/AP có thể không xử lý secondary-IP/GARP như Ethernet. Lab vẫn có thể dùng từ chính host; nếu cần client LAN truy cập ổn định, ưu tiên NIC Ethernet hoặc management bridge đã được kiểm thử thay vì bỏ qua kết quả này.

### 3.5 Đồng bộ thời gian

```bash
timedatectl
sudo timedatectl set-ntp true
timedatectl timesync-status
```

Nếu môi trường dùng Chrony:

```bash
sudo apt install -y chrony
sudo systemctl enable --now chrony
chronyc tracking
chronyc sources -v
```

Chỉ nên dùng một cơ chế NTP chính. Clock lệch có thể làm token, TLS và RabbitMQ hoạt động không ổn định.

### 3.6 Cài package nền

```bash
sudo apt install -y \
  ca-certificates \
  curl \
  gcc \
  git \
  gnupg \
  iptables \
  jq \
  libdbus-glib-1-dev \
  libffi-dev \
  libssl-dev \
  qemu-utils \
  python3-dev \
  python3-pip \
  python3-venv \
  wget
```

| Package                                                  | Mục đích                                            |
| -------------------------------------------------------- | ------------------------------------------------------ |
| `python3-dev`, `gcc`, `libffi-dev`, `libssl-dev` | Build Python wheels                                    |
| `libdbus-glib-1-dev`                                   | Dependency được Kolla quick start yêu cầu         |
| `python3-venv`                                         | Cô lập Kolla-Ansible                                 |
| `iptables`                                             | NAT external; trên Ubuntu mới dùng backend nftables |
| `qemu-utils`                                           | Kiểm tra image QCOW2                                  |
| `jq`                                                   | Đọc JSON và kiểm tra registry                      |

Kiểm tra iptables đang dùng backend nft:

```bash
iptables --version
sudo update-alternatives --display iptables
```

Không chuyển qua lại giữa `iptables-legacy` và `iptables-nft` sau khi đã deploy.

### 3.7 Firewall cho lab

Kolla bootstrap mặc định tắt UFW/firewalld. Với mô hình lab:

```bash
sudo ufw status verbose
sudo ufw disable
sudo systemctl disable --now firewalld 2>/dev/null || true
```

Đây không phải khuyến nghị production. Production cần thiết kế firewall theo port matrix của Kolla và không vô hiệu hóa firewall một cách tổng quát.

### 3.8 Kernel modules và sysctl

```bash
sudo tee /etc/modules-load.d/openstack-aio.conf <<'EOF'
br_netfilter
overlay
EOF

sudo modprobe br_netfilter
sudo modprobe overlay
```

Tạo sysctl:

```bash
sudo tee /etc/sysctl.d/99-openstack-aio.conf <<'EOF'
# Routing giữa external network giả lập và Wi-Fi
net.ipv4.ip_forward = 1

# Cho netfilter nhìn thấy traffic qua Linux bridge
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1

# Loose reverse-path filtering phù hợp với nhiều bridge/overlay
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Số lượng file handle hợp lý cho control plane containerized
fs.file-max = 2097152
EOF

sudo sysctl --system
sysctl net.ipv4.ip_forward
sysctl net.bridge.bridge-nf-call-iptables
sysctl net.ipv4.conf.all.rp_filter
```

Không cần đặt `vm.max_map_count=262144` khi OpenSearch bị tắt. Chỉ thêm tham số đó nếu sau này bật OpenSearch theo tài liệu chính thức.

### 3.9 Swap

Kolla không bắt buộc tắt swap. Với 32 GB RAM, có thể giữ một swap nhỏ để tránh
host bị OOM đột ngột, nhưng không để hệ thống swap liên tục:

```bash
swapon --show
free -h
cat /proc/sys/vm/swappiness
```

Giảm xu hướng swap cho lab:

```bash
echo 'vm.swappiness = 10' | sudo tee /etc/sysctl.d/98-openstack-memory.conf
sudo sysctl --system
```

Nếu quyết định tắt swap, kiểm tra RAM còn đủ rồi mới chạy:

```bash
sudo swapoff -a
```

Không xóa entry khỏi `/etc/fstab` nếu chưa có kế hoạch khôi phục.

### 3.10 Ngăn laptop tự suspend

Một AIO phải luôn chạy. Trên laptop dành riêng cho lab:

```bash
sudo systemctl mask \
  sleep.target \
  suspend.target \
  hibernate.target \
  hybrid-sleep.target
```

Khôi phục hành vi mặc định:

```bash
sudo systemctl unmask \
  sleep.target \
  suspend.target \
  hibernate.target \
  hybrid-sleep.target
```

---

## 4. Chuẩn bị mạng external cho máy một NIC

### 4.1 Nguyên tắc

Kolla yêu cầu `neutron_external_interface`:

- Tồn tại trước khi chạy prechecks.
- Ở trạng thái UP.
- Không có địa chỉ IP.
- Được gắn vào OVS bridge `br-ex`.

Ta dùng `veth-peer` làm interface đó. Đầu còn lại `veth-ext` thuộc Linux bridge `br-exnat`, nơi giữ gateway `172.31.250.1/24`.

### 4.2 File cấu hình mạng host

```bash
sudo tee /etc/openstack-external-net.conf <<'EOF'
# Interface có default route ra Internet
UPLINK_IF="wlp0s20f3"

# Linux bridge và hai đầu veth
LINUX_BRIDGE="br-exnat"
VETH_HOST="veth-ext"
VETH_OVS="veth-peer"

# Mạng external giả lập; phải không trùng LAN, VPN, Docker hoặc tenant network
EXT_CIDR="172.31.250.0/24"
EXT_GATEWAY_CIDR="172.31.250.1/24"

# Container/bridge do Kolla tạo
OVS_CONTAINER="openvswitch_vswitchd"
OVS_BRIDGE="br-ex"
EOF

sudo chmod 0644 /etc/openstack-external-net.conf
```

Kiểm tra dải không trùng route hiện có:

```bash
ip -4 route
ip -4 route get 172.31.250.1
```

Trước khi tạo bridge, kết quả không được trỏ `172.31.250.0/24` qua một VPN  hoặc interface khác.

### 4.3 Script lặp lại an toàn với cùng cấu hình để tạo bridge, veth và NAT

```bash
sudo tee /usr/local/sbin/openstack-external-net <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG_FILE="/etc/openstack-external-net.conf"
MODE="${1:-prepare}"

log() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
    log "ERROR: $*"
    exit 1
}

[[ -r "$CONFIG_FILE" ]] || die "Không đọc được $CONFIG_FILE"
source "$CONFIG_FILE"

for var_name in UPLINK_IF LINUX_BRIDGE VETH_HOST VETH_OVS \
                EXT_CIDR EXT_GATEWAY_CIDR OVS_CONTAINER OVS_BRIDGE; do
    [[ -n "${!var_name:-}" ]] || die "Biến $var_name chưa được cấu hình"
done

for command_name in ip iptables sysctl; do
    command -v "$command_name" >/dev/null 2>&1 ||
        die "Thiếu command: $command_name"
done

[[ "$MODE" == "prepare" || "$MODE" == "attach" ]] ||
    die "Cách dùng: $0 [prepare|attach]"

ip link show "$UPLINK_IF" >/dev/null 2>&1 ||
    die "Không tìm thấy uplink $UPLINK_IF"

log "Bảo đảm Linux bridge $LINUX_BRIDGE tồn tại"
if ! ip link show "$LINUX_BRIDGE" >/dev/null 2>&1; then
    ip link add name "$LINUX_BRIDGE" type bridge
fi
ip link set "$LINUX_BRIDGE" up

host_exists=0
ovs_exists=0
ip link show "$VETH_HOST" >/dev/null 2>&1 && host_exists=1
ip link show "$VETH_OVS"  >/dev/null 2>&1 && ovs_exists=1

if (( host_exists == 0 && ovs_exists == 0 )); then
    log "Tạo veth pair $VETH_HOST <-> $VETH_OVS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_OVS"
elif (( host_exists != ovs_exists )); then
    die "Chỉ có một đầu veth tồn tại. Kiểm tra thủ công; script không tự xóa interface."
fi

ip link set "$VETH_HOST" master "$LINUX_BRIDGE"
ip link set "$VETH_HOST" up
ip link set "$VETH_OVS" up

if ! ip -4 address show dev "$LINUX_BRIDGE" |
     grep -Fq "inet $EXT_GATEWAY_CIDR"; then
    log "Gán $EXT_GATEWAY_CIDR cho $LINUX_BRIDGE"
    ip address add "$EXT_GATEWAY_CIDR" dev "$LINUX_BRIDGE"
fi

sysctl -q -w net.ipv4.ip_forward=1

for iface_name in all default "$UPLINK_IF" "$LINUX_BRIDGE"; do
    rp_path="/proc/sys/net/ipv4/conf/${iface_name}/rp_filter"
    if [[ -w "$rp_path" ]]; then
        printf '2\n' >"$rp_path"
    fi
done

ensure_iptables_rule() {
    local table="$1"
    shift
    if ! iptables -w 10 -t "$table" -C "$@" 2>/dev/null; then
        iptables -w 10 -t "$table" -A "$@"
    fi
}

log "Bảo đảm NAT/FORWARD rules tồn tại"
ensure_iptables_rule nat POSTROUTING \
    -s "$EXT_CIDR" -o "$UPLINK_IF" -j MASQUERADE
ensure_iptables_rule filter FORWARD \
    -i "$LINUX_BRIDGE" -o "$UPLINK_IF" -j ACCEPT
ensure_iptables_rule filter FORWARD \
    -i "$UPLINK_IF" -o "$LINUX_BRIDGE" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

attach_ovs_once() {
    command -v docker >/dev/null 2>&1 || return 1
    [[ "$(docker inspect -f '{{.State.Running}}' "$OVS_CONTAINER" \
        2>/dev/null || true)" == "true" ]] || return 1
    docker exec "$OVS_CONTAINER" ovs-vsctl br-exists "$OVS_BRIDGE" \
        >/dev/null 2>&1 || return 1

    docker exec "$OVS_CONTAINER" \
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE" "$VETH_OVS"
    return 0
}

if attach_ovs_once; then
    log "$VETH_OVS đã gắn vào OVS $OVS_BRIDGE"
elif [[ "$MODE" == "attach" ]]; then
    log "Chờ OVS tối đa 180 giây"
    attached=0
    for ((attempt=1; attempt<=90; attempt++)); do
        if attach_ovs_once; then
            attached=1
            break
        fi
        sleep 2
    done

    if (( attached == 1 )); then
        log "$VETH_OVS đã gắn vào OVS $OVS_BRIDGE"
    else
        die "OVS chưa sẵn sàng sau 180 giây"
    fi
else
    log "OVS chưa có; đây là bình thường trước deploy"
fi

log "Hoàn tất: $EXT_CIDR -> $UPLINK_IF qua NAT"
SCRIPT

sudo chmod 0750 /usr/local/sbin/openstack-external-net
```

Điểm an toàn của script:

- Không tự xóa hoặc tạo lại một veth đang tồn tại.
- Chỉ thêm iptables rule khi rule chưa có.
- Không flush toàn bộ firewall table.
- Chế độ `prepare` không chờ Docker/OVS.
- Chế độ `attach` dành cho systemd sau khi OpenStack đã deploy.

Script lặp lại an toàn khi các giá trị trong `/etc/openstack-external-net.conf` không đổi. Nó không tự dọn địa chỉ hoặc iptables rule cũ nếu đổi `EXT_CIDR`, gateway, bridge hay uplink. Nếu phải đổi
các giá trị đó sau khi đã deploy, thực hiện trong maintenance window, ghi lại rule/address cũ và lập kế hoạch migration rõ ràng; không chạy song song hai bộ CIDR rồi giả định script sẽ tự hội tụ.

### 4.4 Chạy chuẩn bị trước prechecks

```bash
sudo /usr/local/sbin/openstack-external-net prepare
```

Kiểm tra:

```bash
ip -br link show | grep -E '^(br-exnat|veth-ext|veth-peer)\b'
ip -4 address show br-exnat
bridge link show

# veth-peer phải UP và không có IP
ip -4 address show veth-peer
```

Kỳ vọng:

```text
br-exnat    UP  172.31.250.1/24
veth-ext    UP
veth-peer   UP
```

### 4.5 Systemd service để khôi phục sau reboot

```bash
sudo tee /etc/systemd/system/openstack-external-net.service <<'EOF'
[Unit]
Description=OpenStack AIO synthetic external bridge, veth and NAT
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/openstack-external-net attach
TimeoutStartSec=240

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable openstack-external-net.service
```

Chưa start service ở đây vì OVS container chưa tồn tại. Sau deploy sẽ dùng:

```bash
sudo systemctl start openstack-external-net.service
```

Không khai báo `ExecStop` để một thao tác stop/restart systemd không làm mất đột ngột dataplane của các VM đang chạy.

---

## 5. Cài Kolla-Ansible 2026.1

### 5.1 Tạo virtual environment

```bash
mkdir -p "$HOME/venvs"
python3 -m venv "$HOME/venvs/kolla-2026.1"
source "$HOME/venvs/kolla-2026.1/bin/activate"

python -m pip install --upgrade pip setuptools wheel
python --version
pip --version
```

Mỗi terminal mới phải kích hoạt lại:

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
```

### 5.2 Cài đúng Ansible Core

```bash
python -m pip install "ansible-core>=2.20,<2.21"
ansible --version
```

Kiểm tra output có:

```text
ansible [core 2.20.x]
python version = 3.12.x

# kết quả:
(kolla-2026.1) nguyen@openstack-aio:~$ ansible --version
ansible [core 2.20.8]
  config file = None
  configured module search path = ['/home/nguyen/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /home/nguyen/venvs/kolla-2026.1/lib/python3.12/site-packages/ansible
  ansible collection location = /home/nguyen/.ansible/collections:/usr/share/ansible/collections
  executable location = /home/nguyen/venvs/kolla-2026.1/bin/ansible
  python version = 3.12.3 (main, Jul 15 2026, 23:46:41) [GCC 13.3.0] (/home/nguyen/venvs/kolla-2026.1/bin/python)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
```

Nếu pip chọn Ansible Core 2.19 hoặc 2.21, kiểm tra lại virtual environment và chạy lệnh pin ở trên. Ansible Core 2.19.1+ vẫn nằm trong dải upstream cho phép, nhưng guide này chuẩn hóa trên 2.20.x; 2.21 vượt giới hạn của release.

### 5.3 Cài Kolla-Ansible stable/2026.1

```bash
python -m pip install \
  "git+https://opendev.org/openstack/kolla-ansible@stable/2026.1"

kolla-ansible --version
kolla-ansible install-deps
ansible-galaxy collection list

# Kết quả:
(kolla-2026.1) nguyen@openstack-aio:~$ kolla-ansible --version
kolla-ansible 22.1.1.dev6

# /home/nguyen/.ansible/collections/ansible_collections
Collection                               Version
---------------------------------------- -------
ansible.netcommon                        8.6.2  
ansible.posix                            2.2.2  
ansible.utils                            6.1.0  
community.crypto                         3.3.0  
community.docker                         4.8.8  
community.general                        11.4.9 
community.library_inventory_filtering_v1 1.1.5  
containers.podman                        1.20.2 
openstack.kolla                          1.0.0
```

`install-deps` cài collection `openstack.kolla` đúng branch 2026.1. Không cài
collection bằng branch `master` cho một deployment stable.

### 5.4 Tạo cây cấu hình

```bash
sudo mkdir -p /etc/kolla/config
sudo mkdir -p /etc/kolla/inventory
sudo chown -R "$USER":"$USER" /etc/kolla

cp -a "$HOME/venvs/kolla-2026.1/share/kolla-ansible/etc_examples/kolla/." \
  /etc/kolla/

cp \
  "$HOME/venvs/kolla-2026.1/share/kolla-ansible/ansible/inventory/all-in-one" \
  /etc/kolla/inventory/all-in-one

chmod 0600 /etc/kolla/passwords.yml
```

Kiểm tra:

```bash
ls -la /etc/kolla
head -n 20 /etc/kolla/inventory/all-in-one

# Kết quả:
(kolla-2026.1) nguyen@openstack-aio:~$ ls -la /etc/kolla
total 64
drwxrwxr-x   4 nguyen nguyen  4096 Sep  1 22:41 .
drwxr-xr-x 146 root   root   12288 Sep  1 22:51 ..
drwxr-xr-x   2 nguyen nguyen  4096 Sep  1 22:51 config
-rw-rw-r--   1 nguyen nguyen 32244 Sep  1 22:41 globals.yml
drwxr-xr-x   2 nguyen nguyen  4096 Sep  1 22:51 inventory
-rw-------   1 nguyen nguyen  4534 Sep  1 22:41 passwords.yml
(kolla-2026.1) nguyen@openstack-aio:~$ head -n 20 /etc/kolla/inventory/all-in-one
# These initial groups are the only groups required to be modified. The
# additional groups are for more control of the environment.
[control]
localhost       ansible_connection=local

[network]
localhost       ansible_connection=local

[compute]
localhost       ansible_connection=local

[storage]
localhost       ansible_connection=local

[monitoring]
localhost       ansible_connection=local

[deployment]
localhost       ansible_connection=local
```

### 5.5 Kiểm tra inventory

Không tự viết lại toàn bộ inventory; dùng file mẫu đúng nhánh `stable/2026.1` đã copy ở Mục 5.4.

```bash
ansible-inventory \
  -i /etc/kolla/inventory/all-in-one \
  --graph

ansible \
  -i /etc/kolla/inventory/all-in-one \
  all \
  -m ping
```

Kỳ vọng `localhost | SUCCESS`.

### 5.6 Không tự cấu hình Docker trước bootstrap

Kolla `bootstrap-servers` sẽ:

- Thêm Docker CE repository theo codename `noble`.
- Cài Docker CE.
- Tạo `/etc/docker/daemon.json`.
- Tắt Docker default bridge, iptables và ip-forward để tránh xung đột.
- Cấu hình log rotation và insecure registry nếu được yêu cầu.

Không sửa tay `/etc/docker/daemon.json`; lần bootstrap sau sẽ ghi lại file đó.
Docker repository chính thức đã có suite `noble` tại thời điểm tài liệu được cập nhật.

Kolla-Ansible triển khai OpenStack bằng container, vì vậy **không thêm Ubuntu Cloud Archive và không cài các package `nova-*`, `neutron-*`, `keystone`, hoặc `glance-*` trực tiếp lên host**. Trộn package deployment với Kolla làm tăng nguy cơ chiếm port và xung đột cấu hình.

Ubuntu Cloud Archive `cloud-archive:gazpacho` có tồn tại cho Noble, nhưng chỉ dùng cho quy trình cài OpenStack native bằng DEB. Nó không thuộc luồng Kolla trong tài liệu này.

---

## 6. Cấu hình Kolla-Ansible

### 6.1 Sinh password

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
kolla-genpwd
chmod 0600 /etc/kolla/passwords.yml
```

Kiểm tra key tồn tại nhưng không in toàn bộ secret ra terminal chia sẻ:

```bash
grep -E '^(keystone_admin_password|database_password):' \
  /etc/kolla/passwords.yml | sed 's|:.*|: <redacted>|'
```

Sao lưu file này sau deploy. Mất `passwords.yml` sẽ làm các thao tác
reconfigure/upgrade rất khó khôi phục.

### 6.2 Tạo `globals.yml`

Ví dụ đầy đủ cho bộ giá trị ở Mục 0:

```bash
cp -a /etc/kolla/globals.yml \
  "/etc/kolla/globals.yml.before-2026.1.$(date +%Y%m%d-%H%M%S)"

tee /etc/kolla/globals.yml <<'EOF'
---
# ================================================================
# OpenStack 2026.1 Gazpacho - AIO lab
# Host: Ubuntu 24.04 Noble (supported by Kolla-Ansible 2026.1)
# Kolla containers: Ubuntu 24.04 Noble
# ================================================================

# Workaround vẫn có trong file mẫu 2026.1
workaround_ansible_issue_8743: true

# Release và image
kolla_base_distro: "ubuntu"
kolla_base_distro_version: "noble"
openstack_release: "2026.1"

# Registry mặc định. Mục 7.5 hướng dẫn mirror local nếu cần.
docker_registry: "quay.io"
docker_namespace: "openstack.kolla"

# Giữ host OS precheck. Noble là host được hỗ trợ chính thức.
prechecks_enable_host_os_checks: true

# Management/API
network_interface: "wlp0s20f3"
kolla_external_vip_interface: "wlp0s20f3"
kolla_internal_vip_address: "192.168.2.250"

# Neutron + OVN
neutron_plugin_agent: "ovn"
neutron_external_interface: "veth-peer"
neutron_bridge_name: "br-ex"
neutron_physical_networks: "physnet1"
enable_neutron_provider_networks: true
enable_neutron_dvr: false
neutron_ovn_distributed_fip: false

# Core services
enable_openstack_core: true
enable_haproxy: true
enable_keepalived: true
enable_horizon: true
enable_heat: true

# Compute: đổi thành qemu nếu host không có /dev/kvm.
nova_compute_virt_type: "kvm"
nova_console: "novnc"

# Cinder không thuộc phạm vi tài liệu này.
enable_cinder: false
enable_cinder_backend_lvm: false

# Storage nâng cao không dùng
glance_backend_ceph: false
enable_manila: false

# Logging/monitoring nâng cao không dùng.
# Fluentd mặc định của Kolla vẫn xử lý log cục bộ.
enable_central_logging: false
enable_opensearch: false
enable_opensearch_dashboards: false
enable_prometheus: false
enable_grafana: false
enable_ceilometer: false
enable_gnocchi: false
enable_aodh: false

# Các service ngoài phạm vi
enable_skyline: false
enable_barbican: false
enable_designate: false
enable_magnum: false
enable_octavia: false
EOF

chmod 0640 /etc/kolla/globals.yml
```

### 6.3 Giải thích các lựa chọn quan trọng

#### `kolla_base_distro_version: "noble"`

Host Ubuntu 24.04 và image Kolla 2026.1 đều dùng Ubuntu Noble. Image đầy đủ có dạng:

```text
quay.io/openstack.kolla/keystone:2026.1-ubuntu-noble
quay.io/openstack.kolla/nova-compute:2026.1-ubuntu-noble
quay.io/openstack.kolla/neutron-server:2026.1-ubuntu-noble
```

Không đổi giá trị thành codename khác trừ khi tự build và tự kiểm thử toàn bộ Kolla image set.

#### `prechecks_enable_host_os_checks: true`

Giữ kiểm tra phân phối/codename của host. Kolla-Ansible 2026.1 chấp nhận Ubuntu Noble; nếu assert này thất bại, cần kiểm tra đúng OS và đúng branch Kolla thay vì tắt precheck.

#### `neutron_plugin_agent: "ovn"`

Kolla 2026.1 vẫn hỗ trợ cả ML2/OVS và OVN; default vẫn là Open vSwitch agent. Tài liệu chọn OVN rõ ràng để dùng kiến trúc OVN. Linux Bridge mechanism driver đã bị gỡ trong 2026.1.

### 6.4 Kiểm tra YAML và biến inventory

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"

ansible-inventory \
  -i /etc/kolla/inventory/all-in-one \
  --list >/tmp/kolla-inventory.json

jq -e 'has("_meta")' /tmp/kolla-inventory.json

grep -E '^(openstack_release|kolla_base_distro|kolla_base_distro_version|neutron_plugin_agent|network_interface|neutron_external_interface|kolla_internal_vip_address):' \
  /etc/kolla/globals.yml
```

Không được có tab trong YAML:

```bash
if grep -n $'\t' /etc/kolla/globals.yml; then
    echo "globals.yml có TAB; hãy đổi thành spaces"
else
    echo "globals.yml không có TAB"
fi
```

---

## 7. Bootstrap, kiểm tra và triển khai OpenStack

### 7.1 Kích hoạt môi trường và đặt biến inventory

```bash
# User không cần password
echo 'nguyen ALL=(ALL:ALL) NOPASSWD: ALL' | \
  sudo tee /etc/sudoers.d/90-kolla-nguyen
sudo chmod 0440 /etc/sudoers.d/90-kolla-nguyen
sudo visudo -cf /etc/sudoers
sudo -k

# Sửa biến SDK
mkdir -p /etc/kolla/inventory/host_vars

cat > /etc/kolla/inventory/host_vars/localhost.yml <<'EOF'
---
ansible_python_interpreter: /usr/bin/python3
EOF

# Kích hoạt môi trường và tạo biến
source "$HOME/venvs/kolla-2026.1/bin/activate"

INVENTORY="/etc/kolla/inventory/all-in-one"
test -r "$INVENTORY"
```

Mọi lệnh bên dưới dùng inventory này.

### 7.2 Bootstrap host và cài Docker

```bash
kolla-ansible bootstrap-servers -i "$INVENTORY"
```

Bootstrap có thể mất vài phút. Sau khi hoàn tất:

```bash
sudo systemctl status docker --no-pager
sudo docker version
sudo docker info
sudo cat /etc/docker/daemon.json | jq
```

Kỳ vọng daemon config do Kolla quản lý có các giá trị tương đương:

```json
{
  "bridge": "none",
  "ip-forward": false,
  "iptables": false,
  "log-opts": {
    "max-file": "5",
    "max-size": "50m"
  }
}
```

Không ghi đè file này bằng một mẫu thủ công.

Kiểm tra Docker repository:

```bash
apt-cache policy docker-ce
grep -R . /etc/apt/sources.list.d/docker.sources
```

Suite phải là `noble`.

### 7.3 Chạy prechecks

Bảo đảm veth còn tồn tại:

```bash
sudo /usr/local/sbin/openstack-external-net prepare
ip link show veth-peer
```

Chạy:

```bash
kolla-ansible prechecks \
  -i "$INVENTORY" \
  --use-test-images
```

Precheck host release bị tắt có chủ đích; mọi lỗi khác phải được sửa, không nên bỏ qua hàng loạt.

Nếu cần log chi tiết:

```bash
set -o pipefail
kolla-ansible -vvv prechecks -i "$INVENTORY" \
  2>&1 | tee "$HOME/kolla-prechecks-2026.1.log"
```

### 7.4 Pull image từ Quay

```bash
kolla-ansible pull -i "$INVENTORY"
```

Kiểm tra tag:

```bash
sudo docker image ls \
  --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' |
  grep '2026.1-ubuntu-noble' |
  head -n 20
```

Không tiếp tục nếu image bị trộn tag `master`, `2025.2` hoặc distro khác.

### 7.5 Tùy chọn: mirror toàn bộ image vào local registry

Bỏ qua mục này nếu mạng Internet ổn định. Quy trình thực hiện **sau khi đã
pull từ Quay ở Mục 7.4 và trước deploy**.

#### Bước 1: chạy registry

```bash
sudo mkdir -p /opt/registry/data

sudo docker run -d \
  --name local-registry \
  --restart unless-stopped \
  --network host \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:4000 \
  -v /opt/registry/data:/var/lib/registry \
  registry:2

curl -fsS http://127.0.0.1:4000/v2/
```

#### Bước 2: đổi Kolla sang registry local

Sửa `/etc/kolla/globals.yml`:

```yaml
docker_registry: "192.168.2.10:4000"
docker_registry_insecure: true
docker_namespace: "openstack.kolla"
```

Chạy bootstrap lại để Kolla cập nhật daemon:

```bash
kolla-ansible bootstrap-servers -i "$INVENTORY"
sudo cat /etc/docker/daemon.json | jq '."insecure-registries"'
curl -fsS http://192.168.2.10:4000/v2/
```

#### Bước 3: mirror đúng tag

```bash
sudo tee /usr/local/sbin/mirror-kolla-2026.1-images <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_PREFIX="quay.io/openstack.kolla"
DEST_PREFIX="192.168.2.10:4000/openstack.kolla"
TAG="2026.1-ubuntu-noble"

mapfile -t IMAGES < <(
    docker image ls --format '{{.Repository}}:{{.Tag}}' |
    grep -E "^quay[.]io/openstack[.]kolla/.+:${TAG}$" |
    sort -u
)

if (( ${#IMAGES[@]} == 0 )); then
    echo "Không tìm thấy image ${SOURCE_PREFIX} với tag ${TAG}" >&2
    exit 1
fi

echo "Sẽ mirror ${#IMAGES[@]} images"
for source_image in "${IMAGES[@]}"; do
    relative="${source_image#${SOURCE_PREFIX}/}"
    destination_image="${DEST_PREFIX}/${relative}"
    printf '\n%s -> %s\n' "$source_image" "$destination_image"
    docker tag "$source_image" "$destination_image"
    docker push "$destination_image"
done
SCRIPT

sudo chmod 0750 /usr/local/sbin/mirror-kolla-2026.1-images
sudo /usr/local/sbin/mirror-kolla-2026.1-images
```

#### Bước 4: kiểm tra và pull từ local

```bash
curl -fsS http://192.168.2.10:4000/v2/_catalog | jq

curl -fsS \
  http://192.168.2.10:4000/v2/openstack.kolla/keystone/tags/list | jq

kolla-ansible pull -i "$INVENTORY"

# Check 1 lần nữa trước khi Deploy
sudo du -sh /opt/registry/data
sudo docker system df
df -h /
kolla-ansible prechecks -i "$INVENTORY"
```

Kolla cấu hình Docker không dùng default bridge/iptables, vì vậy registry ở trên dùng host network thay cho `-p 4000:5000`. HTTP registry bind mọi interface chỉ phù hợp lab. Production phải dùng TLS, authentication, firewall và backup registry.

### 7.6 Deploy

```bash
set -o pipefail
kolla-ansible deploy -i "$INVENTORY" \
  2>&1 | tee "$HOME/kolla-deploy-2026.1.log"
```

Trong terminal khác:

```bash
sudo watch -n 3 \
  'docker ps --format "table {{.Names}}\t{{.Status}}" | sort'
```

Không nhấn `Ctrl+C` ở terminal deploy nếu playbook chỉ đang mất thời gian để
khởi tạo MariaDB, RabbitMQ hoặc pull image.

### 7.7 Kiểm tra container ngay sau deploy

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Status}}'

sudo docker ps -a \
  --filter status=exited \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

kolla-ansible check -i "$INVENTORY"
```

Container quan trọng phải running/healthy:

```bash
for container in \
  mariadb \
  rabbitmq \
  keystone \
  glance_api \
  nova_api \
  nova_compute \
  neutron_server \
  openvswitch_vswitchd \
  ovn_nb_db \
  ovn_sb_db \
  horizon; do
    sudo docker ps --format '{{.Names}}' | grep -Fx "$container" || true
done
```

Tên một vài container có thể thay đổi theo role; dùng `docker ps` làm nguồn chính.

### 7.8 Post-deploy và OpenStack CLI

```bash
kolla-ansible post-deploy -i "$INVENTORY"

python -m pip install \
  python-openstackclient \
  -c https://releases.openstack.org/constraints/upper/2026.1
```

Kolla tạo:

```text
/etc/kolla/clouds.yaml
/etc/kolla/admin-openrc.sh
/etc/kolla/admin-openrc-system.sh
```

Cách khuyến nghị là dùng `clouds.yaml`:

```bash
mkdir -p "$HOME/.config/openstack"
install -m 0600 /etc/kolla/clouds.yaml \
  "$HOME/.config/openstack/clouds.yaml"

openstack --os-cloud kolla-admin token issue
openstack --os-cloud kolla-admin service list
openstack --os-cloud kolla-admin endpoint list
```

Hoặc dùng openrc nội bộ:

```bash
source /etc/kolla/admin-openrc.sh
openstack token issue
```

### 7.9 Kích hoạt external network service

Sau khi OVS container đã chạy:

```bash
sudo systemctl start openstack-external-net.service
sudo systemctl status openstack-external-net.service --no-pager
```

Nếu service từng failed:

```bash
sudo systemctl reset-failed openstack-external-net.service
sudo systemctl restart openstack-external-net.service
journalctl -u openstack-external-net.service -n 100 --no-pager
```

Xác nhận:

```bash
sudo docker exec openvswitch_vswitchd \
  ovs-vsctl port-to-br veth-peer

sudo docker exec openvswitch_vswitchd ovs-vsctl show
ip -4 address show br-exnat
sudo iptables -t nat -L POSTROUTING -n -v
sudo iptables -L FORWARD -n -v
```

`port-to-br` phải trả về `br-ex`.

---

## 8. Tạo mạng OpenStack

Các lệnh dùng cloud `kolla-admin`:

```bash
export OS_CLOUD=kolla-admin
```

### 8.1 Tạo external provider network

```bash
openstack network create public-net \
  --external \
  --share \
  --provider-network-type flat \
  --provider-physical-network physnet1 \
  --mtu 1500
```

Tạo subnet:

```bash
openstack subnet create public-subnet \
  --network public-net \
  --subnet-range 172.31.250.0/24 \
  --gateway 172.31.250.1 \
  --allocation-pool start=172.31.250.200,end=172.31.250.250 \
  --dns-nameserver 1.1.1.1 \
  --dns-nameserver 8.8.8.8 \
  --no-dhcp
```

Giải thích:

- `physnet1` khớp `neutron_physical_networks`.
- `flat` khớp external veth/bridge không gắn VLAN.
- `--no-dhcp` vì đây là mạng ngoài giả lập.
- `.1` thuộc host bridge và không nằm trong allocation pool.
- Một địa chỉ trong pool sẽ được router dùng, phần còn lại dành cho floating IP.

### 8.2 Tạo tenant network

```bash
openstack network create private-net --mtu 1442

openstack subnet create private-subnet \
  --network private-net \
  --subnet-range 10.20.0.0/24 \
  --gateway 10.20.0.1 \
  --allocation-pool start=10.20.0.100,end=10.20.0.200 \
  --dns-nameserver 1.1.1.1 \
  --dns-nameserver 8.8.8.8
```

### 8.3 Tạo router

```bash
openstack router create main-router
openstack router set main-router --external-gateway public-net
openstack router add subnet main-router private-subnet
```

Kiểm tra:

```bash
openstack router show main-router
openstack port list --router main-router
openstack network list
openstack subnet list
```

Router phải có:

- Một interface `10.20.0.1` trên private subnet.
- Một gateway IP thuộc `172.31.250.200-250`.

### 8.4 Kiểm tra host nhìn thấy router external

Lấy IP gateway port:

```bash
ROUTER_GW_IP="$(
  openstack port list \
    --device-owner network:router_gateway \
    --router main-router \
    -f json |
  jq -r '.[0]["Fixed IP Addresses"][0].ip_address'
)"

echo "$ROUTER_GW_IP"
ping -c 3 "$ROUTER_GW_IP"
```

Nếu ping chưa được, kiểm tra OVS/veth trước khi tạo VM:

```bash
sudo apt install -y tcpdump
sudo docker exec openvswitch_vswitchd ovs-vsctl show
ip -s link show veth-ext
ip -s link show veth-peer
sudo tcpdump -ni br-exnat 'arp or icmp'
```

### 8.5 Script tạo network theo tên và kiểm tra thuộc tính

Script sau thuận tiện khi tài nguyên chưa tồn tại; nó không xóa tài nguyên và không tự sửa resource đã có. Sau phần create, các assert buộc resource cùng tên phải có đúng provider type, physnet, CIDR, gateway và MTU của guide:

```bash
tee "$HOME/create-openstack-lab-networks.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

export OS_CLOUD="${OS_CLOUD:-kolla-admin}"

if ! openstack network show public-net >/dev/null 2>&1; then
    openstack network create public-net \
      --external --share \
      --provider-network-type flat \
      --provider-physical-network physnet1 \
      --mtu 1500
fi

if ! openstack subnet show public-subnet >/dev/null 2>&1; then
    openstack subnet create public-subnet \
      --network public-net \
      --subnet-range 172.31.250.0/24 \
      --gateway 172.31.250.1 \
      --allocation-pool start=172.31.250.200,end=172.31.250.250 \
      --dns-nameserver 1.1.1.1 \
      --dns-nameserver 8.8.8.8 \
      --no-dhcp
fi

if ! openstack network show private-net >/dev/null 2>&1; then
    openstack network create private-net --mtu 1442
fi

if ! openstack subnet show private-subnet >/dev/null 2>&1; then
    openstack subnet create private-subnet \
      --network private-net \
      --subnet-range 10.20.0.0/24 \
      --gateway 10.20.0.1 \
      --allocation-pool start=10.20.0.100,end=10.20.0.200 \
      --dns-nameserver 1.1.1.1 \
      --dns-nameserver 8.8.8.8
fi

if ! openstack router show main-router >/dev/null 2>&1; then
    openstack router create main-router
fi

openstack router set main-router --external-gateway public-net

if ! openstack port list --router main-router -f value -c "Fixed IP Addresses" |
     grep -q '10.20.0.1'; then
    openstack router add subnet main-router private-subnet
fi

assert_equal() {
    local actual="$1"
    local expected="$2"
    local label="$3"
    if [[ "$actual" != "$expected" ]]; then
        printf 'SAI %s: thực tế=%q, kỳ vọng=%q\n' \
          "$label" "$actual" "$expected" >&2
        exit 1
    fi
}

assert_equal "$(openstack network show public-net -f value -c provider:network_type)" \
  "flat" "public-net provider type"
assert_equal "$(openstack network show public-net -f value -c provider:physical_network)" \
  "physnet1" "public-net physnet"
assert_equal "$(openstack network show public-net -f value -c router:external)" \
  "True" "public-net external flag"
assert_equal "$(openstack network show public-net -f value -c mtu)" \
  "1500" "public-net MTU"
assert_equal "$(openstack subnet show public-subnet -f value -c cidr)" \
  "172.31.250.0/24" "public-subnet CIDR"
assert_equal "$(openstack subnet show public-subnet -f value -c gateway_ip)" \
  "172.31.250.1" "public-subnet gateway"
assert_equal "$(openstack subnet show public-subnet -f value -c enable_dhcp)" \
  "False" "public-subnet DHCP"
assert_equal "$(openstack network show private-net -f value -c mtu)" \
  "1442" "private-net MTU"
assert_equal "$(openstack subnet show private-subnet -f value -c cidr)" \
  "10.20.0.0/24" "private-subnet CIDR"
assert_equal "$(openstack subnet show private-subnet -f value -c gateway_ip)" \
  "10.20.0.1" "private-subnet gateway"

openstack network list
openstack subnet list
openstack router show main-router
SCRIPT

chmod 0750 "$HOME/create-openstack-lab-networks.sh"
```

---

## 9. Image, flavor, keypair và máy ảo kiểm thử

### 9.1 Security group

```bash
openstack security group create allow-ssh-ping \
  --description "Lab: allow inbound SSH and IPv4 ICMP"

openstack security group rule create allow-ssh-ping \
  --ingress \
  --ethertype IPv4 \
  --protocol tcp \
  --dst-port 22 \
  --remote-ip 0.0.0.0/0

openstack security group rule create allow-ssh-ping \
  --ingress \
  --ethertype IPv4 \
  --protocol icmp \
  --remote-ip 0.0.0.0/0
```

OpenStack tự tạo egress rules mặc định cho security group mới. Kiểm tra trước khi thêm rule egress khác:

```bash
openstack security group rule list allow-ssh-ping
```

Trong production, giới hạn SSH bằng `--remote-ip` theo subnet quản trị thay vì `0.0.0.0/0`.

### 9.2 Tạo flavor

```bash
openstack flavor create m1.tiny \
  --vcpus 1 \
  --ram 512 \
  --disk 1

openstack flavor create m1.small \
  --vcpus 1 \
  --ram 2048 \
  --disk 12

openstack flavor create m1.medium \
  --vcpus 2 \
  --ram 4096 \
  --disk 25

openstack flavor list
```

### 9.3 Upload CirrOS 0.6.3 để test nhanh

```bash
mkdir -p "$HOME/openstack-images/cirros-0.6.3"
cd "$HOME/openstack-images/cirros-0.6.3"

wget -c \
  https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img
wget -c \
  https://download.cirros-cloud.net/0.6.3/SHA256SUMS

grep 'cirros-0.6.3-x86_64-disk.img$' SHA256SUMS |
  sha256sum --check

qemu-img info cirros-0.6.3-x86_64-disk.img

openstack image create "CirrOS-0.6.3" \
  --file cirros-0.6.3-x86_64-disk.img \
  --disk-format qcow2 \
  --container-format bare \
  --property hw_disk_bus=virtio \
  --property hw_vif_model=virtio \
  --public
```

### 9.4 Upload Ubuntu 24.04 cloud image

Dùng generic `amd64` image để tương thích CPU rộng hơn; không chọn file
`amd64v3` nếu chưa kiểm tra CPU:

```bash
mkdir -p "$HOME/openstack-images/ubuntu-24.04"
cd "$HOME/openstack-images/ubuntu-24.04"

wget -c \
  https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img
wget -O SHA256SUMS \
  https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS

grep 'ubuntu-24.04-server-cloudimg-amd64.img$' SHA256SUMS |
  sha256sum --check

qemu-img info ubuntu-24.04-server-cloudimg-amd64.img

openstack image create "Ubuntu-24.04" \
  --file ubuntu-24.04-server-cloudimg-amd64.img \
  --disk-format qcow2 \
  --container-format bare \
  --property hw_disk_bus=virtio \
  --property hw_vif_model=virtio \
  --public
```

Thư mục `release` vẫn được cập nhật theo các bản vá của Ubuntu. Để tái lập chính xác, lưu lại checksum của file đã dùng:

```bash
sha256sum ubuntu-24.04-server-cloudimg-amd64.img \
  | tee ubuntu-24.04-server-cloudimg-amd64.img.sha256
```

### 9.5 Tạo keypair

```bash
install -d -m 0700 "$HOME/.ssh"

if [[ ! -f "$HOME/.ssh/openstack_ed25519" ]]; then
    ssh-keygen \
      -t ed25519 \
      -f "$HOME/.ssh/openstack_ed25519" \
      -C "openstack-aio" \
      -N ""
fi

openstack keypair create \
  --public-key "$HOME/.ssh/openstack_ed25519.pub" \
  lab-key

openstack keypair list
```

Không chạy lại `keypair create` cùng tên nếu key đã tồn tại. So sánh fingerprint trước khi thay key.

### 9.6 Boot CirrOS trước

```bash
openstack server create cirros-test \
  --flavor m1.tiny \
  --image "CirrOS-0.6.3" \
  --network private-net \
  --security-group allow-ssh-ping \
  --key-name lab-key
```

Theo dõi:

```bash
watch -n 3 'openstack server list'
openstack server show cirros-test
openstack console log show cirros-test
```

VM phải chuyển sang `ACTIVE`.

### 9.7 Cấp floating IP

```bash
CIRROS_FIP="$(
  openstack floating ip create public-net \
    -f value \
    -c floating_ip_address
)"

echo "$CIRROS_FIP"
openstack server add floating ip cirros-test "$CIRROS_FIP"
openstack server list
```

Test:

```bash
ping -c 3 "$CIRROS_FIP"
ssh -o StrictHostKeyChecking=accept-new \
  -i "$HOME/.ssh/openstack_ed25519" \
  "cirros@$CIRROS_FIP"
```

Trong VM:

```sh
ip address
ip route
cat /etc/resolv.conf
ping -c 3 1.1.1.1
nslookup docs.openstack.org
```

### 9.8 Boot Ubuntu 24.04

```bash
openstack server create ubuntu2404-test \
  --flavor m1.small \
  --image "Ubuntu-24.04" \
  --network private-net \
  --security-group allow-ssh-ping \
  --key-name lab-key

watch -n 3 'openstack server list'
openstack console log show ubuntu2404-test
```

Cấp floating IP:

```bash
UBUNTU_FIP="$(
  openstack floating ip create public-net \
    -f value \
    -c floating_ip_address
)"

openstack server add floating ip ubuntu2404-test "$UBUNTU_FIP"
echo "$UBUNTU_FIP"

ssh -o StrictHostKeyChecking=accept-new \
  -i "$HOME/.ssh/openstack_ed25519" \
  "ubuntu@$UBUNTU_FIP"
```

Cloud-init có thể mất một vài phút trong lần boot đầu. Xem:

```bash
openstack console log show ubuntu2404-test | tail -n 100
```

### 9.9 Truy cập Horizon

Mở:

```text
http://192.168.2.250/
```

Đăng nhập:

```text
Domain   : Default
Username : admin
Password : xnnVjelMsphVdpbKYni8X4pigPMblMZ1Vuio80F4
```

Đọc password tại console tin cậy:

```bash
sudo grep '^keystone_admin_password:' /etc/kolla/passwords.yml
```

Không gửi file `passwords.yml` hoặc ảnh chụp password lên nơi công cộng.

---

## 10. Kiểm tra toàn hệ thống

### 10.1 Control plane

```bash
export OS_CLOUD=kolla-admin

openstack token issue
openstack catalog list
openstack service list
openstack endpoint list
openstack compute service list
openstack network agent list
openstack hypervisor list
openstack hypervisor stats show
```

Kỳ vọng:

- `nova-compute` enabled/up.
- Neutron/OVN agents alive.
- Một hypervisor hiển thị.

### 10.2 Container

```bash
kolla-ansible check -i /etc/kolla/inventory/all-in-one

sudo docker ps \
  --format '{{.Names}}\t{{.Status}}' |
  sort

sudo docker ps -a \
  --filter status=exited \
  --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
```

Không được có container core lặp restart hoặc exited.

### 10.3 VIP và endpoint

```bash
ip -4 address show dev wlp0s20f3 | grep 192.168.2.250
curl -sS -o /dev/null -w '%{http_code}\n' http://192.168.2.250/
curl -sS http://192.168.2.250:5000/v3/ | jq '.version.status'
```

Horizon thường trả 200 hoặc redirect 302. Keystone phải trả JSON version.

### 10.4 OVN, OVS và veth

```bash
sudo docker exec openvswitch_vswitchd ovs-vsctl show
sudo docker exec openvswitch_vswitchd \
  ovs-vsctl port-to-br veth-peer

ip -s link show br-exnat
ip -s link show veth-ext
ip -s link show veth-peer

sudo docker ps --format '{{.Names}}' | grep -E 'ovn|openvswitch'
```

### 10.5 NAT và forwarding

```bash
sysctl net.ipv4.ip_forward
sudo iptables -t nat -C POSTROUTING \
  -s 172.31.250.0/24 \
  -o wlp0s20f3 \
  -j MASQUERADE

sudo iptables -C FORWARD \
  -i br-exnat \
  -o wlp0s20f3 \
  -j ACCEPT

sudo iptables -t nat -L POSTROUTING -n -v
sudo iptables -L FORWARD -n -v
```

Counter phải tăng khi VM truy cập Internet.

### 10.6 Reboot test

Sau khi đã sao lưu cấu hình và không có VM đang thực hiện I/O quan trọng:

```bash
sudo reboot
```

Sau reboot:

```bash
systemctl status docker --no-pager
systemctl status openstack-external-net.service --no-pager
ip -4 address show br-exnat
sudo docker exec openvswitch_vswitchd \
  ovs-vsctl port-to-br veth-peer

source "$HOME/venvs/kolla-2026.1/bin/activate"
export OS_CLOUD=kolla-admin
kolla-ansible check -i /etc/kolla/inventory/all-in-one
openstack server list
openstack floating ip list
```

Lấy floating IP từ danh sách rồi ping/SSH lại để xác nhận dataplane đã được
khôi phục.

---

## 11. Xử lý lỗi thường gặp

### 11.1 Host là Noble nhưng precheck vẫn báo OS không được hỗ trợ

Thông báo điển hình:

```text
Ubuntu release ... is not supported.
```

Kiểm tra OS, Ansible facts và package Kolla đang dùng:

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
grep -E '^(ID|VERSION_ID|VERSION_CODENAME)=' /etc/os-release
ansible -i /etc/kolla/inventory/all-in-one all -m setup \
  -a 'filter=ansible_distribution*'
python -m pip show kolla-ansible
grep '^prechecks_enable_host_os_checks:' /etc/kolla/globals.yml
```

Với guide này, giá trị phải là:

```yaml
prechecks_enable_host_os_checks: true
```

Kỳ vọng facts trả về `Ubuntu`, release `noble`, version `24.04`. Nếu đúng OS
nhưng role vẫn dùng support matrix cũ, cài lại Kolla-Ansible từ đúng branch
`stable/2026.1` và chạy lại `kolla-ansible install-deps`. Không tắt host OS
check để che một virtual environment hoặc branch bị nhầm.

### 11.2 Phiên bản Ansible không nằm trong dải hỗ trợ

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
python --version
ansible --version
pip show ansible-core kolla-ansible
```

Sửa version:

```bash
python -m pip install --upgrade "ansible-core>=2.20,<2.21"
```

Không dùng Ansible Core 2.21 với Kolla-Ansible 2026.1 vì vượt giới hạn được
release này hỗ trợ.

### 11.3 Bootstrap không tìm thấy Docker repo `noble`

```bash
curl -fsSI \
  https://download.docker.com/linux/ubuntu/dists/noble/Release

grep -R 'Suites:' /etc/apt/sources.list.d/docker.sources
sudo apt update
apt-cache policy docker-ce
```

Nếu endpoint không khả dụng ở mirror/proxy nội bộ, sửa proxy/mirror. Không đổi
suite sang `jammy`, `oracular` hoặc một codename khác trên host Noble chỉ để
bỏ qua lỗi repository.

### 11.4 VIP không xuất hiện

```bash
ip -4 address show wlp0s20f3
sudo docker ps --format '{{.Names}}\t{{.Status}}' |
  grep -E 'keepalived|haproxy'

sudo docker logs --tail 200 keepalived
sudo docker logs --tail 200 haproxy
```

Kiểm tra:

- VIP cùng subnet management.
- VIP không bị thiết bị khác dùng.
- `network_interface` và `kolla_external_vip_interface` đúng tên.
- Wi-Fi vẫn có IP management.

### 11.5 `veth-peer` không tồn tại

```bash
ip link show veth-ext
ip link show veth-peer
sudo /usr/local/sbin/openstack-external-net prepare
```

Nếu chỉ còn một đầu veth, script cố ý dừng. Xác nhận không có dataplane đang
chạy rồi mới xóa chính xác cặp lỗi và tạo lại:

```bash
# Chỉ dùng trong maintenance window khi đã xác nhận đúng interface
if ip link show veth-ext >/dev/null 2>&1; then
    BROKEN_VETH="veth-ext"
elif ip link show veth-peer >/dev/null 2>&1; then
    BROKEN_VETH="veth-peer"
else
    echo "Không còn đầu veth nào để xóa"
    exit 1
fi

sudo ip link delete "$BROKEN_VETH"
sudo /usr/local/sbin/openstack-external-net prepare
sudo systemctl restart openstack-external-net.service
```

Xóa một đầu veth sẽ xóa cả cặp.

### 11.6 `veth-peer` chưa ở `br-ex`

```bash
sudo docker exec openvswitch_vswitchd ovs-vsctl show
sudo systemctl restart openstack-external-net.service
journalctl -u openstack-external-net.service -n 100 --no-pager
```

Gắn thủ công để kiểm tra:

```bash
sudo docker exec openvswitch_vswitchd \
  ovs-vsctl --may-exist add-port br-ex veth-peer
```

Sau đó:

```bash
sudo docker exec openvswitch_vswitchd \
  ovs-vsctl get Interface veth-peer ofport
```

`ofport` không được là `-1`.

### 11.7 VM ACTIVE nhưng không ra Internet

Kiểm tra theo từng lớp:

```bash
# 1. Router và port
openstack router show main-router
openstack port list --router main-router

# 2. Floating/fixed IP
openstack server show ubuntu2404-test
openstack floating ip list

# 3. Host gateway và forwarding
ip -4 address show br-exnat
sysctl net.ipv4.ip_forward

# 4. NAT counter
sudo iptables -t nat -L POSTROUTING -n -v
sudo iptables -L FORWARD -n -v

# 5. Packet capture
sudo tcpdump -ni br-exnat 'arp or icmp or port 53'
```

Trong VM:

```bash
ip route
ping -c 3 10.20.0.1
ping -c 3 1.1.1.1
getent hosts ubuntu.com
```

Diễn giải:

- Không ping `10.20.0.1`: private network/router/security path lỗi.
- Ping `10.20.0.1` nhưng không ping `1.1.1.1`: external bridge/NAT lỗi.
- Ping `1.1.1.1` nhưng DNS lỗi: subnet DNS hoặc resolver lỗi.

### 11.8 Nova compute down hoặc VM ERROR

```bash
VM_NAME="ubuntu2404-test"
openstack compute service list
openstack server show "$VM_NAME"
openstack console log show "$VM_NAME"

sudo docker logs --tail 300 nova_compute
sudo docker logs --tail 300 nova_libvirt
ls -l /dev/kvm
sudo virt-host-validate qemu
```

Nếu không có KVM, sửa:

```yaml
nova_compute_virt_type: "qemu"
```

Rồi:

```bash
kolla-ansible reconfigure \
  -i /etc/kolla/inventory/all-in-one \
  --tags nova
```

### 11.9 Container restart loop

```bash
sudo docker ps -a \
  --format '{{.Names}}\t{{.Status}}' |
  grep -E 'Restarting|Exited'

CONTAINER_NAME="nova_compute"
sudo docker logs --tail 300 "$CONTAINER_NAME"
sudo find /var/log/kolla -type f -mmin -10 -print

# Chọn một file vừa tìm thấy, ví dụ:
LOG_FILE="/var/log/kolla/nova/nova-compute.log"
sudo tail -n 200 "$LOG_FILE"
```

Kiểm tra tài nguyên host:

```bash
free -h
df -hT
df -ih
sudo dmesg -T | grep -Ei 'oom|killed process|I/O error|nvme'
```

### 11.10 Deploy thất bại giữa chừng

Sau khi sửa nguyên nhân, có thể chạy lại:

```bash
kolla-ansible prechecks -i /etc/kolla/inventory/all-in-one
kolla-ansible deploy -i /etc/kolla/inventory/all-in-one
```

Không dùng `destroy` như bước xử lý lỗi đầu tiên. `destroy` xóa container,
volume cấu hình nội bộ và có thể làm mất deployment.

---

## 12. Vận hành, cập nhật và sao lưu

### 12.1 Reconfigure sau khi sửa `globals.yml`

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"

kolla-ansible prechecks -i /etc/kolla/inventory/all-in-one
kolla-ansible reconfigure -i /etc/kolla/inventory/all-in-one
kolla-ansible check -i /etc/kolla/inventory/all-in-one
```

Giới hạn theo service khi thay đổi nhỏ:

```bash
kolla-ansible reconfigure \
  -i /etc/kolla/inventory/all-in-one \
  --tags neutron
```

Không dùng `--tags` nếu thay đổi có quan hệ nhiều service mà chưa hiểu đầy đủ
dependency.

### 12.2 Cập nhật patch trong cùng stable branch

Trước tiên sao lưu và đọc release notes:

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"

python -m pip install --upgrade \
  "git+https://opendev.org/openstack/kolla-ansible@stable/2026.1"

kolla-ansible install-deps
kolla-ansible bootstrap-servers -i /etc/kolla/inventory/all-in-one
kolla-ansible prechecks -i /etc/kolla/inventory/all-in-one
kolla-ansible pull -i /etc/kolla/inventory/all-in-one
kolla-ansible upgrade -i /etc/kolla/inventory/all-in-one
kolla-ansible post-deploy -i /etc/kolla/inventory/all-in-one
kolla-ansible check -i /etc/kolla/inventory/all-in-one
```

Chạy trong maintenance window. Bootstrap có thể cập nhật/restart Docker.

### 12.3 Sao lưu cấu hình và secret

```bash
BACKUP_DIR="/var/backups/openstack-aio/$(date +%F-%H%M%S)"
sudo install -d -m 0700 "$BACKUP_DIR"

sudo tar \
  --create \
  --gzip \
  --file "$BACKUP_DIR/etc-kolla.tar.gz" \
  /etc/kolla

sudo tar \
  --create \
  --gzip \
  --file "$BACKUP_DIR/host-openstack-config.tar.gz" \
  /etc/openstack-external-net.conf \
  /etc/systemd/system/openstack-external-net.service \
  /etc/modules-load.d/openstack-aio.conf \
  /etc/sysctl.d/98-openstack-memory.conf \
  /etc/sysctl.d/99-openstack-aio.conf \
  /usr/local/sbin/openstack-aio-preflight \
  /usr/local/sbin/openstack-external-net

sudo docker inspect local-registry 2>/dev/null |
  sudo tee "$BACKUP_DIR/local-registry.inspect.json" >/dev/null || true

sudo find "$BACKUP_DIR" \
  -maxdepth 1 \
  -type f \
  ! -name SHA256SUMS \
  -exec sha256sum {} + |
  sudo tee "$BACKUP_DIR/SHA256SUMS"
```

Lưu bản sao mã hóa ở thiết bị khác. Archive chứa password toàn hệ thống.

### 12.4 Backup MariaDB

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"

kolla-ansible mariadb-backup \
  -i /etc/kolla/inventory/all-in-one \
  --full
```

Kiểm tra vị trí và log backup theo output của playbook. Database backup không
thay thế backup Glance image, registry hoặc `/etc/kolla`.

### 12.5 Dữ liệu cần bảo vệ riêng

| Dữ liệu               | Vị trí/nguồn                      |
| ----------------------- | ------------------------------------ |
| Kolla config và secret | `/etc/kolla`                       |
| MariaDB backup          | output của`mariadb-backup`        |
| Glance file backend     | Docker volume/bind mount của Glance |
| Local registry          | `/opt/registry/data`               |
| SSH private key         | `~/.ssh/openstack_ed25519`         |
| Image gốc và checksum | `~/openstack-images`               |

Snapshot một filesystem đang có database/I/O mà không quiesce không bảo đảm
nhất quán.

### 12.6 Kiểm tra định kỳ

```bash
export OS_CLOUD=kolla-admin

kolla-ansible check -i /etc/kolla/inventory/all-in-one
openstack compute service list
openstack network agent list
openstack server list --all-projects

sudo docker system df
df -hT
systemctl --failed
```

Kiểm tra network service:

```bash
systemctl is-enabled openstack-external-net.service
systemctl is-active openstack-external-net.service
sudo docker exec openvswitch_vswitchd ovs-vsctl port-to-br veth-peer
```

### 12.7 Checklist hoàn tất

- [ ] Host là Ubuntu 24.04 Noble và host OS precheck vẫn được bật.
- [ ] Python 3.12 dùng Ansible Core 2.20.
- [ ] Kolla-Ansible lấy từ `stable/2026.1`.
- [ ] Image tag là `2026.1-ubuntu-noble`.
- [ ] IP management ổn định và VIP không trùng.
- [ ] `veth-peer` tồn tại, UP, không có IP và thuộc OVS `br-ex`.
- [ ] `br-exnat` có `172.31.250.1/24`.
- [ ] NAT/FORWARD counter tăng khi VM ra Internet.
- [ ] `kolla-ansible check` thành công.
- [ ] Nova và Neutron service đều up.
- [ ] CirrOS có fixed IP, floating IP và Internet.
- [ ] Ubuntu 24.04 guest SSH được.
- [ ] Horizon truy cập được qua VIP.
- [ ] Reboot test thành công.
- [ ] `/etc/kolla`, MariaDB và dữ liệu storage đã có backup.

---

## 13. Tài liệu chính thức tham chiếu

Các link dưới đây là nguồn cần kiểm tra lại trước mỗi lần cài mới:

1. [OpenStack 2026.1 Gazpacho release](https://releases.openstack.org/gazpacho/)
2. [Kolla-Ansible 2026.1 support matrix](https://docs.openstack.org/kolla-ansible/2026.1/user/support-matrix.html)
3. [Kolla-Ansible 2026.1 quick start](https://docs.openstack.org/kolla-ansible/2026.1/user/quickstart.html)
4. [Kolla-Ansible 2026.1 release notes](https://docs.openstack.org/releasenotes/kolla-ansible/2026.1.html)
5. [Kolla Neutron networking reference](https://docs.openstack.org/kolla-ansible/2026.1/reference/networking/neutron.html)
6. [Kolla bootstrapping servers](https://docs.openstack.org/kolla-ansible/2026.1/reference/deployment-and-bootstrapping/bootstrap-servers.html)
7. [Ubuntu 24.04 LTS release notes](https://documentation.ubuntu.com/release-notes/24.04/)
8. [Ubuntu 24.04 released cloud images](https://cloud-images.ubuntu.com/releases/noble/release/)
9. [Ansible Core support matrix](https://docs.ansible.com/projects/ansible/latest/reference_appendices/release_and_maintenance.html)
10. [Docker Engine install for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
11. [CirrOS download index](https://download.cirros-cloud.net/0.6.3/)
12. [Kolla-Ansible advanced configuration](https://docs.openstack.org/kolla-ansible/2026.1/admin/advanced-configuration.html)
13. [Ubuntu Cloud Archive Gazpacho metadata](https://ubuntu-cloud.archive.canonical.com/ubuntu/dists/noble-updates/gazpacho/Release)

> Ubuntu Noble được liệt kê trong support matrix Kolla-Ansible 2026.1. **Trước mỗi lần cài mới vẫn cần đọc release notes và support matrix mới nhất vì các patch release có thể thay đổi dependency, image hoặc quy trình vận hành.**
