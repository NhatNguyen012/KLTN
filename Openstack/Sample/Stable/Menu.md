# START

```bash
# Management IP hiện tại phải có trên Wi-Fi interface.
ip -4 address show dev wlp0s20f3 | grep -Fq '192.168.2.10/24' || {
    echo "Thiếu management IP 192.168.2.10/24 trên wlp0s20f3"
    exit 1
}

source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh
cd /etc/kolla/inventory
export PYTHONWARNINGS="ignore"

# Docker, local-registry và external-net tự khởi động cùng Ubuntu.
systemctl is-active --quiet docker.service || {
    echo "docker.service chưa active"
    exit 1
}

if ! sudo docker inspect -f '{{.State.Running}}' local-registry 2>/dev/null | grep -qx 'true'; then
    echo "local-registry chưa running"
    exit 1
fi

# Kolla 2026.1 quản lý container bằng các systemd unit Restart=always.
mapfile -t KOLLA_UNITS < <(
  systemctl list-unit-files \
    --type=service \
    --no-legend \
    --no-pager |
  awk '$1 ~ /^kolla-.*-container[.]service$/ {print $1}'
)

(( ${#KOLLA_UNITS[@]} > 0 )) || {
    echo "Không tìm thấy Kolla container unit"
    exit 1
}

sudo systemctl daemon-reload
sudo systemctl reset-failed "${KOLLA_UNITS[@]}"
sudo systemctl start "${KOLLA_UNITS[@]}"

sudo docker ps -a --filter status=exited
sudo docker ps -a --filter health=unhealthy

source /etc/kolla/admin-openrc.sh
openstack token issue

watch 'sudo docker ps --format "table {{.Names}}\t{{.Status}}"'
```

Nhấn `Ctrl+C` để thoát `watch`. Không tự động restart hàng loạt container
unhealthy; xem log trước bằng:

```bash
CONTAINER_NAME="nova_compute"
sudo docker logs --tail 200 "$CONTAINER_NAME"
```

---

# STOP

Nên shutdown các VM đang chạy trước khi dừng control plane.

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh

openstack server list --all-projects

# Phải stop systemd unit, không docker stop trực tiếp container Kolla.
mapfile -t KOLLA_UNITS < <(
  systemctl list-unit-files \
    --type=service \
    --no-legend \
    --no-pager |
  awk '$1 ~ /^kolla-.*-container[.]service$/ {print $1}'
)

if (( ${#KOLLA_UNITS[@]} > 0 )); then
    sudo systemctl stop "${KOLLA_UNITS[@]}"
fi
```

STOP chỉ dừng các Kolla container unit. Nó không stop/mask Docker, không stop `local-registry` và không đụng đến `openstack-external-net.service`. Các thành phần này tiếp tục được systemd/Docker khởi động cùng Ubuntu.

Các Kolla unit vẫn `enabled`, vì vậy OpenStack cũng sẽ tự khởi động ở lần boot tiếp theo. Muốn chạy lại ngay, dùng phần **START**.

---

# Đổi management IP hoặc Kolla VIP

Script sử dụng:

```text
Stable/update-kolla-network.sh
```

## 1. Điều kiện trước khi chạy

1. Gán management IP mới bằng NetworkManager.
2. Xác nhận IP mới đã nằm trên `wlp0s20f3`.
3. Chọn VIP trống cùng subnet `/24`.
4. OpenStack và Docker phải đang chạy.

```bash
ip -4 address show dev wlp0s20f3
ip -4 route show default

grep -E \
  '^(network_interface|kolla_internal_vip_address|docker_registry):' \
  /etc/kolla/globals.yml
```

Management IP hiện tại là `192.168.2.10/24`, nhưng hậu kiểm cho thấy nó vẫn
được DHCP cấp. Nên tạo DHCP reservation hoặc đặt IPv4 tĩnh trước khi đổi cấu
hình Kolla.

## 2. Chạy updater

```bash
cd /home/nguyen/Desktop/Openstack/Stable

NEW_IP="192.168.2.20"
NEW_VIP="192.168.2.250"

sudo bash ./update-kolla-network.sh \
  "$NEW_IP" \
  "$NEW_VIP" \
  wlp0s20f3
```

Script yêu cầu gõ chính xác `APPLY` và tạo backup tại:

```text
/var/backups/kolla-network-update/
```

Script chỉ cập nhật:

- `/etc/hosts`;
- `/etc/kolla/globals.yml`;
- `/etc/docker/daemon.json` khi local registry đổi IP.

Script không sửa trực tiếp generated service config, OpenRC hoặc database.

## 3. Reconfigure

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"

kolla-ansible prechecks \
  -i /etc/kolla/inventory/all-in-one

kolla-ansible reconfigure \
  -i /etc/kolla/inventory/all-in-one \
  2>&1 | tee /tmp/kolla-reconfigure.log

kolla-ansible post-deploy \
  -i /etc/kolla/inventory/all-in-one

```

## 4. Hậu kiểm

```bash
cd /home/nguyen/Desktop/Openstack/Stable
sudo bash ./update-kolla-network.sh --check

source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh

openstack token issue
openstack compute service list
openstack network agent list

sudo docker ps -a \
  --format '{{.Names}}\t{{.Status}}' |
  grep -E 'Exited|Restarting|unhealthy' || echo "Không có container lỗi"
```
