# Mục tiêu
Tạo 1 script duy nhất để:
- Nhập `NEW_IP` và `NEW_VIP`
- Tự động cập nhật Kolla + OpenRC + clouds.yaml + Ceph configs
- Giảm tối đa lỗi sau đổi IP/VIP (như lỗi đã ghi trong `tmp.txt`)

> Có khả thi. Tuy nhiên không thể cam kết 100% “không lỗi” cho mọi trạng thái hệ thống. Script dưới đây đã bao gồm các bước quan trọng nhất để tránh các lỗi đã gặp trước đó.

---

# 1) Script 1-shot: update-kolla-ceph-network.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

# =============================
# update-kolla-ceph-network.sh
# =============================
# Chạy:
#   sudo bash ./update-kolla-ceph-network.sh
# Sau đó:
#   source ~/kolla-venv/bin/activate
#   kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one

KOLLA_HOSTNAME_DEFAULT="openstack-aio"
INVENTORY_DEFAULT="/etc/kolla/ansible/inventory/all-in-one"
KOLLA_DIR="/etc/kolla"
CEPH_ETC_DIR="/etc/ceph"
CEPH_VAR_DIR="/var/lib/ceph"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
die()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Vui lòng chạy bằng sudo/root."
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<< "$ip"
  for n in "$a" "$b" "$c" "$d"; do
    [[ "$n" -ge 0 && "$n" -le 255 ]] || return 1
  done
}

backup_file() {
  local f="$1" ts="$2"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.${ts}"
}

replace_in_file() {
  local file="$1" old="$2" new="$3"
  [[ -f "$file" ]] || return 0
  sed -i "s|${old}|${new}|g" "$file"
}

update_hosts_hostname() {
  local ip="$1" host="$2"
  local hosts_file="/etc/hosts"
  cp -a "$hosts_file" "${hosts_file}.bak.${TS}"
  sed -i "/[[:space:]]${host}$/d" "$hosts_file"
  printf "%s %s\n" "$ip" "$host" >> "$hosts_file"
  log "Updated /etc/hosts: ${ip} ${host}"
}

update_globals_yml() {
  local ip="$1" vip="$2" g="$KOLLA_DIR/globals.yml"
  [[ -f "$g" ]] || die "Không tìm thấy $g"
  backup_file "$g" "$TS"

  sed -i "s|^kolla_internal_vip_address:.*|kolla_internal_vip_address: \"${vip}\"|g" "$g"
  if grep -q "^kolla_external_vip_address:" "$g"; then
    sed -i "s|^kolla_external_vip_address:.*|kolla_external_vip_address: \"${vip}\"|g" "$g"
  fi
  if grep -q "^docker_registry:" "$g"; then
    sed -i "s|^docker_registry:.*|docker_registry: \"${ip}:4000\"|g" "$g"
  fi
  log "Updated globals.yml (VIP + docker_registry)"
}

update_openrc_and_clouds() {
  local old_vip="$1" new_vip="$2"
  local files=(
    "$KOLLA_DIR/admin-openrc.sh"
    "$KOLLA_DIR/admin-openrc-system.sh"
    "$KOLLA_DIR/public-openrc.sh"
    "$KOLLA_DIR/public-openrc-system.sh"
    "$KOLLA_DIR/usera-openrc.sh"
    "$KOLLA_DIR/usera1-openrc.sh"
    "$KOLLA_DIR/usera2-openrc.sh"
    "$KOLLA_DIR/userb-openrc.sh"
    "$KOLLA_DIR/clouds.yaml"
  )
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    backup_file "$f" "$TS"
    replace_in_file "$f" "$old_vip" "$new_vip"
  done
  log "Updated OpenRC/clouds.yaml"
}

detect_old_refs() {
  # tìm IP/VIP cũ từ globals/hosts để thay thế diện rộng
  OLD_VIP="$(awk -F'"' '/^kolla_internal_vip_address:/ {print $2}' "$KOLLA_DIR/globals.yml" 2>/dev/null || true)"
  OLD_IP="$(awk -v host="$KOLLA_HOSTNAME" '$2==host {print $1}' /etc/hosts 2>/dev/null | tail -1 || true)"
}

update_kolla_service_configs() {
  local old_ip="$1" new_ip="$2" old_vip="$3" new_vip="$4"
  [[ -d "$KOLLA_DIR" ]] || return 0
  if [[ -n "$old_ip" ]]; then
    find "$KOLLA_DIR" -type f -name "*.conf" -o -name "*.json" -o -name "*.ini" -o -name "*.yaml" -o -name "*.yml" -o -name "*openrc*" | \
      while read -r f; do
        replace_in_file "$f" "$old_ip" "$new_ip"
      done
  fi
  if [[ -n "$old_vip" ]]; then
    find "$KOLLA_DIR" -type f -name "*.conf" -o -name "*.json" -o -name "*.ini" -o -name "*.yaml" -o -name "*.yml" -o -name "*openrc*" | \
      while read -r f; do
        replace_in_file "$f" "$old_vip" "$new_vip"
      done
  fi
  log "Patched /etc/kolla runtime refs"
}

update_ceph_conf_files() {
  local old_ip="$1" new_ip="$2" old_cidr="$3" new_cidr="$4"
  [[ -d "$CEPH_ETC_DIR" ]] || { warn "Không có /etc/ceph, bỏ qua."; return 0; }

  # /etc/ceph và /etc/kolla/manila ceph conf
  local confs=()
  while IFS= read -r f; do confs+=("$f"); done < <(find "$CEPH_ETC_DIR" "$KOLLA_DIR/config/manila" "$KOLLA_DIR/manila-share/ceph" -type f -name "ceph.conf" 2>/dev/null || true)
  for f in "${confs[@]}"; do
    backup_file "$f" "$TS"
    replace_in_file "$f" "$old_ip" "$new_ip"
    if [[ -n "$old_cidr" ]]; then replace_in_file "$f" "$old_cidr" "$new_cidr"; fi
  done

  # cephadm daemon config files
  if [[ -d "$CEPH_VAR_DIR" ]]; then
    while IFS= read -r f; do
      backup_file "$f" "$TS"
      replace_in_file "$f" "$old_ip" "$new_ip"
      if [[ -n "$old_cidr" ]]; then replace_in_file "$f" "$old_cidr" "$new_cidr"; fi
      # đảm bảo osd có network mới
      if [[ "$f" == *"/osd."*/config ]]; then
        grep -q "^\\s*public_network" "$f" || echo "public_network = ${new_cidr}" >> "$f"
        grep -q "^\\s*cluster_network" "$f" || echo "cluster_network = ${new_cidr}" >> "$f"
      fi
    done < <(find "$CEPH_VAR_DIR" -type f -name "config" 2>/dev/null || true)
  fi
  log "Updated Ceph config files"
}

restart_ceph_services() {
  # restart theo cụm fsid nếu có (kèm fallback để tránh miss)
  local ceph_units=""
  ceph_units="$(systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null | awk '/ceph-.*@.*\.service/ {print $1}' || true)"
  if [[ -z "$ceph_units" ]]; then
    ceph_units="$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '/^ceph-.*@.*\.service/ {print $1}' || true)"
  fi
  [[ -n "$ceph_units" ]] || { warn "Không tìm thấy ceph services qua systemd, bỏ qua restart Ceph."; return 0; }

  info "Restart Ceph services (best effort)..."
  while read -r u; do
    [[ -n "$u" ]] || continue
    systemctl restart "$u" || warn "Restart fail: $u"
  done <<< "$ceph_units"
  log "Restart Ceph services done"
}

check_nova_cell_mapping_hint() {
  warn "Sau reconfigure, nếu gặp lại lỗi nova Access denied:"
  warn "  -> Kiểm tra bảng nova_api.cell_mappings có đang dùng sai password cho user nova."
}

main() {
  require_root
  TS="$(date +%Y%m%d_%H%M%S)"

  echo "=== OpenStack/Kolla/Ceph Network Updater ==="
  read -rp "Nhap NEW_IP (vd 10.231.194.18): " NEW_IP
  read -rp "Nhap NEW_VIP (vd 10.231.194.250): " NEW_VIP
  read -rp "Nhap hostname trong /etc/hosts [${KOLLA_HOSTNAME_DEFAULT}]: " KOLLA_HOSTNAME
  KOLLA_HOSTNAME="${KOLLA_HOSTNAME:-$KOLLA_HOSTNAME_DEFAULT}"

  is_ipv4 "$NEW_IP" || die "NEW_IP không hợp lệ."
  is_ipv4 "$NEW_VIP" || die "NEW_VIP không hợp lệ."

  NEW_CIDR="$(echo "$NEW_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')"

  detect_old_refs
  OLD_CIDR=""
  if [[ -n "${OLD_IP:-}" ]]; then
    OLD_CIDR="$(echo "$OLD_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')"
  fi

  info "Old IP=${OLD_IP:-N/A}, Old VIP=${OLD_VIP:-N/A}, Old CIDR=${OLD_CIDR:-N/A}"
  info "New IP=${NEW_IP}, New VIP=${NEW_VIP}, New CIDR=${NEW_CIDR}"
  read -rp "Xac nhan cap nhat? [y/N]: " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || die "Hủy bởi người dùng."

  update_hosts_hostname "$NEW_IP" "$KOLLA_HOSTNAME"
  update_globals_yml "$NEW_IP" "$NEW_VIP"
  update_openrc_and_clouds "${OLD_VIP:-}" "$NEW_VIP"
  update_kolla_service_configs "${OLD_IP:-}" "$NEW_IP" "${OLD_VIP:-}" "$NEW_VIP"
  update_ceph_conf_files "${OLD_IP:-}" "$NEW_IP" "${OLD_CIDR:-}" "$NEW_CIDR"
  restart_ceph_services

  echo
  log "Hoàn tất cập nhật file cấu hình và restart Ceph (best effort)."
  echo "BƯỚC TIẾP THEO (BẮT BUỘC):"
  echo "  source ~/kolla-venv/bin/activate"
  echo "  kolla-ansible reconfigure -i ${INVENTORY_DEFAULT}"
  echo
  echo "BƯỚC KHUYẾN NGHỊ SAU RECONFIGURE:"
  echo "  docker ps --format 'table {{.Names}}\\t{{.Status}}' | grep -E 'unhealthy|Exited'"
  echo "  sudo ceph -s || true"
  check_nova_cell_mapping_hint
}

main "$@"
```

---

# 2) Cách dùng nhanh

```bash
chmod +x update-kolla-ceph-network.sh
sudo ./update-kolla-ceph-network.sh

source ~/kolla-venv/bin/activate
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one
```

---

# 3) Trả lời câu hỏi “có khả thi không?”

**Có, khả thi** và script trên sẽ tự động hóa phần lớn việc đổi IP/VIP để tránh lỗi kiểu:
- config runtime còn IP cũ trong `/etc/kolla/*`
- `openrc`/`clouds.yaml` trỏ VIP cũ
- Ceph conf còn IP/CIDR cũ gây `manila_share` lỗi kết nối Ceph

**Giới hạn thực tế**:
- Không thể đảm bảo tuyệt đối cho mọi trạng thái DB lịch sử (ví dụ `nova_api.cell_mappings` sai password).
- Vì vậy script có cảnh báo hậu kiểm để xử lý nhanh nếu gặp case hiếm.

---

# 4) Theo dõi `reconfigure` đến khi `failed=0`

Chạy reconfigure và ghi log, rồi trong terminal khác chờ **PLAY RECAP** cuối:

```bash
source ~/kolla-venv/bin/activate
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one 2>&1 | tee /tmp/kolla-reconfigure.log
```

```bash
bash /path/to/Stable/update-kolla-ceph-network.sh --wait-log /tmp/kolla-reconfigure.log
```

Script sẽ lặp cho đến khi vài chục dòng cuối log có `PLAY RECAP` và dòng `localhost : ... failed=0`, hoặc báo lỗi nếu `failed` khác 0. **Bản đầy đủ** luôn nằm trong file `Stable/update-kolla-ceph-network.sh` trên đĩa (không chỉ bản trích trong mục 1).

Ngay sau đó chạy hậu kiểm dịch vụ:

```bash
sudo bash /path/to/Stable/update-kolla-ceph-network.sh --postcheck <NEW_IP>
```

Ví dụ:

```bash
sudo bash /path/to/Stable/update-kolla-ceph-network.sh --postcheck 192.168.1.2
```

`--wait-log` chỉ xác nhận Ansible thành công. `--postcheck` mới kiểm tra thêm:

- `manila_share` đã `healthy` hay chưa
- `ceph-mon` đang listen đúng `<NEW_IP>:6789` hay không
- `ceph -s` có trả kết quả (không treo) hay không

---

# 5) Lỗi reconfigure *không* tự hết bằng script mạng (xử lý thủ công / DB)

Các case sau **không** nên tự động hóa mù trong `update-kolla-ceph-network.sh` vì cần đọc DB và quyết định:

- **`nova_api.cell_mappings`**: sai password trong chuỗi `database_connection`, hoặc **hai cell trùng** → cần SQL/ghi chép trong `tmp.txt` (ERROR 1, ERROR 6).
- **Ceph monmap / OSD network**: đổi subnet phải monmap + `ceph.conf` — script đã phần nào sửa file config; monmap vẫn cần quy trình Ceph (xem `tmp.txt` ERROR 4).

**Lệnh đầy đủ** (grep mật khẩu, `SELECT`/`UPDATE` mẫu cho `cell_mappings`, backup, ProxySQL, Ceph monmap inject) được in sẵn bởi script:

```bash
bash update-kolla-ceph-network.sh --manual-help <NEW_IP> <VIP_kolla>
```

Ví dụ: `<NEW_IP>` là IP máy AIO sau khi đổi Wi‑Fi, `<VIP_kolla>` là `kolla_internal_vip_address` trong `/etc/kolla/globals.yml`. Tham số thứ nhất dùng cho khối **Ceph monmap**; thứ hai cho chuỗi **Nova/Rabbit** trong MariaDB.

Ví dụ rút gọn (root trong container `mariadb` — mật khẩu root DB trong Kolla thường là key `database_password` trong `passwords.yml`):

```bash
# DB_ROOT lấy từ passwords.yml — dùng cùng awk như trong output của --manual-help
docker exec mariadb mysql -uroot -p"$DB_ROOT" nova_api -e "SELECT name, uuid FROM cell_mappings;"
```

---

# 6) Patch file YAML *trong kolla-venv* (RabbitMQ / nova-cell)

Đây **không phải** file OpenStack trong `/etc/kolla`, mà là role Ansible trong `~/kolla-venv/share/kolla-ansible/ansible/roles/...`.

- **Mục đích**: giảm lỗi dừng playbook do `rabbitmqctl` tạm lỗi hoặc JSON/`openstack` flake khi chờ nova-compute.
- **Rủi ro**: có thể che bớt lỗi thật — luôn kiểm tra container sau reconfigure.
- **Khi nâng cấp kolla-ansible**: các patch **có thể mất**; cần diff/lưu lại và áp dụng lại sau `pip install --upgrade`.

Chi tiết lỗi và đường dẫn file: xem `tmp.txt` (ERROR 5–7 và bảng phân biệt file).

---

# 7) Case đặc biệt: máy còn giữ cả IP cũ và IP mới

Nếu `ip a` cho thấy cùng một interface đang giữ cả hai IP, ví dụ `192.168.1.2` và `10.231.194.18`, thì rất dễ rơi vào trạng thái:

- Kolla/OpenStack đã `reconfigure` theo **một** dải IP.
- Ceph daemon / monmap vẫn đang bind theo **dải còn lại**.

Triệu chứng điển hình:

- `kolla-ansible reconfigure` vẫn `failed=0`.
- `docker ps` còn `manila_share (unhealthy)`.
- `sudo ceph -s` bị treo hoặc `Cluster connection aborted`.
- `ss -lntp` cho thấy `ceph-mon` đang nghe trên IP khác với `mon_host` trong `ceph.conf`.

Ví dụ thực tế:

- `/etc/kolla/globals.yml` đang là `192.168.1.150`
- `/etc/hosts` đang là `192.168.1.2 openstack-aio`
- nhưng `ceph-mon` lại listen trên `10.231.194.18:6789`

Khi đó hệ thống đang ở **mixed state**. Cần chọn **một** hướng nhất quán:

1. Giữ mạng cũ `192.168.1.x`
2. Chuyển hẳn sang mạng mới `10.231.194.x`

Không nên để OpenStack đi theo một dải và Ceph đi theo dải còn lại.

Script `update-kolla-ceph-network.sh` đã được bổ sung:

- cảnh báo khi interface có **nhiều IPv4**
- cho phép nhập tay `OLD_IP` và `OLD_VIP`
- cho phép nhập danh sách `OLD_IP` bổ sung (CSV), ví dụ `10.231.194.18`
- thêm mode hậu kiểm `--postcheck` để phát hiện case `failed=0` nhưng Ceph/Manila chưa khỏe

để tránh trường hợp tự phát hiện sai IP cũ khi rollback hoặc đổi mạng nhiều lần.

## 8) Lỗi đã gặp thực tế và cách xử lý nhanh

Tình huống thực tế:

- `kolla-ansible reconfigure` có `failed=0`
- nhưng `manila_share` vẫn `unhealthy`
- `sudo ceph -s` treo (`Cluster connection aborted`)

Nguyên nhân: **monmap của Ceph monitor vẫn trỏ IP cũ**, trong khi `ceph.conf` đã đổi.

Kiểm tra nhanh:

```bash
sudo ss -lntp | grep 6789
```

Nếu `ceph-mon` không nghe trên `<NEW_IP>:6789`, cần sửa monmap thủ công:

```bash
sudo systemctl stop ceph-<fsid>@mon.openstack-aio.service
sudo podman run --rm --entrypoint /bin/bash \
  -v /var/lib/ceph/<fsid>/mon.openstack-aio:/var/lib/ceph/mon/ceph-openstack-aio:z \
  -v /tmp:/tmp quay.io/ceph/ceph:v19 \
  -c "ceph-mon -i openstack-aio --extract-monmap /tmp/monmap.bin --mon-data /var/lib/ceph/mon/ceph-openstack-aio && \
      monmaptool --rm openstack-aio /tmp/monmap.bin && \
      monmaptool --add openstack-aio <NEW_IP>:6789 /tmp/monmap.bin && \
      ceph-mon -i openstack-aio --inject-monmap /tmp/monmap.bin --mon-data /var/lib/ceph/mon/ceph-openstack-aio"
sudo systemctl start ceph-<fsid>@mon.openstack-aio.service
docker restart manila_share
```

Sau đó xác nhận:

```bash
sudo ceph --mon-host <NEW_IP>:6789 -s
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep manila_share
```