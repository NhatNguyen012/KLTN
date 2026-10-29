#!/usr/bin/env bash
set -Eeuo pipefail

# Cập nhật management IP, Kolla VIP và local registry cho OpenStack AIO.
# Không có Ceph, Manila, Magnum hoặc Cinder trong deployment này.

readonly KOLLA_DIR="/etc/kolla"
readonly GLOBALS_FILE="${KOLLA_DIR}/globals.yml"
readonly INVENTORY="${KOLLA_DIR}/inventory/all-in-one"
readonly DOCKER_DAEMON_FILE="/etc/docker/daemon.json"
readonly HOSTS_FILE="/etc/hosts"
readonly HOSTNAME_DEFAULT="openstack-aio"
readonly MGMT_IF_DEFAULT="wlp0s20f3"
readonly BACKUP_ROOT="/var/backups/kolla-network-update"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { printf '%b[ OK ]%b %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$*" >&2; }
info() { printf '%b[INFO]%b %s\n' "$BLUE" "$NC" "$*"; }
die()  { printf '%b[FAIL]%b %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Sử dụng:
  sudo bash ./update-kolla-network.sh NEW_IP NEW_VIP [MGMT_IF]
  sudo bash ./update-kolla-network.sh --check
  bash ./update-kolla-network.sh --help

Ví dụ cho cấu hình hiện tại:
  sudo bash ./update-kolla-network.sh 192.168.2.10 192.168.2.250 wlp0s20f3

Điều kiện:
  - NEW_IP đã được gán trên MGMT_IF bằng NetworkManager.
  - NEW_VIP là địa chỉ trống, cùng subnet /24 với NEW_IP.
  - Docker phải đang chạy nếu muốn reload daemon và reconfigure ngay sau đó.

Script chỉ sửa nguồn cấu hình cần thiết:
  - /etc/hosts
  - /etc/kolla/globals.yml
  - /etc/docker/daemon.json khi dùng local registry IP:port

Script không sửa hàng loạt file runtime dưới /etc/kolla và không sửa database.
Kolla-Ansible reconfigure/post-deploy sẽ sinh lại các file runtime/OpenRC.
EOF
}

require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Hãy chạy chế độ cập nhật bằng sudo/root."
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Thiếu lệnh bắt buộc: $1"
}

is_ipv4() {
    local ip="$1" octet
    local -a octets

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
}

is_usable_slash24_host() {
    local last_octet="${1##*.}"
    (( 10#$last_octet >= 1 && 10#$last_octet <= 254 ))
}

slash24_prefix() {
    awk -F. '{print $1 "." $2 "." $3}' <<< "$1"
}

yaml_scalar() {
    local key="$1" file="$2"
    awk -v wanted="${key}:" '
        $1 == wanted {
            value=$2
            gsub(/^["'\'' ]+|["'\'' ]+$/, "", value)
            print value
            exit
        }
    ' "$file"
}

hosts_ip_for_name() {
    local host="$1"
    awk -v wanted="$host" '
        /^[[:space:]]*#/ {next}
        {
            for (i=2; i<=NF; i++) {
                if ($i == wanted) {
                    print $1
                    exit
                }
            }
        }
    ' "$HOSTS_FILE"
}

backup_file() {
    local file="$1" backup_dir="$2"
    [[ -f "$file" ]] || return 0
    cp -a -- "$file" "${backup_dir}/$(basename -- "$file")"
}

set_yaml_key() {
    local key="$1" value="$2"
    grep -Eq "^[[:space:]]*${key}:" "$GLOBALS_FILE" || \
        die "Không tìm thấy key ${key} trong ${GLOBALS_FILE}"
    sed -Ei \
        "s|^([[:space:]]*)${key}:.*|\\1${key}: \"${value}\"|" \
        "$GLOBALS_FILE"
}

update_hosts() {
    local new_ip="$1" host="$2" backup_dir="$3"
    local temporary
    temporary="$(mktemp "${backup_dir}/hosts.XXXXXX")"

    awk -v wanted="$host" '
        {
            keep=1
            if ($0 !~ /^[[:space:]]*#/) {
                for (i=2; i<=NF; i++) {
                    if ($i == wanted) keep=0
                }
            }
            if (keep) print $0
        }
    ' "$HOSTS_FILE" > "$temporary"

    printf '%s %s\n' "$new_ip" "$host" >> "$temporary"
    install -o root -g root -m 0644 "$temporary" "$HOSTS_FILE"
    ok "Đã đặt ${new_ip} ${host} trong /etc/hosts"
}

update_docker_registry() {
    local old_registry="$1" new_registry="$2" backup_dir="$3"
    local temporary

    [[ "$old_registry" != "$new_registry" ]] || {
        info "Local registry không đổi: ${old_registry}"
        return 0
    }

    [[ -f "$DOCKER_DAEMON_FILE" ]] || \
        die "Thiếu ${DOCKER_DAEMON_FILE}; không thể cập nhật insecure registry"

    require_command jq
    temporary="$(mktemp "${backup_dir}/daemon.XXXXXX.json")"
    jq --arg old "$old_registry" --arg new "$new_registry" '
        .["insecure-registries"] = (
            (.["insecure-registries"] // [])
            | map(if . == $old then $new else . end)
            | if index($new) then . else . + [$new] end
            | unique
        )
    ' "$DOCKER_DAEMON_FILE" > "$temporary"

    jq -e . "$temporary" >/dev/null
    install -o root -g root -m 0644 "$temporary" "$DOCKER_DAEMON_FILE"
    ok "Docker insecure registry: ${old_registry} -> ${new_registry}"

    if systemctl is-active --quiet docker.service; then
        systemctl reload docker.service || \
            warn "Docker reload thất bại; kiểm tra journalctl -u docker.service"
    else
        warn "Docker đang tắt; daemon.json sẽ có hiệu lực ở lần start tiếp theo."
    fi
}

check_current() {
    local mgmt_if current_ip current_vip registry vip_count
    local kolla_unit_count kolla_enabled_count registry_policy

    [[ -r "$GLOBALS_FILE" ]] || die "Không đọc được ${GLOBALS_FILE}"
    mgmt_if="$(yaml_scalar network_interface "$GLOBALS_FILE")"
    mgmt_if="${mgmt_if:-$MGMT_IF_DEFAULT}"
    current_ip="$(ip -4 -o address show dev "$mgmt_if" 2>/dev/null | awk 'NR==1 {split($4,a,"/"); print a[1]}')"
    current_vip="$(yaml_scalar kolla_internal_vip_address "$GLOBALS_FILE")"
    registry="$(yaml_scalar docker_registry "$GLOBALS_FILE")"

    printf 'Management interface : %s\n' "$mgmt_if"
    printf 'Management IPv4      : %s\n' "${current_ip:-NOT_FOUND}"
    printf 'Kolla internal VIP   : %s\n' "${current_vip:-NOT_FOUND}"
    printf 'Docker registry      : %s\n' "${registry:-NOT_FOUND}"
    printf 'Inventory            : %s\n' "$INVENTORY"

    ip -4 address show dev "$mgmt_if" 2>/dev/null || true
    if ip -4 -o address show dev "$mgmt_if" 2>/dev/null | grep -qw dynamic; then
        warn "Management IPv4 đang do DHCP cấp (dynamic). Hãy đặt static IP hoặc DHCP reservation."
    fi

    vip_count="$(ip -4 -o address show dev "$mgmt_if" 2>/dev/null | \
        awk -v vip="${current_vip}/32" '$4 == vip {count++} END {print count+0}')"
    if (( vip_count > 1 )); then
        warn "VIP ${current_vip}/32 xuất hiện ${vip_count} lần trên ${mgmt_if}; kiểm tra address trùng."
    fi

    ip -4 address show dev "$mgmt_if" 2>/dev/null | \
        grep -Fq "${current_vip}/" || warn "VIP chưa hiện diện trên ${mgmt_if}"

    if [[ -f "$DOCKER_DAEMON_FILE" ]]; then
        jq '."insecure-registries" // []' "$DOCKER_DAEMON_FILE"
    fi

    kolla_unit_count="$(systemctl list-unit-files \
        --type=service --no-legend --no-pager 2>/dev/null | \
        awk '$1 ~ /^kolla-.*-container[.]service$/ {count++} END {print count+0}')"
    kolla_enabled_count="$(systemctl list-unit-files \
        --type=service --no-legend --no-pager 2>/dev/null | \
        awk '$1 ~ /^kolla-.*-container[.]service$/ && $2 == "enabled" {count++} END {print count+0}')"
    printf 'Kolla systemd units  : %s total, %s enabled\n' \
        "$kolla_unit_count" "$kolla_enabled_count"

    registry_policy="$(docker inspect \
        -f '{{.HostConfig.RestartPolicy.Name}}' local-registry 2>/dev/null || true)"
    printf 'Registry restart     : %s\n' "${registry_policy:-NOT_FOUND}"
    if (( kolla_enabled_count != kolla_unit_count )); then
        warn "Chỉ ${kolla_enabled_count}/${kolla_unit_count} Kolla unit enabled; auto-start chưa đầy đủ."
    fi
    if [[ "$registry_policy" != "unless-stopped" && "$registry_policy" != "always" ]]; then
        warn "local-registry không có restart policy phù hợp auto-start."
    fi

    systemctl is-enabled \
        docker.service docker.socket containerd.service \
        openstack-external-net.service 2>/dev/null || true
    systemctl is-active \
        docker.service docker.socket containerd.service \
        openstack-external-net.service 2>/dev/null || true
}

main() {
    local new_ip="${1:-}" new_vip="${2:-}" mgmt_if="${3:-}"
    local host old_ip old_vip old_registry new_registry registry_port
    local timestamp backup_dir confirmation

    require_root
    require_command awk
    require_command ip
    require_command sed
    require_command systemctl

    [[ -f "$GLOBALS_FILE" ]] || die "Không tìm thấy ${GLOBALS_FILE}"
    [[ -f "$INVENTORY" ]] || die "Không tìm thấy inventory ${INVENTORY}"

    mgmt_if="${mgmt_if:-$(yaml_scalar network_interface "$GLOBALS_FILE")}"
    mgmt_if="${mgmt_if:-$MGMT_IF_DEFAULT}"
    host="$(hostname -s)"
    host="${host:-$HOSTNAME_DEFAULT}"

    if [[ -z "$new_ip" ]]; then
        read -r -p "NEW_IP đã gán trên ${mgmt_if}: " new_ip
    fi
    if [[ -z "$new_vip" ]]; then
        read -r -p "NEW_VIP cùng subnet /24: " new_vip
    fi

    is_ipv4 "$new_ip" || die "NEW_IP không hợp lệ: ${new_ip}"
    is_ipv4 "$new_vip" || die "NEW_VIP không hợp lệ: ${new_vip}"
    is_usable_slash24_host "$new_ip" || die "NEW_IP là network/broadcast address"
    is_usable_slash24_host "$new_vip" || die "NEW_VIP là network/broadcast address"
    [[ "$new_ip" != "$new_vip" ]] || die "NEW_IP và NEW_VIP không được trùng nhau"
    [[ "$(slash24_prefix "$new_ip")" == "$(slash24_prefix "$new_vip")" ]] || \
        die "NEW_IP và NEW_VIP phải cùng subnet /24 theo cấu hình hiện tại"

    ip link show "$mgmt_if" >/dev/null 2>&1 || \
        die "Không tìm thấy management interface ${mgmt_if}"
    ip -4 -o address show dev "$mgmt_if" | grep -qF " ${new_ip}/" || \
        die "${new_ip} chưa được gán trên ${mgmt_if}; hãy sửa NetworkManager trước"

    old_ip="$(hosts_ip_for_name "$host" || true)"
    old_vip="$(yaml_scalar kolla_internal_vip_address "$GLOBALS_FILE")"
    old_registry="$(yaml_scalar docker_registry "$GLOBALS_FILE")"
    new_registry="$old_registry"

    if [[ "$old_registry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:([0-9]+)$ ]]; then
        registry_port="${BASH_REMATCH[2]}"
        new_registry="${new_ip}:${registry_port}"
    fi

    printf '\nCấu hình sẽ cập nhật:\n'
    printf '  Hostname       : %s\n' "$host"
    printf '  Management IF  : %s\n' "$mgmt_if"
    printf '  Management IP  : %s -> %s\n' "${old_ip:-UNKNOWN}" "$new_ip"
    printf '  Kolla VIP      : %s -> %s\n' "${old_vip:-UNKNOWN}" "$new_vip"
    printf '  Registry       : %s -> %s\n' "${old_registry:-UNKNOWN}" "${new_registry:-UNKNOWN}"
    printf '\nKhông sửa database, generated service config hoặc OpenRC trực tiếp.\n'

    read -r -p "Gõ APPLY để tiếp tục: " confirmation
    [[ "$confirmation" == "APPLY" ]] || die "Đã hủy; chưa thay đổi file"

    timestamp="$(date +%Y%m%d-%H%M%S)"
    backup_dir="${BACKUP_ROOT}/${timestamp}"
    install -d -o root -g root -m 0700 "$backup_dir"
    backup_file "$HOSTS_FILE" "$backup_dir"
    backup_file "$GLOBALS_FILE" "$backup_dir"
    backup_file "$DOCKER_DAEMON_FILE" "$backup_dir"

    update_hosts "$new_ip" "$host" "$backup_dir"
    set_yaml_key kolla_internal_vip_address "$new_vip"
    if grep -Eq '^[[:space:]]*kolla_external_vip_address:' "$GLOBALS_FILE"; then
        set_yaml_key kolla_external_vip_address "$new_vip"
    fi
    if [[ -n "$old_registry" && "$new_registry" != "$old_registry" ]]; then
        set_yaml_key docker_registry "$new_registry"
        update_docker_registry "$old_registry" "$new_registry" "$backup_dir"
    fi

    cat > "${backup_dir}/change-summary.txt" <<EOF
timestamp=${timestamp}
hostname=${host}
management_interface=${mgmt_if}
old_management_ip=${old_ip}
new_management_ip=${new_ip}
old_kolla_vip=${old_vip}
new_kolla_vip=${new_vip}
old_registry=${old_registry}
new_registry=${new_registry}
EOF

    ok "Đã cập nhật nguồn cấu hình; backup: ${backup_dir}"
    printf '\nBước tiếp theo (không chạy bằng sudo):\n'
    printf '  source "$HOME/venvs/kolla-2026.1/bin/activate"\n'
    printf '  kolla-ansible prechecks -i %s\n' "$INVENTORY"
    printf '  kolla-ansible reconfigure -i %s\n' "$INVENTORY"
    printf '  kolla-ansible post-deploy -i %s\n' "$INVENTORY"
    printf '  sudo systemctl restart openstack-external-net.service\n'
    printf '  source /etc/kolla/admin-openrc.sh\n'
    printf '  openstack token issue\n'
    printf '\nHậu kiểm:\n'
    printf '  sudo bash %q --check\n' "$0"
    printf '  sudo docker ps -a --format '\''table {{.Names}}\\t{{.Status}}'\''\n'
}

case "${1:-}" in
    -h|--help)
        usage
        ;;
    --check)
        require_root
        require_command jq
        check_current
        ;;
    *)
        main "$@"
        ;;
esac
