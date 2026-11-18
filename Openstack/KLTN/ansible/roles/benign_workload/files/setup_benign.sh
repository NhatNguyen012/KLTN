#!/bin/bash
# Installs the three benign profiles (user/admin/dev) + systemd timers on a victim. Idempotent.
# Env: KLTN_PEER_IP (peer victim), KLTN_ADMIN_PUB (authorized key string). Admin private key placed by driver.
set -eu
PEER="${KLTN_PEER_IP:-}"; PUB="${KLTN_ADMIN_PUB:-}"
id kltn-user  >/dev/null 2>&1 || useradd -m -s /bin/bash kltn-user
id kltn-admin >/dev/null 2>&1 || useradd -m -s /bin/bash kltn-admin
id kltn-dev   >/dev/null 2>&1 || useradd -m -s /bin/bash kltn-dev
usermod -aG sudo kltn-admin
# Curated NOPASSWD set so the admin workload runs unattended. Scoped to read/diagnostic + two safe restarts.
cat > /etc/sudoers.d/kltn-admin <<SUDO
kltn-admin ALL=(root) NOPASSWD: /usr/bin/apt-get update, /usr/bin/journalctl, /usr/bin/systemctl is-active *, /usr/bin/systemctl status *, /usr/bin/systemctl restart rsyslog, /usr/bin/ss, /usr/sbin/ss, /usr/bin/ip, /usr/bin/df, /usr/bin/du, /usr/bin/dmesg
SUDO
chmod 440 /etc/sudoers.d/kltn-admin; visudo -cf /etc/sudoers.d/kltn-admin >/dev/null
# Benign internal-admin key: same keypair on both hosts, authorized for kltn-admin.
install -d -m700 -o kltn-admin -g kltn-admin /home/kltn-admin/.ssh
if [ -n "$PUB" ]; then echo "$PUB" > /home/kltn-admin/.ssh/authorized_keys; chown kltn-admin:kltn-admin /home/kltn-admin/.ssh/authorized_keys; chmod 600 /home/kltn-admin/.ssh/authorized_keys; fi
if [ -f /tmp/kltn_admin_key ]; then install -m600 -o kltn-admin -g kltn-admin /tmp/kltn_admin_key /home/kltn-admin/.ssh/kltn_admin_ed25519; rm -f /tmp/kltn_admin_key; fi
# Scripts
install -m755 /tmp/benign_user.sh  /usr/local/bin/kltn-benign-user
install -m755 /tmp/benign_admin.sh /usr/local/bin/kltn-benign-admin
install -m755 /tmp/benign_dev.sh   /usr/local/bin/kltn-benign-dev
rm -f /tmp/benign_user.sh /tmp/benign_admin.sh /tmp/benign_dev.sh
# Units: one service+timer per profile, staggered intervals + jitter so windows differ.
mk(){ # name user exec boot active jitter
cat > /etc/systemd/system/kltn-benign-$1.service <<U
[Unit]
Description=KLTN benign $1 activity
[Service]
Type=oneshot
User=$2
Environment=KLTN_PEER_IP=${PEER}
ExecStart=$3
U
cat > /etc/systemd/system/kltn-benign-$1.timer <<U
[Unit]
Description=KLTN benign $1 activity
[Timer]
OnBootSec=$4
OnUnitActiveSec=$5
RandomizedDelaySec=$6
[Install]
WantedBy=timers.target
U
}
mk user  kltn-user  /usr/local/bin/kltn-benign-user  3min 3min 90
mk admin kltn-admin /usr/local/bin/kltn-benign-admin 6min 7min 150
mk dev   kltn-dev   /usr/local/bin/kltn-benign-dev   8min 11min 180
systemctl daemon-reload
# Replace the old single-profile timer with the three new ones.
systemctl disable --now kltn-benign.timer >/dev/null 2>&1 || true
for p in user admin dev; do systemctl enable --now kltn-benign-$p.timer >/dev/null; done
echo "OK peer=$PEER users=$(getent passwd kltn-user kltn-admin kltn-dev | cut -d: -f1 | tr '\n' ',')"
systemctl list-timers 'kltn-benign-*' --no-pager | grep kltn || true
