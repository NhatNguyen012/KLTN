#!/bin/bash
set -eu
WEBURL="$1"   # target Juice Shop URL for this host
install -m755 /tmp/benign_web.sh /usr/local/bin/kltn-benign-web
rm -f /tmp/benign_web.sh
cat > /etc/systemd/system/kltn-benign-web.service <<U
[Unit]
Description=KLTN benign web browsing (Juice Shop)
[Service]
Type=oneshot
User=kltn-user
Environment=KLTN_WEB_URL=${WEBURL}
ExecStart=/usr/local/bin/kltn-benign-web
U
cat > /etc/systemd/system/kltn-benign-web.timer <<U
[Unit]
Description=KLTN benign web browsing (Juice Shop)
[Timer]
OnBootSec=4min
OnUnitActiveSec=5min
RandomizedDelaySec=120
[Install]
WantedBy=timers.target
U
systemctl daemon-reload
systemctl enable --now kltn-benign-web.timer >/dev/null
systemctl start kltn-benign-web.service
echo "web benign installed target=$WEBURL -> $(systemctl is-active kltn-benign-web.timer)"
