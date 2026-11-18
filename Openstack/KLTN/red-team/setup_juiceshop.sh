#!/bin/bash
# Deploy OWASP Juice Shop as the exposed web server on ubuntu-1 (authorized lab, red-team/ROE.md).
# Plain Node process (no Docker) under a dedicated 'juice' user, port 80 via CAP_NET_BIND_SERVICE.
set -eu
NODE_VER=v22.11.0
JS_VER=20.4.0
JS_TGZ=juice-shop-${JS_VER}_node22_linux_x64.tgz
cd /tmp
getent passwd juice >/dev/null || useradd -r -m -d /opt/juice-shop -s /usr/sbin/nologin juice
# Node 22 runtime -> /opt/node
if [ ! -x /opt/node/bin/node ]; then
  curl -fsSL -o node.tar.xz "https://nodejs.org/dist/${NODE_VER}/node-${NODE_VER}-linux-x64.tar.xz"
  rm -rf /opt/node && mkdir -p /opt/node && tar -xJf node.tar.xz -C /opt/node --strip-components=1 && rm -f node.tar.xz
fi
# Juice Shop packaged release -> /opt/juice-shop
if [ ! -f /opt/juice-shop/package.json ]; then
  curl -fsSL -o "$JS_TGZ"     "https://github.com/juice-shop/juice-shop/releases/download/v${JS_VER}/${JS_TGZ}"
  curl -fsSL -o "$JS_TGZ.md5" "https://github.com/juice-shop/juice-shop/releases/download/v${JS_VER}/${JS_TGZ}.md5"
  echo "$(cat $JS_TGZ.md5 | awk '{print $1}')  $JS_TGZ" | md5sum -c -
  rm -rf /opt/juice-shop && mkdir -p /opt/juice-shop
  tar -xzf "$JS_TGZ" -C /opt/juice-shop --strip-components=1 && rm -f "$JS_TGZ" "$JS_TGZ.md5"
  chown -R juice:juice /opt/juice-shop
fi
cat > /etc/systemd/system/juice-shop.service <<U
[Unit]
Description=OWASP Juice Shop (lab exposed web app)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=juice
WorkingDirectory=/opt/juice-shop
Environment=PORT=80
ExecStart=/opt/node/bin/node --experimental-require-module /opt/juice-shop/build/app.js
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload
systemctl enable --now juice-shop.service
sleep 12
systemctl is-active juice-shop.service
curl -fsS -o /dev/null -w "http_local=%{http_code} time=%{time_total}s\n" http://127.0.0.1/ || (journalctl -u juice-shop -n 20 --no-pager; exit 1)
