#!/bin/bash
# KLTN campaign guard (runs on the openstack host). Raises /tmp/campaign/PAUSE on the attacker when the
# host is under memory pressure or a core service is unhealthy (ROE §6 auto-stop). Clears it when healthy.
set +u
ATT=172.31.250.234; KEY=/home/nguyen/.ssh/openstack_ed25519
SSH="ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/mnt/SSD_Data/optc/Openstack/KLTN/runtime/known_hosts -o ConnectTimeout=6"
MIN_MB=${MIN_MB:-4096}; MAX_SWAP_MB=${MAX_SWAP_MB:-6144}; LOG=${LOG:-/tmp/campaign_guard.log}
while true; do
  avail=$(free -m|awk '/Mem:/{print $7}'); swap=$(free -m|awk '/Swap:/{print $3}'); reason=""
  [ "${avail:-0}" -lt "$MIN_MB" ] && reason="MemAvailable=${avail}MB<${MIN_MB}"
  [ "${swap:-0}" -gt "$MAX_SWAP_MB" ] && reason="$reason swap=${swap}MB>${MAX_SWAP_MB}"
  unh=$(sudo docker ps --filter health=unhealthy --format '{{.Names}}' 2>/dev/null|tr '\n' ',')
  [ -n "$unh" ] && reason="$reason unhealthy=$unh"
  ts=$(date -u +%FT%TZ)
  if [ -n "$reason" ]; then
    $SSH ubuntu@$ATT "mkdir -p /tmp/campaign; echo '$ts $reason' > /tmp/campaign/PAUSE" 2>/dev/null
    echo "$ts PAUSE $reason" >> "$LOG"
  else
    $SSH ubuntu@$ATT "rm -f /tmp/campaign/PAUSE" 2>/dev/null
    echo "$ts OK avail=${avail}MB swap=${swap}MB" >> "$LOG"
  fi
  sleep ${INTERVAL:-60}
done
