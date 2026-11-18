#!/bin/bash
# KLTN benign — profile "admin" (kltn-admin, sudoer). Routine administration WITH sudo, and an occasional
# benign login session to the peer host over the internal LAN (source = another lab host, never the Internet).
# This is the benign counterpart of attacker ssh-exec sessions, so the model learns internal admin is normal.
set -u
PEER="${KLTN_PEER_IP:-}"
KEY="$HOME/.ssh/kltn_admin_ed25519"
pick(){ echo $((RANDOM % $1)); }
case $(pick 8) in
 0) sudo -n apt-get update -q >/dev/null 2>&1 || true ;;
 1) sudo -n systemctl is-active cron rsyslog ssh >/dev/null 2>&1; sudo -n systemctl status rsyslog >/dev/null 2>&1 || true ;;
 2) sudo -n journalctl -n 50 --no-pager >/dev/null 2>&1 || true ;;
 3) sudo -n ss -tulpn >/dev/null 2>&1 || true; sudo -n ip -br a >/dev/null 2>&1 || true ;;
 4) sudo -n df -h >/dev/null 2>&1; sudo -n du -sh /var/log >/dev/null 2>&1 || true ;;
 5) sudo -n systemctl restart rsyslog >/dev/null 2>&1 || true ;;   # restart a non-critical service
 6) sudo -n dmesg --level=err,warn >/dev/null 2>&1 || true ;;
 7) if [ -n "$PEER" ] && [ -f "$KEY" ]; then
      ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=6 -o BatchMode=yes \
        kltn-admin@"$PEER" 'sudo -n systemctl is-active cron >/dev/null 2>&1; df -h >/dev/null; uptime' >/dev/null 2>&1 || true
    fi ;;
esac
