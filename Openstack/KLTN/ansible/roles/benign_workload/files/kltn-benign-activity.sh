#!/bin/bash
# KLTN benign baseline activity: ordinary administration as an unprivileged user. It gives the models the lab's
# normal behaviour (drift reference, benign rows for incremental learning). No scanning, no privilege change,
# no persistence, nothing an attack would need.
set -u
case $((RANDOM % 7)) in
  0) df -h >/dev/null; free -m >/dev/null; uptime >/dev/null ;;
  1) ls -la /var/log >/dev/null 2>&1; tail -n 20 /var/log/syslog >/dev/null 2>&1 || true ;;
  2) apt-cache policy openssl >/dev/null 2>&1 ;;
  3) curl -fsS -o /dev/null --max-time 10 https://www.ubuntu.com || true ;;
  4) python3 -c 'import json, platform; print(json.dumps(platform.uname()._asdict()))' >/dev/null ;;
  5) cat /etc/os-release >/dev/null; hostnamectl >/dev/null 2>&1 || true ;;
  6) mkdir -p "$HOME/notes" && date >> "$HOME/notes/log.txt" && tail -n 5 "$HOME/notes/log.txt" >/dev/null ;;
esac
