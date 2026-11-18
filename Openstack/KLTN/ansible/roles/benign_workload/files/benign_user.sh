#!/bin/bash
# KLTN benign — profile "user" (kltn-user, unprivileged). Ordinary desktop/daily activity. No scan, no sudo,
# no privilege change, nothing an attack path needs.
set -u
H="$HOME"; mkdir -p "$H/notes" "$H/docs" "$H/Downloads"
pick(){ echo $((RANDOM % $1)); }
for _ in $(seq 1 $(( (RANDOM % 4) + 2 ))); do   # 2-5 actions per run
case $(pick 10) in
 0) df -h >/dev/null; free -m >/dev/null; uptime >/dev/null ;;
 1) ls -la /var/log >/dev/null 2>&1; tail -n 30 /var/log/syslog >/dev/null 2>&1 || true ;;
 2) python3 -c 'import json,platform,datetime; print(json.dumps({"u":platform.uname()._asdict(),"t":str(datetime.datetime.now())}))' >/dev/null ;;
 3) curl -fsS -o /dev/null --max-time 10 "https://www.ubuntu.com" 2>/dev/null || true ;;
 4) curl -fsS -o /dev/null --max-time 10 "https://en.wikipedia.org/wiki/Special:Random" 2>/dev/null || true ;;
 5) date >> "$H/notes/journal.txt"; wc -l "$H/notes/journal.txt" >/dev/null; sort "$H/notes/journal.txt" >/dev/null ;;
 6) echo "report $(date +%s)" > "$H/docs/draft_$((RANDOM%5)).md"; grep -r "report" "$H/docs" >/dev/null 2>&1 ;;
 7) tar -czf "$H/Downloads/notes_backup.tgz" -C "$H" notes >/dev/null 2>&1; rm -f "$H/Downloads/notes_backup.tgz" ;;
 8) find "$H" -maxdepth 2 -type f -newermt "-1 day" >/dev/null 2>&1 ;;
 9) cat /etc/os-release >/dev/null; id >/dev/null; who >/dev/null 2>&1 || true ;;
esac
sleep $(( (RANDOM % 25) + 2 ))
done
