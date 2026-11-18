#!/bin/bash
# Admin cleanup after L1 (reversible). Keeps dmorris/sudoers/pwauth for L5.
set -u
# decrypt canary (key kept) and restore; remove attacker persistence
for f in /opt/kltn-canary/*.enc; do [ -e "$f" ] || continue; openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:LABKEY-L1 -in "$f" -out "${f%.enc}" 2>/dev/null && rm -f "$f"; done
if [ -f /root/.ssh/authorized_keys ]; then grep -v 'attacker@kltn' /root/.ssh/authorized_keys > /root/.ssh/.ak.tmp 2>/dev/null || true; mv /root/.ssh/.ak.tmp /root/.ssh/authorized_keys 2>/dev/null || true; fi
rm -f /etc/cron.d/kltn-lab-beacon
echo "cleaned $(hostname): canary=$(ls /opt/kltn-canary/ | tr '\n' ' ') beacon=$(test -f /etc/cron.d/kltn-lab-beacon && echo present || echo gone)"
