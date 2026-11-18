#!/bin/bash
# Seed L1/L5 prerequisites on a victim (authorized lab, red-team/ROE.md). All reversible; cleanup_lab.sh undoes it.
# Args: ROLE=entry|lateral  P=<foothold password>
set -eu
ROLE="${1:?role}"; P="${2:?password}"
# Foothold user reachable by credential reuse (the web layer "leaks" its password).
if ! id dmorris >/dev/null 2>&1; then useradd -m -s /bin/bash dmorris; fi
echo "dmorris:$P" | chpasswd
# Canary = disposable dummy data; impact (encrypt) is confined here and fully reversible.
install -d -m755 /opt/kltn-canary
for f in quarterly_report finance_notes customers; do echo "LAB CANARY $f $(date -u +%FT%TZ) $(head -c 64 /dev/urandom | base64)" > /opt/kltn-canary/$f.txt; done
if [ "$ROLE" = entry ]; then
  # Controlled privesc path: a sudo misconfig (GTFOBin). This is the host "vulnerability" for T1548.003.
  echo 'dmorris ALL=(ALL) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/90-kltn-lab-dmorris
  chmod 440 /etc/sudoers.d/90-kltn-lab-dmorris; visudo -cf /etc/sudoers.d/90-kltn-lab-dmorris >/dev/null
fi
echo "prepped role=$ROLE user=dmorris canary=/opt/kltn-canary"
