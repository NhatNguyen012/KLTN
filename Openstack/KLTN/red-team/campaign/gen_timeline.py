#!/usr/bin/env python3
"""Generate a dwell timeline for the KLTN campaign. Usage: gen_timeline.py <total_seconds> [seed]
Reads scenarios.conf next to it; staggers scenario starts across the window and spaces each scenario's
actions by jittered per-stage dwell so a campaign looks low-and-slow (APT dwell), overlapping other campaigns."""
import sys, os, random
total=int(sys.argv[1]); random.seed(int(sys.argv[2]) if len(sys.argv)>2 else 1)
conf=os.path.join(os.path.dirname(os.path.abspath(__file__)),"scenarios.conf")
scns=[l.split()[0:1]+l.split()[1:] for l in open(conf) if l.strip() and not l.startswith("#")]
# per-stage dwell weight (relative); scaled so a campaign spans ~ window/len(scns)*1.6 (overlap)
W={"recon":0.3,"web_sqli":0.2,"foothold":0.5,"disc":1.0,"disc_obf":1.0,"privesc":0.6,
   "p_authkeys":0.2,"p_cron":0.2,"p_bashrc":0.2,"p_systemd_svc":0.2,"p_systemd_timer":0.2,
   "lateral":1.5,"exfil_http":0.8,"exfil_tar":0.8,"exfil_dns":0.8,"impact_enc":1.0,"impact_svcstop":1.0,"cleanup":0.3}
N=len(scns); span=total*0.8/max(N,1)*1.6
lines=[]
for i,row in enumerate(scns):
    scn=row[0]; acts=row[1:]
    start=random.uniform(i*(total*0.8/N), i*(total*0.8/N)+total*0.1)
    t=start; wsum=sum(W.get(a,0.5) for a in acts)
    for a in acts:
        lines.append((int(t), scn, a))
        step=span*(W.get(a,0.5)/wsum); t+=step*random.uniform(0.6,1.4)
for off,scn,a in sorted(lines):
    print(f"{min(off,total)} {scn} {a}")
