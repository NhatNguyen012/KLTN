"""Tables for the relabel_v2 report (markdown)."""
import json

import pandas as pd

O = "/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2"
SC = ["SL300_v2", "SL300_v4", "SL300_v5", "SL300_v7", "SL700_a_a", "SL700_a_b", "SL700_a_c", "SL700_b_a", "SL700_e_a", "SL700_f_a"]
ST = ["Initial_Compromise", "Execution_Discovery", "Lateral_Movement", "Exfiltration", "Impact"]
rows, hrows = [], []
for sc in SC:
    r = json.load(open(f"{O}/{sc}/report.json"))
    t = r["totals"]
    ev = t["stage_events"]
    proc = {}
    for h, x in r["hosts"].items():
        for k, n in x["stage_processes"].items():
            proc[k] = proc.get(k, 0) + n
        if x["attack"] or x["coarse_attack"] > 0 and h in ("media", "apps", "dc", "videoserver"):
            hrows.append(dict(scenario=sc, host=h, events=x["events"], coarse=x["coarse_attack"], v2=x["attack"], both=x["both"],
                              coarse_only=x["coarse_only"], v2_only=x["new_only"], procs=x["attack_processes"]))
    rows.append(dict(scenario=sc, events=t["events"], attack=t["attack"],
                     **{s[:3] + "_ev/proc": f"{ev.get(s, 0)}/{proc.get(s, 0)}" for s in ST},
                     evidence=r["actions_with_host_evidence"], attr_none=t["attr"].get("none", 0),
                     clock=";".join(f"{c['host']} {c['residual_s']}s" for c in r["clock"]) if isinstance(r["clock"], list) else "UTC"))
    v1 = r.get("vs_relabel_v1")
    if v1:
        print(sc, "vs v1:", {k: v1[k] for k in ("matched_events", "v1_attack", "v2_attack", "added", "removed")})
print(pd.DataFrame(rows).to_string(index=False))
print()
print(pd.DataFrame(hrows).to_string(index=False))
for sc in ("SL300_v2", "SL300_v4", "SL300_v5"):
    r = json.load(open(f"{O}/{sc}/report.json"))
    print(sc, "attacker_ips", r["attacker_ips"], "| sessions", r["session_hosts"])
