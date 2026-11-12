#!/usr/bin/env python3
"""S29 (STEP 40) - ATLASv2: firefox.exe dương vs benign ở cấp TIẾN TRÌNH (process_guid): tiến trình dương có sinh con lạ (cmd/payload/...) hay không."""
import os
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
pd.set_option("display.width", 250)
D = r"D:\UIT\KLTNv2\02_artifacts\40_why_malicious_v1\atlas"
n = pd.read_csv(os.path.join(D, "atlas_netconn_rows.csv"), low_memory=False)
p = pd.read_csv(os.path.join(D, "atlas_procstart_rows.csv"), low_memory=False)
base = lambda x: str(x).lower().replace("\\", "/").split("/")[-1] if isinstance(x, str) else ""
n["app"] = n.process_path.map(base)
f = n[(n.action != "ACTION_CONNECTION_LISTEN") & n.remote_ip.notna() & (n.remote_ip != "")]
ff = f[f.app == "firefox.exe"]
fo = open(os.path.join(D, "summary2.txt"), "w", encoding="utf-8")


def pr(*a):
    print(*a)
    print(*a, file=fo)


pr("== firefox.exe: trong tệp attack, flow dương / không dương; tệp benign")
pr(ff.groupby(["kind", "label_proc"]).size())
g = ff.groupby("process_guid").agg(label=("label_proc", "max"), n=("label_proc", "size"), kind=("kind", "first"), host=("host", "first"))
pr("\n== số tiến trình firefox (process_guid) theo nhãn / kind")
pr(g.groupby(["kind", "label"]).agg(procs=("n", "size"), flows=("n", "sum")))
# tiến trình firefox sinh con gì (procstart có process_guid = guid)
kids = p.assign(child=p.childproc_name.map(base)).groupby("process_guid").child.agg(lambda s: sorted(set(s)))
g["children"] = g.index.map(lambda x: kids.get(x, []))
odd = {"cmd.exe", "payload.exe", "powershell.exe", "python.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "rundll32.exe"}
g["spawns_odd"] = g.children.map(lambda c: bool(set(c) & odd))
g["spawns_any"] = g.children.map(lambda c: len(c) > 0)
pr("\n== tiến trình firefox: sinh con bất thường (cmd/payload/powershell/python/...)")
pr(g.groupby(["kind", "label"]).agg(procs=("n", "size"), spawns_odd=("spawns_odd", "sum"), spawns_any=("spawns_any", "sum")))
pr("\n== tiến trình firefox dương: số flow mỗi tiến trình, con")
pr(g[g.label == 1][["n", "host", "children"]].sort_values("n", ascending=False).head(15).to_string())
pr("\n== firefox tiến trình (gốc) dương: số flow trước mốc sinh con bất thường đầu tiên (dùng thời gian)")
odd_ps = p.assign(child=p.childproc_name.map(base))
odd_ps = odd_ps[odd_ps.child.isin(odd)].groupby("process_guid").device_timestamp.min()
rows = []
for guid, t0 in odd_ps.items():
    if guid in g.index and g.loc[guid, "label"] == 1:
        x = ff[ff.process_guid == guid]
        rows.append((guid[-8:], len(x), int((x.device_timestamp < t0).sum()), int((x.device_timestamp >= t0).sum())))
pr("guid(8 cuối), flow, trước-sinh-con-lạ, sau-sinh-con-lạ")
for r in rows:
    pr(r)
fo.close()
