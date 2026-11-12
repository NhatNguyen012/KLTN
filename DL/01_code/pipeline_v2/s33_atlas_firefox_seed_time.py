#!/usr/bin/env python3
"""S33 (STEP 42) - ATLASv2 firefox: flow dương nằm trước hay sau lần chạm đầu IP kẻ tấn công của cùng tiến trình."""
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
n = pd.read_csv(r"D:\UIT\KLTNv2\02_artifacts\40_why_malicious_v1\atlas\atlas_netconn_rows.csv", low_memory=False)
n = n[(n.action != "ACTION_CONNECTION_LISTEN") & n.remote_ip.notna() & (n.remote_ip != "")]
n["app"] = n.process_path.str.lower().str.split("\\").str[-1]
ff = n[n.app == "firefox.exe"].copy()
ATT = ["10.193.66.115", "10.193.242.113"]
att = ff[ff.remote_ip.isin(ATT)]
print("flows firefox tới IP attacker:", "dương", int(att.label_proc.sum()), "benign", int((att.label_proc == 0).sum()))
first = att.groupby("process_guid").device_timestamp.min()
pos = ff[ff.label_proc == 1]
fm = pos.process_guid.map(first)
has = fm.notna()
print("tiến trình dương chạm IP attacker:", pos[has].process_guid.nunique(), "/", pos.process_guid.nunique())
after = int((pos[has].device_timestamp >= fm[has]).sum())
print("flow dương của các tiến trình đó: sau/cùng lần chạm đầu", after, "| trước", int(has.sum()) - after, "| tổng dương", len(pos), "| dương của tiến trình không chạm attacker", int((~has).sum()))
print(ff[ff.remote_ip.str.startswith("10.")].groupby(["label_proc", "remote_ip"]).size().sort_values(ascending=False).head(8))
