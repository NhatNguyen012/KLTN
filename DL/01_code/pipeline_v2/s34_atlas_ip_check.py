#!/usr/bin/env python3
"""S34 (STEP 42) - ATLASv2: flow tới 10.193.242.113 / 10.193.66.115 theo tệp (kind/host/scenario), tiến trình và nhãn."""
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
pd.set_option("display.width", 220)
n = pd.read_csv(r"D:\UIT\KLTNv2\02_artifacts\40_why_malicious_v1\atlas\atlas_netconn_rows.csv", low_memory=False)
n["app"] = n.process_path.str.lower().str.split("\\").str[-1]
x = n[n.remote_ip.isin(["10.193.242.113", "10.193.66.115"])]
print(x.groupby(["remote_ip", "kind", "label_proc", "app"]).size().to_string())
print(x[x.kind == "benign"].groupby(["host", "remote_port"]).size())
