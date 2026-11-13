#!/usr/bin/env python3
"""Root cause 2b: what runs inside each ssh login session (audit ses) on videoserver: attacker vs benign."""
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

R = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2")
runs = sys.argv[1:] or ["a_a", "f_a"]
for run in runs:
    df = pd.read_parquet(R / f"SL700_{run}/events.parquet")
    df = df[(df.host == "videoserver")]
    au = df[(df.kind == "auth") & df.ses.notna()]
    src = au[au.rip.fillna("").str.len() > 1].groupby("ses").rip.agg(lambda x: sorted(set(x)))
    print(f"===== {run}")
    for ses, addr in src.items():
        if ses in (4294967295,):
            continue
        s = df[df.ses == ses].sort_values("ts")
        ps = s[s.kind == "procstart"]
        att = int(s.y.sum())
        t0 = pd.to_datetime(s.ts.min(), unit="us").strftime("%H:%M:%S"); t1 = pd.to_datetime(s.ts.max(), unit="us").strftime("%H:%M:%S")
        cmds = Counter(ps.cmd.fillna("").str.slice(0, 70))
        acct = sorted(set(au[au.ses == ses].user.dropna().astype(str)) - {""})
        print(f"ses {int(ses):5d} {addr} acct={acct} {t0}-{t1} events={len(s)} attack={att} kinds={dict(Counter(s.kind))}")
        for c, n in cmds.most_common(12):
            print(f"      {n:4d}  {c}")
