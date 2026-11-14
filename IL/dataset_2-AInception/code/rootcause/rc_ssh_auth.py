#!/usr/bin/env python3
"""Root cause 2: are attacker ssh sessions distinguishable from benign ones with what the model sees?
Lists every auth event (all SL700 runs, all hosts): exe, acct, addr, op, ses, label; and the benign/attack
counts of each token signature the model sees for auth / sshd-child events."""
from collections import Counter
from pathlib import Path

import pandas as pd

R = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2")
cols = ["ts", "host", "kind", "pid", "ppid", "image", "cmd", "tpath", "rip", "rport", "outbound", "user", "uid", "auid", "ses",
        "syscall", "y", "stage"]
for run in ["a_a", "a_b", "b_a", "e_a", "a_c", "f_a"]:
    df = pd.read_parquet(R / f"SL700_{run}/events.parquet")
    have = [c for c in cols if c in df.columns]
    df = df[have]
    au = df[df.kind == "auth"].copy()
    au["exe"] = au.image.fillna("").str.split("/").str[-1]
    au["op"] = au.cmd.fillna("").str.split(" ").str[0]
    au["addr"] = au.rip.fillna("")
    print(f"===== {run}: events {len(df)}, auth {len(au)}, attack auth {int(au.y.sum())}")
    g = au.groupby(["host", "exe", "tpath", "addr", "y"]).size().reset_index(name="n")
    print(g.sort_values("n", ascending=False).head(40).to_string(index=False))
    # sessions: per (host, ses) first auth addr + label
    ss = au[au.ses.notna() & (au.ses != 4294967295)].groupby(["host", "ses"]).agg(
        addr=("addr", lambda x: ",".join(sorted(set(v for v in x if v)))), acct=("user", lambda x: ",".join(sorted(set(map(str, x))))),
        exe=("exe", lambda x: ",".join(sorted(set(x)))), n=("y", "size"), att=("y", "sum")).reset_index()
    print("sessions by (host, addr, exe, attack>0):")
    ss["is_att"] = ss.att > 0
    print(ss.groupby(["host", "addr", "exe", "acct", "is_att"]).size().reset_index(name="n_sessions").to_string(index=False))
