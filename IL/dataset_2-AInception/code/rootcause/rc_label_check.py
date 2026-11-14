#!/usr/bin/env python3
"""Root cause R4 (labels): inside the discovery-script burst, which processes are labelled attack and which are not,
and through which (ghost) parent; plus the a_c PAM-persistence windows (attack events inside a benign session)."""
import sys
from collections import Counter

import pandas as pd

R = "/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2"


def burst(run, t_from, t_to):
    df = pd.read_parquet(f"{R}/SL700_{run}/events.parquet")
    v = df[(df.host == "videoserver")].sort_values(["ts", "line"])
    seen_pid = set(v.pid.dropna().astype(int))
    day = pd.to_datetime(v[v.y == 1].ts.min(), unit="us").strftime("%Y-%m-%d")
    lo, hi = pd.Timestamp(f"{day} {t_from}").value // 1000, pd.Timestamp(f"{day} {t_to}").value // 1000
    b = v[(v.ts >= lo) & (v.ts <= hi) & (v.kind == "procstart")]
    b = b.assign(pp=b.ppid.fillna(-1).astype(int), ghost=~b.ppid.fillna(-1).astype(int).isin(seen_pid))
    print(f"===== {run} {t_from}..{t_to}: procstart {len(b)}  attack {int(b.y.sum())}")
    g = b.groupby(["ghost", "y"]).size()
    print(g.to_string())
    # per ghost parent: n children, label mix, first child time, uid
    gp = b[b.ghost].groupby("pp").agg(n=("y", "size"), att=("y", "sum"), first=("ts", "min"), uid=("uid", "first"),
                                     imgs=("image", lambda x: ",".join(sorted({i.split('/')[-1] for i in x})[:6])))
    gp["first"] = pd.to_datetime(gp["first"], unit="us").dt.strftime("%H:%M:%S")
    print("ghost parents (ppid never seen as a pid):"); print(gp.sort_values("first").to_string())
    ng = b[~b.ghost].groupby(["y"]).agg(n=("y", "size"), parents=("pp", lambda x: Counter(x).most_common(4)))
    print("visible-parent procstarts:"); print(ng.to_string())
    return v


if __name__ == "__main__":
    v = burst("f_a", "14:29:30", "14:43:00")
    v = burst("a_c", "21:40:00", "21:47:00")
    df = pd.read_parquet(f"{R}/SL700_a_c/events.parquet")
    vv = df[(df.host == "videoserver")].sort_values(["ts", "line"])
    day = pd.to_datetime(vv[vv.y == 1].ts.min(), unit="us").strftime("%Y-%m-%d")
    a = vv[(vv.y == 1) & (vv.ts >= pd.Timestamp(f"{day} 22:05:30").value // 1000) & (vv.ts <= pd.Timestamp(f"{day} 22:09:30").value // 1000)]
    print("===== a_c attack events 22:05:30-22:09:30 (val FN windows w0482-w0487)")
    for r in a.head(40).itertuples():
        print(pd.to_datetime(r.ts, unit="us").strftime("%H:%M:%S.%f")[:12], r.kind, r.pid, r.ppid, (r.image or "")[-22:], "|", (r.cmd or "")[:70], "|",
              (r.tpath or "")[:30], r.rip, r.uid, r.auid, r.ses, r.stage_name)
