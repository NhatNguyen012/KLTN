#!/usr/bin/env python3
"""Which DL windows (sl700_windows_v3 TEST) does an ML run miss / flag, and what attack events do they hold?
Usage: ml_window_errors.py <run_dir>   (threshold = the window-level VAL threshold is not stored, so the TEST
windows are listed with their max event score next to the event-level VAL threshold of the run)."""
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

run = Path(sys.argv[1])
res = json.load(open(run / "result.json"))
thr = res["sl700"]["test"]["threshold"]
sc = pd.read_parquet(run / "sl700_test_scores.parquet").sort_values("ts")
by_host = {h: g for h, g in sc.groupby("host")}
blob = pickle.load(open("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/sl700_windows_v3/dataset.pkl", "rb"))
rows = []
for s in blob["splits"]["test"]:
    g = by_host.get(s["host"])
    m = g[(g.ts >= s["start"]) & (g.ts <= s["end"])] if g is not None else g
    p = float(m.p.max()) if m is not None and len(m) else 0.0
    att_kinds = Counter(t[1] for t, y in zip(s["trace"], s["ev_y"]) if y == 1)
    rows.append((s["sample_id"], s["y"], p, dict(att_kinds), int(m.y.sum()) if m is not None and len(m) else 0))
df = pd.DataFrame(rows, columns=["id", "y", "p", "attack_kinds_dl", "attack_rows_ml"])
print(f"event threshold {thr:.4f}; TEST windows {len(df)}, positive {int(df.y.sum())}")
fn = df[(df.y == 1) & (df.p < thr)]
fp = df[(df.y == 0) & (df.p >= thr)]
print(f"positive windows below the event threshold: {len(fn)}")
for r in fn.itertuples():
    print(f"  {r.id:30s} p={r.p:.3f} attack events in window: {r.attack_kinds_dl} | attack ML rows {r.attack_rows_ml}")
print(f"negative windows above the event threshold: {len(fp)}")
for r in fp.head(30).itertuples():
    print(f"  {r.id:30s} p={r.p:.3f}")
