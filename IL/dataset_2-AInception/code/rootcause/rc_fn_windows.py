#!/usr/bin/env python3
"""Root cause 1: which SL700 TEST positives are missed, and what do their attack events look like?"""
import csv
import pickle
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output")
blob = pickle.load(open(ROOT / "sl700_windows_v1/dataset.pkl", "rb"))
F = blob["meta"]["cat_fields"]
te = {s["sample_id"]: s for s in blob["splits"]["test"]}
runs = sorted((ROOT / "il_step3_20261113/runs").glob("*/sl700_test_predictions.csv"))
miss = defaultdict(int); n_cfg = 0
for p in runs:
    if "scratch_selsl_s" in str(p):
        continue
    n_cfg += 1
    for r in csv.DictReader(open(p)):
        if r["y"] == "1" and r["pred"] == "0":
            miss[r["sample_id"]] += 1
pos = [s for s in te.values() if s["y"]]
print(f"test positives {len(pos)}; configs {n_cfg}")
rows = []
for s in sorted(pos, key=lambda s: s["start"]):
    ev = np.asarray(s["ev_y"]) == 1
    toks = [s["tok_raw"][i] for i in np.where(ev)[0]]
    kinds = Counter(t[0] for t in toks)
    act = Counter(f"{t[1]}>{t[4]}" if t[0] == "procstart" else f"{t[0]}:{t[1]}" for t in toks)
    rows.append((s["sample_id"], miss.get(s["sample_id"], 0), int(ev.sum()), len(ev), s["stages"], dict(kinds), act.most_common(6)))
for r in rows:
    print(f"{r[0]:32s} missed {r[1]:2d}/{n_cfg}  att {r[2]:4d}/{r[3]:4d}  st {r[4]}  {r[5]}  {r[6]}")
