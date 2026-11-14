#!/usr/bin/env python3
"""Mean ± std over seeds for train_il_step3_v2.py runs. Usage: summarize_step3_v2.py <runs_dir> [<runs_dir> ...]"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

rows = defaultdict(list)
for d in sys.argv[1:]:
    for f in sorted(Path(d).glob("*/result.json")):
        name = f"{Path(d).parent.name}/{f.parent.name.rsplit('_s', 1)[0]}"
        a = json.load(open(f))["after"]
        s, at = a["sl700"], a["atlas"]
        rows[name].append({
            "SL700 F1": s["test"]["f1"], "SL700 AP": s["test"].get("ap", np.nan),
            "SL700 P": s["test"]["precision"], "SL700 R": s["test"]["recall"],
            "SL700 stage pres": s["stage"]["summary"]["presence_macro_f1_supported"] or 0,
            "SL700 last-stage": s["stage"]["summary"]["last_stage_macro_f1_supported"] or 0,
            "ATLAS F1": at["test"]["f1"], "ATLAS stage": at["stage"]["summary"]["presence_macro_f1_supported"] or 0,
            "OpTC F1": a["optc"]["test_at_base_thr"]["f1"],
            "tp/fp/fn": f"{s['test']['tp']}/{s['test']['fp']}/{s['test']['fn']}"})
cols = ["SL700 F1", "SL700 AP", "SL700 P", "SL700 R", "SL700 stage pres", "SL700 last-stage", "ATLAS F1", "ATLAS stage", "OpTC F1"]
print("| run | n | " + " | ".join(cols) + " | tp/fp/fn |")
print("|---|---:|" + "---:|" * len(cols) + "---|")
for n, rs in sorted(rows.items()):
    vals = []
    for c in cols:
        v = np.array([r[c] for r in rs], float)
        vals.append(f"{np.nanmean(v):.3f} ± {np.nanstd(v):.3f}")
    print(f"| {n} | {len(rs)} | " + " | ".join(vals) + " | " + ", ".join(r["tp/fp/fn"] for r in rs) + " |")
