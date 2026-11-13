#!/usr/bin/env python3
"""Mean ± std over seeds for ML IL step 3 runs. Usage: summarize_ml_step3.py <runs_dir>"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

runs = Path(sys.argv[1] if len(sys.argv) > 1 else "../../output/ml_il_step3_20261113/runs")
rows = defaultdict(list)
for f in sorted(runs.glob("*/result.json")):
    r = json.load(open(f))
    name = f.parent.name.rsplit("_s", 1)[0]
    s, zs = r["sl700"], r["sl700_zero_shot_task1"]
    d = {"SL700 F1": s["test"]["f1"], "AP": s["test"]["ap"], "P": s["test"]["precision"], "R": s["test"]["recall"],
         "win F1": s["window_level_test"]["f1"], "win AP": s["window_level_test"]["ap"],
         "zero-shot F1": zs["test"]["f1"], "zero-shot win F1": zs["window_level_test"]["f1"],
         "ATLAS before": r["before_step3"]["atlas_test"]["f1"], "OpTC before": r["before_step3"]["optc_test"]["f1"]}
    if "after_step3" in r:
        d.update({"ATLAS after": r["after_step3"]["atlas_test"]["f1"], "OpTC after": r["after_step3"]["optc_test"]["f1"],
                  "OpTC FP after": r["after_step3"]["optc_test"]["fp"], "ATLAS FP after": r["after_step3"]["atlas_test"]["fp"]})
    rows[name].append(d)
cols = ["SL700 F1", "AP", "P", "R", "win F1", "win AP", "ATLAS before", "ATLAS after", "OpTC before", "OpTC after",
        "OpTC FP after", "zero-shot F1", "zero-shot win F1"]
print("| run | n | " + " | ".join(cols) + " |")
print("|---|---:|" + "---:|" * len(cols))
for n, rs in sorted(rows.items()):
    vals = []
    for c in cols:
        v = np.array([x.get(c, np.nan) for x in rs], float)
        vals.append("—" if np.all(np.isnan(v)) else (f"{np.nanmean(v):.0f}" if "FP" in c else f"{np.nanmean(v):.3f} ± {np.nanstd(v):.3f}"))
    print(f"| {n} | {len(rs)} | " + " | ".join(vals) + " |")
