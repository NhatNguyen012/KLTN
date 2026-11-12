#!/usr/bin/env python3
"""Stage-result table (mean±std over seeds) for runs trained with --stage-w > 0."""
import json, sys
from collections import defaultdict
from pathlib import Path
import numpy as np

STAGES = ["initial_compromise", "execution_discovery", "lateral_movement", "exfiltration"]
rows = defaultdict(list)
for p in sorted(Path(sys.argv[1]).glob("*/result.json")):
    r = json.loads(p.read_text())
    if "stage" not in r:
        continue
    lab = r["args"]["label"]; st = r["stage"]; ts = st["test_summary"]
    b = r[f"test_{lab}_labels"]
    rows[p.parent.name.rsplit("_s", 1)[0]].append(
        [b["f1"], ts["presence_macro_f1_fixed4"]] + [st["presence"][k]["f1"] for k in STAGES]
        + [ts["last_stage_macro_f1_supported"], ts["last_stage_macro_f1_fixed4"]]
        + [st["last_stage"]["per_stage_f1"][k] for k in STAGES] + [ts["last_stage_acc_on_detected_attacks"] or 0])
    sup = (st["last_stage"]["support"], [st["presence"][k]["support"] for k in STAGES])
cols = ["bin_f1", "pres_macro", "pres_IC", "pres_ED", "pres_LM", "pres_EX", "last_macro_sup", "last_macro_4",
        "last_IC", "last_ED", "last_LM", "last_EX", "last_acc_TP"]
summary = {}
for cfg, xs in rows.items():
    a = np.array(xs); summary[cfg] = {c: [round(float(m), 3), round(float(s), 3)] for c, m, s in zip(cols, a.mean(0), a.std(0))}
    summary[cfg]["n"] = len(xs)
    print(f"\n{cfg} (n={len(xs)})")
    for c in cols:
        print(f"   {c:15s} {summary[cfg][c][0]:.3f} ± {summary[cfg][c][1]:.3f}")
(Path(sys.argv[1]) / "stage_summary.json").write_text(json.dumps(summary, indent=2))
