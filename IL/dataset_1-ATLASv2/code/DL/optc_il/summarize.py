#!/usr/bin/env python3
"""Aggregate optc_il runs (<setting>_s<seed>/result.json) into mean ± std tables."""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

root = Path(sys.argv[1] if len(sys.argv) > 1 else "output/optc_il_20261112/runs")
by = defaultdict(list)
for f in sorted(root.glob("*/result.json")):
    by[f.parent.name.rsplit("_s", 1)[0]].append(json.loads(f.read_text()))

COLS = [
    ("ATLASv2 F1 (v9b)", lambda r: r["atlas"]["test_v9b_labels"]["f1"]),
    ("ATLASv2 AP", lambda r: r["atlas"]["test_v9b_labels"]["ap"]),
    ("ATLASv2 F1 (orig. labels)", lambda r: r["atlas"]["test_legacy_labels"]["f1"]),
    ("Stage presence F1", lambda r: r["atlas"]["stage"]["test_summary"]["presence_macro_f1_supported"]),
    ("Last-stage F1", lambda r: r["atlas"]["stage"]["test_summary"]["last_stage_macro_f1_supported"]),
    ("OpTC F1 before", lambda r: r["optc_test"]["before_base_model_at_base_thr"]["f1"]),
    ("OpTC F1 after (base thr)", lambda r: r["optc_test"]["after_at_base_thr"]["f1"]),
    ("OpTC F1 after (OpTC-val thr)", lambda r: r["optc_test"]["after_at_optc_val_thr"]["f1"]),
    ("OpTC AP after", lambda r: r["optc_test"]["after_at_base_thr"]["ap"]),
    ("BWT (F1, base thr)", lambda r: r["bwt_f1_at_base_thr"]),
]
order = ["freeze_replay", "full_replay", "freeze_noreplay", "full_noreplay"]
names = [n for n in order if n in by] + [n for n in by if n not in order]
print("| Setting | n | " + " | ".join(c for c, _ in COLS) + " |")
print("|---|---:|" + "---:|" * len(COLS))
for n in names:
    rs = by[n]
    cells = []
    for _, fn in COLS:
        v = np.array([fn(r) for r in rs], float)
        cells.append(f"{v.mean():.3f} ± {v.std():.3f}" if len(v) > 1 else f"{v.mean():.3f}")
    print(f"| {n} | {len(rs)} | " + " | ".join(cells) + " |")
print()
for n in names:
    for r in by[n]:
        a, o = r["atlas"]["test_v9b_labels"], r["optc_test"]["after_at_base_thr"]
        print(f"{n:16s} seed {r['args']['seed']}  best ep {r['best_epoch']:2d} ({r['best_stage']})  "
              f"ATLASv2 tp/fp/fn {a['tp']}/{a['fp']}/{a['fn']}  OpTC after tp/fp/fn {o['tp']}/{o['fp']}/{o['fn']}")
