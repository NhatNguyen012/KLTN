#!/usr/bin/env python3
"""Mean ± std over seeds for IL step 3 (OpTC -> ATLASv2 -> SL700). Usage: summarize_step3.py <runs_dir>"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

runs = Path(sys.argv[1] if len(sys.argv) > 1 else "../../output/il_step3_20261113/runs")
rows = defaultdict(list)
for f in sorted(runs.glob("*/result.json")):
    name = f.parent.name.rsplit("_s", 1)[0]
    r = json.load(open(f))
    b, a = r["before_step2_model"], r["after"]
    ss = a["sl700"]["stage"]
    rows[name].append({
        "SL700 F1": a["sl700"]["test"]["f1"], "SL700 AP": a["sl700"]["test"].get("ap", np.nan),
        "SL700 F1 before": b["sl700"]["test"]["f1"],
        "SL700 stage pres": ss["summary"]["presence_macro_f1_supported"] or 0,
        "SL700 IC pres": ss["presence"]["initial_compromise"]["f1"], "SL700 ED pres": ss["presence"]["execution_discovery"]["f1"],
        "SL700 Impact pres": ss["presence"].get("impact", {}).get("f1", np.nan),
        "SL700 last-stage": ss["summary"]["last_stage_macro_f1_supported"] or 0,
        "ATLAS F1 before": b["atlas"]["test"]["f1"], "ATLAS F1 after": a["atlas"]["test"]["f1"],
        "ATLAS stage before": b["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0,
        "ATLAS stage after": a["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0,
        "ATLAS EX before": b["atlas"]["stage"]["presence"]["exfiltration"]["f1"],
        "ATLAS EX after": a["atlas"]["stage"]["presence"]["exfiltration"]["f1"],
        "OpTC F1 before": b["optc"]["test_at_base_thr"]["f1"], "OpTC F1 after": a["optc"]["test_at_base_thr"]["f1"],
        "best ep": r["best_epoch"],
        "SL700 tp/fp/fn": (a["sl700"]["test"]["tp"], a["sl700"]["test"]["fp"], a["sl700"]["test"]["fn"]),
    })
cols = ["SL700 F1", "SL700 AP", "SL700 F1 before", "SL700 stage pres", "SL700 IC pres", "SL700 ED pres", "SL700 Impact pres",
        "SL700 last-stage", "ATLAS F1 before", "ATLAS F1 after", "ATLAS stage before", "ATLAS stage after", "ATLAS EX before",
        "ATLAS EX after", "OpTC F1 before", "OpTC F1 after", "best ep"]
order = ["freeze_replay2", "freeze_replayoptc", "full_noreplay_selsl", "scratch_selsl"]
names = [n for n in order if n in rows] + [n for n in rows if n not in order]
for c in cols:
    line = f"{c:20s}"
    for n in names:
        v = np.array([x[c] for x in rows[n]], float)
        line += f" | {n}: {np.nanmean(v):.3f}±{np.nanstd(v):.3f} (n={len(v)})"
    print(line)
for n in names:
    print(n, "SL700 tp/fp/fn per seed:", [x["SL700 tp/fp/fn"] for x in rows[n]])
