#!/usr/bin/env python3
"""Rehearsal of the IL steps on already-labelled data (code-path check, not a result): SL700 run events with their
relabel_v3 labels stand in for a SOC-verified lab export (split 60/20/20 by time). Writes to a scratch directory and
registers nothing. Usage: rehearsal.py ml|dl <out_dir> [run]"""
import math
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
EV = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v3")
COLS = ["ts", "line", "host", "kind", "pid", "ppid", "image", "cmd", "tpath", "rip", "rport", "outbound", "user", "uid", "auid",
        "ses", "syscall", "success", "y"]


def clean(v):
    return None if isinstance(v, float) and math.isnan(v) else v


def main():
    which, out, run = sys.argv[1], Path(sys.argv[2]), (sys.argv[3] if len(sys.argv) > 3 else "e_a")
    df = pd.read_parquet(EV / f"SL700_{run}/events.parquet", columns=COLS).sort_values(["host", "ts", "line"], kind="stable")
    t = df.ts.quantile([0.6, 0.8]).tolist()
    events = []
    for r in df.to_dict("records"):
        e = {k: clean(v) for k, v in r.items() if k != "y"}
        for k in ("pid", "ppid", "syscall", "uid", "auid", "ses"):
            e[k] = None if e[k] is None else int(e[k])
        e["ts"], e["line"] = int(e["ts"]), int(e["line"])
        sp = "train" if r["ts"] < t[0] else ("val" if r["ts"] < t[1] else "test")
        events.append({"host": r["host"], "key": f"{r['host']}:{r['ts']}:{r['line']}", "ts": r["ts"], "event": e,
                       "y": int(r["y"]), "split": sp})
    data = {"events": events}
    parent = ROOT / "runtime/releases" / ("host-ml-il3-20261114" if which == "ml" else "host-dl-il3-20261114")
    out.mkdir(parents=True, exist_ok=False)
    step = __import__("il.ml_step" if which == "ml" else "il.dl_step", fromlist=["run"])
    r = step.run(parent, "linux-audit", data, out, "rehearsal")
    print({k: v for k, v in r.items() if k != "metrics"})
    m = r["metrics"]
    print("new domain:", m["new_domain"])
    print("old domains:", m.get("old_domains_val") or m.get("old_domains_val_f1"))


if __name__ == "__main__":
    main()
