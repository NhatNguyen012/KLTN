#!/usr/bin/env python3
"""Aggregate v9 sweep results into a table (mean/std per configuration)."""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

root = Path(sys.argv[1])
rows = defaultdict(list)
print(f"{'run':22s} ep head  val_f1  | v9: f1   ap    tp fp fn | legacy: f1   ap    tp fp fn | v9b: f1  ap    tp fp fn")
for p in sorted(root.glob("*/result.json")):
    r = json.loads(p.read_text())
    cfg = p.parent.name.rsplit("_s", 1)[0]
    v, t, l = r["val"], r["test_v9_labels"], r["test_legacy_labels"]
    b = r.get("test_v9b_labels") or {"f1": float("nan"), "ap": float("nan"), "tp": -1, "fp": -1, "fn": -1}
    rows[cfg].append((v["f1"], t["f1"], t["ap"], l["f1"], l["ap"], b["f1"], b["ap"]))
    print(f"{p.parent.name:22s} {str(r['best_epoch']):>2s} {r['head']:4s} {v['f1']:.3f}  | {t['f1']:.3f} {t['ap']:.3f} "
          f"{t['tp']:2d} {t['fp']:2d} {t['fn']:2d} | {l['f1']:.3f} {l['ap']:.3f} {l['tp']:2d} {l['fp']:2d} {l['fn']:2d} | {b['f1']:.3f} {b['ap']:.3f} {b['tp']:2d} {b['fp']:2d} {b['fn']:2d}")
print("\nconfig            n  val_f1        test_f1(v9)    test_ap(v9)    test_f1(legacy) test_ap(legacy) test_f1(v9b)   test_ap(v9b)")
summary = {}
for cfg, xs in rows.items():
    a = np.array(xs)
    m, s = a.mean(0), a.std(0)
    summary[cfg] = {"n": len(xs), "mean": m.tolist(), "std": s.tolist()}
    print(f"{cfg:16s} {len(xs):2d}  " + "  ".join(f"{mi:.3f}±{si:.3f}" for mi, si in zip(m, s)))
(root / "summary.json").write_text(json.dumps(summary, indent=2))
