#!/usr/bin/env python3
"""Root cause R6: what does the LORO fold 'test e_a' miss (C3, seed 42)? Prints the missed windows grouped by time,
with the attack events they contain (kind, exe, command head)."""
import sys
from collections import Counter
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

src = (Path(__file__).parent / "rc_lgbm_v2.py").read_text().split("sel = sys.argv[1:]")[0]
g = {"__file__": str(Path(__file__).parent / "rc_lgbm_v2.py")}
exec(compile(src, "rc_lgbm_v2_head", "exec"), g)
X_for, best_thr, CONFIGS, W, y, ev = g["X_for"], g["best_thr"], g["CONFIGS"], g["W"], g["y"], g["ev"]
te_run, va_run = (sys.argv[1:3] if len(sys.argv) > 2 else ("e_a", "a_c"))
name = sys.argv[3] if len(sys.argv) > 3 else "C3_v1+ev+par+ses"
run = np.array([w["run"] for w in W])
tr, va, te = ~np.isin(run, [te_run, va_run]), run == va_run, run == te_run
X = X_for(*CONFIGS[name])
params = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10, feature_fraction=0.5, bagging_fraction=0.8,
              bagging_freq=1, lambda_l2=1.0, seed=42, verbose=-1, num_threads=10, scale_pos_weight=float(np.sqrt((y[tr] == 0).sum() / y[tr].sum())))
bst = lgb.train(params, lgb.Dataset(X[tr], y[tr]), num_boost_round=600)
best = max(range(50, 601, 50), key=lambda r: average_precision_score(y[va], bst.predict(X[va], num_iteration=r)))
t, _ = best_thr(y[va], bst.predict(X[va], num_iteration=best))
p = bst.predict(X[te], num_iteration=best)
ww = [w for w, m in zip(W, te) if m]
cmd_tok = ev.g_ev.values
print(f"{name} test {te_run} val {va_run}: thr {t:.3f}")
for kind, sel in (("FN", lambda yy, s: yy == 1 and s < t), ("FP", lambda yy, s: yy == 0 and s >= t)):
    rows = [(w, s) for w, yy, s in zip(ww, y[te], p) if sel(yy, s)]
    print(f"--- {kind}: {len(rows)}")
    for w, s in rows:
        idx = w["idx"]
        att = [i for i in idx if ev.y.values[i] == 1]
        t0 = pd.to_datetime(ev.ts.values[idx].min(), unit="us").strftime("%H:%M:%S")
        sig = Counter()
        for i in (att if kind == "FN" else idx):
            toks = cmd_tok[i].split(g["SEP"])
            a0 = next((x.split("=", 1)[1] for x in toks if x.startswith("cmd:argv0=")), "")
            sig[f"{ev.kind.values[i]}:{ev.tok_actor.values[i]}>{ev.tok_target.values[i]}{'(' + a0 + ')' if a0 else ''}"] += 1
        print(f"{kind} {w['sample_id']:28s} {t0} p={s:.3f} att={len(att):3d} {dict(sig.most_common(5))}")
