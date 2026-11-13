#!/usr/bin/env python3
"""Root cause R5: leave-one-run-out check (the fixed split has a single test run). For each of the 6 SL700 runs as
TEST, the next run (cyclic) is VAL (rounds + threshold) and the other 4 are TRAIN. Window-level LightGBM, seed 42,
configs as rc_lgbm_v2.py. EVD env var selects events_v2 (relabel_v2) or events_v3 (relabel_v3)."""
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.metrics import average_precision_score

src = (Path(__file__).parent / "rc_lgbm_v2.py").read_text().split("sel = sys.argv[1:]")[0]
g = {"__file__": str(Path(__file__).parent / "rc_lgbm_v2.py")}
exec(compile(src, "rc_lgbm_v2_head", "exec"), g)
X_for, best_thr, met, CONFIGS, W, y = g["X_for"], g["best_thr"], g["met"], g["CONFIGS"], g["W"], g["y"]
OUT = g["D"] / "r5_loro"; OUT.mkdir(exist_ok=True)
RUNS = ["a_a", "a_b", "b_a", "e_a", "a_c", "f_a"]
run = np.array([w["run"] for w in W])
names = sys.argv[1:] or ["C0_v1", "C3_v1+ev+par+ses", "C4_C3+scope"]
res = {}
for name in names:
    groups, fr = CONFIGS[name]
    X = X_for(groups, fr)
    res[name] = {}
    for k, te_run in enumerate(RUNS):
        va_run = RUNS[(k + 1) % len(RUNS)]
        tr, va, te = ~np.isin(run, [te_run, va_run]), run == va_run, run == te_run
        params = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10, feature_fraction=0.5, bagging_fraction=0.8,
                      bagging_freq=1, lambda_l2=1.0, seed=42, verbose=-1, num_threads=10,
                      scale_pos_weight=float(np.sqrt((y[tr] == 0).sum() / y[tr].sum())))
        bst = lgb.train(params, lgb.Dataset(X[tr], y[tr]), num_boost_round=600)
        best = max(range(50, 601, 50), key=lambda r: average_precision_score(y[va], bst.predict(X[va], num_iteration=r)))
        t, _ = best_thr(y[va], bst.predict(X[va], num_iteration=best))
        m = met(y[te], bst.predict(X[te], num_iteration=best), t)
        res[name][te_run] = m
        print(f"{name:22s} test {te_run} val {va_run}: F1 {m['f1']:.3f} AP {m['ap']:.3f} P/R {m['precision']:.2f}/{m['recall']:.2f} "
              f"(tp {m['tp']} fp {m['fp']} fn {m['fn']})", flush=True)
    f1 = np.array([v["f1"] for v in res[name].values()]); ap = np.array([v["ap"] for v in res[name].values()])
    print(f"{name:22s} LORO mean F1 {f1.mean():.3f} ± {f1.std():.3f}  AP {ap.mean():.3f}  min F1 {f1.min():.3f}", flush=True)
(OUT / f"result_{g['EVD']}.json").write_text(json.dumps(res, indent=1, default=float))
