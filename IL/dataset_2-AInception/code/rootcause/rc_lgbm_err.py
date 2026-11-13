#!/usr/bin/env python3
"""Root cause R3: what are the errors of the R2 LightGBM configs (VAL and TEST, seed 42)?
For every FP / FN window: host, time, attack-event count, and the session origins / commands it contains."""
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

# reuse the matrices / helpers of rc_lgbm_v2.py (EVD env var selects events_v2 / events_v3) without its experiment loop
src = (Path(__file__).parent / "rc_lgbm_v2.py").read_text().split("sel = sys.argv[1:]")[0]
g = {"__file__": str(Path(__file__).parent / "rc_lgbm_v2.py")}
exec(compile(src, "rc_lgbm_v2_head", "exec"), g)
X_for, best_thr, CONFIGS, W, ev, SEP = g["X_for"], g["best_thr"], g["CONFIGS"], g["W"], g["ev"], g["SEP"]
split, y, ids = g["split"], g["y"], g["ids"]
OUT = g["D"] / "r3_errors"; OUT.mkdir(exist_ok=True)
ts = ev.ts.values; ses_tok = ev.g_ses.values; scope_tok = ev.g_scope.values; evtok = ev.g_ev.values


def describe(w):
    idx = w["idx"]
    t0 = pd.to_datetime(ts[idx].min(), unit="us").strftime("%H:%M:%S")
    sess = Counter()
    for i in idx:
        s = ses_tok[i]
        o = [t for t in s.split(SEP) if t.startswith(("ctx:session:origin", "ctx:session:acct"))]
        sc = [t for t in scope_tok[i].split(SEP) if t.startswith("ctx:session:src_scope")]
        if o:
            sess["/".join(x.split("=")[1] for x in o + sc)] += 1
    cmds = Counter(t.split("=", 1)[1] for i in idx for t in evtok[i].split(SEP) if t.startswith("cmd:inline_argv0="))
    return t0, dict(sess.most_common(4)), dict(cmds.most_common(6))


names = ["C0_v1", "C3_v1+ev+par+ses", "C4_C3+scope"]
rep = {}
for name in names:
    groups, fr = CONFIGS[name]
    X = X_for(groups, fr)
    tr, va, te = split == "train", split == "val", split == "test"
    params = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10, feature_fraction=0.5, bagging_fraction=0.8,
                  bagging_freq=1, lambda_l2=1.0, seed=42, verbose=-1, num_threads=10,
                  scale_pos_weight=float(np.sqrt((y[tr] == 0).sum() / y[tr].sum())))
    bst = lgb.train(params, lgb.Dataset(X[tr], y[tr]), num_boost_round=600)
    best = max(range(50, 601, 50), key=lambda r: average_precision_score(y[va], bst.predict(X[va], num_iteration=r)))
    pv = bst.predict(X[va], num_iteration=best); t, _ = best_thr(y[va], pv)
    pt = bst.predict(X[te], num_iteration=best)
    print(f"\n===== {name}  rounds {best} thr {t:.3f}")
    rep[name] = {}
    for sp, mask, p in (("val", va, pv), ("test", te, pt)):
        ww = [w for w, m in zip(W, mask) if m]
        yy = y[mask]
        fp = [(w, s) for w, yv, s in zip(ww, yy, p) if yv == 0 and s >= t]
        fn = [(w, s) for w, yv, s in zip(ww, yy, p) if yv == 1 and s < t]
        print(f"--- {sp}: FP {len(fp)}  FN {len(fn)}  (pos {int(yy.sum())})")
        rows = []
        for kind, lst in (("FP", fp), ("FN", fn)):
            for w, s in sorted(lst, key=lambda x: x[0]["sample_id"]):
                t0, sess, cmds = describe(w)
                n_att = int(sum(1 for i in w["idx"] if ev.y.values[i] == 1))
                rows.append(dict(kind=kind, id=w["sample_id"], start=t0, score=round(float(s), 3), n_att=n_att, sessions=sess, cmds=cmds))
                print(f"{kind} {w['sample_id']:30s} {t0} p={s:.3f} att={n_att:3d} sess={sess} cmds={cmds}")
        rep[name][sp] = rows
(OUT / f"errors_s42_{g['EVD']}.json").write_text(json.dumps(rep, indent=1))
