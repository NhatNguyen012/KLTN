#!/usr/bin/env python3
"""Root cause R1: is the DL model or the SL700 input the bottleneck?

LightGBM on exactly the per-event tokens the DL model sees (sl700_windows_v1, ip_scope dropped like the DL run),
pooled into a bag of tokens per window. Same split (train a_a,a_b,b_a,e_a / val a_c / test f_a); number of
boosting rounds and threshold chosen on VAL; TEST scored once. Also an event-signature ambiguity check: for every
attack event of a TEST positive window, is its full token signature seen in TRAIN as attack, benign or both?
"""
import json
import pickle
import sys
from collections import Counter, defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
from scipy import sparse
from sklearn.feature_extraction import FeatureHasher
from sklearn.metrics import average_precision_score, precision_recall_curve

OUT = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/rootcause_20261113/r1_lgbm_dl_tokens")
OUT.mkdir(parents=True, exist_ok=True)
blob = pickle.load(open("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/sl700_windows_v1/dataset.pkl", "rb"))
F = blob["meta"]["cat_fields"]
DROP = {"ip_scope"}
FLAGN = 18


def ev_tokens(t, flags):
    toks = [f"{f}={v}" for f, v in zip(F, t) if f not in DROP]
    toks.append(f"sig={t[0]}|{t[1]}|{t[4]}")
    toks += [f"flag{j}" for j in range(FLAGN) if flags[j] > 0]
    return toks


def sig(t, flags):
    return "|".join(v for f, v in zip(F, t) if f not in DROP) + "|" + "".join(str(int(x > 0)) for x in flags[:FLAGN])


def window_feats(s):
    c = Counter()
    for t, fl, isx in zip(s["tok_raw"], s["num"], s["is_extra"]):
        for tok in ev_tokens(t, fl):
            c[("x:" if isx else "") + tok] += 1
    n = len(s["tok_raw"])
    c["n_events"] = n
    return {k: float(v) for k, v in c.items()}


fh = FeatureHasher(n_features=2 ** 18, input_type="dict", alternate_sign=False)
X, Y, IDS = {}, {}, {}
for sp, lst in blob["splits"].items():
    X[sp] = fh.transform(window_feats(s) for s in lst).tocsr()
    Y[sp] = np.array([s["y"] for s in lst]); IDS[sp] = [s["sample_id"] for s in lst]
    print(sp, X[sp].shape, int(Y[sp].sum()), flush=True)


def best_thr(y, p):
    pr, rc, th = precision_recall_curve(y, p)
    f1 = 2 * pr * rc / np.clip(pr + rc, 1e-12, None)
    i = int(np.nanargmax(f1[:-1]))
    return float(th[i]), float(f1[i])


def m(y, p, t):
    pred = p >= t
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    pr = tp / max(1, tp + fp); rc = tp / max(1, tp + fn)
    return dict(tp=tp, fp=fp, fn=fn, precision=pr, recall=rc, f1=2 * pr * rc / max(1e-12, pr + rc), ap=float(average_precision_score(y, p)))


res = {}
for seed in (42, 43, 44):
    params = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10, feature_fraction=0.5,
                  bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, seed=seed, verbose=-1, num_threads=6,
                  scale_pos_weight=float(np.sqrt((Y["train"] == 0).sum() / Y["train"].sum())))
    bst = lgb.train(params, lgb.Dataset(X["train"], Y["train"]), num_boost_round=600)
    # rounds chosen on VAL (AP), threshold on VAL
    best = max(range(50, 601, 50), key=lambda r: average_precision_score(Y["val"], bst.predict(X["val"], num_iteration=r)))
    pv = bst.predict(X["val"], num_iteration=best); t, f1v = best_thr(Y["val"], pv)
    pt = bst.predict(X["test"], num_iteration=best)
    res[seed] = {"rounds": best, "val_f1": f1v, "test": m(Y["test"], pt, t), "train": m(Y["train"], bst.predict(X["train"], num_iteration=best), t)}
    print(seed, json.dumps(res[seed]), flush=True)
    if seed == 42:
        missed = [i for i, (y, p) in zip(IDS["test"], zip(Y["test"], pt)) if y == 1 and p < t]
        res["missed_s42"] = missed

# event-signature ambiguity (TRAIN attack vs benign) for attack events of TEST positives
tr_sig = defaultdict(lambda: [0, 0])
for s in blob["splits"]["train"]:
    for t, fl, y in zip(s["tok_raw"], s["num"], s["ev_y"]):
        if y >= 0:
            tr_sig[sig(t, fl)][int(y)] += 1
amb = Counter(); per_win = {}
for s in blob["splits"]["test"]:
    if not s["y"]:
        continue
    cls = Counter()
    for t, fl, y in zip(s["tok_raw"], s["num"], s["ev_y"]):
        if y == 1:
            b, a = tr_sig.get(sig(t, fl), [0, 0])
            c = "unseen" if a + b == 0 else ("attack_only" if b == 0 else ("benign_only" if a == 0 else "both"))
            cls[c] += 1; amb[c] += 1
    per_win[s["sample_id"]] = dict(cls)
res["test_attack_event_signature_in_train"] = dict(amb)
res["per_window"] = per_win
(OUT / "result.json").write_text(json.dumps(res, indent=1))
print("signature classes of TEST attack events:", dict(amb))
for k, v in per_win.items():
    print(k, v)
