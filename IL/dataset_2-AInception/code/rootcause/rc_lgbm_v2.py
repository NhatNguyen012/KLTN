#!/usr/bin/env python3
"""Root cause R2: which input groups close the SL700 gap? Window-level LightGBM (bag of event tokens), identical
windows/labels/split to sl700_windows_v1. Groups (events_v2): v1 = tokens the DL sees today; g_ev = Linux event
tokens (syscall, exe/path class, uid/auid, command line, auth record type/op/account, file path class);
g_par = actor/parent/grandparent context; g_ses = login-session (incoming) context; g_scope = address scope of
the login / connection (kept apart: labels were seeded from the attacker address); fr = sensitive-file reads
(fileread events, input only). Rounds and threshold on VAL (a_c), TEST (f_a) once, 3 seeds."""
import json
import pickle
import sys
from collections import Counter, defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction import FeatureHasher
from sklearn.metrics import average_precision_score, precision_recall_curve

import os
D = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/rootcause_20261113")
EVD = os.environ.get("EVD", "events_v2")          # events_v2 = relabel_v2 labels, events_v3 = relabel_v3 labels
OUT = D / ("r2_lgbm_linux_ctx" + ("" if EVD == "events_v2" else "_" + EVD)); OUT.mkdir(exist_ok=True)
SEP = "\x1f"
ev = pd.read_parquet(D / EVD / "events.parquet")
W = pickle.load(open(D / EVD / "windows.pkl", "rb"))
V1F = [c for c in ev.columns if c.startswith("tok_") and c != "tok_ip_scope"]
n_ev = int(ev.gid.max()) + 1
assert (ev.gid.values == np.arange(len(ev))).all()
pref = np.where(ev.kind.values == "filemod", "x:", np.where(ev.kind.values == "fileread", "r:", ""))


def v1_tokens():
    cols = [ev[c].values for c in V1F]
    fl = np.stack(ev["flags"].values)[:, :18] > 0
    out = []
    for i in range(len(ev)):
        if pref[i] == "r:":
            out.append([]); continue
        t = [f"{pref[i]}v1:{c[4:]}={v[i]}" for c, v in zip(V1F, cols)]
        t.append(f"{pref[i]}v1:sig={ev.tok_kind.values[i]}|{ev.tok_actor.values[i]}|{ev.tok_target.values[i]}")
        t += [f"{pref[i]}v1:flag{j}" for j in np.where(fl[i])[0]]
        out.append(t)
    return out


def grp_tokens(g):
    return [[pref[i] + t for t in s.split(SEP) if t] if s else [] for i, s in enumerate(ev[g].values)]


fh = FeatureHasher(n_features=2 ** 20, input_type="string", alternate_sign=False)
E = {"v1": fh.transform(v1_tokens()).tocsr()}
for g in ("g_ev", "g_par", "g_ses", "g_scope"):
    E[g] = fh.transform(grp_tokens(g)).tocsr()
    print(g, E[g].nnz, flush=True)
rows, cols = [], []
rows_fr, cols_fr = [], []
for i, w in enumerate(W):
    rows += [i] * len(w["idx"]); cols += list(w["idx"])
    rows_fr += [i] * len(w["idx_fileread"]); cols_fr += list(w["idx_fileread"])
M = sparse.csr_matrix((np.ones(len(rows), np.float32), (rows, cols)), shape=(len(W), n_ev))
M_fr = sparse.csr_matrix((np.ones(len(rows_fr), np.float32), (rows_fr, cols_fr)), shape=(len(W), n_ev))
nlen = sparse.csr_matrix(np.asarray([[len(w["idx"])] for w in W], np.float32))
split = np.array([w["split"] for w in W]); y = np.array([w["y"] for w in W]); ids = [w["sample_id"] for w in W]


def X_for(groups, fileread):
    parts = [M @ E[g] for g in groups] + [nlen]
    if fileread:
        parts += [M_fr @ E[g] for g in groups if g != "v1"]
    return sparse.hstack(parts).tocsr()


def best_thr(yy, p):
    pr, rc, th = precision_recall_curve(yy, p)
    f1 = 2 * pr * rc / np.clip(pr + rc, 1e-12, None)
    i = int(np.nanargmax(f1[:-1]))
    return float(th[i]), float(f1[i])


def met(yy, p, t):
    pred = p >= t
    tp = int((pred & (yy == 1)).sum()); fp = int((pred & (yy == 0)).sum()); fn = int((~pred & (yy == 1)).sum())
    pr = tp / max(1, tp + fp); rc = tp / max(1, tp + fn)
    return dict(tp=tp, fp=fp, fn=fn, precision=pr, recall=rc, f1=2 * pr * rc / max(1e-12, pr + rc), ap=float(average_precision_score(yy, p)))


# window groups of the TEST positives (from rc_fn_windows.py), for the miss breakdown
def tgroup(sid):
    """attack phase of a TEST (f_a) videoserver window, by window index (same grid for v2 and v3 labels)"""
    n = int(sid.split("_w")[1][:4])
    return ("ic_exploit" if n < 380 else "msf_shell_pty" if n < 410 else "linpeas" if n < 440 else
            "privesc_wget" if n < 460 else "ssh_root_exec" if n < 497 else "ssh_sudo_impact" if n < 505 else "ssh_sudo")


CONFIGS = {
    "C0_v1": (["v1"], False),
    "C1_v1+ev": (["v1", "g_ev"], False),
    "C2_v1+ev+par": (["v1", "g_ev", "g_par"], False),
    "C3_v1+ev+par+ses": (["v1", "g_ev", "g_par", "g_ses"], False),
    "C4_C3+scope": (["v1", "g_ev", "g_par", "g_ses", "g_scope"], False),
    "C5_C3+fileread": (["v1", "g_ev", "g_par", "g_ses"], True),
    "C6_C4+fileread": (["v1", "g_ev", "g_par", "g_ses", "g_scope"], True),
    "C7_v1+scope_only": (["v1", "g_scope"], False),
    "C8_ev+par+ses_nov1": (["g_ev", "g_par", "g_ses"], False),
}
sel = sys.argv[1:] or list(CONFIGS)
res = {}
for name in sel:
    groups, fr = CONFIGS[name]
    X = X_for(groups, fr)
    Xtr, Xva, Xte = X[split == "train"], X[split == "val"], X[split == "test"]
    ytr, yva, yte = y[split == "train"], y[split == "val"], y[split == "test"]
    ids_te = [i for i, s in zip(ids, split) if s == "test"]
    rr = []
    for seed in (42, 43, 44):
        params = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10, feature_fraction=0.5,
                      bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, seed=seed, verbose=-1, num_threads=10,
                      scale_pos_weight=float(np.sqrt((ytr == 0).sum() / ytr.sum())))
        bst = lgb.train(params, lgb.Dataset(Xtr, ytr), num_boost_round=600)
        best = max(range(50, 601, 50), key=lambda r: average_precision_score(yva, bst.predict(Xva, num_iteration=r)))
        pv = bst.predict(Xva, num_iteration=best); t, f1v = best_thr(yva, pv)
        pt = bst.predict(Xte, num_iteration=best)
        m = met(yte, pt, t); m["val_f1"] = f1v; m["rounds"] = best
        m["train_recall_at_thr"] = met(ytr, bst.predict(Xtr, num_iteration=best), t)["recall"]
        miss = Counter(tgroup(i) for i, yy, p in zip(ids_te, yte, pt) if yy == 1 and p < t)
        m["missed_by_group"] = dict(miss)
        m["fp_hosts"] = dict(Counter(i.split("_")[0] for i, yy, p in zip(ids_te, yte, pt) if yy == 0 and p >= t))
        if seed == 42:
            imp = bst.feature_importance("gain")
            m["n_features_used"] = int((imp > 0).sum())
        rr.append(m)
    f1 = np.array([r["f1"] for r in rr]); ap = np.array([r["ap"] for r in rr])
    res[name] = {"f1_mean": f1.mean(), "f1_std": f1.std(), "ap_mean": ap.mean(), "runs": rr}
    print(f"{name:22s} TEST F1 {f1.mean():.3f}±{f1.std():.3f}  AP {ap.mean():.3f}  "
          f"P/R {np.mean([r['precision'] for r in rr]):.2f}/{np.mean([r['recall'] for r in rr]):.2f}  "
          f"valF1 {np.mean([r['val_f1'] for r in rr]):.3f}  trainR {np.mean([r['train_recall_at_thr'] for r in rr]):.2f}  "
          f"missed {rr[0]['missed_by_group']}  FP {rr[0]['fp_hosts']}", flush=True)
(OUT / f"result_{'_'.join(sel) if len(sel) < 4 else 'all'}.json").write_text(json.dumps(res, indent=1, default=float))
