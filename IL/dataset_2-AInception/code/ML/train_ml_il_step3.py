#!/usr/bin/env python3
"""ML IL step 3: OpTC -> ATLASv2 -> AInception SL700 with LightGBM residual (continual) boosting, same rules as
the ATLASv2 step (IL/dataset_1-ATLASv2/code/ML, notebook lgbm_atlasv2.ipynb, v9b run).

Task-1, frozen (step 2, v9b labels):  z1(x) = 0.8 * z_OpTC(x[:, :10317]) + z_ATLASv2(x[:, :12365])
Step 3, residual booster on SL700:    z2(x) = 0.8 * z1(x) + z_SL700(x),   p = sigmoid(z2)
  * init score 0.8*z1 for SL700 rows and replay negatives, alpha_rep*z1 for replay positives; alpha_rep = 0.5 was
    chosen on the VALIDATION sets of SL700, ATLASv2 and OpTC (eval_old_val.py) among 0.25 (the step-2 rule), 0.5, 0.8;
  * hard negatives (y = 0 and sigmoid(z1) > 0.5) weight 5 (step-2 rule);
  * replay of both old domains: OpTC 12,500 positives + 25,000 negatives from optc_replay_buffer.npz; ATLASv2 v9b
    TRAIN: every positive + negatives (half with the highest Task-1 margin, half random) up to 37,500 rows;
  * LightGBM params of step 2: num_leaves 31, lr 0.03, 300 rounds, max_delta_step 2, reg_lambda 5, deterministic,
    scale_pos_weight = negatives / positives of the SL700 training rows (SL700 negatives capped at 30:1 as step 2).
Baselines: zero-shot Task-1; scratch = same SL700 features, no init score, no replay.
Selection: threshold = F1 maximum on SL700 VAL (run a_c); SL700 TEST (run f_a) scored once.
Backward transfer: ATLASv2 v9b TEST at the step-2 frozen threshold 0.94073; OpTC TEST at the frozen OpTC threshold
0.87427 -- Task-1 (before step 3) vs Task-2 (after). The Task-1 numbers must reproduce the published step-2 run.
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy import sparse
from scipy.special import expit
from sklearn.metrics import average_precision_score, precision_recall_curve

sys.path.insert(0, "/mnt/SSD_Data/optc")
from ML.code.preprocess.host_shards import decode_shard  # noqa: E402

D3 = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output")
DATA = D3 / "ml_il_step3_20261113/data"
CACHE = D3 / "ml_il_step3_20261113/cache"
ML1 = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML")
OPTC_MODEL = ML1 / "pretrained_optc_model/model-slot-0.txt"
ATLAS_RUN = ML1 / "output/v9b_20261112/run_v9b/atlasv2-incremental-2e4a6239dc94/lgbm-kaggle"
ATLAS_MANIFEST = ML1 / "output/v9b_20261112/model_input/manifest.json"
OPTC_REPLAY = ML1 / "preprocess/output/optc_replay_buffer.npz"
OPTC_TEST_MANIFEST = ML1 / "preprocess/output/optc_test/manifest.json"
W_OPTC, W_ATLAS = 10317, 12365
ALPHA, HARD_W = 0.8, 5.0
ALPHA_REP_POS = 0.5        # replay positives; chosen on VAL (step-2 rule was 0.25)
TH_ATLAS, TH_OPTC = 0.94073, 0.87427
CONFIGS = {"ecar": ("ecar",), "ecar_lx": ("ecar", "lx"), "ecar_lx_scope": ("ecar", "lx", "lx_scope")}


# ------------------------------------------------------------------ models and data
def boosters():
    latest = json.loads((ATLAS_RUN / "incremental/model/latest.json").read_text())
    assert latest["complete"] and latest["identity"]["base_margin_alpha"] == ALPHA
    bo = lgb.Booster(model_file=str(OPTC_MODEL))
    ba = lgb.Booster(model_file=str(ATLAS_RUN / "incremental/model" / latest["path"]))
    assert bo.num_feature() == W_OPTC and ba.num_feature() == W_ATLAS
    return bo, ba


def width(X, w):
    if X.shape[1] == w:
        return X
    if X.shape[1] > w:
        return X[:, :w]
    return sparse.hstack([X, sparse.csr_matrix((X.shape[0], w - X.shape[1]), dtype=X.dtype)], format="csr")


def z_task1(bo, ba, X, threads):
    return ALPHA * bo.predict(width(X, W_OPTC), raw_score=True, num_threads=threads) + \
        ba.predict(width(X, W_ATLAS), raw_score=True, num_threads=threads)


def load_npz(p):
    with np.load(p, allow_pickle=False) as z:
        X = sparse.csr_matrix((z["data"], z["indices"], z["indptr"]), shape=tuple(z["shape"]))
        return X, z["labels"].astype(np.int8)


def load_shards(manifest_path, split, w):
    m = json.loads(Path(manifest_path).read_text())
    Xs, ys = [], []
    for s in [s for s in m["shards"] if s["split"] == split]:
        X, y, _ = decode_shard(Path(manifest_path).parent / s["path"], w, s)
        Xs.append(X.astype(np.float32)); ys.append(y.astype(np.int8))
    return sparse.vstack(Xs, format="csr"), np.concatenate(ys)


def cached(name, fn):
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / f"{name}.npy"
    if p.exists():
        return np.load(p)
    v = fn()
    np.save(p, v)
    return v


def select_columns(X, cols, keep_groups):
    """Keep the ATLASv2 prefix and the new SL700 columns of the selected groups (order preserved)."""
    keep = np.r_[np.arange(W_ATLAS), np.array(sorted(int(c) for c, g in cols.items() if g in keep_groups), dtype=np.int64)]
    return X[:, keep], len(keep)


# ------------------------------------------------------------------ metrics
def best_thr(y, p):
    pr, rc, th = precision_recall_curve(y, p)
    f1 = 2 * pr * rc / np.clip(pr + rc, 1e-12, None)
    i = int(np.nanargmax(f1[:-1]))
    return float(th[i]), float(f1[i])


def met(y, p, t):
    pred = p >= t
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    pr = tp / max(1, tp + fp); rc = tp / max(1, tp + fn)
    return dict(threshold=float(t), tp=tp, fp=fp, fn=fn, precision=pr, recall=rc, f1=2 * pr * rc / max(1e-12, pr + rc),
                ap=float(average_precision_score(y, p)) if 0 < y.sum() < len(y) else None)


def window_eval(meta_val, p_val, meta_te, p_te):
    """Window-level view comparable to DL: each DL window (sl700_windows_v3) scores the max over ML rows of its host
    inside [start, end]; threshold on VAL windows, TEST once."""
    blob = pickle.load(open(D3 / "sl700_windows_v3/dataset.pkl", "rb"))
    out = {}
    for sp, meta, p in (("val", meta_val, p_val), ("test", meta_te, p_te)):
        m = meta.assign(p=p).sort_values("ts")
        by_host = {h: (g.ts.values, g.p.values) for h, g in m.groupby("host")}
        ys, ss = [], []
        for s in blob["splits"][sp]:
            ts, pp = by_host.get(s["host"], (np.array([]), np.array([])))
            lo, hi = np.searchsorted(ts, s["start"], "left"), np.searchsorted(ts, s["end"], "right")
            ss.append(float(pp[lo:hi].max()) if hi > lo else 0.0); ys.append(s["y"])
        out[sp] = (np.asarray(ys), np.asarray(ss))
    t, _ = best_thr(*out["val"])
    return met(out["test"][0], out["test"][1], t)


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", default="ecar_lx", choices=list(CONFIGS))
    ap.add_argument("--mode", default="inc", choices=["inc", "scratch"])
    ap.add_argument("--seed", type=int, default=1, help="replay / negative sampling seed (LightGBM itself is deterministic)")
    ap.add_argument("--rounds", type=int, default=300)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--neg-per-pos", type=int, default=30)
    ap.add_argument("--optc-rep", default="12500,25000")
    ap.add_argument("--atlas-rep", type=int, default=37500)
    ap.add_argument("--no-replay", action="store_true", help="ablation: residual boosting on SL700 rows only")
    ap.add_argument("--rep-pos-alpha", type=float, default=ALPHA_REP_POS,
                    help="init-score scale of replay positives (0.5 chosen on VAL; step-2 rule 0.25; 0.8 = inference scale)")
    a = ap.parse_args()
    out = Path(a.out)
    if (out / "result.json").exists():
        raise SystemExit(f"{out} done")
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time(); rng = np.random.default_rng(a.seed); T = a.threads
    bo, ba = boosters()
    cols = json.loads((DATA / "columns.json").read_text())

    # ---- SL700 matrices (feature groups of the config)
    S = {}
    for sp in ("train", "val", "test"):
        X, y = load_npz(DATA / f"{sp}.npz")
        z1 = cached(f"z1_sl700_{sp}", lambda: z_task1(bo, ba, X, T))
        Xs, W = select_columns(X, cols, CONFIGS[a.config])
        S[sp] = dict(X=Xs, y=y, z1=z1, meta=pd.read_parquet(DATA / f"meta_{sp}.parquet"))
    print(f"SL700 width {W} ({a.config}); rows train/val/test {[S[s]['X'].shape[0] for s in S]}, attack {[int(S[s]['y'].sum()) for s in S]}  [{time.time() - t0:.0f}s]", flush=True)

    # ---- old-domain TEST sets and Task-1 reproduction check (must equal the published step-2 run)
    Xa_te, ya_te = load_shards(ATLAS_MANIFEST, "test", W_ATLAS)
    za_te = cached("z1_atlas_test", lambda: z_task1(bo, ba, Xa_te, T))
    Xo_te, yo_te = load_shards(OPTC_TEST_MANIFEST, "test", W_OPTC)
    zo_te = cached("z1_optc_test", lambda: z_task1(bo, ba, Xo_te, T))
    before = {"atlas_test": met(ya_te, expit(za_te), TH_ATLAS), "optc_test": met(yo_te, expit(zo_te), TH_OPTC)}
    pub = json.loads((ATLAS_RUN / "incremental/lgbm_metrics.json").read_text())["test"]["confusion"]
    pub_o = json.loads((ATLAS_RUN / "bwt_metrics.json").read_text())["optc_after_il"]["confusion"]
    chk = {"atlas": (before["atlas_test"]["tp"], before["atlas_test"]["fp"], before["atlas_test"]["fn"]) == (pub["tp"], pub["fp"], pub["fn"]),
           "optc": (before["optc_test"]["tp"], before["optc_test"]["fp"], before["optc_test"]["fn"]) == (pub_o["tp"], pub_o["fp"], pub_o["fn"])}
    before["reproduces_step2_published_confusion"] = chk
    print("Task-1 reproduces step 2 (ATLASv2 test, OpTC test):", chk, before["atlas_test"]["f1"], before["optc_test"]["f1"], flush=True)
    if not all(chk.values()):
        print("WARNING: Task-1 confusion differs from the published step-2 run:", (before["atlas_test"]["tp"], before["atlas_test"]["fp"], before["atlas_test"]["fn"]), pub,
              (before["optc_test"]["tp"], before["optc_test"]["fp"], before["optc_test"]["fn"]), pub_o, flush=True)

    # ---- training rows
    tr = S["train"]
    pos = np.flatnonzero(tr["y"] == 1); neg = np.flatnonzero(tr["y"] == 0)
    if len(neg) > a.neg_per_pos * len(pos):
        neg = rng.choice(neg, a.neg_per_pos * len(pos), replace=False)
    sel = np.sort(np.r_[pos, neg])
    X_tr, y_tr, z1_tr = tr["X"][sel], tr["y"][sel], tr["z1"][sel]
    spw = float((y_tr == 0).sum() / max(1, (y_tr == 1).sum()))
    info = {"sl700_rows": int(len(sel)), "sl700_pos": int(y_tr.sum()), "scale_pos_weight": spw}
    params = dict(objective="binary", metric="None", num_leaves=31, learning_rate=0.03, seed=1, num_threads=T, verbosity=-1,
                  force_col_wise=True, deterministic=True, scale_pos_weight=spw, max_delta_step=2.0, reg_lambda=5.0)
    if a.mode == "inc" and a.no_replay:
        init = ALPHA * z1_tr
        wts = np.where((y_tr == 0) & (expit(z1_tr) > 0.5), HARD_W, 1.0).astype(np.float32)
        info.update(replay_optc=[0, 0], replay_atlas=[0, 0], hard_negatives=int((wts > 1).sum()))
        dtrain = lgb.Dataset(X_tr, label=y_tr, init_score=init, weight=wts, params=params, free_raw_data=True)
    elif a.mode == "inc":
        Xr_o, yr_o = load_npz(OPTC_REPLAY)
        n_p, n_n = (int(v) for v in a.optc_rep.split(","))
        io_ = np.r_[rng.choice(np.flatnonzero(yr_o == 1), n_p, replace=False), rng.choice(np.flatnonzero(yr_o == 0), n_n, replace=False)]
        Xr_o, yr_o = width(Xr_o[io_], W), yr_o[io_]
        zr_o = z_task1(bo, ba, Xr_o, T)
        Xa_tr, ya_tr = load_shards(ATLAS_MANIFEST, "train", W_ATLAS)
        za_tr = cached("z1_atlas_train", lambda: z_task1(bo, ba, Xa_tr, T))
        apos = np.flatnonzero(ya_tr == 1); aneg = np.flatnonzero(ya_tr == 0)
        n_neg = a.atlas_rep - len(apos); hard = aneg[np.argsort(-za_tr[aneg])[:n_neg // 2]]
        rand = rng.choice(np.setdiff1d(aneg, hard), n_neg - len(hard), replace=False)
        ia = np.r_[apos, hard, rand]
        Xr_a, yr_a, zr_a = width(Xa_tr[ia], W), ya_tr[ia], za_tr[ia]
        X_fit = sparse.vstack([X_tr, Xr_o, Xr_a], format="csr")
        y_fit = np.r_[y_tr, yr_o, yr_a]
        z1_fit = np.r_[z1_tr, zr_o, zr_a]
        is_rep = np.r_[np.zeros(len(y_tr), bool), np.ones(len(yr_o) + len(yr_a), bool)]
        init = np.where(is_rep & (y_fit == 1), a.rep_pos_alpha * z1_fit, ALPHA * z1_fit)
        wts = np.where((y_fit == 0) & (expit(z1_fit) > 0.5), HARD_W, 1.0).astype(np.float32)
        info.update(replay_optc=[int(yr_o.sum()), int((yr_o == 0).sum())], replay_atlas=[int(yr_a.sum()), int((yr_a == 0).sum())],
                    hard_negatives=int((wts > 1).sum()))
        dtrain = lgb.Dataset(X_fit, label=y_fit, init_score=init, weight=wts, params=params, free_raw_data=True)
    else:
        dtrain = lgb.Dataset(X_tr, label=y_tr, params=params, free_raw_data=True)
    print("train", json.dumps(info), flush=True)
    model = lgb.train(params, dtrain, num_boost_round=a.rounds)
    model.save_model(str(out / "model.txt"))

    def p_new(X, z1):
        z = model.predict(width(X, W), raw_score=True, num_threads=T)
        return expit(ALPHA * z1 + z) if a.mode == "inc" else expit(z)

    # ---- SL700: VAL threshold, TEST once (event level) + window-level view
    pv, pt = p_new(S["val"]["X"], S["val"]["z1"]), p_new(S["test"]["X"], S["test"]["z1"])
    thr, f1v = best_thr(S["val"]["y"], pv)
    test = met(S["test"]["y"], pt, thr)
    mt = S["test"]["meta"].assign(p=pt, pred=pt >= thr)
    by_kind = {k: dict(attack=int(g.y.sum()), tp=int((g.pred & (g.y == 1)).sum()), fp=int((g.pred & (g.y == 0)).sum()))
               for k, g in mt.groupby("kind")}
    by_stage = {int(k): dict(n=int(len(g)), recall=float(g.pred.mean())) for k, g in mt[mt.y == 1].groupby("stage")}
    zv, zt = expit(S["val"]["z1"]), expit(S["test"]["z1"])
    t0_, _ = best_thr(S["val"]["y"], zv)
    res = {"args": vars(a), "info": info, "width": W,
           "sl700": {"val_f1": f1v, "test": test, "test_by_kind": by_kind, "test_recall_by_stage": by_stage,
                     "window_level_test": window_eval(S["val"]["meta"], pv, S["test"]["meta"], pt)},
           "sl700_zero_shot_task1": {"test": met(S["test"]["y"], zt, t0_),
                                     "window_level_test": window_eval(S["val"]["meta"], zv, S["test"]["meta"], zt)},
           "before_step3": before}
    # ---- backward transfer
    if a.mode == "inc":
        res["after_step3"] = {"atlas_test": met(ya_te, p_new(Xa_te, za_te), TH_ATLAS),
                              "optc_test": met(yo_te, p_new(Xo_te, zo_te), TH_OPTC)}
    res["elapsed_sec"] = round(time.time() - t0)
    (out / "result.json").write_text(json.dumps(res, indent=1, default=float))
    mt[["run", "host", "ts", "line", "kind", "y", "stage", "p"]].to_parquet(out / "sl700_test_scores.parquet", index=False)
    f = lambda d: f"F1 {d['f1']:.4f} AP {d['ap']:.4f} P {d['precision']:.3f} R {d['recall']:.3f} (tp {d['tp']} fp {d['fp']} fn {d['fn']})"
    print(f"RESULT {a.mode} {a.config} seed {a.seed}\n SL700 TEST {f(test)} | window {f(res['sl700']['window_level_test'])}"
          f"\n zero-shot Task-1 SL700 {f(res['sl700_zero_shot_task1']['test'])}"
          + (f"\n ATLASv2 TEST before {f(before['atlas_test'])} -> after {f(res['after_step3']['atlas_test'])}"
             f"\n OpTC TEST before {f(before['optc_test'])} -> after {f(res['after_step3']['optc_test'])}" if a.mode == "inc" else "")
          + f"\n [{res['elapsed_sec']}s]", flush=True)


if __name__ == "__main__":
    main()
