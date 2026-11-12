#!/usr/bin/env python3
"""STEP 12C muc A - baseline fusion khong hoc sau: diem host dang luat + diem network -> OR / trung binh / stacking.

Quy tac (CLAUDE.md): thong ke 'binh thuong' va tu dien cap cha-con chi tu TRAIN; nguong/trong so chon tren VAL; TEST danh gia mot lan.
Don vi: cua so (host, 15 phut). Split: seed_1.
Diem host: voi moi dac trung k (n_parent_lsass, n_cmd_susp, n_proc_writable, n_novel_pairs),
  tail_k(x) = ti le cua so benign TRAIN co gia tri >= x ; s_k = min(1, -log10(max(tail_k, 1e-4)) / 4) (x = 0 -> s_k = 0);
  s_host = max_k s_k. Khong co tham so nao hoc tu VAL/TEST.
Nhan danh gia: (A) nhan mang cua pipeline (manifest label), (B) nhan host cua A New Hope (window_labels_v1.csv: n_host_mal_events > 0).
"""
import argparse
import glob
import json
import os
import sys
from collections import defaultdict

import numpy as np
import pandas as pd

FEATS = ["n_parent_lsass", "n_cmd_susp", "n_proc_writable", "n_novel_pairs"]
NETS = ["bilstm_v2_full_seed1", "bilstm_v2_noapp_seed1", "mixed_v2_full_seed1", "mixed_v2_noapp_seed1"]


def load_features(fdir, scan):
    parts = []
    for f in glob.glob(fdir + "/*.csv"):
        parts.append(pd.read_csv(f))
    d = pd.concat(parts, ignore_index=True)
    sp = scan.drop_duplicates(["host", "day"]).set_index(["host", "day"])["split"]
    d["split"] = [sp.get((h, dy), None) for h, dy in zip(d["host"], d["day"])]
    # cua so EDT -> epoch UTC bat dau cua so
    t = pd.to_datetime(d["win_edt"]) + pd.Timedelta(hours=4)
    d["win_epoch"] = (t - pd.Timestamp("1970-01-01")).dt.total_seconds().astype("int64")
    return d


def novel_pairs(d):
    """n_novel_pairs: so cap cha>con chua tung thay o host TRAIN khac (train: chua thay o host TRAIN nao khac)."""
    host_of = defaultdict(set)
    tr = d[d["split"] == "train"]
    for h, s in zip(tr["host"], tr["pairs_json"]):
        for k in json.loads(s):
            host_of[k].add(h)
    out = []
    for h, sp, s in zip(d["host"], d["split"], d["pairs_json"]):
        n = 0
        for k in json.loads(s):
            hs = host_of.get(k, set())
            if (sp == "train" and not (hs - {h})) or (sp != "train" and not hs):
                n += 1
        out.append(n)
    d["n_novel_pairs"] = out
    return d


def host_score(d):
    tr = d[d["split"] == "train"]
    S = np.zeros(len(d))
    info = {}
    for k in FEATS:
        x = tr[k].to_numpy()
        vals = np.sort(np.unique(x))

        def tail(v, x=x):
            return (x >= v).mean()

        cache = {int(v): tail(v) for v in vals}
        sk = []
        for v in d[k].to_numpy():
            v = int(v)
            if v == 0:
                sk.append(0.0)
            else:
                t = cache.get(v)
                if t is None:  # gia tri vuot moi gia tri TRAIN
                    t = 0.0
                sk.append(min(1.0, -np.log10(max(t, 1e-4)) / 4.0))
        d["s_" + k] = sk
        S = np.maximum(S, np.array(sk))
        info[k] = {"train_max": int(x.max()), "train_p99": float(np.quantile(x, 0.99)), "train_frac_nonzero": float((x > 0).mean())}
    d["s_host"] = S
    return d, info


def prf(y, pred):
    tp = int(((y == 1) & (pred == 1)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def best_thr(y, s):
    cands = np.unique(np.concatenate([np.quantile(s, np.linspace(0, 1, 201)), np.unique(s)]))
    best, bt = -1, []
    for t in cands:
        f = prf(y, (s >= t).astype(int))["f1"]
        if f > best + 1e-12:
            best, bt = f, [t]
        elif abs(f - best) <= 1e-12:
            bt.append(t)
    return float(np.median(bt)), best


def fit_lr(X, y, l2=1.0, it=50):
    Xb = np.hstack([X, np.ones((len(X), 1))])
    w = np.zeros(Xb.shape[1])
    pw = max(1.0, (y == 0).sum() / max(1, (y == 1).sum()))
    sw = np.where(y == 1, min(pw, 50.0), 1.0)
    for _ in range(it):
        z = np.clip(Xb @ w, -30, 30)
        p = 1 / (1 + np.exp(-z))
        g = Xb.T @ (sw * (p - y)) + l2 * np.r_[w[:-1], 0]
        H = (Xb.T * (sw * p * (1 - p))) @ Xb + l2 * np.diag(np.r_[np.ones(len(w) - 1), 0]) + 1e-6 * np.eye(len(w))
        w = w - np.linalg.solve(H, g)
    return w


def pred_lr(X, w):
    Xb = np.hstack([X, np.ones((len(X), 1))])
    return 1 / (1 + np.exp(-np.clip(Xb @ w, -30, 30)))


def logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def net_scores(root, manifest, name):
    m = manifest.set_index("sample_id")
    parts = []
    for sp in ("val", "test"):
        p = pd.read_csv(f"{root}/{name}/{sp}_predictions.csv")
        p = p.join(m[["hostname", "window_start_epoch"]], on="sample_id")
        p["split"] = sp
        parts.append(p)
    p = pd.concat(parts)
    g = p.groupby(["hostname", "window_start_epoch"]).agg(p_net=("probability", "max"), y_net=("label", "max")).reset_index()
    g = g.rename(columns={"hostname": "host", "window_start_epoch": "win_epoch"})
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="D:/UIT/KLTNv2")
    a = ap.parse_args()
    R = a.root
    out = R + "/02_artifacts/12c_host_features_v1/"
    scan = pd.read_csv(out + "scan_list.csv")
    d = load_features(out + "features", scan)
    d = d[d["split"].notna()].copy()
    d = novel_pairs(d)
    d, info = host_score(d)
    lab = pd.read_csv(R + "/02_artifacts/12b_multilabel_stage_v1/window_labels_v1.csv")
    lab["win_epoch"] = ((pd.to_datetime(lab["window_start_utc"]) - pd.Timestamp("1970-01-01")).dt.total_seconds()).astype("int64")
    hl = lab[lab["n_host_mal_events"] > 0][["host", "win_epoch"]].assign(y_host=1)
    d = d.merge(hl, on=["host", "win_epoch"], how="left")
    d["y_host"] = d["y_host"].fillna(0).astype(int)
    manifest = pd.read_csv(R + "/03_datasets/random_network_dl_v1_1_15m/seed_1/split/network_sample_manifest.csv")
    mroot = R + "/05_models/10_random_seed1_v1"
    results = {"feature_stats_train": info, "n_windows": d.groupby("split").size().to_dict(), "methods": {}}
    persc = {}
    for name in NETS:
        g = net_scores(mroot, manifest, name)
        x = d.merge(g, on=["host", "win_epoch"], how="left")
        x["has_net"] = x["p_net"].notna().astype(int)
        x["p_net_f"] = x["p_net"].fillna(0.0)
        x["y_net"] = x["y_net"].fillna(0).astype(int)
        v, t = x[x["split"] == "val"], x[x["split"] == "test"]
        res = {}
        for tgt in ("y_net", "y_host"):
            yv, yt = v[tgt].to_numpy(), t[tgt].to_numpy()
            r = {"val_pos": int(yv.sum()), "test_pos": int(yt.sum())}
            # chi network
            thr, _ = best_thr(yv, v["p_net_f"].to_numpy())
            r["net_only"] = {"thr": thr, **prf(yt, (t["p_net_f"].to_numpy() >= thr).astype(int))}
            # chi host
            thr, _ = best_thr(yv, v["s_host"].to_numpy())
            r["host_only"] = {"thr": thr, **prf(yt, (t["s_host"].to_numpy() >= thr).astype(int))}
            # OR: moi nhanh dung nguong rieng chon tren VAL
            thn, _ = best_thr(yv, v["p_net_f"].to_numpy())
            thh, _ = best_thr(yv, v["s_host"].to_numpy())
            orp = ((t["p_net_f"].to_numpy() >= thn) | (t["s_host"].to_numpy() >= thh)).astype(int)
            r["OR"] = {"thr_net": thn, "thr_host": thh, **prf(yt, orp)}
            # trung binh co trong so: w chon tren VAL
            bw, bf, bt = 0.5, -1, 0
            for w_ in np.linspace(0, 1, 11):
                s = w_ * v["p_net_f"].to_numpy() + (1 - w_) * v["s_host"].to_numpy()
                tt, f = best_thr(yv, s)
                if f > bf + 1e-12:
                    bw, bf, bt = w_, f, tt
            s_t = bw * t["p_net_f"].to_numpy() + (1 - bw) * t["s_host"].to_numpy()
            r["average"] = {"w_net": float(bw), "thr": bt, **prf(yt, (s_t >= bt).astype(int))}
            # stacking logistic tren VAL
            Xv = np.c_[logit(v["p_net_f"].to_numpy()), v["s_host"].to_numpy(), 1 - v["has_net"].to_numpy()]
            Xt = np.c_[logit(t["p_net_f"].to_numpy()), t["s_host"].to_numpy(), 1 - t["has_net"].to_numpy()]
            mu, sd = Xv.mean(0), Xv.std(0) + 1e-9
            w = fit_lr((Xv - mu) / sd, yv)
            pv, pt = pred_lr((Xv - mu) / sd, w), pred_lr((Xt - mu) / sd, w)
            thr, _ = best_thr(yv, pv)
            r["stacking"] = {"thr": thr, "coef": [round(float(c), 3) for c in w], **prf(yt, (pt >= thr).astype(int))}
            res[tgt] = r
            if tgt == "y_net" and name == "mixed_v2_noapp_seed1":
                x.loc[x["split"] == "test", "stack_p"] = pt
        results["methods"][name] = res
        if name == "mixed_v2_noapp_seed1":
            x.to_csv(out + "window_scores_test_val_seed1.csv", index=False)
    with open(out + "fusion_baseline_results.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(json.dumps(results, ensure_ascii=False, indent=1)[:6000])


if __name__ == "__main__":
    main()
