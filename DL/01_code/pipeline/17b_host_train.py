#!/usr/bin/env python3
"""STEP 17b - gộp từ điển (chỉ TRAIN), dựng ma trận thưa theo mẫu 30:1, train LightGBM/XGBoost, chọn ngưỡng trên VAL, chấm TEST một lần.

Bản gọn của pipeline Nguyễn, split theo hostname (host_split_seed1.csv). Tham số model lấy từ profile "kaggle" của Nguyễn
(code/kaggle/host_training_runtime.py và refresh_host_notebooks.py): LightGBM num_leaves=31, lr=0.05; XGBoost max_depth=8, eta=0.05,
tree_method=hist, max_bin=16; cả hai 300 vòng, scale_pos_weight=(neg/pos) của mẫu TRAIN, seed=1.
Chạy bằng Python trong .venv-host (có scipy, lightgbm, xgboost, scikit-learn).
"""
import argparse
import concurrent.futures as cf
import glob
import gzip
import json
import os
import sys
import time
from collections import Counter

import numpy as np
import orjson
import pandas as pd
from scipy import sparse

sys.path.insert(0, "D:/UIT/KLTN/KLTN-main/code")
from build_vocab import select_vocabulary  # noqa: E402
from ecar_tokenizer import GROUPS, flatten_tokens, tokenize_record  # noqa: E402

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/17_host_retrain_v1"
WORK = OUT + "/work"
Q0 = {"train": 0.004, "val": 0.006, "test": 0.006}
RATIO = 30
VOCAB = {}


def merge_chunk(files):
    tf = {g: Counter() for g in GROUPS}
    df = {g: Counter() for g in GROUPS}
    for f in files:
        with gzip.open(f, "rt") as fh:
            d = json.load(fh)
        for g in GROUPS:
            tf[g].update(d["tf"][g])
            df[g].update(d["df"][g])
    return tf, df


def init_vocab(v):
    global VOCAB
    VOCAB = v


def rows_for_file(task):
    path, cut = task
    indptr, indices, data, labels, meta = [0], [], [], [], []
    with gzip.open(path, "rb") as fh:
        for line in fh:
            rec = orjson.loads(line)
            label = int(rec["label"])
            if label == 0 and rec["_u"] >= cut:
                continue
            grouped, audit = tokenize_record(rec)
            if not audit["eligible"]:
                continue
            counts = Counter()
            for tok in flatten_tokens(grouped):
                i = VOCAB.get(tok)
                if i is not None:
                    counts[i] += 1
            for i in sorted(counts):
                indices.append(i)
                data.append(counts[i])
            indptr.append(len(indices))
            labels.append(label)
            meta.append((rec["_host"], rec["_day"], rec.get("timestamp", "")))
    n = len(labels)
    X = sparse.csr_matrix((np.array(data, dtype=np.float32), np.array(indices, dtype=np.int32), np.array(indptr, dtype=np.int64)),
                          shape=(n, len(VOCAB)))
    return X, np.array(labels, dtype=np.int8), meta


def build_split(split, cut, vocab, workers):
    files = sorted(glob.glob(f"{WORK}/sample/{split}/*.jsonl.gz"))
    Xs, ys, ms = [], [], []
    t0 = time.time()
    with cf.ProcessPoolExecutor(workers, initializer=init_vocab, initargs=(vocab,)) as ex:
        for i, (X, y, m) in enumerate(ex.map(rows_for_file, [(f, cut) for f in files], chunksize=8), 1):
            if X.shape[0]:
                Xs.append(X)
                ys.append(y)
                ms += m
            if i % 200 == 0:
                print(f"  {split}: {i}/{len(files)} files {time.time() - t0:.0f}s", flush=True)
    X = sparse.vstack(Xs, format="csr")
    y = np.concatenate(ys)
    meta = pd.DataFrame(ms, columns=["hostname", "day", "timestamp"])
    return X, y, meta


def best_f1_threshold(y, p):
    from sklearn.metrics import precision_recall_curve
    pr, rc, th = precision_recall_curve(y, p)
    f1 = 2 * pr[:-1] * rc[:-1] / np.maximum(pr[:-1] + rc[:-1], 1e-12)
    k = int(np.argmax(f1))
    return float(th[k]), float(f1[k])


def metrics(y, p, thr):
    from sklearn.metrics import average_precision_score, roc_auc_score
    pred = (p >= thr).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    tn = int(((y == 0) & (pred == 0)).sum())
    pr_ = tp / max(tp + fp, 1)
    rc = tp / max(tp + fn, 1)
    return {"threshold": thr, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr_, 4), "recall": round(rc, 4),
            "f1": round(2 * pr_ * rc / max(pr_ + rc, 1e-12), 4), "fpr": round(fp / max(fp + tn, 1), 6),
            "pr_auc": round(float(average_precision_score(y, p)), 4), "roc_auc": round(float(roc_auc_score(y, p)), 4),
            "rows": int(len(y)), "positives": int(y.sum())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--rounds", type=int, default=300)
    ap.add_argument("--models", nargs="+", default=["lgbm", "xgb"])
    ap.add_argument("--stage", default="all", choices=["vocab", "matrix", "train", "all"])
    a = ap.parse_args()
    os.makedirs(OUT + "/models", exist_ok=True)
    os.makedirs(OUT + "/matrices", exist_ok=True)

    # 1) tổng số event theo tập
    summ = pd.DataFrame([json.load(open(f)) for f in glob.glob(WORK + "/summary/*.json")])
    tot = summ.groupby("split")[["lines", "eligible", "pos", "neg", "neg_kept"]].sum()
    print(tot.to_string(), flush=True)
    tot.to_csv(OUT + "/sampling_totals_by_split.csv", encoding="utf-8-sig")
    cuts = {s: min(Q0[s], RATIO * tot.loc[s, "pos"] / tot.loc[s, "neg"]) for s in ("train", "val", "test")}
    print("cắt u (xác suất giữ event âm cuối):", cuts, flush=True)

    # 2) từ điển (chỉ TRAIN)
    vpath = OUT + "/vocab.json"
    if os.path.exists(vpath):
        vocab = json.load(open(vpath, encoding="utf-8"))
    else:
        files = sorted(glob.glob(WORK + "/vocab/*.json.gz"))
        print("gộp từ điển từ", len(files), "file", flush=True)
        chunks = [files[i::a.workers] for i in range(a.workers)]
        tf = {g: Counter() for g in GROUPS}
        df = {g: Counter() for g in GROUPS}
        with cf.ProcessPoolExecutor(a.workers) as ex:
            for t_, d_ in ex.map(merge_chunk, chunks):
                for g in GROUPS:
                    tf[g].update(t_[g])
                    df[g].update(d_[g])
        vocab, groups = select_vocabulary(df, tf, 2, 1, None, "term-frequency", None)
        json.dump(vocab, open(vpath, "w", encoding="utf-8"), ensure_ascii=False)
        meta = {"vocab_size": len(vocab), "fit_scope": "TRAIN hosts only; 100% positive events + negative events sampled with prob 0.03 "
                "(deviation from Nguyen: not every TRAIN event)", "min_frequency": 2, "min_document_frequency": 1,
                "tokens_by_group": dict(Counter(groups[t] for t in vocab))}
        json.dump(meta, open(OUT + "/vocab_metadata.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("từ điển:", meta, flush=True)
    if a.stage == "vocab":
        return

    # 3) ma trận
    mats = {}
    for s in ("train", "val", "test"):
        xp = f"{OUT}/matrices/{s}_X.npz"
        if os.path.exists(xp):
            mats[s] = (sparse.load_npz(xp), np.load(f"{OUT}/matrices/{s}_y.npy"))
            continue
        X, y, meta = build_split(s, cuts[s], vocab, a.workers)
        sparse.save_npz(xp, X)
        np.save(f"{OUT}/matrices/{s}_y.npy", y)
        meta.to_csv(f"{OUT}/matrices/{s}_meta.csv.gz", index=False)
        mats[s] = (X, y)
        print(f"{s}: X={X.shape} nnz={X.nnz:,} pos={int(y.sum()):,}", flush=True)
    if a.stage == "matrix":
        return

    # 4) train + đánh giá
    Xtr, ytr = mats["train"]
    Xva, yva = mats["val"]
    Xte, yte = mats["test"]
    pw = float((len(ytr) - ytr.sum()) / max(ytr.sum(), 1))
    print(f"scale_pos_weight={pw:.2f}", flush=True)
    report = {}
    for m in a.models:
        t0 = time.time()
        if m == "lgbm":
            import lightgbm as lgb
            params = dict(objective="binary", metric="None", num_leaves=31, learning_rate=0.05, seed=1, num_threads=a.threads,
                          verbosity=1, force_col_wise=True, deterministic=True, scale_pos_weight=pw)
            model = lgb.train(params, lgb.Dataset(Xtr, label=ytr), num_boost_round=a.rounds)
            model.save_model(OUT + "/models/lgbm_model.txt")
            pv, pt = model.predict(Xva, num_threads=a.threads), model.predict(Xte, num_threads=a.threads)
        else:
            import xgboost as xgb
            params = dict(objective="binary:logistic", eval_metric="aucpr", tree_method="hist", device="cpu", max_depth=8, eta=0.05,
                          seed=1, nthread=a.threads, max_bin=16, scale_pos_weight=pw)
            dtr = xgb.QuantileDMatrix(Xtr, label=ytr, max_bin=16, nthread=a.threads)
            model = xgb.train(params, dtr, num_boost_round=a.rounds)
            model.save_model(OUT + "/models/xgb_model.ubj")
            pv, pt = model.predict(xgb.DMatrix(Xva)), model.predict(xgb.DMatrix(Xte))
        thr, f1v = best_f1_threshold(yva, pv)
        report[m] = {"train_seconds": round(time.time() - t0), "val": metrics(yva, pv, thr), "test": metrics(yte, pt, thr), "threshold_from_val": thr}
        print(m, json.dumps(report[m], ensure_ascii=False), flush=True)
        json.dump(report, open(OUT + "/metrics_event_level.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
