#!/usr/bin/env python3
"""STEP 17c - chấm điểm nhánh Host trên các cửa sổ 15 phút của eval_windows_seed1.csv (VAL và TEST) và gộp từ event lên cửa sổ.

Đọc lại file eCAR thô của host VAL/TEST, chỉ lấy event hợp lệ nằm trong cửa sổ cần chấm, tokenize bằng từ điển TRAIN, chấm bằng model đã train.
Đầu ra: window_scores_host.csv (mỗi dòng một cửa sổ x model: max_prob, mean_prob, p99_prob, n_above_thr, n_label1...).
Chạy bằng Python trong .venv-host.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import glob
import gzip
import json
import os
import re
import sys
import time
from collections import Counter

import numpy as np
import orjson
import pandas as pd
from scipy import sparse

sys.path.insert(0, "D:/UIT/KLTN/KLTN-main/code")
from ecar_tokenizer import HOST_OBJECT_FIELDS, flatten_tokens, tokenize_record  # noqa: E402

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/17_host_retrain_v1"
TS = re.compile(rb'"timestamp": "(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})')
G = {}


def init(vocab, thr):
    G["vocab"] = vocab
    G["thr"] = thr
    G["models"] = {}
    if "lgbm" in thr:
        import lightgbm as lgb
        G["models"]["lgbm"] = lgb.Booster(model_file=OUT + "/models/lgbm_model.txt")
    if "xgb" in thr:
        import xgboost as xgb
        b = xgb.Booster()
        b.load_model(OUT + "/models/xgb_model.ubj")
        b.set_param({"nthread": 1})
        G["models"]["xgb"] = b


def window_of(line):
    m = TS.search(line, max(len(line) - 80, 0))
    if not m:
        return None
    y, mo, d, h, mi = (int(x) for x in m.groups())
    base = int((dt.datetime(y, mo, d) - dt.datetime(1970, 1, 1)).total_seconds())
    return base + 4 * 3600 + h * 3600 + (mi // 15) * 900   # giờ EDT -> epoch UTC bắt đầu cửa sổ


def score_file(task):
    path, host, day, split, wins = task
    vocab = G["vocab"]
    rows_idx, rows_dat, indptr, labels, wkeys = [], [], [0], [], []
    with gzip.open(path, "rb") as f:
        for line in f:
            i = line.find(b'"object": "')
            if i < 0:
                continue
            j = line.find(b'"', i + 11)
            if line[i + 11:j].decode("ascii", "ignore").casefold() not in HOST_OBJECT_FIELDS:
                continue
            w = window_of(line)
            if w is None or w not in wins:
                continue
            rec = orjson.loads(line)
            grouped, audit = tokenize_record(rec)
            if not audit["eligible"]:
                continue
            counts = Counter()
            for tok in flatten_tokens(grouped):
                k = vocab.get(tok)
                if k is not None:
                    counts[k] += 1
            for k in sorted(counts):
                rows_idx.append(k)
                rows_dat.append(counts[k])
            indptr.append(len(rows_idx))
            labels.append(1 if b'"label": 1}' in line[-16:] else 0)
            wkeys.append(w)
    n = len(labels)
    out = []
    if n == 0:
        return out
    X = sparse.csr_matrix((np.array(rows_dat, dtype=np.float32), np.array(rows_idx, dtype=np.int32), np.array(indptr, dtype=np.int64)),
                          shape=(n, len(vocab)))
    wk = np.array(wkeys)
    lab = np.array(labels)
    for m, model in G["models"].items():
        if m == "lgbm":
            p = model.predict(X, num_threads=1)
        else:
            import xgboost as xgb
            p = model.predict(xgb.DMatrix(X))
        thr = G["thr"][m]
        for w in np.unique(wk):
            s = wk == w
            ps = p[s]
            out.append({"split": split, "hostname": host, "day": day, "window_start_epoch_utc": int(w), "model": m,
                        "n_events_scored": int(s.sum()), "max_prob": float(ps.max()), "mean_prob": float(ps.mean()),
                        "p99_prob": float(np.quantile(ps, 0.99)), "n_above_thr": int((ps >= thr).sum()),
                        "n_label1": int(lab[s].sum()), "threshold": thr})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    vocab = json.load(open(OUT + "/vocab.json", encoding="utf-8"))
    rep = json.load(open(OUT + "/metrics_event_level.json", encoding="utf-8"))
    thr = {m: rep[m]["threshold_from_val"] for m in rep}
    print("models:", list(thr), "thr:", thr, flush=True)
    ew = pd.read_csv(R + "/02_artifacts/16_host_branch_request_v1/eval_windows_seed1.csv")
    tasks = []
    for (host, day, split), g in ew.groupby(["hostname", "day", "split"]):
        kind = "host-begnin" if day <= "2019-09-22" else "host-malicious"
        pat = f"E:/{kind}/{day}/*/*ecar-{day}-{host}.json.gz"
        hit = glob.glob(pat)
        if hit:
            tasks.append((hit[0].replace("\\", "/"), host, day, split, set(int(x) for x in g["window_start_epoch_utc"])))
    if a.limit:
        tasks = tasks[: a.limit]
    print(len(tasks), "file;", sum(len(t[4]) for t in tasks), "cửa sổ", flush=True)
    rows, t0 = [], time.time()
    with cf.ProcessPoolExecutor(a.workers, initializer=init, initargs=(vocab, thr)) as ex:
        for i, r in enumerate(ex.map(score_file, tasks, chunksize=1), 1):
            rows += r
            if i % 20 == 0 or i == len(tasks):
                print(f"[{i}/{len(tasks)}] {time.time() - t0:.0f}s, {len(rows)} dòng", flush=True)
    out = pd.DataFrame(rows).sort_values(["split", "hostname", "window_start_epoch_utc", "model"])
    out.to_csv(OUT + "/window_scores_host.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print("DONE", len(out), flush=True)


if __name__ == "__main__":
    main()
