#!/usr/bin/env python3
"""STEP 10H - phân tích 4 run "beacon chưa từng thấy" (holdout scenario, bỏ app_family).

Chỉ đọc: predictions/metrics của 05_models/10g_unseen_v1/<run>/ và manifest của dataset holdout. Không train, không sửa artifact cũ.
Chỉ số tính lại bằng numpy (máy local không có sklearn ở Python hệ thống). Số 'ở ngưỡng chọn trên VAL' là kết quả chính thức;
số 'recall tại FPR cố định' dùng TEST nên chỉ là CHẨN ĐOÁN (không dùng để chọn ngưỡng).
"""
import json
import os

import numpy as np
import pandas as pd

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/10h_unseen_beacon_analysis_v1"
RUNS = [("bilstm", "sc1"), ("bilstm", "sc2"), ("mixed", "sc1"), ("mixed", "sc2")]


def average_precision(y, s):
    o = np.argsort(-s, kind="mergesort")
    y, s = y[o], s[o]
    tp, fp = np.cumsum(y), np.cumsum(1 - y)
    last = np.r_[np.where(np.diff(s))[0], len(s) - 1]
    tp, fp = tp[last], fp[last]
    prec, rec = tp / (tp + fp), tp / y.sum()
    return float(np.sum((rec - np.r_[0.0, rec[:-1]]) * prec))


def roc_auc(y, s):
    r = pd.Series(s).rank(method="average").to_numpy()
    n1, n0 = y.sum(), len(y) - y.sum()
    return float((r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def recall_at_fpr(y, s, fpr):
    neg = np.sort(s[y == 0])
    thr = neg[int(np.ceil(len(neg) * (1 - fpr))) - 1] if fpr < 1 else neg[0]
    return float((s[y == 1] > thr).mean()), float(thr)


def main():
    os.makedirs(OUT, exist_ok=True)
    rows, hostrows = [], []
    for model, tag in RUNS:
        run = f"{model}_unseen_{tag}_noapp"
        d = f"{R}/05_models/10g_unseen_v1/{run}"
        man = pd.read_csv(f"{R}/03_datasets/loso_network_dl_v1_1_15m/holdout_scenario_{tag[-1]}/split/network_sample_manifest.csv").set_index("sample_id")
        mj = json.load(open(d + "/metrics.json", encoding="utf-8"))
        cfg = json.load(open(d + "/config.json", encoding="utf-8"))
        thr = mj["threshold_selected_on_val"]
        te = pd.read_csv(d + "/test_predictions.csv").join(man[["hostname", "window_start_utc", "date"]], on="sample_id")
        va = pd.read_csv(d + "/val_predictions.csv")
        y, s = te["label"].to_numpy().astype(int), te["probability"].to_numpy()
        yv, sv = va["label"].to_numpy().astype(int), va["probability"].to_numpy()
        pred = (s >= thr).astype(int)
        r = {"run": run, "model": model, "holdout": tag, "best_epoch": mj["best_epoch"], "thr_val": thr,
             "val_pos": int(yv.sum()), "val_recall": round(float(((sv >= thr) & (yv == 1)).sum() / yv.sum()), 3),
             "val_pr_auc": round(average_precision(yv, sv), 3),
             "test_pos": int(y.sum()), "test_windows": int(len(y)), "test_prevalence": round(float(y.mean()), 4),
             "tp": int(((pred == 1) & (y == 1)).sum()), "fn": int(((pred == 0) & (y == 1)).sum()), "fp": int(((pred == 1) & (y == 0)).sum()),
             "test_recall_at_val_thr": round(float(((pred == 1) & (y == 1)).sum() / y.sum()), 3),
             "test_pr_auc": round(average_precision(y, s), 3), "test_roc_auc": round(roc_auc(y, s), 3),
             "pos_score_median": float(np.median(s[y == 1])), "neg_score_p99": float(np.quantile(s[y == 0], 0.99)),
             "neg_score_p999": float(np.quantile(s[y == 0], 0.999))}
        for f in (1e-4, 1e-3, 1e-2):
            rc, _ = recall_at_fpr(y, s, f)
            r[f"recall_at_fpr_{f:g}"] = round(rc, 3)
        rows.append(r)
        pos = te[te["label"] == 1].copy()
        pos["caught"] = (pos["probability"] >= thr).astype(int)
        g = pos.groupby("hostname").agg(positive_windows=("label", "size"), caught=("caught", "sum"),
                                         median_prob=("probability", "median"), max_prob=("probability", "max")).reset_index()
        g.insert(0, "run", run)
        hostrows.append(g)
    pd.DataFrame(rows).to_csv(OUT + "/unseen_beacon_summary.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    pd.concat(hostrows).to_csv(OUT + "/unseen_beacon_per_host.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 40)
    print(pd.DataFrame(rows).T.to_string())
    h = pd.concat(hostrows)
    print(h.groupby("run").agg(hosts=("hostname", "count"), hosts_caught_ge1=("caught", lambda s: int((s > 0).sum())),
                               pos=("positive_windows", "sum"), caught=("caught", "sum")).to_string())


if __name__ == "__main__":
    main()
