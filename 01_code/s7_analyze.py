#!/usr/bin/env python3
"""S7 - PHÂN TÍCH KẾT QUẢ train (sau khi chạy Kaggle): giải nén zip kết quả, tính chỉ số TEST tại ngưỡng chọn trên VAL, tổng và theo scenario.

Input : output_kaggle/bilstm_v2.zip, output_kaggle/mixed_v2.zip (hoặc --bilstm / --mixed), S4_shards/data/samples.csv, S2_windows_split/data/windows.csv
Output: 02_artifacts/22_v2_pipeline/S7_results/{results.json, per_scenario.csv, test_positive_samples.csv, STEP_S7_RESULTS.md}; mô hình giải nén ở 05_models/v2_final/<run>/
TEST chỉ được đọc để TÍNH chỉ số tại ngưỡng đã chốt trên VAL; không dùng để chọn gì.
"""
import argparse
import json
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
OUT = V2 / "S7_results"


def metrics_at(y, p, thr):
    pred = (p >= thr).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"threshold": float(thr), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4), "fpr": round(fp / (fp + tn), 6) if fp + tn else None,
            "pr_auc": round(float(average_precision_score(y, p)), 4) if y.sum() else None, "roc_auc": round(float(roc_auc_score(y, p)), 4) if 0 < y.sum() < len(y) else None}


def load_run(zpath, name):
    dest = ROOT / "05_models/v2_final" / name
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zpath) as zf:
        zf.extractall(dest)
    base = dest if (dest / "threshold.json").exists() else next(p.parent for p in dest.rglob("threshold.json"))
    thr = json.load(open(base / "threshold.json", encoding="utf-8"))["threshold"]
    return base, thr, pd.read_csv(base / "val_predictions.csv"), pd.read_csv(base / "test_predictions.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bilstm", default=str(ROOT / "output_kaggle/bilstm_v2.zip"))
    ap.add_argument("--mixed", default=str(ROOT / "output_kaggle/mixed_v2.zip"))
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    sm = pd.read_csv(V2 / "S4_shards/data/samples.csv")
    w = pd.read_csv(V2 / "S2_windows_split/data/windows.csv")[["hostname", "window_start_epoch", "scenario"]]
    sm = sm.merge(w, on=["hostname", "window_start_epoch"], how="left")
    res, tp_rows, per = {}, [], []
    for name, zp in (("bilstm_v2", a.bilstm), ("mixed_v2", a.mixed)):
        if not Path(zp).exists():
            print("bỏ qua (chưa có):", zp)
            continue
        base, thr, val, test = load_run(zp, name)
        t = test.merge(sm[["sample_id", "hostname", "window_start_epoch", "window_start_utc", "chunk_index", "scenario", "event_count"]], on="sample_id", how="left")
        y, p = t.label.to_numpy(), t.probability.to_numpy()
        res[name] = {"threshold_from_val": float(thr), "test_overall": metrics_at(y, p, thr), "val_overall": metrics_at(val.label.to_numpy(), val.probability.to_numpy(), thr)}
        for sc in ("scenario_1", "scenario_2", "scenario_3"):
            g = t[(t.label == 1) & (t.scenario == sc)]
            per.append({"model": name, "scenario": sc, "test_positive_samples": int(len(g)), "detected": int((g.probability >= thr).sum()),
                        "recall": round(float((g.probability >= thr).mean()), 4) if len(g) else None,
                        "median_score": float(g.probability.median()) if len(g) else None})
        tp_rows.append(t[t.label == 1].assign(model=name, threshold=thr, detected=lambda d: (d.probability >= thr).astype(int)))
    json.dump(res, open(OUT / "results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    pd.DataFrame(per).to_csv(OUT / "per_scenario.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    if tp_rows:
        pd.concat(tp_rows).sort_values(["scenario", "hostname", "window_start_epoch", "model"]).to_csv(OUT / "test_positive_samples.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print(json.dumps(res, ensure_ascii=False, indent=1))
    print(pd.DataFrame(per).to_string(index=False))


if __name__ == "__main__":
    main()
