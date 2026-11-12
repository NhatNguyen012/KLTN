#!/usr/bin/env python3
"""S9 - PHÂN TÍCH kết quả train phương án B (STEP 23): bỏ field Bro và principal_class; chỉ giữ app_family, proto, resp_port_class, image_dir_class, delta_t.

Input : output_kaggle/bilstm_v2_subsetB.zip, mixed_v2_subsetB.zip; S4_shards/data/samples.csv; S2 windows.csv; S7_results/results.json (bản đầy đủ để so sánh)
Output: 02_artifacts/24_v2_subsetB_results/{results.json, per_scenario.csv, test_positive_samples.csv, diagnostics.json}; mô hình giải nén ở 05_models/v2_subsetB/<run>/
TEST chỉ được dùng để TÍNH chỉ số tại ngưỡng đã chốt trên VAL. Không ghi đè S7_results.
"""
import json
import sys
import zipfile
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
OUT = ROOT / "02_artifacts/24_v2_subsetB_results"
RUNS = {"bilstm_v2_subsetB": ROOT / "output_kaggle/bilstm_v2_subsetB.zip", "mixed_v2_subsetB": ROOT / "output_kaggle/mixed_v2_subsetB.zip"}
FULL = {"bilstm_v2_subsetB": "bilstm_v2", "mixed_v2_subsetB": "mixed_v2"}


def metrics_at(y, p, thr):
    pred = (p >= thr).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"threshold": float(thr), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4),
            "fpr": round(fp / (fp + tn), 6) if fp + tn else None, "pr_auc": round(float(average_precision_score(y, p)), 4) if y.sum() else None,
            "roc_auc": round(float(roc_auc_score(y, p)), 4) if 0 < y.sum() < len(y) else None}


def prf(y, pred):
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


def load_run(name, zpath):
    dest = ROOT / "05_models/v2_subsetB" / name
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zpath) as zf:
        zf.extractall(dest)
    base = dest if (dest / "threshold.json").exists() else next(p.parent for p in dest.rglob("threshold.json"))
    thr = json.load(open(base / "threshold.json", encoding="utf-8"))
    return base, thr, pd.read_csv(base / "val_predictions.csv"), pd.read_csv(base / "test_predictions.csv")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    spec = json.load(open(V2 / "S3_preprocess/data/preprocess_spec.json", encoding="utf-8"))
    cats = spec["model_input_layout"]["x_cat_columns"]
    vid = {f: {e["value"]: e["id"] for e in spec["categorical"]["fields"][f]["vocab"]} for f in cats}
    sm = pd.read_csv(V2 / "S4_shards/data/samples.csv")
    w = pd.read_csv(V2 / "S2_windows_split/data/windows.csv")[["hostname", "window_start_epoch", "scenario"]]
    sm = sm.merge(w, on=["hostname", "window_start_epoch"], how="left")
    test = sm[sm.split == "test"].copy()
    # cờ host theo sample (chỉ app_family/image_dir_class là đầu vào của mô hình B; administrator chỉ để đối chiếu)
    flags = {"powershell": (0, vid["app_family"]["powershell.exe"]), "temp_appdata": (cats.index("image_dir_class"), vid["image_dir_class"]["TEMP_OR_APPDATA"]),
             "administrator": (cats.index("principal_class"), vid["principal_class"]["ADMINISTRATOR"])}
    rows = []
    for fn, g in test.groupby("shard_file"):
        z = np.load(V2 / "S4_shards" / fn)
        off, xc = z["sample_offsets"], z["x_cat"]
        for r in g.itertuples():
            seg = xc[int(off[r.shard_sample_index]):int(off[r.shard_sample_index + 1])]
            rows.append({"sample_id": r.sample_id, **{k: int((seg[:, c] == v).any()) for k, (c, v) in flags.items()}})
    test = test.merge(pd.DataFrame(rows), on="sample_id")
    y = test.label.to_numpy()
    diag = {"rules_on_test": {"co_powershell": prf(y, test.powershell.to_numpy()), "co_powershell_hoac_temp_appdata": prf(y, (test.powershell | test.temp_appdata).to_numpy()),
                              "chi_temp_appdata": prf(y, test.temp_appdata.to_numpy())}}
    pos = test[test.label == 1]
    diag["test_positive_flags"] = {"n": int(len(pos)), "powershell": int(pos.powershell.sum()), "temp_appdata": int(pos.temp_appdata.sum()),
                                   "none_of_powershell_or_temp": int(((pos.powershell + pos.temp_appdata) == 0).sum())}
    neg = test[test.label == 0]
    diag["test_negative_flags"] = {"n": int(len(neg)), "powershell": int(neg.powershell.sum()), "temp_appdata": int(neg.temp_appdata.sum())}
    full_res = json.load(open(V2 / "S7_results/results.json", encoding="utf-8"))
    con = duckdb.connect()
    F = str(V2 / "S1_join/data/flows_joined.parquet").replace("\\", "/")
    res, per, tp_rows = {}, [], []
    for name, zp in RUNS.items():
        if not zp.exists():
            print("chưa có:", zp)
            continue
        base, thr_json, val, tst = load_run(name, zp)
        thr = thr_json["threshold"]
        t = tst.merge(test[["sample_id", "hostname", "window_start_epoch", "window_start_utc", "chunk_index", "scenario", "event_count", "powershell", "temp_appdata", "administrator"]], on="sample_id", how="left")
        assert len(t) == len(tst) == len(test), (len(t), len(tst), len(test))
        yy, p = t.label.to_numpy(), t.probability.to_numpy()
        cfg = json.load(open(base / "config.json", encoding="utf-8"))
        hist = pd.read_csv(base / "history.csv")
        res[name] = {"threshold_from_val": float(thr), "best_epoch": thr_json.get("best_epoch"), "epochs_run": int(len(hist)), "categorical_fields": cfg.get("categorical_fields"),
                     "numerical_fields": cfg.get("numerical_fields"), "trainable_parameters": cfg.get("trainable_parameters"),
                     "test_overall": metrics_at(yy, p, thr), "val_overall": metrics_at(val.label.to_numpy(), val.probability.to_numpy(), thr),
                     "full_v2_for_comparison": {"test_f1": full_res[FULL[name]]["test_overall"]["f1"], "test_recall": full_res[FULL[name]]["test_overall"]["recall"],
                                                "test_precision": full_res[FULL[name]]["test_overall"]["precision"], "test_pr_auc": full_res[FULL[name]]["test_overall"]["pr_auc"],
                                                "tp_fp_fn": [full_res[FULL[name]]["test_overall"][k] for k in ("tp", "fp", "fn")]}}
        for sc in ("scenario_1", "scenario_2", "scenario_3"):
            g = t[(t.label == 1) & (t.scenario == sc)]
            per.append({"model": name, "scenario": sc, "test_positive_samples": int(len(g)), "detected": int((g.probability >= thr).sum()),
                        "recall": round(float((g.probability >= thr).mean()), 4) if len(g) else None, "median_score": float(g.probability.median()) if len(g) else None})
        tp_rows.append(t[t.label == 1].assign(model=name, threshold=thr, detected=lambda d, th=thr: (d.probability >= th).astype(int)))
        pos_p, neg_p = t[t.label == 1].probability, t[t.label == 0].probability
        d = {"threshold": thr, "n_positive_prob_eq_1": int((pos_p >= 1.0).sum()), "n_positive": int(len(pos_p)), "min_positive_prob": float(pos_p.min()), "max_negative_prob": float(neg_p.max()),
             "n_negative_prob_ge_0.5": int((neg_p >= 0.5).sum()), "n_negative_prob_ge_0.01": int((neg_p >= 0.01).sum()), "median_positive_prob": float(pos_p.median()),
             "recall_if_threshold": {str(x): round(float((pos_p >= x).mean()), 4) for x in (0.99, 0.9, 0.5, 0.1, 0.01)},
             "fp_if_threshold": {str(x): int((neg_p >= x).sum()) for x in (0.99, 0.9, 0.5, 0.1, 0.01)}, "history": hist.round(5).to_dict("records"),
             "errors": {"false_negatives": [], "false_positives": []}}
        for kind, sel in (("false_negatives", t[(t.label == 1) & (t.probability < thr)]), ("false_positives", t[(t.label == 0) & (t.probability >= thr)])):
            for r in sel.itertuples():
                fl_ = con.execute(f"""SELECT app_family, image_path, principal, resp_h, resp_p, service, conn_state, count(*) n FROM read_parquet('{F}')
                      WHERE hostname = '{r.hostname}' AND window_start_epoch = {int(r.window_start_epoch)} GROUP BY ALL ORDER BY n DESC LIMIT 5""").df().to_dict("records")
                d["errors"][kind].append({"hostname": r.hostname, "window_utc": r.window_start_utc, "scenario": r.scenario, "probability": float(r.probability), "event_count": int(r.event_count),
                                          "has_powershell": int(r.powershell), "has_temp_appdata": int(r.temp_appdata), "top_flow_groups": fl_})
        ap = base / "attention_audit.json"
        if ap.exists():
            d["attention_audit_feature_attention_received"] = json.load(open(ap, encoding="utf-8")).get("feature_attention_received")
        diag[name] = d
    json.dump(res, open(OUT / "results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(diag, open(OUT / "diagnostics.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    pd.DataFrame(per).to_csv(OUT / "per_scenario.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    if tp_rows:
        pd.concat(tp_rows).sort_values(["scenario", "hostname", "window_start_epoch", "model"]).to_csv(OUT / "test_positive_samples.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print(json.dumps(res, ensure_ascii=False, indent=1))
    print(pd.DataFrame(per).to_string(index=False))
    print(json.dumps({k: v for k, v in diag.items() if k in ("rules_on_test", "test_positive_flags", "test_negative_flags")}, ensure_ascii=False, indent=1))
    for n in RUNS:
        if n in diag:
            dd = diag[n]
            print(n, {k: dd[k] for k in ("n_positive_prob_eq_1", "n_positive", "min_positive_prob", "max_negative_prob", "n_negative_prob_ge_0.5", "n_negative_prob_ge_0.01", "recall_if_threshold", "fp_if_threshold")})
            print(" FN:", json.dumps(dd["errors"]["false_negatives"], ensure_ascii=False, default=str)[:1800])
            print(" FP:", json.dumps(dd["errors"]["false_positives"], ensure_ascii=False, default=str)[:1800])
            print(" attention:", json.dumps(dd.get("attention_audit_feature_attention_received"), ensure_ascii=False)[:1500])


if __name__ == "__main__":
    main()
