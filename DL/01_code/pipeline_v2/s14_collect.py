#!/usr/bin/env python3
"""S14e - Gộp và phân tích kết quả fine-tune từ Kaggle (STEP 31): ghép dự đoán out-of-fold của các fold, so với zero-shot, luật token và OpTC TEST trước/sau; kiểm tra mô hình có khớp dữ liệu TRAIN của chính nó không.

Input : 05_models/v3_finetune/<model>_finetune_seed42/ (result_*.json, predictions_*), 03_datasets/v3_ft_kaggle_upload (folds, ref zero-shot, base_models), STEP 26/29 (sample_features)
Output: 02_artifacts/33_finetune_results_v1/results_<model>.json, positives_<model>.csv
Cách dùng: python s14_collect.py bilstm"""
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import beta
from sklearn.metrics import average_precision_score, roc_auc_score

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
ROOT = Path("D:/UIT/KLTNv2")
FT = ROOT / "03_datasets/v3_ft_kaggle_upload"
OUT = ROOT / "02_artifacts/33_finetune_results_v1"
FEATS = {"skrghosh": ROOT / "02_artifacts/26_newdataset_eval_v1/sample_features_skrghosh.csv", "fivedirections": ROOT / "02_artifacts/29_fivedirections_analysis_v1/eval_zeroshot/sample_features_fivedirections.csv"}


def cp(x, n, a=0.05):
    lo = 0.0 if x == 0 else beta.ppf(a / 2, x, n - x + 1)
    hi = 1.0 if x == n else beta.ppf(1 - a / 2, x + 1, n - x)
    return [round(float(lo), 3), round(float(hi), 3)]


def at(y, p, thr):
    pred = p >= thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(2 * pr * rc / (pr + rc), 4) if pr + rc else 0.0}


def auc(y, s):
    return {"pr_auc": round(float(average_precision_score(y, s)), 4), "roc_auc": round(float(roc_auc_score(y, s)), 4), "base_rate": round(float(y.mean()), 4)} if 0 < y.sum() < len(y) else {}


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "bilstm"
    run = ROOT / f"05_models/v3_finetune/{kind}_finetune_seed42"
    OUT.mkdir(parents=True, exist_ok=True)
    thr_val = float(json.load(open(FT / "base_models" / kind / "threshold.json", encoding="utf-8"))["threshold"])
    folds = pd.read_csv(FT / "folds.csv")
    after = pd.concat([pd.read_csv(p) for p in sorted(run.glob(f"predictions_{kind}_fold*_newdomains.csv"))], ignore_index=True)
    ref = pd.concat([pd.read_csv(FT / "ref_zeroshot" / f"predictions_{ds}_{kind}.csv")[["sample_id", "logit", "probability"]].assign(dataset=ds) for ds in ("skrghosh", "fivedirections")])
    ref = ref.rename(columns={"logit": "logit_before", "probability": "prob_before"})
    m = after.rename(columns={"logit": "logit_after", "probability": "prob_after"}).merge(ref[["sample_id", "logit_before", "prob_before"]], on="sample_id")
    assert len(m) == len(after) == len(folds), (len(m), len(after), len(folds))
    res = {"model": kind, "folds_found": sorted(m.fold.unique().tolist()), "optc_threshold": thr_val, "pooled": {}, "by_dataset": {}}
    for name, d in (("pooled", m), *[(ds, m[m.dataset == ds]) for ds in ("skrghosh", "fivedirections")]):
        y = d.label.to_numpy()
        entry = {"n": int(len(d)), "positives": int(y.sum())}
        for tag, col in (("before_zeroshot", "logit_before"), ("after_finetune", "logit_after")):
            pc = "prob_before" if tag.startswith("before") else "prob_after"
            entry[tag] = {"auc": auc(y, d[col].to_numpy()), "at_optc_val": at(y, d[pc].to_numpy(), thr_val), "at_0.5": at(y, d[pc].to_numpy(), 0.5)}
        (res["pooled"] if name == "pooled" else res["by_dataset"]).update({name: entry} if name != "pooled" else entry)
    # chi tiết từng mẫu dương: điểm trước/sau và hạng trong các mẫu âm cùng bộ
    rows = []
    for ds in ("skrghosh", "fivedirections"):
        d = m[m.dataset == ds]
        neg_b, neg_a = d[d.label == 0].logit_before.to_numpy(), d[d.label == 0].logit_after.to_numpy()
        for r in d[d.label == 1].itertuples():
            rows.append({"dataset": ds, "fold": int(r.fold), "sample_id": r.sample_id, "prob_before": round(float(r.prob_before), 5), "prob_after": round(float(r.prob_after), 5),
                         "share_neg_scoring_higher_before": round(float((neg_b > r.logit_before).mean()), 3), "share_neg_scoring_higher_after": round(float((neg_a > r.logit_after).mean()), 3)})
    pos = pd.DataFrame(rows)
    pos.to_csv(OUT / f"positives_{kind}.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    res["positives_summary"] = {"n": int(len(pos)), "median_share_neg_higher_before": float(pos.share_neg_scoring_higher_before.median()), "median_share_neg_higher_after": float(pos.share_neg_scoring_higher_after.median()),
                                "n_in_top10pct_before": int((pos.share_neg_scoring_higher_before <= 0.10).sum()), "n_in_top10pct_after": int((pos.share_neg_scoring_higher_after <= 0.10).sum())}
    # luật token (powershell.exe) trên toàn bộ mẫu hai bộ
    feats = pd.concat([pd.read_csv(p)[["sample_id", "has_powershell", "label"]].assign(dataset=ds) for ds, p in FEATS.items()])
    f = feats.merge(m[["sample_id"]], on="sample_id")
    res["rule_has_powershell_pooled"] = at(f.label.to_numpy(), f.has_powershell.to_numpy().astype(float), 0.5)
    # đếm phát hiện: khoảng tin cậy
    res["detection_ci95"] = {"0_of_%d" % res["pooled"]["positives"]: cp(0, res["pooled"]["positives"])}
    # OpTC TEST trước/sau
    base_pred = pd.read_csv(ROOT / f"05_models/v2_subsetB/{kind}_v2_subsetB/test_predictions.csv")
    yb, pb = base_pred.label.to_numpy(), base_pred.probability.to_numpy()
    optc = {"before": {"at_optc_val": at(yb, pb, thr_val), "at_0.5": at(yb, pb, 0.5)}, "after_by_fold": {}}
    for p in sorted(run.glob(f"predictions_{kind}_fold*_optc_test.csv")):
        k = int(p.stem.split("fold")[1].split("_")[0])
        a = pd.read_csv(p).merge(base_pred[["sample_id", "probability"]].rename(columns={"probability": "prob_base"}), on="sample_id")
        ya, pa = a.label.to_numpy(), a.probability.to_numpy()
        optc["after_by_fold"][k] = {"at_optc_val": at(ya, pa, thr_val), "at_0.5": at(ya, pa, 0.5), "auc": auc(ya, a.logit.to_numpy()), "max_abs_prob_change": round(float((a.probability - a.prob_base).abs().max()), 4),
                                    "n_decision_changes_at_optc_val": int(((a.probability >= thr_val) != (a.prob_base >= thr_val)).sum()), "n_decision_changes_at_0.5": int(((a.probability >= 0.5) != (a.prob_base >= 0.5)).sum())}
    res["optc_test"] = optc
    # kiểm tra khớp dữ liệu TRAIN của chính mô hình (từng fold)
    res["train_fit"] = train_fit(kind, run)
    json.dump(res, open(OUT / f"results_{kind}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: res[k] for k in ("pooled", "positives_summary", "rule_has_powershell_pooled")}, ensure_ascii=False, indent=1)[:6000])
    print(json.dumps(res["by_dataset"], ensure_ascii=False)[:2500])
    print(json.dumps(res["optc_test"], ensure_ascii=False)[:2500])
    print(json.dumps(res["train_fit"], ensure_ascii=False)[:2000])


def train_fit(kind, run):
    import torch
    import s14_ft_train as T
    from s8_notebooks_subset import extract_files
    code = Path(tempfile.mkdtemp(prefix="s14c_code_"))
    nbname = "06e_BiLSTM_Kaggle_v2_subsetB.ipynb" if kind == "bilstm" else "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb"
    nb = json.load(open(ROOT / "04_notebooks" / nbname, encoding="utf-8"))
    d, _ = extract_files(nb, "c")
    for p in d.iterdir():
        (code / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    cfg = json.load(open(FT / "base_models" / kind / "config.json", encoding="utf-8"))
    folds = pd.read_csv(FT / "folds.csv")
    out = {}
    for ck_path in sorted(run.glob(f"model_{kind}_fold*.pt")):
        k = int(ck_path.stem.split("fold")[1])
        ck = torch.load(ck_path, map_location="cpu", weights_only=False)
        model = T.build_model(kind, cfg, ck["cardinalities"], code)
        model.load_state_dict(ck["model_state_dict"])
        rows = []
        for ds in ("skrghosh", "fivedirections"):
            sm = pd.read_csv(FT / f"fold{k}/{ds}/data/samples.csv")[["sample_id", "shard_file", "shard_sample_index"]]
            mm = sm.merge(folds[folds.dataset == ds][["sample_id", "fold", "label"]], on="sample_id")
            mm["root"] = str(FT / f"fold{k}/{ds}")
            rows.append(mm)
        rows = pd.concat(rows, ignore_index=True)
        rows = rows[rows.fold != k].reset_index(drop=True)
        samples = T.materialize(rows)
        pr = T.predict(model, kind, samples, torch.device("cpu"), 64)
        y = pr.label.to_numpy()
        out[k] = {"train_samples": int(len(pr)), "train_positives": int(y.sum()), "at_optc_val": at(y, pr.probability.to_numpy(), float(json.load(open(FT / 'base_models' / kind / 'threshold.json'))['threshold'])),
                  "at_0.5": at(y, pr.probability.to_numpy(), 0.5), "auc": auc(y, pr.logit.to_numpy())}
    return out


if __name__ == "__main__":
    main()
