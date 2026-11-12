#!/usr/bin/env python3
"""S14f - Tách kết quả fine-tune theo mẫu dương có/không có powershell.exe (STEP 33 Mixed-Type): out-of-fold và khớp TRAIN.

Input : 05_models/v3_finetune/<model>_finetune_seed42/, 03_datasets/v3_ft_kaggle_upload, sample_features STEP 26/29
Output: 02_artifacts/33_finetune_results_v1/ps_breakdown_<model>.json
Cách dùng: python s14_mixed_ps_breakdown.py mixed"""
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
import s14_collect as C  # noqa: E402

ROOT, FT, OUT = C.ROOT, C.FT, C.OUT


def main():
    import torch
    import s14_ft_train as T
    from s8_notebooks_subset import extract_files
    kind = sys.argv[1] if len(sys.argv) > 1 else "mixed"
    run = ROOT / f"05_models/v3_finetune/{kind}_finetune_seed42"
    thr = float(json.load(open(FT / "base_models" / kind / "threshold.json", encoding="utf-8"))["threshold"])
    feats = pd.concat([pd.read_csv(p)[["sample_id", "has_powershell"]] for p in C.FEATS.values()])
    ps = dict(zip(feats.sample_id, feats.has_powershell))
    res = {"model": kind, "threshold": thr}
    # out-of-fold
    after = pd.concat([pd.read_csv(p) for p in sorted(run.glob(f"predictions_{kind}_fold*_newdomains.csv"))], ignore_index=True)
    after["ps"] = after.sample_id.map(ps)
    pos = after[after.label == 1]
    oof = {}
    for g, d in pos.groupby("ps"):
        oof[f"has_powershell={int(g)}"] = {"n_pos": int(len(d)), "tp_at_optc_val": int((d.probability >= thr).sum()), "tp_at_0.5": int((d.probability >= 0.5).sum()), "max_prob": round(float(d.probability.max()), 4)}
    neg = after[after.label == 0]
    oof["negatives_with_powershell"] = {"n": int(neg.ps.sum()), "fp_at_0.5": int(((neg.probability >= 0.5) & (neg.ps == 1)).sum())}
    res["out_of_fold"] = oof
    # TRAIN
    code = Path(tempfile.mkdtemp(prefix="s14f_code_"))
    nbname = "06e_BiLSTM_Kaggle_v2_subsetB.ipynb" if kind == "bilstm" else "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb"
    d, _ = extract_files(json.load(open(ROOT / "04_notebooks" / nbname, encoding="utf-8")), "c")
    for p in d.iterdir():
        (code / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    cfg = json.load(open(FT / "base_models" / kind / "config.json", encoding="utf-8"))
    folds = pd.read_csv(FT / "folds.csv")
    rows_all = []
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
        pr = T.predict(model, kind, T.materialize(rows), torch.device("cpu"), 64)
        pr["fold_model"] = k
        pr["ps"] = pr.sample_id.map(ps)
        rows_all.append(pr)
    tr = pd.concat(rows_all, ignore_index=True)
    tp = tr[tr.label == 1]
    out = {}
    for g, d in tp.groupby("ps"):
        out[f"has_powershell={int(g)}"] = {"n_pos_instances": int(len(d)), "tp_at_optc_val": int((d.probability >= thr).sum()), "tp_at_0.5": int((d.probability >= 0.5).sum()), "median_prob": round(float(d.probability.median()), 4), "max_prob": round(float(d.probability.max()), 4)}
    tn = tr[tr.label == 0]
    out["negatives_with_powershell"] = {"n_instances": int(tn.ps.sum()), "fp_at_0.5": int(((tn.probability >= 0.5) & (tn.ps == 1)).sum())}
    res["train_fit_by_powershell"] = out
    json.dump(res, open(OUT / f"ps_breakdown_{kind}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
