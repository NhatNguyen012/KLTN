#!/usr/bin/env python3
"""S11 - Suy luận CPU của mô hình B (STEP 24) trên bộ đánh giá skrghosh và AIT (STEP 25); ngưỡng lấy NGUYÊN từ VAL của OpTC (threshold.json), không chọn lại.

Bước 0 (kiểm tra mã suy luận): chạy lại trên một tập con của TEST OpTC (mọi mẫu dương + 600 mẫu âm) và so xác suất từng mẫu với test_predictions.csv do Kaggle sinh ra.
Mô phỏng AMP của Kaggle: logit tính fp32 trên CPU rồi ép về float16 trước sigmoid (xác suất lưu trong CSV Kaggle là giá trị float16, ngưỡng 1.0 của Mixed-Type chỉ có nghĩa ở độ chính xác đó).
Output: 02_artifacts/26_newdataset_eval_v1/{results.json, verification_optc.json, predictions_<dataset>_<model>.csv, sample_features_<dataset>.csv}
Mô hình và dữ liệu chỉ đọc; không train, không chọn ngưỡng trên dữ liệu mới."""
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, roc_auc_score
from torch.utils.data import DataLoader

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
NB = ROOT / "04_notebooks"
V2 = ROOT / "02_artifacts/22_v2_pipeline"
PKG = ROOT / "03_datasets/v2_network_dl_kaggle_upload"
NEW = ROOT / "02_artifacts/25_newdataset_preprocess_v1"
OUT = ROOT / "02_artifacts/26_newdataset_eval_v1"
DIRS = {"skrghosh": NEW / "skrghosh", "ait": NEW / "ait", "theia": ROOT / "02_artifacts/28_theia_analysis_v1/theia", "fivedirections": ROOT / "02_artifacts/29_fivedirections_analysis_v1/fivedirections"}
DATASETS = ["skrghosh", "ait"]
MODELS = {"bilstm": ROOT / "05_models/v2_subsetB/bilstm_v2_subsetB", "mixed": ROOT / "05_models/v2_subsetB/mixed_v2_subsetB"}
NOTEBOOKS = {"bilstm": "06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "mixed": "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb"}
SUBSET = {"x_cat_columns_all": ["app_family", "proto", "service", "conn_state", "resp_port_class", "image_dir_class", "principal_class"],
          "keep_categorical": ["app_family", "proto", "resp_port_class", "image_dir_class"], "drop_numeric": True, "zero_binary": True}
torch.set_num_threads(8)


def extract_code(nbname, tag):
    nb = json.load(open(NB / nbname, encoding="utf-8"))
    d = Path(tempfile.mkdtemp(prefix=f"s11_{tag}_"))
    for c in nb["cells"]:
        src = "".join(c["source"])
        if "WORK_CODE = Path(" in src and "write_text(" in src:
            m = re.search(r"WORK_CODE = Path\('([^']+)'\)", src)
            exec("import sys, os, json\nfrom pathlib import Path\n" + src.replace(m.group(0), f"WORK_CODE = Path(r'{d}')"), {})
            return d
    raise RuntimeError("không thấy cell ghi mã")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def build_models():
    out = {}
    for tag in ("bilstm", "mixed"):
        d = extract_code(NOTEBOOKS[tag], tag)
        sys.path.insert(0, str(d))
        loader_mod = load_module(d / "network_dl_dataset_v1_1.py", "network_dl_dataset_v1_1")
        cfg = json.load(open(MODELS[tag] / "config.json", encoding="utf-8"))
        ck = torch.load(MODELS[tag] / "best_model.pt", map_location="cpu", weights_only=False)
        if tag == "bilstm":
            m = load_module(d / "05b_train_bilstm.py", "train_bilstm")
            model = m.BiLSTMBaseline(categorical_cardinalities=cfg["categorical_cardinalities"], numerical_dim=len(cfg["numerical_fields"]), event_dim=cfg["event_dim"],
                                     hidden_dim=cfg["hidden_dim"], lstm_layers=cfg["lstm_layers"], dropout=cfg["dropout"])
        else:
            m = load_module(d / "mixed_type_attention_model.py", "mixed_model")
            model = m.MixedTypeSelfAttentionClassifier(m.MixedTypeModelConfig(categorical_cardinalities=cfg["categorical_cardinalities"], numerical_dim=len(cfg["numerical_fields"]), binary_dim=1,
                                                                              max_events=cfg["max_events"], d_model=cfg["d_model"], num_heads=cfg["num_heads"], feature_layers=cfg["feature_layers"],
                                                                              temporal_layers=cfg["temporal_layers"], ff_dim=cfg["ff_dim"], dropout=cfg["dropout"]))
        model.load_state_dict(ck["model_state_dict"])
        model.eval()
        thr = json.load(open(MODELS[tag] / "threshold.json", encoding="utf-8"))["threshold"]
        out[tag] = {"model": model, "threshold": float(thr), "loader": loader_mod, "params": sum(p.numel() for p in model.parameters())}
        assert out[tag]["params"] == cfg["trainable_parameters"], (tag, out[tag]["params"], cfg["trainable_parameters"])
    return out


@torch.no_grad()
def predict(tag, bundle, root, split="test", bs=None, log=True):
    L = bundle["loader"]
    ds = L.PackedNetworkDataset(root, split, cache_shards=1)
    assert ds.cat_idx is not None and ds.drop_numeric, "feature_subset.json không được áp dụng"
    sampler = L.ShardAwareBatchSampler(ds, bs or (64 if tag == "bilstm" else 16), shuffle=False)
    loader = DataLoader(ds, batch_sampler=sampler, num_workers=0, collate_fn=L.collate_sequence_batch)
    ids, y, logit = [], [], []
    t0 = time.time()
    for i, b in enumerate(loader, 1):
        kw = dict(x_cat=b["x_cat"], x_num=b["x_num"], x_num_missing=b["x_num_missing"], x_bin=b["x_bin"], delta_t_log1p=b["delta_t_log1p"])
        if tag == "bilstm":
            lg = bundle["model"](lengths=b["lengths"], **kw)
        else:
            lg = bundle["model"](attention_mask=b["attention_mask"], **kw)
        logit.append(lg.float().numpy())
        y.append(b["labels"].numpy())
        ids += b["sample_ids"]
        if log and i % 100 == 0:
            print(f"   {tag} {i}/{len(loader)} lô ({time.time() - t0:.0f}s)", flush=True)
    logit = np.concatenate(logit)
    prob = torch.sigmoid(torch.from_numpy(logit).half()).float().numpy()  # mô phỏng AMP fp16 của Kaggle
    return pd.DataFrame({"sample_id": ids, "label": np.concatenate(y).astype(int), "logit": logit, "probability": prob})


def metrics_at(y, p, thr):
    pred = (p >= thr).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"threshold": float(thr), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4), "fpr": round(fp / (fp + tn), 6) if fp + tn else None}


def rank_metrics(y, s):
    if y.sum() == 0 or y.sum() == len(y):
        return {"pr_auc": None, "roc_auc": None}
    return {"pr_auc": round(float(average_precision_score(y, s)), 4), "roc_auc": round(float(roc_auc_score(y, s)), 4)}


def make_root_for_new(name):
    d = DIRS[name]
    pre = d / "preprocessing"
    pre.mkdir(exist_ok=True)
    (pre / "feature_subset.json").write_text(json.dumps(SUBSET, indent=2), encoding="utf-8")
    return d


def verify_on_optc(models):
    """Chạy lại trên TEST OpTC (mọi mẫu dương + 600 mẫu âm) và so với test_predictions.csv của Kaggle."""
    root = Path(tempfile.mkdtemp(prefix="s11_optc_"))
    for z in ("split", "preprocessing"):
        with zipfile.ZipFile(PKG / f"{z}.zip") as zf:
            zf.extractall(root)
    (root / "preprocessing/feature_subset.json").write_text(json.dumps(SUBSET, indent=2), encoding="utf-8")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "shards"), str(V2 / "S4_shards/shards")], check=True, capture_output=True)
    man = pd.read_csv(root / "split/network_sample_manifest.csv")
    te = man[man.split == "test"]
    pos, neg = te[te.label == 1], te[te.label == 0].sample(600, random_state=7)
    pd.concat([pos, neg]).to_csv(root / "split/network_sample_manifest.csv", index=False)
    res = {}
    for tag, b in models.items():
        t0 = time.time()
        p = predict(tag, b, root, log=False)
        ref = pd.read_csv(MODELS[tag] / "test_predictions.csv")[["sample_id", "probability"]].rename(columns={"probability": "kaggle_probability"})
        m = p.merge(ref, on="sample_id")
        assert len(m) == len(p), "thiếu sample_id"
        d = (m.probability - m.kaggle_probability).abs()
        thr = b["threshold"]
        res[tag] = {"samples": int(len(m)), "max_abs_diff": round(float(d.max()), 5), "mean_abs_diff": round(float(d.mean()), 6), "n_diff_gt_0.01": int((d > 0.01).sum()),
                    "decision_agreement_at_threshold": round(float(((m.probability >= thr) == (m.kaggle_probability >= thr)).mean()), 4),
                    "positives_pred_cpu": int(((m.probability >= thr) & (m.label == 1)).sum()), "positives_pred_kaggle": int(((m.kaggle_probability >= thr) & (m.label == 1)).sum()),
                    "seconds": round(time.time() - t0)}
        print("verify", tag, res[tag], flush=True)
    return res


def main():
    global OUT
    ds_list = sys.argv[1].split(",") if len(sys.argv) > 1 else DATASETS  # python s11_eval_subsetB.py theia <thư mục ra>
    if len(sys.argv) > 2:
        OUT = Path(sys.argv[2])
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    models = build_models()
    ver = verify_on_optc(models)
    json.dump(ver, open(OUT / "verification_optc.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    spec = json.load(open(V2 / "S3_preprocess/data/preprocess_spec.json", encoding="utf-8"))
    app_inv = {e["id"]: e["value"] for e in spec["categorical"]["fields"]["app_family"]["vocab"]}
    app_inv.setdefault(0, "<UNK>")
    app_inv.setdefault(1, "<MISSING>")
    ps_id = {v: k for k, v in app_inv.items()}["powershell.exe"]
    results = {"thresholds_from_optc_val": {t: b["threshold"] for t, b in models.items()}, "verification_optc": ver, "datasets": {}}
    for ds in ds_list:
        root = make_root_for_new(ds)
        sm = pd.read_csv(root / "data/samples.csv")
        # đặc trưng mô tả từng sample (từ shards)
        feats = []
        for fn, g in sm.groupby("shard_file"):
            z = np.load(root / fn)
            off, xc = z["sample_offsets"], z["x_cat"]
            for r in g.itertuples():
                seg = xc[int(off[r.shard_sample_index]):int(off[r.shard_sample_index + 1])]
                a = seg[:, 0]
                vals, cnt = np.unique(a, return_counts=True)
                top = app_inv.get(int(vals[cnt.argmax()]), f"id{int(vals[cnt.argmax()])}")
                feats.append({"sample_id": r.sample_id, "share_app_unk": round(float((a == 0).mean()), 3), "has_powershell": int((a == ps_id).any()), "top_app_id": int(vals[cnt.argmax()]), "top_app": top,
                              "share_proto_unk": round(float((seg[:, 1] == 0).mean()), 3), "share_port_unk": round(float((seg[:, 4] == 0).mean()), 3)})
        fd = pd.DataFrame(feats)
        fd.merge(sm[["sample_id", "hostname", "window_start_utc", "chunk_index", "label", "event_count", "positive_event_count"]], on="sample_id").to_csv(OUT / f"sample_features_{ds}.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
        results["datasets"][ds] = {"samples": int(len(sm)), "positive_samples": int(sm.label.sum()), "flows": int(sm.event_count.sum()), "positive_flows": int(sm.positive_event_count.sum()), "models": {}}
        meta = sm.merge(fd, on="sample_id")
        meta["group"] = meta.hostname
        for tag, b in models.items():
            t1 = time.time()
            p = predict(tag, b, root)
            assert set(p.sample_id) == set(sm.sample_id) and len(p) == len(sm)
            p = p.merge(meta[["sample_id", "hostname", "window_start_utc", "chunk_index", "event_count", "positive_event_count", "share_app_unk", "has_powershell", "top_app", "share_proto_unk", "share_port_unk"]], on="sample_id")
            p.to_csv(OUT / f"predictions_{ds}_{tag}.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
            y, pr, lg = p.label.to_numpy(), p.probability.to_numpy(), p.logit.to_numpy()
            thr = b["threshold"]
            r = {"threshold": thr, "at_frozen_threshold": metrics_at(y, pr, thr), "rank_metrics_by_logit": rank_metrics(y, lg),
                 "score_stats": {"positive_median_prob": float(np.median(pr[y == 1])) if y.sum() else None, "negative_median_prob": float(np.median(pr[y == 0])),
                                 "n_pred_positive": int((pr >= thr).sum()), "max_negative_prob": float(pr[y == 0].max()), "max_positive_prob": float(pr[y == 1].max()) if y.sum() else None,
                                 "n_negative_prob_ge_0.5": int((pr[y == 0] >= 0.5).sum())},
                 "by_group": {}, "seconds": round(time.time() - t1)}
            for gname, g in p.groupby("hostname"):
                yy, pp = g.label.to_numpy(), g.probability.to_numpy()
                r["by_group"][gname] = {"samples": int(len(g)), "positive_samples": int(yy.sum()), "detected": int(((pp >= thr) & (yy == 1)).sum()), "false_positives": int(((pp >= thr) & (yy == 0)).sum())}
            # chẩn đoán KHÔNG dùng để chọn gì: điểm F1 tốt nhất có thể trên chính bộ này (oracle) cho thấy phần lỗi do ngưỡng
            if y.sum():
                best = max((metrics_at(y, pr, t) for t in np.unique(np.r_[pr[y == 1], 1.0])), key=lambda m: m["f1"])
                r["oracle_best_threshold_diagnostic_only"] = best
            results["datasets"][ds]["models"][tag] = r
            print(ds, tag, json.dumps({k: r[k] for k in ("at_frozen_threshold", "rank_metrics_by_logit")}, ensure_ascii=False), f"{r['seconds']}s", flush=True)
        # luật tham chiếu: có powershell.exe (chỉ để đối chiếu)
        yy = meta.label.to_numpy()
        results["datasets"][ds]["rule_has_powershell"] = metrics_at(yy, meta.has_powershell.to_numpy().astype(float), 0.5)
        results["datasets"][ds]["share_app_unk_positive"] = round(float(meta[meta.label == 1].share_app_unk.mean()), 3) if yy.sum() else None
        results["datasets"][ds]["share_app_unk_negative"] = round(float(meta[meta.label == 0].share_app_unk.mean()), 3)
    results["seconds"] = round(time.time() - t0)
    json.dump(results, open(OUT / "results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print("xong", results["seconds"], "s")


if __name__ == "__main__":
    main()
