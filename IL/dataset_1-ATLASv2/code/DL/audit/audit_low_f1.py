#!/usr/bin/env python3
"""Recompute historical metrics, export checkpoint predictions, audit feature collisions.

Never selects a threshold on test. Test predictions are diagnostic on a previously
inspected benchmark, not a fresh generalization estimate.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
import torch
from sklearn.metrics import confusion_matrix, f1_score, average_precision_score

DL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DL / "model"))
from bilstm import BiLSTMBaseline
from dataset import PackedNetworkDataset
from train_local import make_loader
from decision_policy import select_binary_threshold, global_predictions, attack_macro_f1
from research_paths import validate_output_dir


def metrics(y, pred):
    y, pred = np.asarray(y), np.asarray(pred)
    b, p = y > 0, pred > 0
    tp, fp, fn, tn = [int(v) for v in [sum(b & p), sum(~b & p), sum(b & ~p), sum(~b & ~p)]]
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, binary_f1=float(f1_score(b, p, zero_division=0)),
                fpr=fp / max(1, fp + tn), attack_macro_f1=attack_macro_f1(y, pred),
                stage_macro_f1=float(f1_score(y, pred, labels=list(range(5)), average="macro", zero_division=0)),
                confusion_matrix=confusion_matrix(y, pred, labels=list(range(5))).tolist())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=DL / "preprocess/output")
    ap.add_argument("--output-dir", type=Path, default=DL / "output/research_20261111/audit")
    ap.add_argument("--checkpoint", type=Path, default=DL / "output/local_output/local_run_v5/best_model.pt")
    args = ap.parse_args()
    out = validate_output_dir(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    torch.set_num_threads(2)
    result = {"historical": {}, "features": {}, "checkpoints": {}}
    for path in sorted((DL / "output/local_output").glob("*/training_summary.json")):
        d = json.loads(path.read_text())
        items = {}
        for name, v in d.items():
            if isinstance(v, dict) and "confusion_matrix" in v:
                cm = np.asarray(v["confusion_matrix"])
                ys, ps = [], []
                for i in range(5):
                    for j in range(5):
                        ys += [i] * int(cm[i, j]); ps += [j] * int(cm[i, j])
                items[name] = dict(recomputed=metrics(ys, ps), reported_attack_macro_f1=v.get("attack_macro_f1"))
        result["historical"][path.parent.name] = items

    datasets = {s: PackedNetworkDataset(args.data_dir, s, cache_shards=10) for s in ("train", "val", "test")}
    seen = defaultdict(list)
    discrete = defaultdict(list)
    for split, ds in datasets.items():
        stages, lens, unknowns, total = Counter(), [], np.zeros(4, int), 0
        for i, row in enumerate(ds.rows):
            item = ds[i]
            stages[item["stage"]] += 1; lens.append(item["event_count"])
            cats = item["x_cat"]
            unknowns += (cats == 0).sum(axis=0); total += len(cats)
            raw = b"".join(np.ascontiguousarray(item[k]).tobytes() for k in ["x_cat", "x_bin", "delta_t_log1p"])
            seen[hashlib.sha256(raw).hexdigest()].append((split, row["sample_id"], item["stage"]))
            catraw = b"".join(np.ascontiguousarray(item[k]).tobytes() for k in ["x_cat", "x_bin"])
            discrete[hashlib.sha256(catraw).hexdigest()].append((split, row["sample_id"], item["stage"]))
        result["features"][split] = dict(stage_counts=dict(stages), length_quantiles=np.percentile(lens, [0, 25, 50, 90, 100]).tolist(), unknown_fraction=(unknowns/max(1,total)).tolist())
    result["exact_cross_split_duplicates"] = [v for v in seen.values() if len({x[0] for x in v}) > 1]
    result["exact_conflicting_labels"] = [v for v in seen.values() if len({x[2] for x in v}) > 1]
    result["categorical_conflicting_labels"] = [v for v in discrete.values() if len({x[2] for x in v}) > 1]
    maps = json.loads((args.data_dir / "preprocessing/network_category_maps.json").read_text())
    cards = [maps["fields"][f]["size"] for f in ["app_family", "proto", "resp_port_class", "image_dir_class"]]
    # Only v5 has the current attention architecture. Earlier states must not be
    # silently loaded into a different forward function.
    model = BiLSTMBaseline(categorical_cardinalities=cards, num_stages=4)
    ckpt_path = args.checkpoint
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    model.load_state_dict(ckpt["model_state_dict"], strict=True)
    model.eval()
    cache_identity = hashlib.sha256(ckpt_path.read_bytes()
        + (args.data_dir / "split/network_sample_manifest.csv").read_bytes()
        + (DL / "model/bilstm.py").read_bytes()).hexdigest()
    arrays = {}
    for split in ("val", "test"):
        cache = out / f"v5_{split}_predictions.npz"
        if cache.exists():
            with np.load(cache) as z:
                if "cache_identity" in z and str(z["cache_identity"]) == cache_identity:
                    arrays[split] = {k:z[k] for k in z.files}
                    continue
        loader, _ = make_loader(datasets[split], batch_size=64, shuffle=False)
        probs, logits, stages, ids = [], [], [], []
        with torch.no_grad():
            for batch in loader:
                b, s = model(**{k:batch[k] for k in ["x_cat", "x_num", "x_num_missing", "x_bin", "delta_t_log1p", "lengths"]}, return_stage_logits=True)
                probs.extend(b.sigmoid().tolist()); logits.extend(s.tolist())
                stages.extend(batch["stages"].tolist()); ids.extend(batch["sample_ids"])
        arrays[split] = dict(probs=np.array(probs), logits=np.array(logits), stages=np.array(stages), ids=np.array(ids))
        np.savez_compressed(cache, cache_identity=cache_identity, **arrays[split])
        print(f"Predicted {split}: {len(probs)}", flush=True)
    v, t = arrays["val"], arrays["test"]
    threshold = select_binary_threshold(v["stages"] > 0, v["probs"], .02)
    result["checkpoints"]["v5_recalibrated"] = {"threshold":threshold, "precision":"CPU float32; historical reports used CUDA AMP", "checkpoint_sha256":hashlib.sha256(ckpt_path.read_bytes()).hexdigest()}
    for split, a in arrays.items():
        pred = global_predictions(a["probs"], a["logits"], threshold)
        result["checkpoints"]["v5_recalibrated"][split] = metrics(a["stages"], pred)
        result["checkpoints"]["v5_recalibrated"][split]["average_precision"] = float(average_precision_score(a["stages"] > 0, a["probs"]))
        with (out / f"v5_{split}_errors.csv").open("w") as f:
            w = csv.writer(f); w.writerow(["sample_id", "true_stage", "pred_stage", "p_attack", "error_type"])
            for sid, y, p, score in zip(a["ids"], a["stages"], pred, a["probs"]):
                typ = "FP" if y == 0 and p > 0 else "FN" if y > 0 and p == 0 else "stage_error" if y != p else "correct"
                w.writerow([sid, y, p, score, typ])
    temp = out / "audit_summary.json.tmp"
    temp.write_text(json.dumps(result, indent=2)); temp.replace(out / "audit_summary.json")
    print(json.dumps(result["checkpoints"], indent=2), flush=True)


if __name__ == "__main__":
    main()
