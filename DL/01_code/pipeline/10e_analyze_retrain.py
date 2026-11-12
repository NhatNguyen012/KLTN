"""STEP 10E — Phan tich ket qua retrain (4 run / seed: {BiLSTM, Mixed-Type} x {full, noapp}).

Chi doc: predictions/metrics/config cua model + manifest/shards cua dataset. Khong train, khong sua artifact cu.
Metric tinh lai tu *_predictions.csv bang numpy (may local khong co sklearn) va doi chieu voi metrics.json.

    python 10e_analyze_retrain.py --project-root D:\\UIT\\KLTNv2 --seed 1
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

RUNS = {
    "bilstm_full": "bilstm_v2_full_seed{k}",
    "bilstm_noapp": "bilstm_v2_noapp_seed{k}",
    "mixed_full": "mixed_v2_full_seed{k}",
    "mixed_noapp": "mixed_v2_noapp_seed{k}",
}


# ------------------------------------------------------------------ metrics (numpy)
def average_precision(y: np.ndarray, s: np.ndarray) -> float:
    order = np.argsort(-s, kind="mergesort")
    y, s = y[order], s[order]
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    last = np.r_[np.where(np.diff(s))[0], len(s) - 1]  # cuoi moi nhom diem bang nhau
    tp, fp = tp[last], fp[last]
    prec = tp / (tp + fp)
    rec = tp / y.sum()
    rec_prev = np.r_[0.0, rec[:-1]]
    return float(np.sum((rec - rec_prev) * prec))


def roc_auc(y: np.ndarray, s: np.ndarray) -> float:
    order = np.argsort(s, kind="mergesort")
    s_sorted = s[order]
    ranks = np.empty(len(s))
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s_sorted[j + 1] == s_sorted[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    n_pos = y.sum()
    n_neg = len(y) - n_pos
    return float((ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def confusion(y: np.ndarray, pred: np.ndarray) -> dict[str, Any]:
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f1}


def best_f1_threshold(y: np.ndarray, s: np.ndarray) -> float:
    cands = np.unique(s)
    best, best_t = -1.0, 1.0
    for t in cands:
        f = confusion(y, (s >= t).astype(int))["f1"]
        if f > best:
            best, best_t = f, float(t)
    return best_t


def recall_at_fp(y: np.ndarray, s: np.ndarray, max_fp: int) -> float:
    """Chan doan (oracle tren chinh tap nay, KHONG dung de chon threshold): recall khi cho phep <= max_fp FP window."""
    neg_sorted = np.sort(s[y == 0])[::-1]
    thr = neg_sorted[max_fp] if max_fp < len(neg_sorted) else -np.inf  # score > thr de co <= max_fp FP
    return float(((s > thr) & (y == 1)).sum() / y.sum())


# ------------------------------------------------------------------ io
def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_manifest(dataset: Path) -> dict[str, dict[str, Any]]:
    host_scen: dict[str, str] = {}
    for r in read_csv(dataset / "split" / "host_split_frozen.csv"):
        host_scen[r["hostname"]] = r["gt_primary_scenario"] or ""
    out = {}
    for r in read_csv(dataset / "split" / "network_sample_manifest.csv"):
        out[r["sample_id"]] = {
            "split": r["split"], "host": r["hostname"], "scenario": host_scen.get(r["hostname"], ""),
            "label": int(r["label"]), "event_count": int(r["event_count"]),
            "app_node_count": int(r["app_node_count"]), "remote_node_count": int(r["remote_node_count"]),
            "chunk_index": int(r["chunk_index"]), "shard_file": r["shard_file"],
            "idx": int(r["shard_sample_index"]), "date": r["date"],
        }
    return out


def load_preds(path: Path, manifest: dict[str, dict[str, Any]], split: str) -> dict[str, np.ndarray]:
    rows = read_csv(path)
    ids = [r["sample_id"] for r in rows]
    for i in ids:
        if manifest[i]["split"] != split:
            raise RuntimeError(f"{path.name}: sample {i} khong thuoc split {split}")
    return {
        "ids": np.array(ids),
        "y": np.array([int(r["label"]) for r in rows]),
        "s": np.array([float(r["probability"]) for r in rows]),
        "pred": np.array([int(r["prediction"]) for r in rows]),
        "host": np.array([manifest[i]["host"] for i in ids]),
        "scenario": np.array([manifest[i]["scenario"] for i in ids]),
    }


def powershell_flags(dataset: Path, manifest: dict[str, dict[str, Any]], ids: np.ndarray, ps_id: int) -> np.ndarray:
    by_shard: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for pos, sid in enumerate(ids):
        m = manifest[sid]
        by_shard[m["shard_file"]].append((pos, m["idx"]))
    flags = np.zeros(len(ids), dtype=int)
    for shard, items in by_shard.items():
        with np.load(dataset / shard, allow_pickle=False) as z:
            off, xc = z["sample_offsets"], z["x_cat"][:, 0]
            for pos, i in items:
                flags[pos] = int((xc[int(off[i]):int(off[i + 1])] == ps_id).any())
    return flags


# ------------------------------------------------------------------ B2-lite: cay quyet dinh depth 3 (numpy)
def fit_tree(X: np.ndarray, y: np.ndarray, w: np.ndarray, depth: int = 3, min_leaf: int = 20):
    def gini(pw, tw):
        p = pw / tw if tw > 0 else 0
        return 2 * p * (1 - p)

    def build(idx, d):
        pw = float(w[idx][y[idx] == 1].sum())
        tw = float(w[idx].sum())
        node = {"p": pw / tw if tw else 0.0}
        if d == 0 or len(idx) < 2 * min_leaf or pw == 0 or pw == tw:
            return node
        best = None
        for f in range(X.shape[1]):
            col = X[idx, f]
            order = np.argsort(col, kind="mergesort")
            c, yy, ww = col[order], y[idx][order], w[idx][order]
            cum_t, cum_p = np.cumsum(ww), np.cumsum(ww * yy)
            valid = np.where((np.diff(c) > 0))[0]
            valid = valid[(valid + 1 >= min_leaf) & (len(c) - valid - 1 >= min_leaf)]
            if len(valid) == 0:
                continue
            if len(valid) > 200:
                valid = valid[np.linspace(0, len(valid) - 1, 200).astype(int)]
            for k in valid:
                lw, lp = cum_t[k], cum_p[k]
                rw, rp = tw - lw, pw - lp
                imp = (lw * gini(lp, lw) + rw * gini(rp, rw)) / tw
                if best is None or imp < best[0]:
                    best = (imp, f, (c[k] + c[k + 1]) / 2)
        if best is None:
            return node
        _, f, t = best
        left = idx[X[idx, f] <= t]
        right = idx[X[idx, f] > t]
        node.update({"f": f, "t": float(t), "l": build(left, d - 1), "r": build(right, d - 1)})
        return node

    return build(np.arange(len(y)), depth)


def predict_tree(node, X: np.ndarray) -> np.ndarray:
    out = np.empty(len(X))
    for i, x in enumerate(X):
        n = node
        while "f" in n:
            n = n["l"] if x[n["f"]] <= n["t"] else n["r"]
        out[i] = n["p"]
    return out


# ------------------------------------------------------------------ analysis
def eval_run(name: str, dpath: Path, manifest, threshold_from_json: float) -> dict[str, Any]:
    val = load_preds(dpath / "val_predictions.csv", manifest, "val")
    test = load_preds(dpath / "test_predictions.csv", manifest, "test")
    metrics = json.loads((dpath / "metrics.json").read_text(encoding="utf-8"))
    config = json.loads((dpath / "config.json").read_text(encoding="utf-8"))
    thr = float(json.loads((dpath / "threshold.json").read_text(encoding="utf-8"))["threshold"])

    res: dict[str, Any] = {"run": name, "drop_app_family": config.get("drop_app_family"), "threshold": thr,
                           "best_epoch": metrics["best_epoch"], "trainable_parameters": config.get("trainable_parameters")}

    for split, d in (("val", val), ("test", test)):
        pred = (d["s"] >= thr).astype(int)
        c = confusion(d["y"], pred)
        c["pr_auc"] = average_precision(d["y"], d["s"])
        c["roc_auc"] = roc_auc(d["y"], d["s"])
        # doi chieu voi metrics.json (provenance)
        ref = metrics[split]
        c["matches_metrics_json"] = bool(
            c["tp"] == ref["tp"] and c["fp"] == ref["fp"] and c["fn"] == ref["fn"]
            and abs(c["pr_auc"] - ref["pr_auc"]) < 1e-6 and abs(c["roc_auc"] - ref["roc_auc"]) < 1e-6)
        c["pred_csv_matches_threshold"] = bool((pred == d["pred"]).all())
        res[split] = c

    # per-host / per-scenario tren TEST
    pred = (test["s"] >= thr).astype(int)
    hosts = {}
    for h in sorted(set(test["host"][test["y"] == 1]) | set(test["host"][(pred == 1)])):
        m = test["host"] == h
        pos = int(test["y"][m].sum())
        tp = int(((pred == 1) & (test["y"] == 1) & m).sum())
        fp = int(((pred == 1) & (test["y"] == 0) & m).sum())
        hosts[h] = {"scenario": str(test["scenario"][m][0]), "positive_windows": pos, "tp": tp, "fp": fp,
                    "recall": (tp / pos) if pos else None}
    res["test_hosts"] = hosts
    pos_hosts = {h: v for h, v in hosts.items() if v["positive_windows"] > 0}
    res["test_host_level"] = {
        "positive_hosts": len(pos_hosts),
        "hosts_detected": sum(1 for v in pos_hosts.values() if v["tp"] > 0),
        "macro_recall_over_positive_hosts": float(np.mean([v["recall"] for v in pos_hosts.values()])),
        "false_positive_hosts": sum(1 for v in hosts.values() if v["positive_windows"] == 0 and v["fp"] > 0),
    }
    scen = {}
    for sc in sorted(set(test["scenario"][test["y"] == 1])):
        m = (test["scenario"] == sc) & (test["y"] == 1)
        scen[sc] = {"positive_windows": int(m.sum()), "tp": int((pred[m] == 1).sum())}
    res["test_scenarios"] = scen

    # do mong cua threshold / margin diem so
    vpos = val["s"][val["y"] == 1]
    vneg = val["s"][val["y"] == 0]
    tpos = test["s"][test["y"] == 1]
    tneg = test["s"][test["y"] == 0]
    res["scores"] = {
        "val_min_positive": float(vpos.min()), "val_max_negative": float(vneg.max()), "threshold": thr,
        "val_threshold_equals_min_positive": bool(abs(thr - vpos.min()) < 1e-12),
        "test_min_positive": float(tpos.min()), "test_max_negative": float(tneg.max()),
        "test_recall_at_fp0": recall_at_fp(test["y"], test["s"], 0),
        "test_recall_at_fp1": recall_at_fp(test["y"], test["s"], 1),
        "test_recall_at_fp5": recall_at_fp(test["y"], test["s"], 5),
        "test_recall_at_fp20": recall_at_fp(test["y"], test["s"], 20),
    }
    # cua so bi bo sot
    miss = np.where((pred == 0) & (test["y"] == 1))[0]
    res["test_missed_windows"] = [
        {"sample_id": str(test["ids"][i]), "host": str(test["host"][i]), "score": float(test["s"][i]),
         "negatives_scoring_above": int((tneg >= test["s"][i]).sum())} for i in miss]

    # training dynamics
    hist = read_csv(dpath / "history.csv")
    pr = [float(r["val_pr_auc"]) for r in hist]
    res["history"] = {"epochs_run": len(hist), "val_pr_auc": pr, "train_loss": [float(r["train_loss"]) for r in hist],
                      "val_pr_auc_range": [min(pr), max(pr)],
                      "best_epoch_is_last": metrics["best_epoch"] == len(hist),
                      "seconds_per_epoch": float(np.mean([float(r["elapsed_seconds"]) for r in hist]))}
    res["_test"] = {"ids": test["ids"], "y": test["y"], "s": test["s"], "host": test["host"], "pred": pred}
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--seed", type=int, default=1, help="seed cua split (suffix _seed{k})")
    ap.add_argument("--models-dir", default=None)
    ap.add_argument("--dataset-dir", default=None)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    root = Path(args.project_root)
    k = args.seed
    models = Path(args.models_dir) if args.models_dir else root / "05_models" / f"10_random_seed{k}_v1"
    dataset = Path(args.dataset_dir) if args.dataset_dir else root / "03_datasets" / "random_network_dl_v1_1_15m" / f"seed_{k}"
    out = Path(args.out_dir) if args.out_dir else root / "02_artifacts" / "10e_retrain_analysis_v1" / f"seed_{k}"
    if out.exists():
        raise FileExistsError(f"{out} da ton tai; khong ghi de")
    out.mkdir(parents=True)

    manifest = load_manifest(dataset)
    maps = json.loads((dataset / "preprocessing" / "network_category_maps.json").read_text(encoding="utf-8"))
    ps_id = int(maps["fields"]["app_family"]["mapping"]["powershell.exe"])

    results = {}
    for name, pat in RUNS.items():
        results[name] = eval_run(name, models / pat.format(k=k), manifest, 0.0)

    # ---- baselines (tren cung val/test) ----
    any_run = next(iter(results.values()))
    test_ids = any_run["_test"]["ids"]
    test_y = any_run["_test"]["y"]
    test_host = any_run["_test"]["host"]
    val_rows = read_csv(models / RUNS["bilstm_full"].format(k=k) / "val_predictions.csv")
    val_ids = np.array([r["sample_id"] for r in val_rows])
    val_y = np.array([int(r["label"]) for r in val_rows])

    b1_test = powershell_flags(dataset, manifest, test_ids, ps_id)
    b1_val = powershell_flags(dataset, manifest, val_ids, ps_id)
    baselines: dict[str, Any] = {
        "B1_rule_has_powershell": {"val": confusion(val_y, b1_val), "test": confusion(test_y, b1_test)}}
    b1_pred = b1_test

    # B2-lite: cay quyet dinh depth 3 tren 4 so metadata (fit TRAIN, threshold chon tren VAL)
    def feats(ids):
        return np.array([[manifest[i]["event_count"], manifest[i]["app_node_count"],
                          manifest[i]["remote_node_count"], manifest[i]["chunk_index"]] for i in ids], dtype=float)

    train_ids = np.array([i for i, m in manifest.items() if m["split"] == "train"])
    ytr = np.array([manifest[i]["label"] for i in train_ids])
    w = np.where(ytr == 1, (ytr == 0).sum() / max(1, (ytr == 1).sum()), 1.0)
    tree = fit_tree(feats(train_ids), ytr, w)
    sv, st = predict_tree(tree, feats(val_ids)), predict_tree(tree, feats(test_ids))
    tb = best_f1_threshold(val_y, sv)
    baselines["B2lite_metadata_tree_depth3"] = {
        "threshold_selected_on_val": tb,
        "val": {**confusion(val_y, (sv >= tb).astype(int)), "pr_auc": average_precision(val_y, sv), "roc_auc": roc_auc(val_y, sv)},
        "test": {**confusion(test_y, (st >= tb).astype(int)), "pr_auc": average_precision(test_y, st), "roc_auc": roc_auc(test_y, st)},
        "note": "thay HGB cua STEP 09B (may local khong co sklearn): cay quyet dinh depth 3 tu cai bang numpy, "
                "feature = event_count, app_node_count, remote_node_count, chunk_index",
    }
    # TEST positive host breakdown cho B1
    bh = {}
    for h in sorted(set(test_host[test_y == 1])):
        m = (test_host == h) & (test_y == 1)
        bh[h] = {"positive_windows": int(m.sum()), "b1_tp": int((b1_pred[m] == 1).sum())}
    baselines["B1_rule_has_powershell"]["test_hosts"] = bh

    # ---- so sanh cap doi tren TEST positive windows ----
    caught = {n: (r["_test"]["pred"] == 1) & (r["_test"]["y"] == 1) for n, r in results.items()}
    pos_mask = test_y == 1

    def pair(a: str, b: str) -> dict[str, int]:
        return {"only_" + a: int((caught[a] & ~caught[b] & pos_mask).sum()),
                "only_" + b: int((caught[b] & ~caught[a] & pos_mask).sum()),
                "both": int((caught[a] & caught[b] & pos_mask).sum()),
                "neither": int((~caught[a] & ~caught[b] & pos_mask).sum())}

    pairs = {
        "bilstm: full vs noapp": pair("bilstm_full", "bilstm_noapp"),
        "mixed: full vs noapp": pair("mixed_full", "mixed_noapp"),
        "full: bilstm vs mixed": pair("bilstm_full", "mixed_full"),
        "noapp: bilstm vs mixed": pair("bilstm_noapp", "mixed_noapp"),
    }
    b1_caught = (b1_pred == 1) & pos_mask
    pairs["bilstm_full vs rule B1"] = {"only_model": int((caught["bilstm_full"] & ~b1_caught).sum()),
                                       "only_rule": int((b1_caught & ~caught["bilstm_full"]).sum())}

    # ---- attention audit (mixed) ----
    att = {}
    for n in ("mixed_full", "mixed_noapp"):
        a = json.loads((models / RUNS[n].format(k=k) / "attention_audit.json").read_text(encoding="utf-8"))
        att[n] = {cls: [(x["field"], round(x["mean_attention_received"], 4)) for x in lst[:5]]
                  for cls, lst in a["feature_attention_received"].items()}

    # ---- luu ----
    for r in results.values():
        r.pop("_test")
    summary = {"seed": k, "dataset": str(dataset), "models": str(models), "powershell_id": ps_id,
               "runs": results, "baselines": baselines, "paired_test_positive_windows": pairs, "attention_top5": att}
    (out / "analysis.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")

    # in tom tat
    print(f"{'run':14s} {'thr':>10s} {'TP':>3s} {'FP':>3s} {'FN':>3s} {'P':>6s} {'R':>6s} {'F1':>6s} {'PRAUC':>6s} {'ROC':>7s} hostsDet macroR  match")
    for n, r in results.items():
        t = r["test"]
        h = r["test_host_level"]
        print(f"{n:14s} {r['threshold']:10.4g} {t['tp']:3d} {t['fp']:3d} {t['fn']:3d} {t['precision']:6.3f} {t['recall']:6.3f} "
              f"{t['f1']:6.3f} {t['pr_auc']:6.3f} {t['roc_auc']:7.4f} {h['hosts_detected']}/{h['positive_hosts']}      "
              f"{h['macro_recall_over_positive_hosts']:.3f}  {r['val']['matches_metrics_json'] and t['matches_metrics_json']}")
    for n, b in baselines.items():
        t = b["test"]
        print(f"{n:30s} TP={t['tp']} FP={t['fp']} FN={t['fn']} P={t['precision']:.3f} R={t['recall']:.3f} F1={t['f1']:.3f}"
              + (f" PR-AUC={t['pr_auc']:.3f} ROC={t['roc_auc']:.4f}" if "pr_auc" in t else ""))
    print(json.dumps(pairs, indent=1))
    print("[OUT]", out / "analysis.json")


if __name__ == "__main__":
    main()
