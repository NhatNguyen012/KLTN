"""STEP 10F — Gop ket qua 3 seed (split) tu analysis.json cua STEP 10E: mean +- std, so sanh cap theo seed.

Chi doc; std la do lech chuan mau (ddof=1) tren n seed -> chi mang tinh mo ta (n nho), KHONG phai kiem dinh y nghia.

    python 10f_aggregate_seeds.py --project-root D:\\UIT\\KLTNv2 --seeds 1 2 3
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

RUNS = ["bilstm_full", "bilstm_noapp", "mixed_full", "mixed_noapp"]
METRICS = ["precision", "recall", "f1", "pr_auc", "roc_auc", "tp", "fp", "fn"]


def ms(x):
    a = np.array(x, dtype=float)
    return float(a.mean()), float(a.std(ddof=1)) if len(a) > 1 else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    args = ap.parse_args()
    root = Path(args.project_root) / "02_artifacts" / "10e_retrain_analysis_v1"
    out = root / "aggregate"
    if out.exists():
        raise FileExistsError(f"{out} da ton tai; khong ghi de")
    out.mkdir()

    A = {k: json.loads((root / f"seed_{k}" / "analysis.json").read_text(encoding="utf-8")) for k in args.seeds}
    res: dict = {"seeds": args.seeds, "per_seed": {}, "mean_std": {}, "paired": {}, "scenario_windows": {}}

    def pick(k, run):
        r = A[k]["runs"][run]
        t = r["test"]
        h = r["test_host_level"]
        sc = r["test_scenarios"]
        d = {m: t[m] for m in METRICS}
        d["hosts_detected"] = h["hosts_detected"]
        d["positive_hosts"] = h["positive_hosts"]
        d["macro_recall_hosts"] = h["macro_recall_over_positive_hosts"]
        d["fp_hosts"] = h["false_positive_hosts"]
        d["positive_windows"] = t["tp"] + t["fn"]
        for s in ("scenario_1", "scenario_2", "scenario_3"):
            d[f"{s}_tp"] = sc.get(s, {}).get("tp", 0)
            d[f"{s}_pos"] = sc.get(s, {}).get("positive_windows", 0)
        d["best_epoch"] = r["best_epoch"]
        d["epochs_run"] = r["history"]["epochs_run"]
        d["threshold"] = r["threshold"]
        d["val_f1"] = r["val"]["f1"]
        d["val_pr_auc"] = r["val"]["pr_auc"]
        return d

    for k in args.seeds:
        res["per_seed"][k] = {run: pick(k, run) for run in RUNS}
        b1 = A[k]["baselines"]["B1_rule_has_powershell"]["test"]
        b2 = A[k]["baselines"]["B2lite_metadata_tree_depth3"]["test"]
        res["per_seed"][k]["B1"] = {m: b1[m] for m in ("precision", "recall", "f1", "tp", "fp", "fn")}
        res["per_seed"][k]["B2lite"] = {m: b2[m] for m in ("precision", "recall", "f1", "pr_auc", "roc_auc", "tp", "fp", "fn")}

    for run in RUNS + ["B1", "B2lite"]:
        keys = res["per_seed"][args.seeds[0]][run].keys()
        res["mean_std"][run] = {}
        for m in keys:
            if m in ("threshold",):
                continue
            res["mean_std"][run][m] = ms([res["per_seed"][k][run][m] for k in args.seeds])

    def delta(a, b, m):
        return [res["per_seed"][k][a][m] - res["per_seed"][k][b][m] for k in args.seeds]

    for name, (a, b) in {
        "bilstm: full - noapp": ("bilstm_full", "bilstm_noapp"),
        "mixed: full - noapp": ("mixed_full", "mixed_noapp"),
        "full: mixed - bilstm": ("mixed_full", "bilstm_full"),
        "noapp: mixed - bilstm": ("mixed_noapp", "bilstm_noapp"),
        "bilstm_full - B1": ("bilstm_full", "B1"),
        "mixed_full - B1": ("mixed_full", "B1"),
        "bilstm_noapp - B1": ("bilstm_noapp", "B1"),
        "mixed_noapp - B1": ("mixed_noapp", "B1"),
    }.items():
        res["paired"][name] = {}
        for m in ("f1", "pr_auc", "roc_auc", "fn", "recall"):
            d = delta(a, b, m) if m in res["per_seed"][args.seeds[0]][b] else None
            if d is None:
                continue
            res["paired"][name][m] = {"per_seed": d, "mean": float(np.mean(d)), "std": float(np.std(d, ddof=1)),
                                      "seeds_positive": int(sum(x > 0 for x in d)), "seeds_negative": int(sum(x < 0 for x in d))}

    # tong window theo scenario gop 3 seed
    for run in RUNS:
        res["scenario_windows"][run] = {
            s: {"tp": int(sum(res["per_seed"][k][run][f"{s}_tp"] for k in args.seeds)),
                "pos": int(sum(res["per_seed"][k][run][f"{s}_pos"] for k in args.seeds))}
            for s in ("scenario_1", "scenario_2", "scenario_3")}
    # SC3 host rieng le theo seed
    (out / "aggregate.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")

    # ---- in ----
    print(f"{'run':14s}" + "".join(f"{m:>16s}" for m in ("F1", "PR-AUC", "ROC-AUC", "FN windows", "hosts det", "macro recall")))
    for run in RUNS + ["B1", "B2lite"]:
        s = res["mean_std"][run]
        def f(m, d=3):
            return f"{s[m][0]:.{d}f}±{s[m][1]:.{d}f}" if m in s else "-"
        print(f"{run:14s}{f('f1'):>16s}{f('pr_auc'):>16s}{f('roc_auc',4):>16s}{f('fn',1):>16s}{f('hosts_detected',1):>16s}{f('macro_recall_hosts'):>16s}")
    print("\nper-seed F1:")
    for run in RUNS + ["B1", "B2lite"]:
        print(f"{run:14s}", [round(res['per_seed'][k][run]['f1'], 3) for k in args.seeds],
              "FN", [res["per_seed"][k][run]["fn"] for k in args.seeds])
    print("\npaired (mean, std, seeds>0 / seeds<0):")
    for name, d in res["paired"].items():
        x = d["f1"]
        y = d["fn"]
        print(f"{name:26s} dF1 {x['mean']:+.3f}±{x['std']:.3f} ({x['seeds_positive']}/{x['seeds_negative']}) per-seed {[round(v,3) for v in x['per_seed']]} | dFN {y['per_seed']}")
    print("\nscenario windows pooled over seeds (tp/pos):")
    for run in RUNS:
        print(run, {s: f"{v['tp']}/{v['pos']}" for s, v in res["scenario_windows"][run].items()})
    print("best epochs:", {run: [res["per_seed"][k][run]["best_epoch"] for k in args.seeds] for run in RUNS})
    print("[OUT]", out / "aggregate.json")


if __name__ == "__main__":
    main()
