#!/usr/bin/env python3
"""Confusion matrices for optc_il runs, from result.json (TEST only).

Per run  -> <run>/confusion_matrix.png
Per setting (sum over seeds) -> <root>/confusion_matrix_<setting>.png
Panels: ATLASv2 binary (v9b labels) | OpTC before (base model) | OpTC after IL | ATLASv2 last stage (5 classes).
Cell colour = share of the true class (row-normalised, sequential blue); text = count and row %.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

SURFACE, INK, INK2 = "#fcfcfb", "#0b0b0b", "#52514e"
RAMP = ["#f3f7fd", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
CMAP = LinearSegmentedColormap.from_list("seq_blue", RAMP)
STAGE_LBL = ["Benign", "Initial\ncompromise", "Execution/\ndiscovery", "Lateral\nmovement", "Exfiltration"]


def binary(m):
    return np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]], dtype=float)


def panels(r):
    return [
        ("ATLASv2 TEST: attack vs benign (v9b)", binary(r["atlas"]["test_v9b_labels"]), ["Benign", "Attack"]),
        ("OpTC TEST before (OpTC base model)", binary(r["optc_test"]["before_base_model_at_base_thr"]), ["Benign", "Attack"]),
        ("OpTC TEST after IL (base threshold)", binary(r["optc_test"]["after_at_base_thr"]), ["Benign", "Attack"]),
        ("ATLASv2 TEST: last attack stage", np.array(r["atlas"]["stage"]["last_stage"]["confusion_true_rows_0to4"], float), STAGE_LBL),
    ]


def draw(ax, title, cm, labels):
    rows = cm.sum(1, keepdims=True)
    share = np.divide(cm, rows, out=np.zeros_like(cm), where=rows > 0)
    n = len(labels)
    ax.pcolormesh(share, cmap=CMAP, vmin=0, vmax=1, edgecolors=SURFACE, linewidth=2)
    ax.set_xlim(0, n); ax.set_ylim(n, 0); ax.set_aspect("equal")
    fs = 10 if n == 2 else 8
    for i in range(n):
        for j in range(n):
            if rows[i, 0] == 0:
                txt = "–"
            else:
                c = int(round(cm[i, j]))
                txt = f"{c:,}\n{share[i, j] * 100:.0f}%"
            ax.text(j + 0.5, i + 0.5, txt, ha="center", va="center", fontsize=fs,
                    color="#ffffff" if share[i, j] > 0.55 else INK)
    ax.set_xticks(np.arange(n) + 0.5); ax.set_yticks(np.arange(n) + 0.5)
    ax.set_xticklabels(labels, fontsize=8, color=INK2); ax.set_yticklabels(labels, fontsize=8, color=INK2)
    ax.set_xlabel("Predicted", fontsize=9, color=INK2); ax.set_ylabel("True", fontsize=9, color=INK2)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title(title, fontsize=10, color=INK, loc="left")


def figure(results, title, path):
    if len(results) == 1:
        ps = panels(results[0])
    else:  # sum counts over seeds
        ps = [(t, sum(panels(r)[k][1] for r in results), lab) for k, (t, _, lab) in enumerate(panels(results[0]))]
    fig = plt.figure(figsize=(17, 4.6), facecolor=SURFACE)
    gs = fig.add_gridspec(1, 4, width_ratios=[1, 1, 1, 1.9], wspace=0.35)
    for k, (t, cm, lab) in enumerate(ps):
        ax = fig.add_subplot(gs[0, k]); ax.set_facecolor(SURFACE)
        draw(ax, t, cm, lab)
    fig.suptitle(title, x=0.01, ha="left", fontsize=12, color=INK)
    fig.text(0.01, 0.01, "Cell shade = share of the true class (row %). Thresholds chosen on validation; TEST scored once.",
             fontsize=8, color=INK2)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "output/optc_il_20261112/runs")
    by = defaultdict(list)
    for f in sorted(root.glob("*/result.json")):
        r = json.loads(f.read_text())
        name, seed = f.parent.name.rsplit("_s", 1)
        figure([r], f"{name}, seed {seed}", f.parent / "confusion_matrix.png")
        by[name].append(r)
    for name, rs in by.items():
        p = root.parent / f"confusion_matrix_{name}.png"
        figure(rs, f"{name}: sum over {len(rs)} seeds ({', '.join(str(r['args']['seed']) for r in rs)})", p)
        print("wrote", p)


if __name__ == "__main__":
    main()
