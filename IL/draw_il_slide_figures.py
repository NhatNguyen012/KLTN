#!/usr/bin/env python3
"""Slide figures of the final IL models (IL/README.md), in the style of a paper system figure (solid blue
components, dotted groups with green name tabs, red outputs), plus TEST confusion matrices of the deployed models.

  figures/DL_model_overview.png        BiLSTM after step 3 (OpTC -> ATLASv2 -> SL700), main blocks
  figures/ML_model_overview.png        LightGBM residual boosting after step 3, main blocks
  figures/confusion_step3_binary.png   TEST confusion, DL (seed 43) and ML, OpTC / ATLASv2 / SL700
  figures/confusion_step3_stage_dl.png TEST last-stage confusion of the DL stage head (seed 43)
  figures/confusion_ml_old_domains.png ML old domains before vs after step 3 (forgetting)

Confusion counts are read from the run results (never typed in): DL = the deployed seed-43 run, ML = the run
the deployed bundle was built from; ML true negatives = TEST rows - tp - fp - fn (rows from the z1 caches).
Detailed per-layer drawings stay in DL_IL_architecture.png / ML_IL_architecture.png (draw_il_architecture.py).
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import Circle, FancyArrowPatch, Polygon, Rectangle  # noqa: E402

IL = Path(__file__).resolve().parent
OUT = IL / "figures"
DL_RUN = IL / "dataset_2-AInception/output/il_step3v3_20261113/runs/bag_freeze_replay2_s43/result.json"
ML_DIR = IL / "dataset_2-AInception/output/ml_il_step3_20261113"
ML_RUN = ML_DIR / "runs/incA05_ecar_lx_s1/result.json"

plt.rcParams.update({"font.family": ["Liberation Sans", "DejaVu Sans"]})
BLUE, BLUE_EDGE, SUB = "#4472C4", "#2F528F", "#DCE6F7"
TAB, ALERT, INK = "#70AD47", "#E3211C", "#111111"


# ------------------------------------------------------------------------------------------- drawing helpers
def canvas(w, h):
    fig = plt.figure(figsize=(w * 0.85, h * 0.85), dpi=110)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.set_aspect("equal")
    ax.axis("off")
    return fig, ax


def box(ax, x0, y0, x1, y1, title, sub=None, fs=19):
    ax.add_patch(Rectangle((x0, y0), x1 - x0, y1 - y0, facecolor=BLUE, edgecolor=BLUE_EDGE, lw=1.6, zorder=3))
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    if sub:
        ax.text(cx, cy + 0.25, title, ha="center", va="center", color="white", fontsize=fs, zorder=4)
        ax.text(cx, cy - 0.36, sub, ha="center", va="center", color=SUB, fontsize=fs - 5.5, zorder=4)
    else:
        ax.text(cx, cy, title, ha="center", va="center", color="white", fontsize=fs, zorder=4, linespacing=1.15)


def group(ax, x0, y0, x1, y1, label, tab_x=None, fs=17):
    ax.add_patch(Rectangle((x0, y0), x1 - x0, y1 - y0, fill=False, edgecolor=INK, lw=1.8,
                           linestyle=(0, (2.2, 2.2)), zorder=2))
    w = 0.158 * len(label) + 0.8
    cx = tab_x if tab_x is not None else (x0 + x1) / 2
    ax.add_patch(Rectangle((cx - w / 2, y0 - 0.32), w, 0.64, facecolor=TAB, edgecolor=TAB, zorder=5))
    ax.text(cx, y0, label, ha="center", va="center", color="white", fontsize=fs, fontweight="bold", zorder=6)


def arrow(ax, p0, p1, label=None, lpos=None, lha="center", lfs=14, dashed=False):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=24, color=INK, lw=3.0, shrinkA=0,
                                 shrinkB=0, linestyle=(0, (5, 3)) if dashed else "solid", zorder=6))
    if label:
        x, y = lpos if lpos else ((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2 + 0.3)
        ax.text(x, y, label, ha=lha, va="center", fontsize=lfs, style="italic", color=INK, zorder=8,
                bbox=dict(facecolor="white", edgecolor="none", pad=1.2))


def path(ax, pts, label=None, lpos=None, lha="left"):
    for a, b in zip(pts[:-2], pts[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=INK, lw=3.0, solid_capstyle="butt", zorder=6)
    arrow(ax, pts[-2], pts[-1], label=label, lpos=lpos, lha=lha)


def plus(ax, x, y, r=0.42):
    ax.add_patch(Circle((x, y), r, facecolor="white", edgecolor=INK, lw=2.4, zorder=7))
    ax.text(x, y - 0.03, "+", ha="center", va="center", fontsize=24, fontweight="bold", zorder=8)


def document(ax, x, y, caption):
    """A stack of two pages (input data), caption underneath."""
    for dx, dy in ((0.25, 0.25), (0.0, 0.0)):
        ax.add_patch(Polygon([(x + dx, y + dy), (x + dx + 1.3, y + dy), (x + dx + 1.3, y + dy + 1.25),
                              (x + dx + 1.0, y + dy + 1.55), (x + dx, y + dy + 1.55)], closed=True,
                             facecolor="#C9D7F0", edgecolor="#7F9CD3", lw=1.6, zorder=3))
        for k in range(4):
            ax.plot([x + dx + 0.2, x + dx + 1.05], [y + dy + 0.3 + 0.25 * k] * 2, color="#5B7FC4", lw=1.6, zorder=4)
    ax.text(x + 0.78, y - 0.45, caption, ha="center", va="top", fontsize=15, linespacing=1.25)


def red_circle(ax, x, y, r, text, fs=17):
    ax.add_patch(Circle((x, y), r, facecolor=ALERT, edgecolor="#A8140F", lw=1.6, zorder=3))
    ax.text(x, y, text, ha="center", va="center", color="white", fontsize=fs, zorder=4, linespacing=1.2)


# ------------------------------------------------------------------------------------------- DL overview
def dl_overview():
    W, H = 30.0, 14.6
    fig, ax = canvas(W, H)
    document(ax, 0.35, 11.05, "180-s window\n≤ 512 events")
    ya0, ya1 = 10.95, 12.65
    group(ax, 2.85, 10.35, 21.1, 13.25, "OpTC base model (step 1)", tab_x=6.6)
    box(ax, 3.1, ya0, 6.9, ya1, "Ext. Embedding ×4", "OpTC contract + Δt")
    box(ax, 7.4, ya0, 11.2, ya1, "Event Encoder", "Linear 35→64 · LayerNorm")
    plus(ax, 12.0, 11.8)
    box(ax, 12.8, ya0, 16.2, ya1, "BiLSTM-1", "64 → 2×64")
    box(ax, 16.7, ya0, 20.85, ya1, "Classifier", "logit z_old")
    arrow(ax, (2.25, 11.8), (3.1, 11.8))
    arrow(ax, (6.9, 11.8), (7.4, 11.8))
    arrow(ax, (11.2, 11.8), (11.58, 11.8))
    arrow(ax, (12.42, 11.8), (12.8, 11.8))
    arrow(ax, (16.2, 11.8), (16.7, 11.8))
    plus(ax, 22.15, 11.8)
    arrow(ax, (20.85, 11.8), (21.73, 11.8))
    red_circle(ax, 25.3, 11.8, 1.7, "Window\nscore z")
    arrow(ax, (22.57, 11.8), (23.6, 11.8))
    ax.text(25.3, 13.95, "z = z_old + g · max_t e_t ≥ VAL threshold → alert", ha="center", va="center",
            fontsize=15)

    # host context (left) and heads (right)
    group(ax, 0.3, 4.85, 11.2, 9.45, "Host context (step 2 · token bag: step 3)")
    box(ax, 0.55, 7.45, 5.15, 9.0, "Context Embedding ×10", "kind · actor · parent · user …", fs=17)
    box(ax, 0.55, 5.4, 5.15, 6.95, "Linux Token Bag", "EmbeddingBag · step 3", fs=17)
    box(ax, 6.2, 6.3, 10.95, 8.1, "Context Projection", "+ 21 numeric features", fs=18)
    arrow(ax, (5.15, 8.22), (6.2, 7.55))
    arrow(ax, (5.15, 6.18), (6.2, 6.85))
    path(ax, [(10.95, 7.2), (12.0, 7.2), (12.0, 11.38)], label="× has_ctx\n(zero-init)", lpos=(11.85, 9.95),
         lha="right")

    group(ax, 13.15, 4.85, 23.4, 9.45, "Heads (step 2 · Impact class: step 3)", tab_x=18.6)
    box(ax, 13.4, 6.3, 16.6, 8.1, "BiLSTM-2", "128 → 2×64")
    box(ax, 17.6, 7.45, 23.15, 9.0, "Event Head", "logit e_t per event", fs=18)
    box(ax, 17.6, 5.4, 23.15, 6.95, "Stage Head", "IC · ED · LM · EX · Impact", fs=18)
    arrow(ax, (14.5, ya0), (14.5, 8.1), label="h_1 … h_T", lpos=(14.65, 9.95), lha="left")
    arrow(ax, (16.6, 7.6), (17.6, 8.22))
    arrow(ax, (16.6, 6.8), (17.6, 6.18))
    path(ax, [(23.15, 8.22), (23.75, 8.22), (23.75, 10.4), (22.15, 10.4), (22.15, 11.38)],
         label="max_t × gate g\n(g = 0 at init)", lpos=(24.0, 9.3))
    red_circle(ax, 26.9, 6.18, 1.45, "Stage per\nevent", fs=16)
    arrow(ax, (23.15, 6.18), (25.45, 6.18))

    # incremental-learning procedure
    yl0, yl1 = 1.3, 3.2
    group(ax, 0.3, 0.75, 29.7, 3.75, "Incremental learning (same procedure in steps 2 and 3)")
    steps = [("Equivalent init", "new rows = <UNK> · gate = 0"), ("Progressive unfreezing", "A → B → C · 20 epochs"),
             ("Replay real data", "OpTC + ATLASv2 every epoch"), ("Loss", "window BCE + 0.5 event + 0.5 stage"),
             ("Model selection", "VAL of all learned domains")]
    x, w, gap = 0.55, 5.18, 0.6
    for i, (t, s) in enumerate(steps):
        box(ax, x, yl0, x + w, yl1, t, s, fs=18)
        if i < len(steps) - 1:
            arrow(ax, (x + w, (yl0 + yl1) / 2), (x + w + gap, (yl0 + yl1) / 2))
        x += w + gap
    ax.text(0.3, 14.2, "282,521 parameters after step 3 · OpTC base: 78,698", ha="left", va="center", fontsize=15,
            color="#444444")
    fig.savefig(OUT / "DL_model_overview.png", dpi=110, facecolor="white")
    plt.close(fig)


# ------------------------------------------------------------------------------------------- ML overview
def ml_overview():
    W, H = 30.0, 14.6
    fig, ax = canvas(W, H)
    document(ax, 0.45, 9.25, "host event\neCAR · CBC\nauditd")
    group(ax, 2.85, 6.55, 15.15, 13.25, "Tokenizer (Base OpTC contract)", tab_x=6.0)
    rows = [(11.35, "eCAR tokens", "action · object · path · cmd"),
            (9.25, "Context tokens", "parent · incoming · has_netconn"),
            (7.15, "Linux tokens lx:", "SL700 events only · step 3")]
    for y, t, s in rows:
        box(ax, 3.1, y, 8.6, y + 1.6, t, s, fs=18)
        arrow(ax, (8.6, y + 0.8), (9.55, 10.05))
    box(ax, 9.55, 9.25, 14.9, 10.85, "Binary vector x", "21,487 columns", fs=19)
    arrow(ax, (2.25, 10.05), (3.1, 12.15))
    arrow(ax, (2.25, 10.05), (3.1, 10.05))
    arrow(ax, (2.25, 10.05), (3.1, 7.95))

    group(ax, 15.95, 6.55, 24.25, 13.25, "Boosters (old ones frozen)", tab_x=20.1)
    boosters = [(11.35, "Booster OpTC", "300 trees · frozen · cols 0–10,316", "× 0.64"),
                (9.25, "Residual Booster ATLASv2", "300 trees · frozen · cols 0–12,364", "× 0.8"),
                (7.15, "Residual Booster SL700", "300 trees · step 3 · all 21,487 cols", "× 1")]
    plus(ax, 25.35, 10.05)
    for y, t, s, wgt in boosters:
        box(ax, 16.2, y, 24.0, y + 1.6, t, s, fs=18)
        arrow(ax, (14.9, 10.05), (16.2, y + 0.8))
        arrow(ax, (24.0, y + 0.8), (24.97, 10.05 + (y + 0.8 - 10.05) * 0.12))
        ax.text(24.5, {11.35: 11.6, 9.25: 10.62, 7.15: 8.5}[y], wgt, ha="left", va="center", fontsize=14,
                style="italic", zorder=8, bbox=dict(facecolor="white", edgecolor="none", pad=1))
    red_circle(ax, 27.95, 10.05, 1.65, "p = σ(z)\n≥ VAL\nthreshold", fs=16)
    arrow(ax, (25.77, 10.05), (26.3, 10.05))
    ax.text(20.1, 13.85, "deployed as one model: z = 0.64 · z_OpTC + 0.8 · z_ATLASv2 + z_SL700 (900 trees)",
            ha="center", va="center", fontsize=15, color="#444444")

    # training of the step-3 residual booster
    group(ax, 0.3, 0.75, 29.7, 5.55, "Training the step-3 residual booster (step 2 is alike)")
    ins = [(3.85, "SL700 TRAIN", "344,271 events · 33,752 attacks"), (2.4, "Replay OpTC", "12,500 pos + 25,000 neg"),
           (0.95 + 0.0, "Replay ATLASv2", "2,244 pos + 35,256 neg")]
    for y, t, s in ins:
        box(ax, 0.55, y + 0.1, 6.25, y + 1.3, t, s, fs=16)
        arrow(ax, (6.25, y + 0.7), (7.05, 3.15))
    box(ax, 7.05, 2.25, 11.9, 4.05, "z1 per row", "frozen step-2 model", fs=18)
    box(ax, 12.85, 3.25, 18.6, 4.95, "Init score", "0.8 · z1 (replay pos: 0.5 · z1)", fs=18)
    box(ax, 12.85, 1.3, 18.6, 3.0, "Sample weight", "×5 hard negatives (σ(z1) > 0.5)", fs=18)
    arrow(ax, (11.9, 3.15), (12.85, 4.1))
    arrow(ax, (11.9, 3.15), (12.85, 2.15))
    box(ax, 19.55, 2.25, 24.1, 4.05, "LightGBM", "300 rounds · lr 0.03 · 31 leaves", fs=18)
    arrow(ax, (18.6, 4.1), (19.55, 3.15))
    arrow(ax, (18.6, 2.15), (19.55, 3.15))
    box(ax, 25.0, 2.25, 29.45, 4.05, "Residual Booster", "VAL threshold · forgetting gate", fs=18)
    arrow(ax, (24.1, 3.15), (25.0, 3.15))
    fig.savefig(OUT / "ML_model_overview.png", dpi=110, facecolor="white")
    plt.close(fig)


# ------------------------------------------------------------------------------------------- confusion matrices
def vn(n):
    return f"{n:,}".replace(",", ".")


def pct(x):
    return f"{100 * x:.2f}%".replace(".", ",")


def f1(cm):
    tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]
    return 2 * tp / (2 * tp + fp + fn)


def draw_cm(ax, cm, labels_true, labels_pred, title, fs=15):
    rows = cm.sum(axis=1, keepdims=True)
    norm = np.divide(cm, rows, out=np.zeros_like(cm, dtype=float), where=rows > 0)
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            dark = norm[i, j] > 0.55
            ax.text(j, i - 0.12, vn(int(cm[i, j])), ha="center", va="center", fontsize=fs + 2, fontweight="bold",
                    color="white" if dark else "#14202E")
            ax.text(j, i + 0.2, pct(norm[i, j]), ha="center", va="center", fontsize=fs - 2,
                    color="white" if dark else "#46505E")
    ax.set_xticks(range(len(labels_pred)), labels_pred, fontsize=fs - 1)
    ax.set_yticks(range(len(labels_true)), labels_true, fontsize=fs - 1)
    ax.set_xlabel("Dự đoán", fontsize=fs - 1)
    ax.set_ylabel("Thực tế", fontsize=fs - 1)
    ax.set_title(title, fontsize=fs + 2, fontweight="bold", pad=10)
    for s in ax.spines.values():
        s.set_visible(False)


def binary_cm(d, n_rows=None):
    tp, fp, fn = d["tp"], d["fp"], d["fn"]
    tn = d["tn"] if "tn" in d else n_rows - tp - fp - fn
    return np.array([[tn, fp], [fn, tp]])


def confusion_figures():
    dl = json.loads(DL_RUN.read_text())["after"]
    ml = json.loads(ML_RUN.read_text())
    n = {d: np.load(ML_DIR / f"cache/z1_{d}_test.npy", mmap_mode="r").shape[0] for d in ("optc", "atlas", "sl700")}
    lab = ["Benign", "Tấn công"]
    panels = [
        ("DL · cửa sổ 180 s (seed 43)", [("OpTC", binary_cm(dl["optc"]["test_at_base_thr"])),
                                         ("ATLASv2", binary_cm(dl["atlas"]["test"])),
                                         ("AInception SL700", binary_cm(dl["sl700"]["test"]))]),
        ("ML · từng sự kiện", [("OpTC", binary_cm(ml["after_step3"]["optc_test"], n["optc"])),
                               ("ATLASv2", binary_cm(ml["after_step3"]["atlas_test"], n["atlas"])),
                               ("AInception SL700", binary_cm(ml["sl700"]["test"], n["sl700"]))]),
    ]
    fig, axes = plt.subplots(2, 3, figsize=(17, 10.4), dpi=130)
    plt.rcParams.update({"font.family": ["DejaVu Sans"]})
    for r, (rowname, cms) in enumerate(panels):
        for c, (dom, cm) in enumerate(cms):
            draw_cm(axes[r, c], cm, lab, lab, f"{dom} · F1 {f1(cm):.3f}".replace("0.", "0,"))
        axes[r, 0].annotate(rowname, xy=(-0.42, 0.5), xycoords="axes fraction", rotation=90, ha="center",
                            va="center", fontsize=18, fontweight="bold", color="#1F5FBF")
    fig.suptitle("Confusion matrix trên TEST sau bước 3 (mô hình đang triển khai)", fontsize=20, fontweight="bold")
    fig.tight_layout(rect=(0.03, 0, 1, 0.95))
    fig.savefig(OUT / "confusion_step3_binary.png", facecolor="white")
    plt.close(fig)

    names = ["benign", "IC", "ED", "LM", "EX", "Impact"]
    fig, axes = plt.subplots(1, 2, figsize=(17, 8.0), dpi=130, gridspec_kw={"width_ratios": [4, 6]})
    for ax, dom, title in ((axes[0], "sl700", "AInception SL700"), (axes[1], "atlas", "ATLASv2")):
        rows = {int(k): v for k, v in dl[dom]["stage"]["last_stage"]["confusion_true_rows"].items()}
        keep_r = [k for k in sorted(rows) if sum(rows[k]) > 0]
        keep_c = [j for j in range(6) if any(rows[k][j] for k in keep_r) or j in keep_r]
        cm = np.array([[rows[k][j] for j in keep_c] for k in keep_r])
        draw_cm(ax, cm, [names[k] for k in keep_r], [names[j] for j in keep_c], title)
    fig.suptitle("Stage cuối của cửa sổ — head stage của DL (TEST, seed 43)", fontsize=20, fontweight="bold")
    fig.text(0.5, 0.012, "IC: initial compromise · ED: execution/discovery · LM: lateral movement · "
             "EX: exfiltration · hàng benign = cửa sổ không có sự kiện tấn công", ha="center", fontsize=13,
             color="#46505E")
    fig.tight_layout(rect=(0, 0.06, 1, 0.94))
    fig.savefig(OUT / "confusion_step3_stage_dl.png", facecolor="white")
    plt.close(fig)

    fig, axes = plt.subplots(2, 2, figsize=(12.5, 10.4), dpi=130)
    for r, (dom, key, name) in enumerate((("atlas", "atlas_test", "ATLASv2"), ("optc", "optc_test", "OpTC"))):
        for c, (when, label) in enumerate((("before_step3", "trước bước 3"), ("after_step3", "sau bước 3"))):
            cm = binary_cm(ml[when][key], n[dom])
            draw_cm(axes[r, c], cm, lab, lab, f"{name} · {label} · F1 {f1(cm):.3f}".replace("0.", "0,"))
    fig.suptitle("ML: miền cũ trước và sau khi học SL700 (TEST)", fontsize=20, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(OUT / "confusion_ml_old_domains.png", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    dl_overview()
    ml_overview()
    confusion_figures()
    for p in sorted(OUT.glob("*.png")):
        print(p.relative_to(IL))
