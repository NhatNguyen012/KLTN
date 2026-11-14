#!/usr/bin/env python3
"""Draw the deployed KLTN IL3 infrastructure (Openstack/KLTN, 14/11/2026) in the style of a paper system figure:
solid blue components, black data-flow arrows, dotted component groups with green name tabs, a green data store,
a red alert output. Output: images/KLTN-IL3-architecture.png (run: python3 images/render_il3_architecture.py).
Every component and number shown here is the deployed one (README.md, sections 1 and 9)."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import (Circle, Ellipse, FancyArrow, FancyArrowPatch, Polygon, Rectangle,  # noqa: E402
                                RegularPolygon)

OUT = Path(__file__).resolve().parent / "KLTN-IL3-architecture.png"
plt.rcParams.update({"font.family": ["Liberation Sans", "DejaVu Sans"]})

BLUE, BLUE_EDGE, SUB = "#4472C4", "#2F528F", "#DCE6F7"
TAB, STORE, ALERT = "#70AD47", "#548235", "#E3211C"
LIGHT, LIGHT_EDGE, INK = "#DAE3F3", "#8FAADC", "#111111"
W, H = 32.0, 14.0


def box(ax, x0, y0, x1, y1, title, sub=None, fs=20):
    ax.add_patch(Rectangle((x0, y0), x1 - x0, y1 - y0, facecolor=BLUE, edgecolor=BLUE_EDGE, lw=1.6, zorder=3))
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    if sub:
        ax.text(cx, cy + 0.26, title, ha="center", va="center", color="white", fontsize=fs, zorder=4)
        ax.text(cx, cy - 0.38, sub, ha="center", va="center", color=SUB, fontsize=fs - 6, zorder=4)
    else:
        ax.text(cx, cy, title, ha="center", va="center", color="white", fontsize=fs, zorder=4, linespacing=1.15)


def group(ax, x0, y0, x1, y1, label, fs=18):
    ax.add_patch(Rectangle((x0, y0), x1 - x0, y1 - y0, fill=False, edgecolor=INK, lw=1.8,
                           linestyle=(0, (2.2, 2.2)), zorder=2))
    w = 0.165 * len(label) + 0.8
    cx = (x0 + x1) / 2
    ax.add_patch(Rectangle((cx - w / 2, y0 - 0.33), w, 0.66, facecolor=TAB, edgecolor=TAB, zorder=5))
    ax.text(cx, y0, label, ha="center", va="center", color="white", fontsize=fs, fontweight="bold", zorder=6)


def arrow(ax, p0, p1, dashed=False, lw=3.2, label=None, lpos=None, lha="center", lfs=15):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=26, color=INK, lw=lw,
                                 linestyle=(0, (5, 3)) if dashed else "solid", shrinkA=0, shrinkB=0, zorder=6))
    if label:
        x, y = lpos if lpos else ((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2 + 0.3)
        ax.text(x, y, label, ha=lha, va="center", fontsize=lfs, style="italic", color=INK, zorder=8,
                bbox=dict(facecolor="white", edgecolor="none", pad=1.5))


def path(ax, pts, dashed=False, lw=3.2):
    """Polyline whose last segment ends in an arrow head."""
    ls = (0, (5, 3)) if dashed else "solid"
    for a, b in zip(pts[:-2], pts[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=INK, lw=lw, linestyle=ls, solid_capstyle="butt", zorder=6)
    arrow(ax, pts[-2], pts[-1], dashed=dashed, lw=lw)


def cylinder(ax, x0, y0, x1, y1, title, sub):
    h, rx = y1 - y0, 0.42
    cy = (y0 + y1) / 2
    ax.add_patch(Ellipse((x0 + rx, cy), 2 * rx, h, facecolor=BLUE, edgecolor=BLUE_EDGE, lw=1.6, zorder=3))
    ax.add_patch(Rectangle((x0 + rx, y0), x1 - x0 - 2 * rx, h, facecolor=BLUE, edgecolor="none", zorder=3))
    ax.plot([x0 + rx, x1 - rx], [y0, y0], color=BLUE_EDGE, lw=1.6, zorder=3)
    ax.plot([x0 + rx, x1 - rx], [y1, y1], color=BLUE_EDGE, lw=1.6, zorder=3)
    ax.add_patch(Ellipse((x1 - rx, cy), 2 * rx, h, facecolor="#5B85D0", edgecolor=BLUE_EDGE, lw=1.6, zorder=3))
    ax.text((x0 + x1) / 2 - 0.2, cy + 0.26, title, ha="center", va="center", color="white", fontsize=20, zorder=4)
    ax.text((x0 + x1) / 2 - 0.2, cy - 0.38, sub, ha="center", va="center", color=SUB, fontsize=14, zorder=4)


def monitor(ax, x, y, kind):
    """A generic host icon: screen + stand; `kind` linux shows a shell prompt, windows four panes."""
    ax.add_patch(Rectangle((x, y + 0.42), 1.75, 1.15, facecolor="#F2F2F2", edgecolor="#404040", lw=2.2, zorder=3))
    ax.add_patch(Polygon([(x + 0.65, y + 0.42), (x + 1.1, y + 0.42), (x + 1.25, y + 0.12), (x + 0.5, y + 0.12)],
                         closed=True, facecolor="#404040", edgecolor="#404040", zorder=3))
    if kind == "linux":
        ax.text(x + 0.875, y + 1.0, ">_", ha="center", va="center", fontsize=24, fontweight="bold",
                family="DejaVu Sans Mono", color="#2E2E2E", zorder=4)
    else:
        for i in (0, 1):
            for j in (0, 1):
                ax.add_patch(Rectangle((x + 0.5 + i * 0.4, y + 0.6 + j * 0.42), 0.34, 0.36, facecolor="#2F7FD8",
                                       edgecolor="none", zorder=4))


def light_arrow(ax, x0, y0, x1, y1):
    ax.add_patch(FancyArrow(x0, y0, x1 - x0, y1 - y0, width=0.32, head_width=0.62, head_length=0.38,
                            length_includes_head=True, facecolor=LIGHT, edgecolor=LIGHT_EDGE, lw=1.6, zorder=3))


def main():
    fig = plt.figure(figsize=(W * 0.85, H * 0.85), dpi=110)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.set_aspect("equal")
    ax.axis("off")

    ax.text(0.3, 13.55, "END HOSTS · OpenStack VMs", fontsize=17, fontweight="bold", color="#5A5A5A", va="center")
    ax.text(15.1, 13.55, "CENTRAL VM · Docker Compose + systemd", fontsize=17, fontweight="bold", color="#5A5A5A",
            va="center")

    # ---- top lane: telemetry -> endpoint agent -> central ingest -> store
    yb0, yb1 = 9.05, 10.85
    monitor(ax, 0.3, 11.05, "linux")
    ax.text(1.18, 10.72, "Ubuntu 24.04 ×2", ha="center", fontsize=15, fontweight="bold", va="center")
    ax.text(1.18, 10.3, "auditd · SL700 rules", ha="center", fontsize=13, va="center")
    monitor(ax, 0.3, 7.75, "windows")
    ax.text(1.18, 7.42, "Windows 11", ha="center", fontsize=15, fontweight="bold", va="center")
    ax.text(1.18, 7.0, "Sysmon v3", ha="center", fontsize=13, va="center")
    light_arrow(ax, 2.15, 11.55, 2.85, 10.45)
    light_arrow(ax, 2.15, 8.35, 2.85, 9.45)
    cylinder(ax, 2.95, yb0, 5.55, yb1, "Fluent Bit", "disk buffer")

    group(ax, 6.1, 8.45, 14.55, 11.45, "Endpoint Agent (each host)")
    box(ax, 6.35, yb0, 8.85, yb1, "Event\nGrouping", fs=19)
    box(ax, 9.3, yb0, 11.8, yb1, "Feature\nExtractor", fs=19)
    box(ax, 12.25, yb0, 14.3, yb1, "LightGBM\n900 trees", fs=19)
    arrow(ax, (5.55, 9.95), (6.35, 9.95))
    arrow(ax, (8.85, 9.95), (9.3, 9.95))
    arrow(ax, (11.8, 9.95), (12.25, 9.95))

    group(ax, 15.4, 8.45, 22.35, 11.45, "Central Ingest")
    box(ax, 15.65, yb0, 18.75, yb1, "Log Receive", "API · TLS · NATS")
    box(ax, 19.2, yb0, 22.1, yb1, "Normalizer", "auditd · Sysmon→CBC")
    arrow(ax, (14.3, 9.95), (15.65, 9.95), label="score +\nselected logs", lpos=(14.98, 8.0), lfs=14)
    arrow(ax, (18.75, 9.95), (19.2, 9.95))
    path(ax, [(4.25, yb1), (4.25, 12.45), (17.2, 12.45), (17.2, yb1)])
    ax.text(10.6, 12.78, "raw logs (TLS, per-host token)", ha="center", fontsize=15, style="italic", va="center")

    ax.add_patch(Circle((24.65, 9.95), 1.62, facecolor=STORE, edgecolor="#3B5E25", lw=1.6, zorder=3))
    ax.text(24.65, 10.55, "PostgreSQL", ha="center", va="center", color="white", fontsize=19, zorder=4)
    ax.text(24.65, 9.75, "raw logs · events\nscores · labels", ha="center", va="center", color="white",
            fontsize=14, zorder=4, linespacing=1.3)
    arrow(ax, (22.1, 9.95), (23.03, 9.95))

    # ---- middle lane: detection & fusion -> alerts
    ym0, ym1 = 5.25, 7.05
    group(ax, 15.4, 4.65, 26.7, 7.65, "Detection & Fusion")
    box(ax, 15.65, ym0, 19.95, ym1, "DL Inference", "IL BiLSTM · 180-s windows")
    box(ax, 20.85, ym0, 26.45, ym1, "Context-Aware Fusion", "noisy-OR · 15-min incidents")
    arrow(ax, (23.35, 8.95), (19.3, ym1), label="host events", lpos=(22.55, 7.98), lfs=14)
    arrow(ax, (25.05, 8.36), (25.05, ym1), label="ML scores", lpos=(25.25, 8.05), lha="left", lfs=14)
    arrow(ax, (19.95, 6.15), (20.85, 6.15))

    ax.add_patch(Rectangle((27.35, 4.65), 4.4, 8.45, fill=False, edgecolor=INK, lw=1.8, linestyle=(0, (2.2, 2.2)),
                           zorder=2))
    ax.add_patch(RegularPolygon((29.55, 11.25), 3, radius=0.95, facecolor=ALERT, edgecolor=INK, lw=2.4, zorder=3))
    ax.text(29.55, 11.05, "!", ha="center", va="center", color="white", fontsize=30, fontweight="bold", zorder=4)
    ax.text(29.55, 9.85, "Alert!", ha="center", va="center", fontsize=20, zorder=4)
    ax.add_patch(Circle((29.55, 6.95), 1.55, facecolor=ALERT, edgecolor="#A8140F", lw=1.6, zorder=3))
    ax.text(29.55, 6.95, "Alerts /\nIncidents\n+ evidence", ha="center", va="center", color="white", fontsize=17,
            zorder=4, linespacing=1.2)
    arrow(ax, (26.45, 6.15), (28.03, 6.4))

    # ---- bottom lane: incremental learning loop (right to left) and SOC & response
    yl0, yl1 = 1.55, 3.35
    group(ax, 4.6, 0.95, 22.0, 3.95, "Incremental Learning Loop")
    box(ax, 4.85, yl0, 8.35, yl1, "Deploy", "Ansible · DL worker")
    box(ax, 8.85, yl0, 12.65, yl1, "MLflow Registry", "candidate → champion")
    box(ax, 13.15, yl0, 16.75, yl1, "IL Service", "GPU · replay · gates")
    box(ax, 17.25, yl0, 21.75, yl1, "Triggers", "drift ‖ scheduled ‖ labels")
    arrow(ax, (17.25, 2.45), (16.75, 2.45))
    arrow(ax, (13.15, 2.45), (12.65, 2.45))
    arrow(ax, (8.85, 2.45), (8.35, 2.45))
    arrow(ax, (17.75, ym0), (17.75, yl1), label="drift (OOV · PSI)", lpos=(17.55, 4.3), lha="right", lfs=14)
    arrow(ax, (6.6, yl1), (6.6, 8.45), dashed=True)
    ax.text(6.8, 6.0, "new model\nversion", fontsize=15, style="italic", va="center", ha="left")

    group(ax, 22.8, 0.95, 31.75, 3.95, "SOC & Response")
    box(ax, 23.05, yl0, 27.0, yl1, "SOC Dashboard", "verify · label events")
    box(ax, 27.5, yl0, 31.5, yl1, "Response", "OpenStack SG quarantine")
    arrow(ax, (28.75, 5.43), (26.2, yl1), label="risk & evidence", lpos=(28.6, 4.25), lha="left", lfs=14)
    arrow(ax, (27.0, 2.45), (27.5, 2.45))
    arrow(ax, (23.05, 2.45), (21.75, 2.45))
    ax.text(22.4, 3.0, "verified\nlabels", fontsize=13, style="italic", ha="center", va="center", zorder=8,
            bbox=dict(facecolor="white", edgecolor="none", pad=1))
    path(ax, [(30.9, yl0), (30.9, 0.3), (1.18, 0.3), (1.18, 6.7)], dashed=True)
    ax.text(15.5, 0.3, "isolate victim host (approved response)", ha="center", va="center", fontsize=15,
            style="italic", zorder=8, bbox=dict(facecolor="white", edgecolor="none", pad=2))

    # legend (solid = data flow, dashed = control)
    ax.plot([8.6, 9.8], [6.35, 6.35], color=INK, lw=3.2)
    ax.text(10.05, 6.35, "data flow", fontsize=15, va="center")
    ax.plot([8.6, 9.8], [5.55, 5.55], color=INK, lw=3.2, linestyle=(0, (5, 3)))
    ax.text(10.05, 5.55, "control: model rollout, host isolation", fontsize=15, va="center")

    fig.savefig(OUT, dpi=110, facecolor="white")
    print(OUT)


if __name__ == "__main__":
    main()
