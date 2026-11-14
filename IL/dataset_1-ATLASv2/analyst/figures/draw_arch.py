#!/usr/bin/env python3
"""Architecture diagrams of the current ML (LightGBM continual boosting) and DL (BiLSTM optc_il) models."""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Circle  # noqa: E402

plt.rcParams["font.family"] = "DejaVu Sans"
SURF, INK, INK2 = "#fcfcfb", "#0b0b0b", "#52514e"
STY = {
    "old": dict(fc="#e3eefb", ec="#2a78d6"),
    "new": dict(fc="#fde6dc", ec="#eb6834"),
    "io": dict(fc="#f0efec", ec="#8a8984"),
    "res": dict(fc="#ffffff", ec="#52514e"),
}
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")


def canvas(w, h):
    fig = plt.figure(figsize=(w / 10, h / 10), facecolor=SURF)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, w); ax.set_ylim(0, h); ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, title, body="", kind="io", tag=None, fs=11, bfs=9.5, dashed=False, align="center"):
    s = STY[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=1.2", fc=s["fc"], ec=s["ec"],
                                lw=1.6, ls="--" if dashed else "-", zorder=2))
    cx = x + w / 2 if align == "center" else x + 1.5
    ha = "center" if align == "center" else "left"
    if body:
        ax.text(cx, y + h - 1.6, title, ha=ha, va="top", fontsize=fs, weight="bold", color=INK, zorder=3)
        ax.text(cx, y + h - 1.6 - fs * 0.30, body, ha=ha, va="top", fontsize=bfs, color=INK2, zorder=3, linespacing=1.45)
    else:
        ax.text(cx, y + h / 2, title, ha=ha, va="center", fontsize=fs, weight="bold", color=INK, zorder=3)
    if tag:
        ax.text(x + w - 0.8, y + h - 0.6, tag, ha="right", va="top", fontsize=8, weight="bold", color=s["ec"], zorder=3)


def arrow(ax, p, q, label="", lpos=0.5, dx=1.0, dy=0.0, ha="left", rad=0.0, color=INK2):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=13, lw=1.3, color=color,
                                 connectionstyle=f"arc3,rad={rad}", zorder=1, shrinkA=2, shrinkB=2))
    if label:
        mx, my = p[0] + (q[0] - p[0]) * lpos, p[1] + (q[1] - p[1]) * lpos
        ax.text(mx + dx, my + dy, label, fontsize=8.5, color=INK2, ha=ha, va="center", style="italic", zorder=3)


def node(ax, x, y, txt, r=2.0, kind="res"):
    s = STY[kind]
    ax.add_patch(Circle((x, y), r, fc=s["fc"], ec=s["ec"], lw=1.6, zorder=2))
    ax.text(x, y, txt, ha="center", va="center", fontsize=10, weight="bold", color=INK, zorder=3)


def legend(ax, x, y):
    for i, (k, t) in enumerate([("old", "CŨ: phần học trên OpTC"), ("new", "MỚI: thêm khi học ATLASv2"), ("io", "Dữ liệu / xử lý / đầu ra")]):
        s = STY[k]
        ax.add_patch(FancyBboxPatch((x + i * 42, y), 4, 2.4, boxstyle="round,pad=0.1,rounding_size=0.4", fc=s["fc"], ec=s["ec"], lw=1.4))
        ax.text(x + i * 42 + 5.5, y + 1.2, t, fontsize=9.5, color=INK, va="center")


# ============================================================ ML
def draw_ml():
    W, H = 170, 102
    fig, ax = canvas(W, H)
    ax.text(3, H - 3, "ML: LightGBM continual boosting (Host ML, OpTC → ATLASv2)", fontsize=17, weight="bold", color=INK, va="top")
    ax.text(3, H - 8, "Đơn vị: từng sự kiện host  ·  Đầu ra: binary (tấn công / lành)  ·  Không phát hiện stage",
            fontsize=10.5, color=INK2, va="top")
    legend(ax, 3, H - 14)

    # data
    box(ax, 6, 73, 52, 10, "OpTC: eCAR (Windows)", "log host: PROCESS, FILE, FLOW, REGISTRY…\nnhãn tấn công từ bài A New Hope", kind="io")
    box(ax, 66, 73, 60, 10, "ATLASv2: CBC-EDR (Windows)",
        "cbc_adapter → CanonicalEvent\nLabelRefiner v9b → nhãn 0/1 cho từng sự kiện", kind="io")
    box(ax, 6, 57, 120, 10.5, "Token hoá ngữ nghĩa  (build_host_shards)",
        "mỗi sự kiện → túi token: loại sự kiện · tiến trình · thư mục chạy · tiến trình cha · ngữ cảnh incoming\n"
        "(PROCESS OPEN, THREAD REMOTE_CREATE…) · chuyển thư mục · chỉ mục thời gian nhân quả", kind="io")
    arrow(ax, (32, 73), (40, 68)); arrow(ax, (96, 73), (88, 68))
    # vector
    ax.text(6, 51, "x = vector thưa nhị phân cho mỗi sự kiện", fontsize=10, color=INK, weight="bold")
    box(ax, 6, 41, 78, 8, "10.317 cột: vocab OpTC (vocab.json, đóng băng)", kind="old", tag="CŨ", fs=10)
    box(ax, 85, 41, 41, 8, "cột mới của ATLASv2 (vocab_extended)", kind="new", tag="MỚI", fs=10)
    arrow(ax, (66, 57), (66, 49.6))

    # model
    box(ax, 6, 20, 46, 13, "Booster OpTC", "đọc x[:, :10317]\nđóng băng, không train lại", kind="old", tag="CŨ")
    box(ax, 6, 3, 46, 13, "Booster residual", "đọc toàn bộ x\nhọc phần model OpTC còn sai\n(train: xem khung bên phải)", kind="new", tag="MỚI")
    arrow(ax, (30, 41), (29, 33.5), "x[:, :10317]", dx=1.2)
    ax.annotate("", xy=(5.5, 9.5), xytext=(5.5, 41), arrowprops=dict(arrowstyle="-|>", color=INK2, lw=1.3, connectionstyle="angle,angleA=180,angleB=90,rad=0"))
    ax.text(1.2, 25, "x đủ cột", fontsize=8.5, color=INK2, style="italic", rotation=90, va="center")
    node(ax, 64, 26.5, "× 0.8", r=3.2)
    arrow(ax, (52.5, 26.5), (60.6, 26.5), "z_OpTC", lpos=0.5, dx=0, dy=2.0, ha="center")
    node(ax, 78, 17, "+", r=2.4)
    arrow(ax, (66.6, 24.4), (76.3, 18.8))
    arrow(ax, (52.5, 9.5), (75.8, 16.0), "z_residual", lpos=0.45, dx=0, dy=-1.8, ha="center")
    box(ax, 88, 11, 38, 12, "p = σ(margin)", "≥ ngưỡng chọn trên VAL\n→ tấn công / lành", kind="io")
    arrow(ax, (80.4, 17), (87.6, 17), "margin", lpos=0.5, dx=0, dy=1.6, ha="center")

    # training panel
    box(ax, 132, 22, 35, 61, "Huấn luyện booster residual (MỚI)", (
        "init_score = α · z_OpTC\n"
        "  α = 0.8: ATLASv2 và replay âm\n"
        "  α = 0.25: replay dương\n"
        "  (chống mất gradient)\n\n"
        "Tập train =\n"
        "  ATLASv2 TRAIN\n"
        "  + replay OpTC THẬT 75.000:\n"
        "    25.000 tấn công\n"
        "    35.000 hard negative\n"
        "    15.000 âm ngẫu nhiên\n\n"
        "Hard negative (y = 0 mà\n"
        "  OpTC báo > 0.5): trọng số × 5\n\n"
        "LightGBM: num_leaves 31,\n"
        "  lr 0.03, scale_pos_weight\n"
        "Ngưỡng: chọn trên VAL"), kind="new", align="left", bfs=9.3)

    # results
    box(ax, 132, 3, 35, 13, "Kết quả (nhãn v9b)",
        "ATLASv2 F1 0.959\nOpTC F1 0.9963 → 0.9905\nBWT −0.58%", kind="res", align="left", bfs=9.5)
    fig.savefig(OUT / "arch_ML_lightgbm.png", dpi=170, facecolor=SURF)
    plt.close(fig)


# ============================================================ DL
def draw_dl():
    W, H = 170, 150
    fig, ax = canvas(W, H)
    ax.text(3, H - 3, "DL: BiLSTM incremental learning OpTC → ATLASv2  (code/DL/optc_il)", fontsize=17, weight="bold", color=INK, va="top")
    ax.text(3, H - 8, "Đơn vị: cửa sổ 180 s (trượt 30 s, ≤ 512 sự kiện)  ·  Đầu ra: binary + stage của chuỗi tấn công",
            fontsize=10.5, color=INK2, va="top")
    legend(ax, 3, H - 14)

    # per-event frame
    ax.add_patch(FancyBboxPatch((3, 90.5), 126, 39.5, boxstyle="round,pad=0.3,rounding_size=1.5", fc="none", ec="#b9b8b2", lw=1.2, ls="--"))
    ax.text(5, 128.6, "MỖI SỰ KIỆN t  (t = 1 … T)", fontsize=9.5, color=INK2, weight="bold", va="top")
    box(ax, 6, 114, 58, 11, "4 field hợp đồng OpTC  + Δt", (
        "app_family 61 (+46 id mới) · proto 4\n"
        "resp_port_class 11 (+4 id mới) · image_dir_class 10"), kind="old", tag="CŨ")
    box(ax, 6, 104.5, 29, 6.5, "Embedding hàng cũ", kind="old", tag="CŨ", fs=9.5)
    box(ax, 36, 104.5, 28, 6.5, "hàng mới = bản sao <UNK>", kind="new", tag="MỚI", fs=9)
    box(ax, 6, 93, 58, 8.5, "Event encoder", "Linear → LayerNorm → GELU (64)", kind="old", tag="CŨ")
    arrow(ax, (35, 114), (35, 111.3)); arrow(ax, (35, 104.5), (35, 101.8))

    box(ax, 70, 114, 56, 11, "Ngữ cảnh host (chỉ có ở ATLASv2)", (
        "kind · actor · actor_dir · parent · target · target_dir\n"
        "net · user · pub · tpub + 18 cờ dòng lệnh + dt, rel, is_filemod"), kind="new", tag="MỚI", bfs=9)
    box(ax, 70, 93, 56, 14, "Nhánh ngữ cảnh", (
        "Embed → Linear → LN → GELU → Linear\n(Linear cuối khởi tạo = 0)\n× has_ctx (flow OpTC = 0)"), kind="new", tag="MỚI", bfs=9)
    arrow(ax, (98, 114), (98, 107.4))
    node(ax, 66.5, 83, "+", r=2.4)
    arrow(ax, (35, 93), (64.4, 84.1)); arrow(ax, (98, 93), (68.8, 84.3))

    # sequence
    box(ax, 40, 68, 53, 9, "BiLSTM 1  (64 × 2 chiều)", kind="old", tag="CŨ")
    arrow(ax, (66.5, 80.6), (66.5, 77.4), "e₁ … e_T", dx=1.5)
    box(ax, 6, 46, 44, 11, "Classifier", "LayerNorm → 64 → 1", kind="old", tag="CŨ")
    arrow(ax, (48, 68), (32, 57.4), "trạng thái cuối h_fwd ‖ h_bwd", lpos=0.45, dx=-1.5, ha="right")
    box(ax, 84, 46, 44, 11, "BiLSTM 2  (64 × 2 chiều)", "chạy trên trạng thái từng bước", kind="new", tag="MỚI")
    arrow(ax, (85, 68), (100, 57.4), "trạng thái từng bước", lpos=0.45, dx=1.5)
    box(ax, 74, 27, 30, 12, "Event head", "logit tấn công\ncủa từng sự kiện", kind="new", tag="MỚI", bfs=9)
    box(ax, 108, 27, 30, 12, "Stage head", "4 lớp cho\ntừng sự kiện", kind="new", tag="MỚI", bfs=9)
    arrow(ax, (99, 46), (90, 39.4)); arrow(ax, (113, 46), (122, 39.4))

    node(ax, 64, 33, "× g", r=3.0, kind="new")
    ax.text(64, 28.6, "gate, khởi tạo 0", fontsize=8.5, color=INK2, ha="center", va="top", style="italic")
    arrow(ax, (73.6, 33), (67.2, 33), "max_t", lpos=0.5, dx=0, dy=1.6, ha="center")
    node(ax, 28, 33, "+", r=2.4)
    arrow(ax, (28, 46), (28, 35.6), "z_old", dx=1.2)
    arrow(ax, (60.8, 33), (30.6, 33))
    box(ax, 6, 6, 52, 18, "BINARY: tấn công / lành",
        "z = z_old + g · maxₜ(event logit)\nmột model chung cho OpTC và ATLASv2\nngưỡng chọn trên VAL", kind="io")
    arrow(ax, (28, 30.5), (28, 24.4))
    box(ax, 98, 6, 40, 18, "STAGE (khi z ≥ ngưỡng)",
        "presence: stage nào có trong cửa sổ\nlast stage: stage của sự kiện\nbị báo động cuối cùng\nIC · ED · LM · EX", kind="io", bfs=9)
    arrow(ax, (123, 27), (118, 24.4))
    ax.add_patch(FancyArrowPatch((58.5, 15), (97.6, 15), arrowstyle="-|>", mutation_scale=13, lw=1.1, color=INK2, ls="--"))
    ax.text(78, 16.6, "chỉ xét khi binary báo tấn công", fontsize=8.3, color=INK2, ha="center", style="italic")

    # side panel
    box(ax, 133, 72, 35, 58, "Huấn luyện", (
        "Lúc khởi tạo: model mở rộng\n≡ model OpTC gốc\n(chênh logit = 0.0, đã kiểm)\n\n"
        "Lịch freeze → mở dần:\n"
        "A (ep 1–4): chỉ phần MỚI\n   lr 1e-3\n"
        "B (ep 5–12): + encoder,\n   BiLSTM 1, classifier CŨ\n   lr 5e-4 / 1e-4\n"
        "C (ep 13–20): + hàng\n   embedding CŨ, lr 2.5e-5\n\n"
        "Loss:\n BCE cửa sổ\n + 0.5 · BCE sự kiện\n + 0.5 · CE stage\n\n"
        "Replay OpTC THẬT / epoch:\n 150 dương + 450 âm\n\n"
        "Chọn epoch, ngưỡng: VAL\nTEST: chấm một lần"), kind="new", align="left", bfs=9.1)
    box(ax, 141, 30, 27, 36, "Kết quả", (
        "3 seed, TEST\n\n"
        "ATLASv2 F1\n  0.990 ± 0.014\n"
        "Stage presence\n  0.84\n"
        "Last stage\n  0.81\n"
        "OpTC F1\n  0.988 → 0.994"), kind="res", align="left", bfs=9.3)
    fig.savefig(OUT / "arch_DL_bilstm_il.png", dpi=170, facecolor=SURF)
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    draw_ml(); draw_dl()
    print("ok", OUT)
