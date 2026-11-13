#!/usr/bin/env python3
"""Draw the internal architecture of the final IL models (see IL/README.md):
  DL_IL_architecture.png  BiLSTM learned OpTC -> ATLASv2 -> SL700 (after step 3)
  ML_IL_architecture.png  LightGBM residual boosting OpTC -> ATLASv2 -> SL700 (after step 3)
Colours mark the step that added each part. Usage: python3 draw_il_architecture.py [out_dir]  (matplotlib only)
"""
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import to_rgba  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch  # noqa: E402

STEP1, STEP2, STEP3, INPUT, NEUTRAL, TEXT = "#3B6FB6", "#2E9E5B", "#E07B2E", "#8A8A8A", "#5A5A5A", "#1F1F1F"
plt.rcParams.update({"font.family": "DejaVu Sans"})


def canvas(w=22, h=12.6, title="", subtitle=""):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w); ax.set_ylim(0, h); ax.axis("off")
    ax.text(0.3, h - 0.35, title, fontsize=17, fontweight="bold", color=TEXT, va="top")
    ax.text(0.3, h - 0.95, subtitle, fontsize=11.5, color="#444444", va="top")
    return fig, ax


def box(ax, x, y, w, h, title, lines=(), color=STEP1, fs=11.5, fill=0.11, lw=1.9, dashed=False, notes=()):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.12", lw=lw,
                                ls=(0, (4, 3)) if dashed else "-", ec=color, fc=to_rgba(color, fill)))
    ax.text(x + w / 2, y + h - 0.15, title, ha="center", va="top", fontsize=fs, fontweight="bold", color=TEXT)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.53 - i * 0.31, line, ha="center", va="top", fontsize=fs - 2, color="#333333")
    for i, (txt, c) in enumerate(notes):  # coloured notes at the bottom of the box
        ax.text(x + w / 2, y + 0.12 + i * 0.29, txt, ha="center", va="bottom", fontsize=fs - 2.3, color=c, fontweight="bold")
    return dict(x=x, y=y, w=w, h=h)


def L(b, f=0.5): return (b["x"], b["y"] + b["h"] * f)
def R(b, f=0.5): return (b["x"] + b["w"], b["y"] + b["h"] * f)
def T(b, f=0.5): return (b["x"] + b["w"] * f, b["y"] + b["h"])
def B(b, f=0.5): return (b["x"] + b["w"] * f, b["y"])


def arrow(ax, p0, p1, color=NEUTRAL, lw=1.7, text=None, tpos=0.5, toff=(0.0, 0.08), fs=9.5, rad=0.0, ls="-", ha="center"):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=17, lw=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}", linestyle=ls, shrinkA=1, shrinkB=1))
    if text:
        ax.text(p0[0] + (p1[0] - p0[0]) * tpos + toff[0], p0[1] + (p1[1] - p0[1]) * tpos + toff[1], text,
                ha=ha, va="bottom", fontsize=fs, color=color, style="italic")


def plus(ax, x, y, r=0.25, color=NEUTRAL):
    ax.add_patch(Circle((x, y), r, fc="white", ec=color, lw=1.9, zorder=3))
    ax.text(x, y - 0.01, "+", ha="center", va="center", fontsize=15, fontweight="bold", color=color, zorder=4)
    return (x, y)


def legend(ax, x, y, items=((INPUT, "Đầu vào"), (STEP1, "Bước 1 · OpTC (model gốc)"),
                            (STEP2, "Thêm ở bước 2 · ATLASv2"), (STEP3, "Thêm ở bước 3 · SL700")), step=4.9):
    for i, (c, t) in enumerate(items):
        ax.add_patch(FancyBboxPatch((x + i * step, y), 0.45, 0.3, boxstyle="round,pad=0,rounding_size=0.05",
                                    ec=c, fc=to_rgba(c, 0.25), lw=1.8))
        ax.text(x + i * step + 0.6, y + 0.15, t, va="center", fontsize=11, color=TEXT)


def band_title(ax, x, y, text):
    ax.text(x, y, text, fontsize=13, fontweight="bold", color=TEXT, va="bottom")
    ax.add_line(Line2D([x, 21.7], [y - 0.08, y - 0.08], color="#BBBBBB", lw=1))


# ====================================================================== DL
def draw_dl(out):
    fig, ax = canvas(title="Mô hình DL — BiLSTM học tăng dần OpTC → ATLASv2 → AInception SL700 (kiến trúc bên trong sau bước 3 · 282.521 tham số)",
                     subtitle="Một cửa sổ 180 s gồm ≤ 512 sự kiện; hình vẽ cho một sự kiện t (các khối dùng chung theo t). "
                              "Màu cho biết khối được thêm ở bước nào; mọi phần mới khởi tạo để điểm ban đầu trùng model trước.")
    legend(ax, 0.3, 10.95, ((INPUT, "Đầu vào"), (STEP1, "Bước 1 · OpTC gốc (78.698 tham số)"),
                            (STEP2, "Thêm ở bước 2 · ATLASv2"), (STEP3, "Thêm ở bước 3 · SL700")))
    # inputs
    a1 = box(ax, 0.3, 9.15, 3.5, 1.5, "4 trường contract OpTC", ["app_family · proto", "resp_port_class · image_dir_class"], INPUT)
    a2 = box(ax, 0.3, 8.3, 3.5, 0.8, "Δt", ["log1p(giây từ sự kiện trước)"], INPUT)
    a3 = box(ax, 0.3, 6.25, 3.5, 1.75, "10 trường ngữ cảnh host", ["kind · actor · actor_dir · parent", "target · target_dir · net", "user · pub · tpub"], INPUT)
    a4 = box(ax, 0.3, 5.15, 3.5, 0.85, "21 đặc trưng số", ["18 cờ dòng lệnh · Δt · vị trí · filemod"], INPUT)
    a5 = box(ax, 0.3, 3.6, 3.5, 1.45, "Túi token Linux", ["dòng lệnh · đường dẫn · uid/auid", "cha, ông bà · phiên đăng nhập"], INPUT,
             notes=[("chỉ sự kiện SL700 · ≤ 64 token", STEP3)])
    # embeddings
    b1 = box(ax, 4.3, 9.15, 3.7, 1.5, "ExtEmbedding × 4", ["hàng OpTC 61 · 4 · 11 · 10 (1.129)", "16 + 4 + 7 + 6 = 33 chiều"], STEP1,
             notes=[("+ hàng mới bước 2/3 = <UNK> (1.740)", STEP2)])
    b3 = box(ax, 4.3, 6.25, 3.7, 1.75, "Embedding × 10", ["từ điển TRAIN ATLASv2 + SL700", "kind 14 · actor 123 · target 339 …", "tổng 90 chiều · 10.300 tham số"], STEP2,
             notes=[("từ điển mở rộng ở bước 3", STEP3)])
    b5 = box(ax, 4.3, 3.6, 3.7, 1.45, "EmbeddingBag", ["1.939 token × 32 · trung bình", "62.048 tham số"], STEP3)
    # encoders
    c1 = box(ax, 8.5, 8.6, 3.9, 1.6, "event_encoder", ["concat 33 + Δt + 1 = 35", "Linear 35→64 · LayerNorm", "GELU · Dropout 0,2"], STEP1)
    c3 = box(ax, 8.5, 4.35, 3.9, 2.15, "ctx_proj", ["concat 90 + 21 + 32 = 143", "Linear 143→64 · LayerNorm · GELU", "Dropout · Linear 64→64", "13.504 tham số"], STEP2,
             notes=[("lớp cuối = 0 · cột túi token = 0 (bước 3)", STEP3)])
    s1 = plus(ax, 10.45, 7.75)
    arrow(ax, R(a1), L(b1)); arrow(ax, R(b1), L(c1, 0.72))
    arrow(ax, R(a2), L(c1, 0.22))
    arrow(ax, R(a3), L(b3)); arrow(ax, R(b3), L(c3, 0.85))
    arrow(ax, R(a4), L(c3, 0.55))
    arrow(ax, R(a5), L(b5)); arrow(ax, R(b5), L(c3, 0.2))
    arrow(ax, B(c1), (10.45, 8.0))
    arrow(ax, T(c3), (10.45, 7.5), text="× has_ctx  (OpTC = 0)", tpos=0.45, toff=(0.15, 0.0), ha="left")
    # recurrent part
    d0 = box(ax, 12.9, 9.25, 3.1, 1.3, "classifier", ["LayerNorm · Linear 128→64", "GELU · Linear 64→1"], STEP1)
    d1 = box(ax, 12.9, 7.2, 3.1, 1.1, "BiLSTM-1", ["64 → 2 × 64 · 1 lớp"], STEP1)
    d2 = box(ax, 12.9, 5.2, 3.1, 1.1, "BiLSTM-2", ["128 → 2 × 64 · 99.328 tham số"], STEP2)
    arrow(ax, (10.7, 7.75), L(d1))
    arrow(ax, T(d1), B(d0), text="trạng thái cuối", toff=(0.1, -0.05), ha="left")
    arrow(ax, B(d1), T(d2), text="chuỗi h₁…h_T", toff=(0.1, -0.05), ha="left")
    # heads and outputs
    e0 = box(ax, 16.5, 9.5, 1.5, 0.8, "z_old", [], STEP1)
    e1 = box(ax, 16.5, 5.45, 2.9, 1.35, "event head", ["Linear 128→64 · GELU", "Linear 64→1"], STEP2)
    e1b = box(ax, 16.5, 7.3, 2.6, 1.05, "max theo t · × gate", ["gate khởi tạo 0, học được"], STEP2)
    e2 = box(ax, 16.5, 3.6, 3.0, 1.35, "stage head", ["Linear 128→64 · GELU", "Linear 64→5"], STEP2,
             notes=[("lớp Impact thêm ở bước 3", STEP3)])
    arrow(ax, R(d0), L(e0))
    arrow(ax, R(d2, 0.7), L(e1, 0.5))
    arrow(ax, R(d2, 0.25), L(e2, 0.6), rad=-0.15)
    arrow(ax, T(e1), B(e1b), text="logit từng sự kiện", toff=(0.12, -0.05), ha="left")
    s2 = plus(ax, 19.5, 8.75)
    arrow(ax, R(e0), (19.27, 8.88)); arrow(ax, R(e1b), (19.27, 8.62))
    z = box(ax, 20.05, 8.05, 1.75, 1.4, "z cửa sổ", ["z_old + gate · max", "≥ ngưỡng VAL", "→ cảnh báo"], NEUTRAL, fs=11)
    arrow(ax, (19.75, 8.75), L(z))
    st = box(ax, 19.95, 3.65, 1.85, 1.25, "stage / sự kiện", ["IC · ED · LM", "EX · Impact"], NEUTRAL, fs=11)
    arrow(ax, R(e2), L(st))
    # IL mechanism band
    band_title(ax, 0.3, 2.95, "Cơ chế học tăng dần (giống nhau ở bước 2 và bước 3)")
    xs, w, h, y = [0.3, 4.62, 8.94, 13.26, 17.58], 4.1, 1.95, 0.55
    box(ax, xs[0], y, w, h, "Khởi tạo tương đương", ["token mới: hàng = <UNK>", "lớp chiếu cuối = 0 · gate = 0", "lớp Impact: w = 0, bias thấp", "kiểm: |z mới − z cũ| ≤ 1,7e-5"], NEUTRAL, fs=11)
    box(ax, xs[1], y, w, h, "Mở băng dần (20 epoch)", ["A · 4: chỉ phần mới · lr 1e-3", "B · 8: + encoder, BiLSTM-1,", "classifier cũ · lr 1e-4", "C · 8: + hàng embedding cũ · 2,5e-5"], NEUTRAL, fs=11)
    box(ax, xs[2], y, w, h, "Replay dữ liệu thật / epoch", ["OpTC: 150 dương + 450 âm", "ATLASv2: 100 dương + 400 âm", "(từ bước 3)", "trộn với toàn bộ TRAIN miền mới"], NEUTRAL, fs=11)
    box(ax, xs[3], y, w, h, "Loss", ["BCE cửa sổ, trọng số √(âm/dương)", "+ 0,5 · BCE từng sự kiện", "+ 0,5 · CE stage", "(trọng số lớp ∝ 1/√tần suất)"], NEUTRAL, fs=11)
    box(ax, xs[4], y, w, h, "Chọn mô hình", ["epoch: TB (AP + F1)/2 trên VAL", "của mọi miền đã học", "ngưỡng: VAL từng miền", "TEST chấm một lần"], NEUTRAL, fs=11)
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ====================================================================== ML
def bracket(ax, x0, x1, y, color, text, fs=10):
    ax.add_line(Line2D([x0, x0, x1, x1], [y + 0.12, y, y, y + 0.12], color=color, lw=2))
    ax.text(x0 + 0.1, y - 0.05, text, ha="left", va="top", fontsize=fs, color=color, fontweight="bold")


def draw_ml(out):
    fig, ax = canvas(title="Mô hình ML — LightGBM boosting phần dư OpTC → ATLASv2 → AInception SL700 (kiến trúc bên trong sau bước 3)",
                     subtitle="Mỗi sự kiện host là một hàng. Ba booster cộng dồn margin; booster cũ đóng băng và chỉ đọc phần cột thuộc từ vựng của nó, "
                              "nên cột mới không làm đổi điểm của chúng.")
    legend(ax, 0.3, 10.95)
    ev = box(ax, 0.3, 8.45, 3.0, 1.75, "Sự kiện host", ["OpTC: eCAR", "ATLASv2: CBC EDR", "SL700: auditd"], INPUT)
    # tokenisation
    ax.add_patch(FancyBboxPatch((3.7, 6.75), 4.6, 4.0, boxstyle="round,pad=0,rounding_size=0.12", lw=1.4, ls=(0, (4, 3)),
                                ec=NEUTRAL, fc="none"))
    ax.text(6.0, 10.62, "Token hoá theo hợp đồng Base OpTC", ha="center", va="top", fontsize=11, fontweight="bold", color=TEXT)
    box(ax, 3.9, 8.95, 4.2, 1.3, "token eCAR", ["action · object · principal", "đường dẫn · dòng lệnh"], STEP1, fs=11)
    box(ax, 3.9, 7.9, 4.2, 0.95, "token ngữ cảnh", ["cha · incoming · has_netconn"], STEP2, fs=11)
    box(ax, 3.9, 6.9, 4.2, 0.9, "token Linux lx:", ["chỉ sự kiện SL700"], STEP3, fs=11)
    arrow(ax, R(ev), (3.7, 9.3))
    # feature vector
    x0, wbar, ybar, hbar = 8.7, 12.9, 9.55, 0.62
    n1, n2, n3 = 10317, 2048, 9122
    tot = n1 + n2 + n3
    w1, w2, w3 = wbar * n1 / tot, wbar * n2 / tot, wbar * n3 / tot
    for xx, ww, c in ((x0, w1, STEP1), (x0 + w1, w2, STEP2), (x0 + w1 + w2, w3, STEP3)):
        ax.add_patch(FancyBboxPatch((xx, ybar), ww, hbar, boxstyle="square,pad=0", lw=1.6, ec=c, fc=to_rgba(c, 0.3)))
    ax.text(x0, ybar + hbar + 0.45, "Vector nhị phân x · 21.487 cột (cấu hình chính; 6 cột phạm vi địa chỉ để riêng)",
            fontsize=11.5, fontweight="bold", color=TEXT, va="bottom")
    ax.text(x0 + w1 / 2, ybar + hbar / 2, "cột 0 – 10.316 · từ vựng OpTC", ha="center", va="center", fontsize=10, color=TEXT)
    ax.text(x0 + w1 + w2 / 2, ybar + hbar + 0.05, "10.317 – 12.364", ha="center", va="bottom", fontsize=9, color=STEP2)
    ax.text(x0 + w1 + w2 / 2, ybar + hbar / 2, "+2.048", ha="center", va="center", fontsize=9.5, color=TEXT)
    ax.text(x0 + w1 + w2 + w3 / 2, ybar + hbar / 2, "12.365 – 21.486 · 7.118 eCAR + 2.004 Linux", ha="center", va="center", fontsize=10, color=TEXT)
    arrow(ax, (8.3, 9.3), (x0, ybar + hbar / 2))
    bracket(ax, x0, x0 + w1, ybar - 0.25, STEP1, "")
    bracket(ax, x0, x0 + w1 + w2, ybar - 0.75, STEP2, "")
    bracket(ax, x0, x0 + wbar, ybar - 1.25, STEP3, "")
    # boosters
    bo = box(ax, 8.7, 5.75, 3.7, 1.55, "Booster OpTC", ["300 cây · ≤ 31 lá", "đóng băng từ bước 1"], STEP1)
    ba = box(ax, 12.95, 5.75, 3.7, 1.55, "Booster phần dư ATLASv2", ["300 cây · ≤ 31 lá", "đóng băng từ bước 2"], STEP2)
    bs = box(ax, 17.2, 5.75, 3.7, 1.55, "Booster phần dư SL700", ["300 cây · ≤ 31 lá", "học ở bước 3"], STEP3)
    arrow(ax, (T(bo)[0], ybar - 0.25), T(bo), color=STEP1)
    arrow(ax, (T(ba)[0], ybar - 0.75), T(ba), color=STEP2)
    arrow(ax, (T(bs)[0], ybar - 1.25), T(bs), color=STEP3)
    lab = dict(fontsize=10, fontweight="bold", va="top")
    ax.text(T(bo)[0] + 0.15, ybar - 0.3, "đọc 10.317 cột đầu", ha="left", color=STEP1, **lab)
    ax.text(T(ba)[0] + 0.15, ybar - 0.8, "đọc 12.365 cột đầu", ha="left", color=STEP2, **lab)
    ax.text(T(bs)[0] - 0.15, ybar - 1.3, "đọc toàn bộ 21.487 cột", ha="right", color=STEP3, **lab)
    # margin composition
    s1 = plus(ax, 12.7, 4.3)
    s2 = plus(ax, 19.05, 4.3)
    arrow(ax, B(bo), (12.48, 4.42), text="z_OpTC × 0,8", tpos=0.35, toff=(-0.4, 0.0), ha="right")
    arrow(ax, B(ba), (12.92, 4.42), text="z_ATLASv2", tpos=0.45, toff=(0.45, 0.0), ha="left")
    arrow(ax, (12.95, 4.3), (18.8, 4.3), text="z1 = margin của model sau bước 2   × 0,8", tpos=0.5, toff=(0, 0.1))
    arrow(ax, B(bs), (19.05, 4.55), text="z_SL700", tpos=0.4, toff=(0.15, 0.0), ha="left")
    p = box(ax, 19.75, 3.65, 2.05, 1.3, "p = sigmoid(z2)", ["≥ ngưỡng VAL", "→ cảnh báo"], NEUTRAL, fs=11)
    arrow(ax, (19.3, 4.3), L(p), text="z2", tpos=0.5, toff=(0, 0.06))
    ax.text(8.7, 3.75, "z1 = 0,8 · z_OpTC + z_ATLASv2        z2 = 0,8 · z1 + z_SL700",
            fontsize=11.5, fontweight="bold", color=TEXT, va="bottom")
    ax.text(8.7, 3.6, "Ngưỡng đóng băng cho miền cũ: OpTC 0,87427 · ATLASv2 0,94073; miền mới: F1 lớn nhất trên VAL.",
            fontsize=10, color="#444444", va="top")
    # training band (step 3)
    band_title(ax, 0.3, 3.05 - 0.15, "Huấn luyện booster SL700 ở bước 3 (bước 2 làm tương tự với booster ATLASv2)")
    d1 = box(ax, 0.3, 1.95, 3.6, 0.75, "SL700 TRAIN", ["344.271 sự kiện · 33.752 tấn công"], STEP3, fs=10.5)
    d2 = box(ax, 0.3, 1.1, 3.6, 0.75, "Replay OpTC", ["12.500 dương + 25.000 âm"], STEP1, fs=10.5)
    d3 = box(ax, 0.3, 0.25, 3.6, 0.75, "Replay ATLASv2", ["2.244 dương + 35.256 âm"], STEP2, fs=10.5)
    zz = box(ax, 4.55, 0.25, 3.3, 2.45, "z1 của từng dòng", ["model sau bước 2", "(OpTC + ATLASv2)", "đóng băng", "âm ATLASv2: nửa có", "z1 cao nhất"], NEUTRAL, fs=11)
    for d in (d1, d2, d3):
        arrow(ax, R(d), L(zz, (d["y"] + d["h"] / 2 - 0.25) / 2.45))
    ini = box(ax, 8.5, 1.5, 4.3, 1.2, "init score", ["0,8 · z1: SL700 và replay âm", "0,5 · z1: replay dương (chọn trên VAL)"], STEP3, fs=11)
    wt = box(ax, 8.5, 0.25, 4.3, 1.1, "trọng số mẫu", ["5 nếu y = 0 và sigmoid(z1) > 0,5", "1 với mọi mẫu khác"], STEP3, fs=11)
    arrow(ax, R(zz, 0.75), L(ini)); arrow(ax, R(zz, 0.25), L(wt))
    lg = box(ax, 13.4, 0.25, 4.3, 2.45, "LightGBM nhị phân", ["X, y: SL700 + replay (75.000 dòng)", "300 vòng · lr 0,03 · 31 lá", "max_delta_step 2 · reg_lambda 5", "scale_pos_weight 9,2 · deterministic"], STEP3, fs=11)
    arrow(ax, R(ini), L(lg, 0.75)); arrow(ax, R(wt), L(lg, 0.3))
    out_b = box(ax, 18.3, 0.6, 3.5, 1.7, "Booster phần dư SL700", ["300 cây · đọc 21.487 cột", "= khối cam ở hàng trên"], STEP3, fs=11)
    arrow(ax, R(lg), L(out_b))
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent)
    draw_dl(out_dir / "DL_IL_architecture.png")
    draw_ml(out_dir / "ML_IL_architecture.png")
    print("written:", out_dir / "DL_IL_architecture.png", out_dir / "ML_IL_architecture.png")
