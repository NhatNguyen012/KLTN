#!/usr/bin/env python3
"""Export a conceptual view of DL_IL_architecture without tensor dimensions.

Run from any directory. Outputs are confined to this script's IL directory;
the detailed architecture image and all model artifacts remain untouched.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.colors import to_rgba

BLUE, GREEN, ORANGE = "#356CB1", "#278263", "#C57626"
INK, GRAY = "#000000", "#303030"
plt.rcParams.update({"font.family": "DejaVu Sans", "svg.fonttype": "none"})


def main():
    out = Path(__file__).resolve().parent
    root = out.parent
    for name in ("host-begnin", "host-malicious", "ecar-bro", "bro"):
        if out.is_relative_to((root / name).resolve()):
            raise ValueError("Architecture output must be outside dataset roots")
    fig, ax = plt.subplots(figsize=(20, 11.5))
    fig.patch.set_facecolor("#FFFFFF")
    ax.set(xlim=(0, 20), ylim=(0, 11.5))
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)

    def text(x, y, s, size=12, color=INK, weight="normal", ha="center"):
        ax.text(x, y, s, ha=ha, va="center", fontsize=size * 1.3,
                color="#000000", fontweight="bold",
                linespacing=1.2)

    def box(x, y, w, h, title, sub="", color=BLUE, fs=13):
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                     boxstyle="round,pad=0,rounding_size=0.14",
                     fc=to_rgba(color, .045), ec=color, lw=2.3, zorder=2))
        text(x+w/2, y+h/2+(.23 if sub else 0), title, fs, color, "bold")
        if sub:
            text(x+w/2, y+h/2-.24, sub, 11.2, GRAY)

    def arrow(points, color=GRAY):
        for a, b in zip(points[:-2], points[1:-1]):
            ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=2.2, zorder=1)
        ax.add_patch(FancyArrowPatch(points[-2], points[-1], arrowstyle="-|>",
                     mutation_scale=19, lw=2.2, color=color, zorder=1,
                     shrinkA=0, shrinkB=3))

    text(.6, 10.95, "DL · HỌC TĂNG DẦN QUA CÁC MIỀN DỮ LIỆU", 21, weight="bold", ha="left")
    text(.6, 10.48, "Kiến trúc tổng quát sau khi học OpTC → ATLASv2 → AInception SL700", 12, GRAY, ha="left")

    box(.6, 9.15, 5.7, .95, "OpTC", "Học mô hình nền", BLUE)
    box(7.15, 9.15, 5.7, .95, "ATLASv2", "Thêm ngữ cảnh host và BiLSTM bổ sung", GREEN)
    box(13.7, 9.15, 5.7, .95, "AInception SL700", "Mở rộng biểu diễn với token Linux", ORANGE)
    arrow([(6.3, 9.63), (7.15, 9.63)])
    arrow([(12.85, 9.63), (13.7, 9.63)])

    text(.6, 8.65, "LUỒNG SUY LUẬN", 11, GRAY, "bold", ha="left")
    box(.6, 6.05, 3.0, 1.15, "Chuỗi sự kiện", "Đặc trưng sự kiện\n+ thời gian", BLUE)
    box(4.25, 6.05, 3.0, 1.15, "Biểu diễn kết hợp", "Mã hóa\n+ bổ sung ngữ cảnh", BLUE)
    box(7.95, 6.05, 3.0, 1.15, "BiLSTM nền", "Học từ OpTC", BLUE)
    box(11.65, 6.05, 3.0, 1.15, "BiLSTM bổ sung", "Thêm từ ATLASv2", GREEN)
    box(15.35, 6.05, 4.05, 1.15, "Điểm từng sự kiện", "Nhánh phát hiện bổ sung", GREEN)
    for a, b in ((3.6, 4.25), (7.25, 7.95), (10.95, 11.65), (14.65, 15.35)):
        arrow([(a, 6.625), (b, 6.625)])

    box(.6, 4.15, 3.0, 1.15, "Ngữ cảnh host", "Bổ sung từ ATLASv2", GREEN)
    box(4.25, 4.15, 3.0, 1.15, "Token Linux", "Bổ sung ở SL700", ORANGE)
    arrow([(3.6, 4.725), (3.92, 4.725), (3.92, 5.65), (5.15, 5.65), (5.15, 6.05)], GREEN)
    arrow([(6.35, 5.3), (6.35, 6.05)], ORANGE)

    box(11.65, 7.75, 3.0, .95, "Điểm nền", "Nhánh phân loại gốc", BLUE)
    arrow([(9.45, 7.2), (9.45, 8.225), (11.65, 8.225)], BLUE)
    box(15.35, 7.75, 4.05, .95, "Phát hiện tấn công", "Kết hợp điểm → ngưỡng từ VAL", BLUE)
    arrow([(14.65, 8.225), (15.35, 8.225)], BLUE)
    arrow([(17.375, 7.2), (17.375, 7.75)], GREEN)
    text(17.1, 7.48, "Max theo thời gian × gate", 11.2, GREEN, ha="right")

    box(15.35, 4.15, 4.05, 1.15, "Giai đoạn tấn công", "Dự đoán stage theo sự kiện", GREEN)
    arrow([(13.15, 6.05), (13.15, 4.725), (15.35, 4.725)], GREEN)
    text(10.0, 3.55, "Các miền dùng chung mô hình; SL700 tiếp tục hai tầng BiLSTM hiện có.", 12, GRAY)

    ax.add_patch(FancyBboxPatch((.6, .55), 18.8, 2.45,
                 boxstyle="round,pad=0,rounding_size=0.18", fc="#FAFAFA", ec="#707070", lw=1.5))
    text(1.0, 2.62, "CƠ CHẾ HỌC TĂNG DẦN · CHỈ KHI HUẤN LUYỆN", 11, GRAY, "bold", ha="left")
    box(1.0, 1.13, 5.1, 1.05, "Mở rộng mô hình", "Giữ hành vi ban đầu của mô hình trước", BLUE, 12)
    box(7.1, 1.13, 5.8, 1.05, "Học miền mới + replay miền cũ", "Mở khóa dần các thành phần để cập nhật", GREEN, 12)
    box(13.9, 1.13, 5.1, 1.05, "Chọn trên validation", "Checkpoint, ngưỡng và kiểm tra miền cũ", GRAY, 12)
    arrow([(6.1, 1.655), (7.1, 1.655)])
    arrow([(12.9, 1.655), (13.9, 1.655)])

    for ext in ("png", "svg", "pdf"):
        target = out / f"DL_IL_architecture_overview.{ext}"
        fig.savefig(target, dpi=180, facecolor="white")
        print(target)
    plt.close(fig)


if __name__ == "__main__":
    main()
