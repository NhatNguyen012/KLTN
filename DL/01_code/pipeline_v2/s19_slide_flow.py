#!/usr/bin/env python3
"""S19b - Vẽ slide flow incremental learning đơn giản (PNG 1920x1080 + SVG). Cách dùng: python s19_slide_flow.py"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.stdout.reconfigure(encoding="utf-8")
OUT = Path("D:/UIT/KLTNv2/02_artifacts/38_slide_records_v1")
W, H = 1920, 1080
FONT = "C:/Windows/Fonts/segoeui.ttf"
FONTB = "C:/Windows/Fonts/segoeuib.ttf"
BG, FG, MUT, ACC = (255, 255, 255), (31, 35, 40), (91, 100, 112), (47, 95, 179)

STEPS = [
    ("1", "Mô hình gốc", ["Đã train trên OpTC", "(BiLSTM, Mixed-Type)"], (214, 236, 220), (20, 83, 45)),
    ("2", "Mở rộng từ điển", ["Thêm token mới của", "THEIA, ATLASv2", "(hàng mới = bản sao UNK)"], (219, 232, 251), (27, 61, 115)),
    ("3", "Đầu vào", ["5 trường chuẩn hóa:", "app_family, proto,", "resp_port_class,", "image_dir_class, delta_t"], (253, 240, 199), (107, 78, 0)),
    ("4", "Fine-tune", ["Học thêm trên dữ liệu mới", "(tốc độ học nhỏ)"], (219, 232, 251), (27, 61, 115)),
    ("5", "Đánh giá", ["F1 trên THEIA, ATLASv2", "F1 trên OpTC", "(có bị quên không)"], (230, 220, 247), (67, 38, 111)),
]
CHIPS3 = ["THEIA", "ATLASv2", "OpTC (một phần, replay)"]
CW, GAP, X0, Y0, CH = 340, 46, 18, 330, 360


def font(path, size):
    return ImageFont.truetype(path, size)


def png():
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.text((W // 2, 90), "Incremental learning (fine-tune): hướng thực hiện", font=font(FONTB, 56), fill=FG, anchor="mm")
    d.text((W // 2, 160), "Từ mô hình đã train trên OpTC, học thêm dữ liệu mới mà không train lại từ đầu", font=font(FONT, 32), fill=MUT, anchor="mm")
    for i, (n, title, lines, col, dark) in enumerate(STEPS):
        x = X0 + i * (CW + GAP)
        d.rounded_rectangle([x, Y0, x + CW, Y0 + CH], radius=28, fill=col, outline=dark, width=4)
        d.ellipse([x + CW // 2 - 36, Y0 - 36, x + CW // 2 + 36, Y0 + 36], fill=dark)
        d.text((x + CW // 2, Y0), n, font=font(FONTB, 44), fill=(255, 255, 255), anchor="mm")
        d.text((x + CW // 2, Y0 + 85), title, font=font(FONTB, 38), fill=dark, anchor="mm")
        for j, ln in enumerate(lines):
            d.text((x + CW // 2, Y0 + 150 + j * 46), ln, font=font(FONT, 26), fill=FG, anchor="mm")
        if i < len(STEPS) - 1:
            ax = x + CW + 4
            ay = Y0 + CH // 2
            d.line([ax, ay, ax + GAP - 18, ay], fill=ACC, width=7)
            d.polygon([(ax + GAP - 8, ay), (ax + GAP - 26, ay - 15), (ax + GAP - 26, ay + 15)], fill=ACC)
    # nguồn dữ liệu đưa vào bước 3
    x3 = X0 + 2 * (CW + GAP)
    cx = x3 + CW // 2
    yy = Y0 + CH + 70
    d.line([cx, Y0 + CH + 6, cx, yy - 70 + 40], fill=ACC, width=6)
    d.polygon([(cx, Y0 + CH + 4), (cx - 14, Y0 + CH + 30), (cx + 14, Y0 + CH + 30)], fill=ACC)
    widths = [190, 210, 420]
    gap = 24
    total = sum(widths) + gap * 2
    sx = cx - total // 2
    for t, w in zip(CHIPS3, widths):
        d.rounded_rectangle([sx, yy + 10, sx + w, yy + 80], radius=18, fill=(255, 255, 255), outline=ACC, width=3)
        d.text((sx + w // 2, yy + 45), t, font=font(FONTB, 30), fill=ACC, anchor="mm")
        sx += w + gap
    d.text((cx, yy + 120), "dữ liệu mới + một phần OpTC để không quên", font=font(FONT, 28), fill=MUT, anchor="mm")
    im.save(OUT / "4_slide_flow_incremental.png")


def svg():
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="Segoe UI, Arial, sans-serif">',
         f'<rect width="{W}" height="{H}" fill="#fff"/>',
         '<text x="960" y="105" font-size="56" font-weight="700" text-anchor="middle" fill="#1f2328">Incremental learning (fine-tune): hướng thực hiện</text>',
         '<text x="960" y="170" font-size="32" text-anchor="middle" fill="#5b6470">Từ mô hình đã train trên OpTC, học thêm dữ liệu mới mà không train lại từ đầu</text>']
    rgb = lambda c: "#%02x%02x%02x" % c
    for i, (n, title, lines, col, dark) in enumerate(STEPS):
        x = X0 + i * (CW + GAP)
        s.append(f'<rect x="{x}" y="{Y0}" width="{CW}" height="{CH}" rx="28" fill="{rgb(col)}" stroke="{rgb(dark)}" stroke-width="4"/>')
        s.append(f'<circle cx="{x + CW // 2}" cy="{Y0}" r="36" fill="{rgb(dark)}"/><text x="{x + CW // 2}" y="{Y0 + 15}" font-size="44" font-weight="700" text-anchor="middle" fill="#fff">{n}</text>')
        s.append(f'<text x="{x + CW // 2}" y="{Y0 + 98}" font-size="38" font-weight="700" text-anchor="middle" fill="{rgb(dark)}">{title}</text>')
        for j, ln in enumerate(lines):
            s.append(f'<text x="{x + CW // 2}" y="{Y0 + 160 + j * 46}" font-size="26" text-anchor="middle" fill="#1f2328">{ln}</text>')
        if i < len(STEPS) - 1:
            ax, ay = x + CW + 4, Y0 + CH // 2
            s.append(f'<path d="M{ax} {ay} L{ax + GAP - 18} {ay}" stroke="#2f5fb3" stroke-width="7"/><path d="M{ax + GAP - 8} {ay} L{ax + GAP - 26} {ay - 15} L{ax + GAP - 26} {ay + 15}Z" fill="#2f5fb3"/>')
    x3 = X0 + 2 * (CW + GAP)
    cx = x3 + CW // 2
    yy = Y0 + CH + 70
    s.append(f'<path d="M{cx} {Y0 + CH + 6} L{cx} {yy + 10}" stroke="#2f5fb3" stroke-width="6"/><path d="M{cx} {Y0 + CH + 4} L{cx - 14} {Y0 + CH + 30} L{cx + 14} {Y0 + CH + 30}Z" fill="#2f5fb3"/>')
    widths = [190, 210, 420]
    sx = cx - (sum(widths) + 48) // 2
    for t, w in zip(CHIPS3, widths):
        s.append(f'<rect x="{sx}" y="{yy + 10}" width="{w}" height="70" rx="18" fill="#fff" stroke="#2f5fb3" stroke-width="3"/><text x="{sx + w // 2}" y="{yy + 55}" font-size="30" font-weight="700" text-anchor="middle" fill="#2f5fb3">{t}</text>')
        sx += w + 24
    s.append(f'<text x="{cx}" y="{yy + 130}" font-size="28" text-anchor="middle" fill="#5b6470">dữ liệu mới + một phần OpTC để không quên</text>')
    s.append("</svg>")
    (OUT / "4_slide_flow_incremental.svg").write_text("\n".join(s), encoding="utf-8")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    png()
    svg()
    print("ok")
