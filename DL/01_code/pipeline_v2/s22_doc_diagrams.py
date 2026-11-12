#!/usr/bin/env python3
"""S22 - Vẽ 3 sơ đồ PNG cho các file Word: BiLSTM, Mixed-Type, pipeline raw -> shards. Cách dùng: python s22_doc_diagrams.py"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.stdout.reconfigure(encoding="utf-8")
OUT = Path("D:/UIT/KLTNv2/02_artifacts/39_dataset_word_v1/img")
FONT, FONTB = "C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"
ACC = (47, 95, 179)
COLORS = {"g": ((214, 236, 220), (20, 83, 45)), "b": ((219, 232, 251), (27, 61, 115)), "y": ((253, 240, 199), (107, 78, 0)), "p": ((230, 220, 247), (67, 38, 111)), "w": ((245, 245, 245), (70, 70, 70))}


def f(p, s):
    return ImageFont.truetype(p, s)


def arrow(d, x1, y, x2):
    d.line([x1, y, x2 - 14, y], fill=ACC, width=6)
    d.polygon([(x2, y), (x2 - 22, y - 12), (x2 - 22, y + 12)], fill=ACC)


def chain(name, W, H, boxes, title, foot=None, bw=None, gap=56, y0=130, bh=None, size=24):
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    d.text((W // 2, 44), title, font=f(FONTB, 38), fill=(31, 35, 40), anchor="mm")
    n = len(boxes)
    bw = bw or (W - 40 - gap * (n - 1)) // n
    bh = bh or (H - y0 - 90)
    for i, (num, head, lines, c) in enumerate(boxes):
        x = 20 + i * (bw + gap)
        fill, dark = COLORS[c]
        d.rounded_rectangle([x, y0, x + bw, y0 + bh], radius=22, fill=fill, outline=dark, width=4)
        d.ellipse([x + bw // 2 - 26, y0 - 26, x + bw // 2 + 26, y0 + 26], fill=dark)
        d.text((x + bw // 2, y0), num, font=f(FONTB, 30), fill=(255, 255, 255), anchor="mm")
        d.text((x + bw // 2, y0 + 62), head, font=f(FONTB, size + 4), fill=dark, anchor="mm")
        for j, ln in enumerate(lines):
            d.text((x + bw // 2, y0 + 112 + j * (size + 12)), ln, font=f(FONT, size), fill=(31, 35, 40), anchor="mm")
        if i < n - 1:
            arrow(d, x + bw + 6, y0 + bh // 2, x + bw + gap - 6)
    if foot:
        d.text((W // 2, H - 36), foot, font=f(FONT, 26), fill=(91, 100, 112), anchor="mm")
    im.save(OUT / name)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    chain("bilstm_flow.png", 1900, 500, [
        ("1", "Cửa sổ", ["≤ 512 flow của", "một máy, 15 phút", "mỗi flow: 4 id", "+ delta_t"], "g"),
        ("2", "Tra embedding", ["mỗi id → một vector", "app 16, proto 4,", "cổng 7, thư mục 6", "= 33 số + 2 số"], "b"),
        ("3", "Vector flow", ["gộp 35 số thành", "vector 64 chiều", "(mô tả một flow)"], "b"),
        ("4", "BiLSTM", ["đọc lần lượt các flow", "theo thời gian,", "cả hai chiều", "(xuôi và ngược)"], "y"),
        ("5", "Tóm tắt cửa sổ", ["vector 128 chiều", "gom ghi nhớ của", "hai chiều đọc"], "b"),
        ("6", "Phân loại", ["MLP 128 → 64 → 1", "sigmoid → xác suất", "≥ ngưỡng = tấn công"], "p"),
    ], "BiLSTM: từ cửa sổ flow đến xác suất tấn công", foot="Mỗi cửa sổ cho đúng một xác suất; nhãn cửa sổ = có ít nhất một flow dương", gap=50, size=24, bh=300)
    chain("mixed_flow.png", 1900, 500, [
        ("1", "6 token / flow", ["app_family, proto,", "resp_port_class,", "image_dir_class,", "cờ nhị phân, delta_t"], "g"),
        ("2", "Attention tầng 1", ["trong MỘT flow: mỗi", "token nhìn 5 token còn", "lại, chọn cái quan trọng", "(1 lớp, 4 đầu)"], "y"),
        ("3", "Vector flow", ["lấy trung bình 6 token", "→ vector 64 chiều"], "b"),
        ("4", "Thêm vị trí", ["cộng embedding vị trí:", "flow thứ mấy trong", "cửa sổ (tối đa 512)"], "b"),
        ("5", "Attention tầng 2", ["GIỮA các flow: mỗi flow", "nhìn các flow khác", "trong cửa sổ", "(2 lớp, 4 đầu)"], "y"),
        ("6", "Phân loại", ["trung bình các flow,", "MLP 64 → 64 → 1,", "sigmoid → xác suất"], "p"),
    ], "Mixed-Type Self-Attention: hai tầng attention", foot="Tầng 1 trộn các trường trong một flow; tầng 2 trộn các flow trong một cửa sổ", gap=50, size=24, bh=300)
    chain("pipeline_flow.png", 1900, 500, [
        ("0", "Raw", ["Bro conn.log.gz", "(TSV, 22 cột)", "eCAR-Bro", "ecarbro.json.gz"], "w"),
        ("S1", "Join", ["INNER JOIN", "uid = bro_uid", "→ flows_joined", ".parquet"], "g"),
        ("S2", "Cửa sổ + split", ["máy × 15 phút", "chia 70/15/15", "→ windows.csv"], "b"),
        ("S3", "Preprocess", ["chỉ fit trên TRAIN", "từ điển, mean/std", "→ preprocess_spec", ".json"], "y"),
        ("S4", "Shards", ["mã hóa từng flow,", "đóng gói sample", "→ .npz + samples.csv"], "b"),
        ("S5", "Kiểm tra", ["giải mã ngược 400", "sample, so với raw", "→ PASS"], "p"),
    ], "Từ raw đến shards: đầu vào và đầu ra từng bước", foot="Sau S5: train trên Kaggle (BiLSTM, Mixed-Type)", gap=44, size=23, bh=300)
    print("ok")


if __name__ == "__main__":
    main()
