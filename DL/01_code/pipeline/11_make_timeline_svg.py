"""STEP 11 — Ve timeline 29 host bi tan cong (gio EDT) thanh SVG (khong can matplotlib).

Doc scenario_hosts_29.csv (sinh boi 11_dataset_profile.py). Thanh = tu positive network event dau tien den cuoi cung cua host.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path

COLORS = {
    "132.197.158.98": "#2563eb",  # C2 "A": HTTP :80, nhip ~5 giay
    "202.6.172.98": "#ea580c",    # C2 "B": HTTPS :443, nhip ~30 giay
    "53.192.68.50": "#dc2626",    # C2 SC3
}
LABELS = {"132.197.158.98": "C2 A: 132.197.158.98 (HTTP :80, ~5 s)",
          "202.6.172.98": "C2 B: 202.6.172.98 (HTTPS :443, ~30 s)",
          "53.192.68.50": "C2 SC3: 53.192.68.50 (:80/:8080)"}
SCEN_TITLE = {"scenario_1": "SC1 (23/9)", "scenario_2": "SC2 (24-25/9)", "scenario_3": "SC3 (25/9)"}


def hours(s: str) -> float:
    d = datetime.strptime("2019-" + s, "%Y-%m-%d %H:%M")
    return (d - datetime(2019, 9, 23)).total_seconds() / 3600


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows = list(csv.DictReader(open(a.csv, encoding="utf-8")))
    rows.sort(key=lambda r: (r["scenario"], hours(r["first_pos_edt"]) if r["first_pos_edt"] else 999, r["hostname"]))

    W, left, top, rh = 1280, 190, 70, 20
    plot_w = W - left - 40
    t0, t1 = 0.0, 72.0
    x = lambda h: left + (h - t0) / (t1 - t0) * plot_w
    H = top + rh * (len(rows) + 6) + 90
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="Segoe UI, Arial, sans-serif" font-size="12">',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         f'<text x="{left}" y="24" font-size="16" font-weight="bold">Thoi gian cac host bi tan cong (positive network event, gio EDT = UTC-4)</text>',
         f'<text x="{left}" y="42" fill="#555">Moi thanh: tu flow positive dau tien den cuoi cung cua host; mau = may chu C2 chinh. Muc tieu: nhin SC1/SC2/SC3 dien ra khi nao.</text>']
    # truc ngay/gio
    for d in range(3):
        xd = x(24 * d)
        o.append(f'<line x1="{xd}" y1="{top - 8}" x2="{xd}" y2="{top + rh * (len(rows) + 3)}" stroke="#444" stroke-width="1.5"/>')
        o.append(f'<text x="{xd + 4}" y="{top - 14}" font-weight="bold">{23 + d}/9</text>')
        for hh in range(6, 24, 6):
            xh = x(24 * d + hh)
            o.append(f'<line x1="{xh}" y1="{top - 4}" x2="{xh}" y2="{top + rh * (len(rows) + 3)}" stroke="#ddd"/>')
            o.append(f'<text x="{xh - 8}" y="{top + rh * (len(rows) + 3) + 14}" fill="#666">{hh:02d}h</text>')
    y = top
    prev = None
    for r in rows:
        if r["scenario"] != prev:
            y += 6
            o.append(f'<text x="8" y="{y + 14}" font-weight="bold" fill="#111">{SCEN_TITLE[r["scenario"]]}</text>')
            prev = r["scenario"]
        name = r["hostname"].replace("sysclient", "host ")
        o.append(f'<text x="{left - 8}" y="{y + 14}" text-anchor="end">{name}</text>')
        if r["first_pos_edt"]:
            ip = r["main_endpoint"].split(":")[0]
            xa, xb = x(hours(r["first_pos_edt"])), x(hours(r["last_pos_edt"]))
            o.append(f'<rect x="{xa:.1f}" y="{y + 3}" width="{max(xb - xa, 3):.1f}" height="{rh - 7}" fill="{COLORS.get(ip, "#666")}" rx="2"/>')
            o.append(f'<text x="{xb + 6:.1f}" y="{y + 14}" fill="#333" font-size="11">{int(float(r["net_positive_events"])):,} ev | {r["first_pos_edt"][6:]}-{r["last_pos_edt"][6:]}</text>')
        else:
            o.append(f'<text x="{left + 6}" y="{y + 14}" fill="#888" font-size="11">khong co positive network event (chi co nhan o host eCAR)</text>')
        y += rh
    ly = top + rh * (len(rows) + 3) + 36
    lx = left
    for ip, lab in LABELS.items():
        o.append(f'<rect x="{lx}" y="{ly}" width="14" height="12" fill="{COLORS[ip]}"/><text x="{lx + 20}" y="{ly + 11}">{lab}</text>')
        lx += 330
    o.append("</svg>")
    Path(a.out).write_text("\n".join(o), encoding="utf-8", newline="\n")
    print("[WROTE]", a.out)


if __name__ == "__main__":
    main()
