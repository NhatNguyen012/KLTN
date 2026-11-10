#!/usr/bin/env python3
"""Render the KLTN deployment topology poster.

Brand marks are sourced from Simple Icons v16, except Windows and LightGBM,
which are sourced from Wikimedia Commons. The renderer expects the downloaded
SVG files in /tmp/kltn-deployment-icons and publishes deployment.png beside
this script.
"""
from __future__ import annotations

import math
from pathlib import Path
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

TEMP_DEPS = Path("/tmp/kltn-diagram-deps")
if TEMP_DEPS.is_dir():
    sys.path.insert(0, str(TEMP_DEPS))
import cairosvg


ROOT = Path(__file__).resolve().parent
ICON_ROOT = Path("/tmp/kltn-deployment-icons")
OUT = ROOT / "deployment.png"

W, H = 4200, 2550
BG = "#F7F9FC"
INK = "#172033"
MUTED = "#596579"
LINE = "#CBD5E1"
BLUE = "#1677C8"
BLUE_LIGHT = "#EAF4FD"
RED = "#E44747"
RED_LIGHT = "#FFF0F0"
PURPLE = "#7456C8"
PURPLE_LIGHT = "#F3EFFF"
GREEN = "#168A5B"
GREEN_LIGHT = "#EAF8F2"
AMBER = "#C47B12"
AMBER_LIGHT = "#FFF7E5"
CYAN = "#168DA0"

BRAND = {
    "windows11": "#0078D4",
    "ubuntu": "#E95420",
    "linux": "#111827",
    "fluentbit": "#49BDA5",
    "sqlite": "#003B57",
    "python": "#3776AB",
    "fastapi": "#009688",
    "lightgbm": "#2F8F46",
    "caddy": "#1F88C0",
    "natsdotio": "#27AAE1",
    "postgresql": "#4169E1",
    "pytorch": "#EE4C2C",
    "docker": "#2496ED",
    "openstack": "#ED1944",
    "terraform": "#844FBA",
    "ansible": "#EE0000",
}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    suffix = "-Bold" if bold else ""
    return ImageFont.truetype(
        f"/usr/share/fonts/truetype/dejavu/DejaVuSans{suffix}.ttf", size
    )


im = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(im)


def rr(box, radius=24, fill="white", outline=LINE, width=3):
    d.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def label(x, y, value, size=30, color=INK, bold=False, anchor="la"):
    d.text((x, y), value, font=font(size, bold), fill=color, anchor=anchor)


def wrapped(x, y, value, width_chars, size=25, color=MUTED, bold=False,
            line_gap=8, anchor="la"):
    lines = textwrap.wrap(value, width=width_chars, break_long_words=False)
    for idx, line in enumerate(lines):
        label(x, y + idx * (size + line_gap), line, size, color, bold, anchor)
    return len(lines) * (size + line_gap)


def tint_icon(name: str, max_w: int, max_h: int) -> Image.Image:
    svg = ICON_ROOT / f"{name}.svg"
    png = ICON_ROOT / f"{name}.png"
    if not svg.is_file():
        raise FileNotFoundError(f"Missing icon: {svg}")
    # Always rasterize with CairoSVG so the result does not depend on an older
    # ImageMagick conversion left in the temporary icon cache.
    cairosvg.svg2png(bytestring=svg.read_bytes(), write_to=str(png), output_width=512)
    raw = Image.open(png).convert("RGBA")
    alpha = raw.getchannel("A")
    colored = Image.new("RGBA", raw.size, BRAND[name])
    colored.putalpha(alpha)
    ratio = min(max_w / colored.width, max_h / colored.height)
    return colored.resize(
        (max(1, int(colored.width * ratio)), max(1, int(colored.height * ratio))),
        Image.Resampling.LANCZOS,
    )


def icon(name: str, cx: int, cy: int, max_w=80, max_h=80):
    img = tint_icon(name, max_w, max_h)
    im.paste(img, (int(cx - img.width / 2), int(cy - img.height / 2)), img)


def arrow(points, color=INK, width=5, dashed=False, head=18):
    if dashed:
        for a, b in zip(points, points[1:]):
            dx, dy = b[0] - a[0], b[1] - a[1]
            dist = max(1.0, math.hypot(dx, dy))
            ux, uy = dx / dist, dy / dist
            pos = 0.0
            while pos < dist:
                end = min(pos + 18, dist)
                d.line((a[0] + ux * pos, a[1] + uy * pos,
                        a[0] + ux * end, a[1] + uy * end), fill=color, width=width)
                pos += 31
    else:
        d.line(points, fill=color, width=width, joint="curve")
    a, b = points[-2], points[-1]
    ang = math.atan2(b[1] - a[1], b[0] - a[0])
    left = (b[0] - head * math.cos(ang - 0.55), b[1] - head * math.sin(ang - 0.55))
    right = (b[0] - head * math.cos(ang + 0.55), b[1] - head * math.sin(ang + 0.55))
    d.polygon([b, left, right], fill=color)


def pill(x, y, text, fill, color, width=None):
    f = font(22, True)
    natural = int(d.textlength(text, font=f)) + 34
    w = width or natural
    rr((x, y, x + w, y + 42), 20, fill, fill, 1)
    label(x + w / 2, y + 21, text, 22, color, True, "mm")
    return w


def section(x, y, w, h, title, subtitle, color, fill):
    rr((x, y, x + w, y + h), 32, "white", color, 5)
    d.rounded_rectangle((x, y, x + w, y + 112), radius=30, fill=fill)
    d.rectangle((x, y + 76, x + w, y + 112), fill=fill)
    label(x + 35, y + 33, title, 37, color, True)
    label(x + 35, y + 78, subtitle, 23, MUTED)


def vm_card(x, y, w, h, icon_name, title, subtitle, border, status, status_fill,
            status_color):
    rr((x, y, x + w, y + h), 28, "#FCFDFE", border, 3)
    rr((x + 24, y + 22, x + 112, y + 110), 20, "white", LINE, 2)
    icon(icon_name, x + 68, y + 66, 58, 58)
    label(x + 135, y + 34, title, 30, INK, True)
    label(x + 135, y + 76, subtitle, 21, MUTED)
    pw = int(d.textlength(status, font=font(20, True))) + 30
    pill(x + w - pw - 25, y + 33, status, status_fill, status_color, pw)


def tool_card(x, y, w, h, icons, title, subtitle, border=LINE, fill="white",
              badge=None, badge_fill=GREEN_LIGHT, badge_color=GREEN):
    rr((x, y, x + w, y + h), 22, fill, border, 3)
    if not isinstance(icons, (tuple, list)):
        icons = [icons]
    spacing = 74
    start = x + 58 - (len(icons) - 1) * spacing / 2
    for idx, name in enumerate(icons):
        icon(name, int(start + idx * spacing), y + h // 2, 64, 64)
    tx = x + 110 if len(icons) == 1 else x + 155
    badge_space = 0
    if badge:
        badge_space = int(d.textlength(badge, font=font(18, True))) + 52
    available = max(120, w - (tx - x) - badge_space - 20)
    title_size = 26
    while title_size > 19 and d.textlength(title, font=font(title_size, True)) > available:
        title_size -= 1
    label(tx, y + 30, title, title_size, INK, True)
    wrapped(tx, y + 67, subtitle, max(18, int((w - (tx - x) - 26) / 13)), 20, MUTED)
    if badge:
        bw = int(d.textlength(badge, font=font(18, True))) + 24
        pill(x + w - bw - 16, y + 14, badge, badge_fill, badge_color, bw)


def mini_tool(x, y, w, icon_name, title, subtitle, border=LINE):
    tool_card(x, y, w, 132, icon_name, title, subtitle, border)


# Header
label(90, 68, "KLTN APT DETECTION", 54, BLUE, True)
label(90, 132, "Deployment Topology", 42, RED, True)
label(90, 190,
      "OpenStack end hosts  •  durable telemetry  •  model-gated detection  •  SOC & MLOps control plane",
      25, MUTED)

pill(3250, 75, "RAW HTTPS", BLUE_LIGHT, BLUE)
pill(3440, 75, "SCORE.V1", GREEN_LIGHT, GREEN)
pill(3635, 75, "APPROVAL GATED", AMBER_LIGHT, AMBER)
pill(3905, 75, "FAIL CLOSED", RED_LIGHT, RED)

# Infrastructure strip
rr((80, 250, 4120, 430), 28, "#0F1E32", "#0F1E32", 1)
label(120, 288, "INFRASTRUCTURE & AUTOMATION", 27, "#A9C9EA", True)
label(120, 337, "Physical host: openstack-aio  |  Kolla OpenStack AIO  |  Central services on Docker Compose",
      24, "white")

infra = [
    ("openstack", "OpenStack", "Nova • Neutron • Kolla"),
    ("terraform", "Terraform", "VM • network • FIP"),
    ("ansible", "Ansible", "Sensors • agents • rollout"),
    ("docker", "Docker Compose", "Central service runtime"),
]
ix = 2180
for name, title, sub in infra:
    rr((ix, 274, ix + 445, 408), 20, "#172B45", "#35506F", 2)
    icon(name, ix + 58, 341, 62, 62)
    label(ix + 105, 300, title, 24, "white", True)
    label(ix + 105, 345, sub, 18, "#BDD0E5")
    ix += 475

# Main sections
section(80, 470, 1260, 1810, "END HOSTS", "OpenStack Nova instances • native OS telemetry", BLUE, BLUE_LIGHT)
section(1440, 470, 1650, 1810, "CENTRAL DETECTION PLATFORM", "Physical host • Docker Compose • loopback data plane", RED, RED_LIGHT)
section(3190, 470, 930, 1810, "SOC • RESPONSE • MLOPS", "Approval-gated control plane and lifecycle", PURPLE, PURPLE_LIGHT)

# End hosts — Windows
vm_card(125, 610, 1170, 760, "windows11", "Nova VM — Windows 11 LTSC",
        "Supported Host ML domain: windows-sysmon", BLUE, "MODEL GATED", GREEN_LIGHT, GREEN)

mini_tool(165, 750, 330, "windows11", "OS telemetry", "Host process, file, registry and script activity", BLUE)
mini_tool(550, 750, 330, "windows11", "Sysmon + Event Logs", "Sysmon • Security 4688 • PowerShell 4104", BLUE)
mini_tool(935, 750, 320, "fluentbit", "Fluent Bit 5.1.5", "TLS fan-out with filesystem buffers", CYAN)
arrow([(495, 816), (550, 816)], BLUE, 5)
arrow([(880, 816), (935, 816)], BLUE, 5)

mini_tool(165, 1030, 330, "sqlite", "SQLite WAL", "50k / 128 MiB inbox + durable score outbox", BRAND["sqlite"])
mini_tool(550, 1030, 330, "fastapi", "Python Agent", "FastAPI/Uvicorn loopback :18081", BRAND["fastapi"])
mini_tool(935, 1030, 320, "lightgbm", "LightGBM 4.6", "12,337 binary sparse features", BRAND["lightgbm"])
arrow([(1095, 882), (1095, 965), (330, 965), (330, 1030)], CYAN, 5)
arrow([(495, 1096), (550, 1096)], GREEN, 5)
arrow([(880, 1096), (935, 1096)], GREEN, 5)

pill(165, 1220, "RAW → CENTRAL", BLUE_LIGHT, BLUE)
pill(395, 1220, "LOCAL NORMALIZATION", GREEN_LIGHT, GREEN)
pill(700, 1220, "SHADOW SCORE", AMBER_LIGHT, AMBER)
pill(935, 1220, "WinSW SERVICE", PURPLE_LIGHT, PURPLE)

# End hosts — Ubuntu
vm_card(125, 1420, 1170, 720, "ubuntu", "2 × Nova VM — Ubuntu 24.04",
        "Linux/THEIA collection domain", BLUE, "TELEMETRY ONLY", AMBER_LIGHT, AMBER)

mini_tool(165, 1560, 330, "linux", "auditd + journald", "Bounded audit rules • SSH/journal sources", BLUE)
mini_tool(550, 1560, 330, "fluentbit", "Fluent Bit", "TLS raw forwarding + disk buffer", CYAN)
mini_tool(935, 1560, 320, "sqlite", "SQLite WAL", "Local durable inbox / collection state", BRAND["sqlite"])
arrow([(495, 1626), (550, 1626)], BLUE, 5)
arrow([(880, 1626), (935, 1626)], BLUE, 5)

mini_tool(165, 1840, 330, "python", "Python Agent", "systemd-supervised collector", BRAND["python"])
tool_card(550, 1840, 705, 132, ["linux", "lightgbm"], "Fail-closed inference boundary",
          "No Linux model loaded • unsupported_domain • score remains null",
          AMBER, AMBER_LIGHT, "NO MODEL", RED_LIGHT, RED)
arrow([(1095, 1692), (1095, 1775), (330, 1775), (330, 1840)], CYAN, 5)
arrow([(495, 1906), (550, 1906)], AMBER, 5)
pill(165, 2030, "RAW ARCHIVE CONTINUES", BLUE_LIGHT, BLUE)
pill(485, 2030, "NO FALSE BENIGN", RED_LIGHT, RED)
pill(745, 2030, "systemd SERVICE", PURPLE_LIGHT, PURPLE)

# Central — ingress
label(1490, 618, "01  INGEST & DURABLE QUEUE", 25, RED, True)
mini_tool(1490, 675, 430, "caddy", "Caddy 2.10", "TLS :18443 • per-host bearer auth", BRAND["caddy"])
mini_tool(1975, 675, 500, "fastapi", "FastAPI Central", "Raw + score APIs • bounded requests", BRAND["fastapi"])
mini_tool(2530, 675, 510, "natsdotio", "NATS JetStream 2.11", "File-backed KLTN_EVENTS work queue", BRAND["natsdotio"])
arrow([(1920, 741), (1975, 741)], RED, 5)
arrow([(2475, 741), (2530, 741)], RED, 5)

# Central — archive
label(1490, 900, "02  NORMALIZE & STORE", 25, RED, True)
tool_card(1490, 955, 630, 150, ["python", "fastapi"], "Archive / Normalization Worker",
          "Common event schema • dedup • ACK-after-commit", BRAND["python"])
tool_card(2180, 955, 860, 150, "postgresql", "PostgreSQL 17",
          "events • normalized_events • scores • alerts • reviews • registry", BRAND["postgresql"])
arrow([(2785, 807), (2785, 895), (1805, 895), (1805, 955)], RED, 5)
arrow([(2120, 1030), (2180, 1030)], BRAND["postgresql"], 5)

# Central — inference
label(1490, 1180, "03  MODEL-GATED INFERENCE", 25, RED, True)
tool_card(1490, 1235, 720, 160, ["lightgbm", "sqlite"], "Host ML score relay",
          "Endpoint score_outbox → /v1/scores → durable score table", GREEN)
tool_card(2270, 1235, 770, 160, "pytorch", "Network DL — BiLSTM",
          "PyTorch 2.7 CPU • 15-minute windows • max 512 events", BRAND["pytorch"],
          badge="SHADOW", badge_fill=AMBER_LIGHT, badge_color=AMBER)
arrow([(1750, 1105), (1750, 1235)], GREEN, 5)
arrow([(2610, 1105), (2610, 1235)], BRAND["pytorch"], 5)

# Central — fusion/SOC
label(1490, 1485, "04  FUSION, EVIDENCE & VERIFICATION", 25, RED, True)
tool_card(1490, 1540, 650, 170, "python", "Availability-gated Fusion",
          "Weighted risk • explicit source masks • 900-second buckets", PURPLE)
tool_card(2200, 1540, 420, 170, "postgresql", "Alerts & Evidence",
          "Risk, score refs, normalized event references", BRAND["postgresql"])
tool_card(2680, 1540, 360, 170, "fastapi", "SOC Portal",
          "GET /soc • review workflow", BRAND["fastapi"])
arrow([(2210, 1395), (2210, 1470), (1815, 1470), (1815, 1540)], GREEN, 5)
arrow([(2655, 1395), (2655, 1470), (1815, 1470)], BRAND["pytorch"], 5)
arrow([(2140, 1625), (2200, 1625)], PURPLE, 5)
arrow([(2620, 1625), (2680, 1625)], PURPLE, 5)

# Central operational detail strip
rr((1490, 1800, 3040, 2185), 24, "#FCFDFE", LINE, 3)
label(1530, 1840, "RUNTIME BOUNDARIES", 24, INK, True)
details = [
    ("docker", "Containers", "read-only rootfs • bounded CPU/RAM • rotated json logs"),
    ("postgresql", "Durability", "PostgreSQL volume + idempotent event/score identities"),
    ("natsdotio", "Backpressure", "512 MiB file stream • retry / NAK archive worker"),
    ("python", "Model policy", "missing/incompatible model = unavailable, never benign"),
]
for idx, (ic, title, sub) in enumerate(details):
    col = idx % 2
    row = idx // 2
    x = 1530 + col * 755
    y = 1900 + row * 120
    icon(ic, x + 36, y + 43, 58, 58)
    label(x + 82, y + 14, title, 23, INK, True)
    wrapped(x + 82, y + 50, sub, 48, 19, MUTED)

# MLOps and response cards
tool_card(3240, 620, 830, 205, "python", "Drift & Trigger Worker",
          "24h categorical PSI ≥ 0.25 • monthly • every 100 verified labels",
          PURPLE, "white", "REQUEST ONLY", AMBER_LIGHT, AMBER)

tool_card(3240, 875, 830, 205, "lightgbm", "Incremental Learning Runner",
          "Approval-gated continual LightGBM candidate generation",
          BRAND["lightgbm"], "white", "EXTERNAL DAEMON", PURPLE_LIGHT, PURPLE)

tool_card(3240, 1130, 830, 205, ["postgresql", "python"], "Evaluation & Model Registry",
          "candidate → validated → canary → active • SHA256 artifact inventory",
          BRAND["postgresql"])

tool_card(3240, 1385, 830, 205, ["ansible", "docker"], "Validated Rollout",
          "Ansible Windows model deploy • staged DL bundle + container recreate",
          BRAND["ansible"], "white", "EXPLICIT", GREEN_LIGHT, GREEN)

tool_card(3240, 1640, 830, 205, ["python", "openstack"], "Response Controller",
          "Confirmed alert + separate approval → Neutron quarantine / release",
          RED, "white", "ROLLBACK", RED_LIGHT, RED)

tool_card(3240, 1895, 830, 205, ["terraform", "openstack"], "Infrastructure Controller",
          "Nova instance identity • Neutron port security groups • Terraform state",
          BRAND["openstack"])

for y1, y2 in [(825, 875), (1080, 1130), (1335, 1385)]:
    arrow([(3655, y1), (3655, y2)], PURPLE, 5)
arrow([(3655, 1590), (3655, 1640)], RED, 5)
arrow([(3655, 1845), (3655, 1895)], RED, 5)

# Cross-section buses
# Windows raw -> Caddy
arrow([(1255, 816), (1385, 816), (1385, 741), (1490, 741)], BLUE, 7)
label(1375, 785, "RAW HTTPS", 19, BLUE, True, "ra")
# Ubuntu raw -> Caddy
arrow([(880, 1626), (1385, 1626), (1385, 790), (1490, 790)], BLUE, 6)
# Windows score -> host score relay
arrow([(1255, 1096), (1405, 1096), (1405, 1315), (1490, 1315)], GREEN, 7)
label(1400, 1275, "SCORE.V1", 19, GREEN, True, "ra")
# Registry rollout back to endpoint
arrow([(3240, 1490), (3140, 1490), (3140, 2230), (110, 2230), (110, 1180), (165, 1180)], PURPLE, 5, True)
label(2020, 2210, "VALIDATED MODEL ROLLOUT", 20, PURPLE, True, "mm")
# Response controller to OpenStack infrastructure
arrow([(4070, 1740), (4145, 1740), (4145, 340), (4080, 340)], RED, 5, True)

# Footer and legend
label(90, 2360, "DATA FLOW", 22, INK, True)
d.line((235, 2375, 330, 2375), fill=BLUE, width=7)
label(350, 2375, "Raw telemetry", 20, MUTED, anchor="lm")
d.line((540, 2375, 635, 2375), fill=GREEN, width=7)
label(655, 2375, "Model scores", 20, MUTED, anchor="lm")
d.line((850, 2375, 945, 2375), fill=PURPLE, width=5)
label(965, 2375, "Lifecycle rollout", 20, MUTED, anchor="lm")
d.line((1225, 2375, 1320, 2375), fill=RED, width=5)
label(1340, 2375, "Response action", 20, MUTED, anchor="lm")

label(90, 2445,
      "Brand icons: Simple Icons v16; Windows and LightGBM marks: Wikimedia Commons. Product names and marks belong to their respective owners.",
      18, "#778397")
label(4110, 2445, "KLTN • generated 07 Nov 2026", 18, "#778397", anchor="ra")

im.save(OUT, optimize=True)
print(OUT)
