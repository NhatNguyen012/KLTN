"""Reproducible deployment status diagram: editable SVG + high-resolution PNG.
Reflects actual KLTN framework status: full control plane implemented,
29 unit/contract tests passing, validated run-12 model bundles, and model-gated runtime.
"""
from pathlib import Path
from html import escape
from PIL import Image, ImageDraw, ImageFont
import math

ROOT = Path(__file__).resolve().parent
W, H = 2400, 1840
im = Image.new('RGB', (W, H), 'white')
d = ImageDraw.Draw(im)
svg = [
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
    '<rect width="100%" height="100%" fill="white"/>'
]

C = {
    'ink': '#162b40',
    'muted': '#52657a',
    'green': '#16704a',
    'amber': '#a36709',
    'red': '#b33d43',
    'blue': '#146f9c',
    'pink': '#b83b68',
}

def font(n, b=False):
    return ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans' + ('-Bold' if b else '') + '.ttf', n)

def text(x, y, s, n=22, color=None, b=False):
    color = color or C['ink']
    d.text((x, y), s, font=font(n, b), fill=color)
    svg.append(f'<text x="{x}" y="{y + n * 0.94}" font-family="DejaVu Sans, sans-serif" font-size="{n}" font-weight="{"bold" if b else "normal"}" fill="{color}">{escape(s)}</text>')

def line(points, color=None, width=2, dash=False, arrow=False):
    color = color or C['ink']
    if not dash:
        d.line(points, fill=color, width=width)
    else:
        for (x1, y1), (x2, y2) in zip(points, points[1:]):
            dist = math.hypot(x2 - x1, y2 - y1)
            for start in range(0, int(dist), 16):
                a = start / max(dist, 1)
                b = min(start + 9, dist) / max(dist, 1)
                d.line((x1 + (x2 - x1) * a, y1 + (y2 - y1) * a, x1 + (x2 - x1) * b, y1 + (y2 - y1) * b), fill=color, width=width)
    svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x, y in points)}" fill="none" stroke="{color}" stroke-width="{width}"' + (' stroke-dasharray="9 7"' if dash else '') + '/>')
    if arrow:
        (x0, y0), (x, y) = points[-2:]
        a = math.atan2(y - y0, x - x0)
        pts = [(x, y), (x - 14 * math.cos(a - 0.45), y - 14 * math.sin(a - 0.45)), (x - 14 * math.cos(a + 0.45), y - 14 * math.sin(a + 0.45))]
        d.polygon(pts, fill=color)
        svg.append(f'<polygon points="{" ".join(f"{u},{v}" for u, v in pts)}" fill="{color}"/>')

def box(x, y, w, h, stroke='#aebac6', fill='white', dash=False):
    d.rectangle((x, y, x + w, y + h), fill=fill)
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}"/>')
    line([(x, y), (x + w, y), (x + w, y + h), (x, y + h), (x, y)], stroke, 2, dash)

def badge(x, y, label, color):
    w = int(d.textlength(label, font=font(20, True))) + 28
    box(x, y, w, 34, color, 'white')
    text(x + 14, y + 4, label, 20, color, True)

def icon(x, y, label, color):
    box(x, y, 58, 48, color, 'white')
    text(x + 8, y + 9, label, 21, color, True)
    line([(x + 29, y + 48), (x + 29, y + 55), (x + 10, y + 55)], color, 2)

def node(x, y, w, h, title, lines, tag='ON', color=None):
    color = color or C['green']
    bg = '#f7fbfa' if color == C['green'] else ('#fff9ed' if color == C['amber'] else '#f4f8fc')
    box(x, y, w, h, color, bg)
    icon(x + 16, y + 17, tag, color)
    text(x + 90, y + 17, title, 24, color, True)
    for i, s in enumerate(lines):
        text(x + 18, y + 76 + i * 29, s, 21)

# =====================================================================
# Header Section
# =====================================================================
text(45, 30, 'KLTN | DEPLOYMENT TOPOLOGY & ARCHITECTURE STATUS', 37, C['blue'], True)
text(47, 84, 'Snapshot: 05 November 2026  •  Full Framework Implemented  •  29 Unit/Contract Tests Pass  •  Validated Run-12 Bundles', 23)
badge(48, 126, 'GREEN: Implemented & Unit/Parity Tested', C['green'])
badge(560, 126, 'AMBER: Model-Gated / Standby / Candidate', C['amber'])
badge(1110, 126, 'BLUE: Automation & Infrastructure State', C['blue'])
text(1680, 133, 'All 29 Tests Passing • Fail-Closed by Design', 22, C['green'], True)

# =====================================================================
# Main Topology Box (Physical Host)
# =====================================================================
box(35, 180, 2330, 1170, '#273f55')
text(60, 196, 'PHYSICAL HOST: openstack-aio  |  Kolla OpenStack AIO + Central Services + Standby Detection Runtime', 26, b=True)

# ---------------------------------------------------------------------
# Left: OpenStack Nova Guest Instances
# ---------------------------------------------------------------------
box(60, 250, 750, 1075, C['pink'], dash=True)
text(82, 264, 'OPENSTACK NOVA GUEST INSTANCES', 26, C['pink'], True)

# Raw transport bus
for y in (475, 795, 1115):
    line([(785, y), (895, y)], C['blue'], 3)
line([(895, 475), (895, 1115)], C['blue'], 3)
line([(895, 485), (1045, 485)], C['blue'], 3, arrow=True)
text(825, 350, 'RAW', 22, C['blue'], True)
text(825, 378, 'HTTPS', 20, C['blue'], True)
text(825, 405, ':18443', 20, C['blue'])
text(825, 1165, '7 event', 19, C['blue'])
text(825, 1192, 'streams', 19, C['blue'])

# VM Card Helper
def vm(y, name, os_name, ip, subnet, is_windows=False):
    box(85, y, 700, 295, C['blue'])
    icon(105, y + 14, 'WIN' if is_windows else 'UB', C['blue'])
    text(182, y + 12, name + '  |  ' + os_name, 23, C['blue'], True)
    text(182, y + 46, 'Floating IP ' + ip + '  •  Subnet ' + subnet, 19)
    
    # Telemetry Collector
    box(105, y + 86, 660, 46, C['green'], '#f5faf7')
    text(118, y + 96, 'Sysmon + Security + PowerShell (7 event channels)' if is_windows else 'auditd + journald (Linux system telemetry)', 21, C['green'], True)
    
    # Local Ingest / Forwarder
    box(105, y + 146, 310, 48, C['green'], '#f5faf7')
    text(118, y + 158, 'Fluent Bit + disk buffer', 21, C['green'], True)
    line([(415, y + 170), (450, y + 170)], C['ink'], 2, arrow=True)
    box(450, y + 146, 315, 48, C['green'] if is_windows else C['amber'], '#f5faf7' if is_windows else '#fff9ed')
    text(462, y + 158, 'SQLite Inbox / Outbox' if is_windows else 'SQLite (Audit telemetry)', 21, C['green'] if is_windows else C['amber'], True)
    
    # Model runtime
    if is_windows:
        text(108, y + 210, 'Agent + LightGBM (host-ml-run12-v1 validated, 12,337 cols)', 21, C['green'], True)
        text(108, y + 242, 'WinSW Service • Score outbox -> Central /v1/scores (score.v1)', 20, C['ink'])
    else:
        text(108, y + 210, 'Agent collector • Linux domain (telemetry only, score fail-closed)', 21, C['amber'], True)
        text(108, y + 242, 'systemd service • No Linux model loaded (score null, by design)', 20, C['muted'])

vm(315, 'kltn-ubuntu-1', 'Ubuntu 24.04', '172.31.250.228', '10.30.1.0/24')
vm(635, 'kltn-ubuntu-2', 'Ubuntu 24.04', '172.31.250.208', '10.30.2.0/24')
vm(955, 'kltn-windows-1', 'Windows 11 LTSC', '172.31.250.236', '10.30.3.0/24', True)
text(95, 1282, 'Agent Ingress: 127.0.0.1:18081  •  Durable WAL dedup  •  Atomic score outbox', 20)

# ---------------------------------------------------------------------
# Top Right: Management & MLOps Automation
# ---------------------------------------------------------------------
box(850, 250, 1485, 95, C['blue'], '#f4f8fc')
text(870, 263, 'MANAGEMENT & AUTOMATION CONTROL PLANE ON PHYSICAL HOST', 24, C['blue'], True)
text(870, 301, 'Terraform (3 VMs, network, FIP)  |  Ansible site.yml  |  Promote/Rollout CLI  |  Response & Incremental Daemons', 21)

# ---------------------------------------------------------------------
# Center-Right: Docker Compose kltn-central
# ---------------------------------------------------------------------
box(1000, 370, 1335, 955, C['blue'], dash=True)
text(1020, 384, 'DOCKER COMPOSE: kltn-central  |  Central Ingestion, Storage, Scoring & Verification', 24, C['blue'], True)

# Row 1: Caddy, FastAPI Ingest, NATS JetStream
node(1045, 435, 350, 145, 'Caddy TLS', ['TLS :18443 Ingress', 'Per-host token auth', 'Lab interface only'], tag='TLS', color=C['green'])
node(1460, 435, 380, 145, 'FastAPI Central', ['Loopback :18080', 'POST /v1/events & /scores', 'SOC & Review APIs'], tag='API', color=C['green'])
node(1915, 435, 375, 145, 'NATS JetStream', ['Loopback :14222', 'Durable raw stream', 'Ack-after-persist'], tag='JS', color=C['green'])

line([(1395, 480), (1460, 480)], arrow=True)
line([(1840, 480), (1915, 480)], arrow=True)

# Row 2: Framework Worker, PostgreSQL, Archive Worker
node(1045, 650, 350, 185, 'Framework Worker', ['Calibrated Shadow Fusion', 'Source mask [m_h, m_n]', 'Alert & Drift snapshots', 'State: operational'], tag='FW', color=C['green'])
node(1460, 650, 380, 185, 'PostgreSQL DB', ['Loopback :15432', 'events & normalized_events', 'scores, alerts, drift_snapshots', 'serving_status heartbeat'], tag='DB', color=C['green'])
node(1915, 650, 375, 185, 'Archive Worker', ['Python -> PostgreSQL', 'Atomic DB transaction', 'Normalized Sysmon/audit view', 'Retry deduplication'], tag='PY', color=C['green'])

line([(1915, 715), (1840, 715)], arrow=True)
line([(1460, 715), (1395, 715)], arrow=True)

# Row 3: BiLSTM Worker & SOC UI / Response
node(1045, 910, 520, 215, 'BiLSTM Network DL Worker', [
    'PyTorch 2.7.1 • 15-min sequence builder',
    'network-dl-run12-v1 validated (p50: 4.41ms)',
    '4 categorical fields + delta_t_log1p',
    'Window score -> PostgreSQL scores table'
], tag='DL', color=C['green'])

node(1620, 910, 670, 215, 'SOC Verification & Active Response', [
    'Lightweight verification dashboard at /soc',
    'Analyst review workflow: needs_review -> confirmed',
    'kltn-response-controller: Neutron isolation request',
    'kltn-incremental-runner: Replay buffer & retrain loop'
], tag='SOC', color=C['green'])

line([(1565, 1000), (1620, 1000)], C['blue'], 2, arrow=True)

# Row 4: Security, boundaries & fail-closed policy
text(1045, 1165, 'Security, Provenance & Fail-Closed Boundaries', 23, b=True)
text(1045, 1200, 'Persistent Docker volumes  •  Runtime secrets outside source control  •  Fail-closed: missing models emit null, never false benign', 21)
text(1045, 1235, 'BiLSTM worker has no public port  •  Two detection branches: host_ml (LightGBM) + network_dl (BiLSTM); no GraphSAGE branch', 21)
text(1045, 1270, 'OpenStack Nova instances remain codified in Terraform/Ansible; ready for on-demand live deployment without code modification', 20, C['muted'])

# =====================================================================
# Bottom Section: Implementation Status of 14 Functions
# =====================================================================
text(45, 1385, 'FRAMEWORK IMPLEMENTATION & VALIDATION STATUS  |  14 ARCHITECTURAL FUNCTIONS', 28, C['ink'], True)

cols = [
    (45, 735, 'ENDPOINT & DETECTION LAYER', [
        ('Bounded Semantic Normalization (endpoint_normalization.py)', True),
        ('Local SQLite Inbox & Score Outbox with dedup (agent.py)', True),
        ('Validated LightGBM Engine (host-ml-run12-v1, F1: 0.874)', True),
        ('Central 15-min BiLSTM Engine (network-dl-run12-v1, F1: 1.0)', True),
        ('Process Lifetime & Causal Parity (Live VM benchmark pending)', False),
    ]),
    (820, 735, 'CENTRAL FUSION, SOC & RESPONSE', [
        ('PostgreSQL Raw JSONB & Normalized Tables (common.py)', True),
        ('Context-Aware Shadow Fusion Engine with source masks', True),
        ('SOC Verification Dashboard & Review APIs (GET /soc)', True),
        ('Closed-Loop Response Controller (kltn-response-controller)', True),
        ('OpenStack Neutron Isolation (Simulation & dry-run verified)', False),
    ]),
    (1595, 760, 'CLOSED-LOOP MLOPS LIFECYCLE', [
        ('Drift Snapshots & Retraining Triggers (framework.py)', True),
        ('Autonomous Incremental Runner (kltn-incremental-runner)', True),
        ('Model Registry Lifecycle (candidate -> validated -> active)', True),
        ('Golden Parity Fixtures (LightGBM & BiLSTM bit-exact pass)', True),
        ('Linux/THEIA Domain Model (Fail-closed by design; audit-only)', False),
    ])
]

for x, w, title, items in cols:
    box(x, 1430, w, 280, C['blue'], '#fffafa')
    text(x + 18, 1448, title, 23, C['blue'], True)
    for i, (s, is_done) in enumerate(items):
        icon_str = '✓ ' if is_done else '• '
        color = C['green'] if is_done else C['amber']
        text(x + 20, 1494 + i * 33, icon_str + s, 20, color, is_done)

text(48, 1740, 'All 29 contract, parity, inbox, outbox, fusion, and response unit tests passing. Fail-closed model gates prevent false benign scores.', 23, C['ink'], True)
text(48, 1780, 'Full pipeline source code implemented and validated locally. OpenStack infrastructure is automated via Terraform & Ansible.', 21, C['muted'])

# Save SVG and PNG
svg.append('</svg>')
(ROOT / 'KLTN-deployment-status.svg').write_text('\n'.join(svg))
im.save(ROOT / 'KLTN-deployment-status.png')
print(f"Successfully generated:\n- {ROOT / 'KLTN-deployment-status.svg'}\n- {ROOT / 'KLTN-deployment-status.png'}")
