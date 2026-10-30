"""Reproducible deployment status diagram: editable SVG + high-resolution PNG.
Uses Pillow only; diagram geometry/text are source-controlled, no model-generated labels.
"""
from pathlib import Path
from html import escape
from PIL import Image, ImageDraw, ImageFont
import math
ROOT=Path(__file__).resolve().parent
W,H=2400,1840
im=Image.new('RGB',(W,H),'white'); d=ImageDraw.Draw(im)
svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">', '<rect width="100%" height="100%" fill="white"/>']
C={'ink':'#162b40','muted':'#52657a','green':'#16704a','amber':'#a36709','red':'#b33d43','blue':'#146f9c','pink':'#e74370'}
def font(n,b=False):return ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans'+('-Bold' if b else '')+'.ttf',n)
def text(x,y,s,n=22,color=None,b=False):
 color=color or C['ink'];d.text((x,y),s,font=font(n,b),fill=color)
 svg.append(f'<text x="{x}" y="{y+n*.94}" font-family="DejaVu Sans, sans-serif" font-size="{n}" font-weight="{"bold" if b else "normal"}" fill="{color}">{escape(s)}</text>')
def line(points,color=None,width=2,dash=False,arrow=False):
 color=color or C['ink']
 if not dash:d.line(points,fill=color,width=width)
 else:
  for (x1,y1),(x2,y2) in zip(points,points[1:]):
   dist=math.hypot(x2-x1,y2-y1)
   for start in range(0,int(dist),16):
    a=start/max(dist,1);b=min(start+9,dist)/max(dist,1)
    d.line((x1+(x2-x1)*a,y1+(y2-y1)*a,x1+(x2-x1)*b,y1+(y2-y1)*b),fill=color,width=width)
 svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="{width}"'+(' stroke-dasharray="9 7"' if dash else '')+'/>')
 if arrow:
  (x0,y0),(x,y)=points[-2:];a=math.atan2(y-y0,x-x0)
  pts=[(x,y),(x-14*math.cos(a-.45),y-14*math.sin(a-.45)),(x-14*math.cos(a+.45),y-14*math.sin(a+.45))]
  d.polygon(pts,fill=color);svg.append(f'<polygon points="{" ".join(f"{u},{v}" for u,v in pts)}" fill="{color}"/>')
def box(x,y,w,h,stroke='#aebac6',fill='white',dash=False):
 d.rectangle((x,y,x+w,y+h),fill=fill)
 svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}"/>')
 line([(x,y),(x+w,y),(x+w,y+h),(x,y+h),(x,y)],stroke,2,dash)
def badge(x,y,label,color):
 w=int(d.textlength(label,font=font(20,True)))+28
 box(x,y,w,34,color,'white');text(x+14,y+4,label,20,color,True)
def icon(x,y,label,color):
 box(x,y,58,48,color,'white');text(x+8,y+9,label,21,color,True)
 line([(x+29,y+48),(x+29,y+55),(x+10,y+55)],color,2)
def node(x,y,w,h,title,lines,tag='ON',color=None):
 color=color or C['green'];box(x,y,w,h,color,'#f7fbfa' if color==C['green'] else '#fff9ed')
 icon(x+16,y+17,tag,color);text(x+90,y+17,title,24,color,True)
 for i,s in enumerate(lines):text(x+18,y+76+i*29,s,21)

text(45,32,'KLTN | DEPLOYMENT TOPOLOGY & IMPLEMENTATION STATUS',37,C['red'],True)
text(47,88,'Snapshot: 30 October 2026   •   One physical OpenStack AIO host; three guest VMs; six central containers',24)
badge(48,130,'GREEN: installed & operational',C['green']);badge(535,130,'AMBER: installed, model-free preparation',C['amber']);badge(1160,130,'RED PANELS: not implemented',C['red'])
text(1735,137,'No model loaded • No scores emitted',22,C['muted'],True)
box(35,190,2330,1175,'#273f55')
text(60,205,'PHYSICAL HOST: openstack-aio  |  Kolla OpenStack + central Docker services',27,b=True)
box(60,265,750,1065,C['pink'],dash=True)
text(82,279,'OPENSTACK NOVA INSTANCES',27,C['pink'],True)
# Raw transport bus, drawn behind component cards.
for y in (490,810,1130):line([(785,y),(900,y)],C['blue'],3)
line([(900,490),(900,1130)],C['blue'],3)
line([(900,500),(1045,500)],C['blue'],3,arrow=True)
text(830,365,'RAW',23,C['blue'],True);text(830,396,'HTTPS',21,C['blue'],True);text(830,425,':18443',21,C['blue'])
text(830,1183,'All 7',20,C['blue']);text(830,1213,'sources',20,C['blue'])

def vm(y,name,os,ip,network,windows=False):
 box(85,y,700,295,C['blue'])
 icon(105,y+14,'WIN' if windows else 'UB',C['blue'])
 text(182,y+12,name+'  |  '+os,24,C['blue'],True)
 text(182,y+47,'Floating IP '+ip+'  •  '+network,19)
 box(105,y+89,660,47,C['green'],'#f5faf7')
 text(118,y+100,'Sysmon + Security + PowerShell' if windows else 'auditd + journald',22,C['green'],True)
 box(105,y+151,310,49,C['green'],'#f5faf7');text(118,y+164,'Fluent Bit + disk buffer',21,C['green'],True)
 line([(415,y+175),(450,y+175)],C['ink'],2,arrow=True)
 box(450,y+151,315,49,C['amber'],'#fff9ed');text(462,y+164,'Loopback API + SQLite',21,C['amber'],True)
 text(108,y+215,'Python agent + LightGBM / NumPy / SciPy',23,C['amber'],True)
 text(108,y+248,('WinSW / LocalService' if windows else 'systemd / kltn-agent user')+'  •  waiting_for_model',21)
vm(330,'kltn-ubuntu-1','Ubuntu 24.04','172.31.250.228','10.30.1.0/24')
vm(650,'kltn-ubuntu-2','Ubuntu 24.04','172.31.250.208','10.30.2.0/24')
vm(970,'kltn-windows-1','Windows 11 LTSC','172.31.250.236','10.30.3.0/24',True)
text(95,1287,'Agent ingress: 127.0.0.1:18081 • /readyz = 503 by design',20)

box(850,265,1485,90,C['blue'],'#f4f8fc')
text(870,278,'MANAGEMENT ON THE PHYSICAL HOST',24,C['blue'],True)
text(870,316,'Terraform → VMs / networks   |   Ansible → SSH :22 / WinRM TLS :5986   |   Lab ingress: 172.31.250.1',22)
box(1000,385,1335,945,C['blue'],dash=True)
text(1020,399,'DOCKER COMPOSE: kltn-central  |  central role runs here, not in a fourth VM',24,C['blue'],True)
node(1045,455,350,145,'Caddy',['TLS :18443','Lab interface only'],tag='TLS')
node(1460,455,380,145,'FastAPI ingest',['Loopback :18080','Per-host token + queue ACK'],tag='API')
node(1915,455,375,145,'NATS JetStream',['Loopback :14222','Durable raw-event queue'],tag='JS')
line([(1395,500),(1460,500)],arrow=True);line([(1840,500),(1915,500)],arrow=True)
node(1915,675,375,170,'Archive worker',['Python → PostgreSQL','ACK after DB commit','Retry deduplication'],tag='PY')
line([(2100,600),(2100,675)],arrow=True)
node(1460,675,380,185,'PostgreSQL',['Loopback :15432','events: raw JSONB','dl_jobs: event references','serving_status: heartbeat'],tag='DB')
line([(1915,740),(1840,740)],arrow=True)
node(1045,940,520,200,'DL preparation worker',['CPU PyTorch 2.7.1 • 1 GiB cap','Stages up to 50,000 event references','No sequences / weights / predictions','State: waiting_for_model'],tag='DL',color=C['amber'])
line([(1550,860),(1550,900),(1300,900),(1300,940)],C['amber'],3,arrow=True)
text(1050,839,'Independent PostgreSQL scan',21,C['amber'],True)
text(1050,870,'Read event IDs / persist staging state',19,C['amber'])
box(1645,940,645,200,C['red'],'#fff7f7',True)
text(1665,961,'CENTRAL DETECTION: STILL MISSING',23,C['red'],True)
for i,s in enumerate(['Normalization / correlation / sequence builder','ML result relay / score API / feature adapters','BiLSTM & GraphSAGE inference / fusion','SOC UI / verified-label feedback / response']):text(1665,1002+i*30,s,21)
text(1045,1184,'Storage & safety boundaries',23,b=True)
text(1045,1221,'Persistent Docker volumes • runtime secrets outside source control',22)
text(1045,1257,'DL has no public port and cannot delete raw events; no OpenStack admin key in DL',21)

# Missing functions are a separate zone, never depicted as deployed nodes.
text(45,1400,'ARCHITECTURE GAP MAP  |  DASHED BOXES BELOW ARE NOT DEPLOYED',29,C['red'],True)
cols=[(45,735,'ENDPOINT / DETECTION',['Semantic normalization + field availability','Actor/parent tracking + PID lifetime handling','Training-compatible features / vocab / loaders','ML scoring + selected logs + score outbox','DL windows / chunks + per-chunk scoring']),
      (820,735,'SOC / CENTRAL STORAGE / RESPONSE',['Processed logs / validated datasets / Parquet','Context-aware fusion + source masks','SOC dashboard + evidence / label workflow','Approval → response service → infra controller','OpenStack quarantine / verification / restore']),
      (1595,760,'MLOPS LIFECYCLE',['Drift / schedule / sufficient-data triggers','Dataset curation + feedback + replay buffer','Incremental training orchestration','Evaluation gates + versioned model registry','Validated rollout + monitoring + rollback'])]
for x,w,title,items in cols:
 box(x,1450,w,260,C['red'],'#fffafa',True);text(x+18,1468,title,23,C['red'],True)
 for i,s in enumerate(items):text(x+20,1515+i*34,'• '+s,21)
text(48,1742,'Infrastructure automation ≠ MLOps. Empty model folders and staging jobs are not a model registry or replay buffer.',24,C['ink'],True)
text(48,1785,'No Zeek / network-flow pipeline deployed. Sensor coverage is selective; percentages from the older table were not measured.',22,C['muted'])
svg.append('</svg>');(ROOT/'KLTN-deployment-status.svg').write_text('\n'.join(svg));im.save(ROOT/'KLTN-deployment-status.png')
print(ROOT/'KLTN-deployment-status.png')
