from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
import html,math
O=Path(__file__).resolve().parent
O.mkdir(parents=True,exist_ok=True)
assert not any(O.is_relative_to(Path('/mnt/SSD_Data/optc')/d) for d in ['bro','ecar-bro','host-begnin','host-malicious'])
W,H=2040,1800
im=Image.new('RGB',(W,H),'white'); d=ImageDraw.Draw(im)
s=['<svg xmlns="http://www.w3.org/2000/svg" width="2040" height="1800" viewBox="0 0 2040 1800">','<rect width="2040" height="1800" fill="white"/>']
ink='#183047'; muted='#536779'; blue='#2879a0'; amber='#b77b11'
def text(x,y,t,size=22,bold=False,color=ink):
 f=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans'+('-Bold' if bold else '')+'.ttf',size)
 d.text((x,y),t,font=f,fill=color,anchor='mm')
 s.append(f'<text x="{x}" y="{y}" text-anchor="middle" dominant-baseline="central" font-family="DejaVu Sans,sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}">{html.escape(t)}</text>')
def rect(x,y,w,h,fill,stroke=ink,r=20,width=2):
 d.rounded_rectangle((x,y,x+w,y+h),r,fill,stroke,width)
 s.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{width}"/>')
def box(x,y,w,h,title,lines,fill='#ffffff',size=21):
 rect(x,y,w,h,fill)
 text(x+w/2,y+30,title,23,True)
 for i,l in enumerate(lines): text(x+w/2,y+66+i*29,l,size)
def line(pts,color=ink,dash=False,arrow=True):
 for a,b in zip(pts,pts[1:]):
  if dash:
   dist=math.dist(a,b)
   for z in range(0,int(dist),18):
    e=min(z+10,dist)
    d.line((a[0]+(b[0]-a[0])*z/dist,a[1]+(b[1]-a[1])*z/dist,a[0]+(b[0]-a[0])*e/dist,a[1]+(b[1]-a[1])*e/dist),fill=color,width=3)
  else:d.line((a,b),fill=color,width=3)
 s.append('<polyline points="'+' '.join(f'{x},{y}' for x,y in pts)+f'" fill="none" stroke="{color}" stroke-width="3"'+(' stroke-dasharray="10 8"' if dash else '')+'/>')
 if arrow:
  a,b=pts[-2:]; ang=math.atan2(b[1]-a[1],b[0]-a[0]); p=[b]+[(b[0]-15*math.cos(ang+v),b[1]-15*math.sin(ang+v)) for v in [-.45,.45]]
  d.polygon(p,fill=color);s.append('<polygon points="'+' '.join(f'{x},{y}' for x,y in p)+f'" fill="{color}"/>')
rect(20,30,2000,1740,'white','#aac7e7',55,3)
rect(325,12,1390,64,'#b8d2ef','#b8d2ef')
text(1020,44,'Multi-source Context-aware APT Detection Framework',33,True)
text(1020,110,'Code-grounded high-level design • Lam pipeline v2 @ 5e283bc • 14 Oct 2026',23,color=muted)
box(65,170,520,145,'Host telemetry',['host-begnin / host-malicious','Corrected eCAR events'],'#dfeaf4',22)
box(705,170,560,145,'Network flow logs',['bro / conn.*.log.gz','Zeek connection statistics + flow labels'],'#dfeaf4',21)
box(1345,170,620,145,'Host-to-flow context',['ecar-bro / ecarbro.json.gz','hostname • image_path • principal • bro_uid'],'#dfeaf4',20)
# Current host branch
rect(65,365,520,730,'#d6edf7','#d6edf7',32)
text(325,400,'Host ML / Provenance',27,True)
text(325,433,'Existing separate branch',19,color=muted)
box(100,475,450,130,'Semantic feature encoder',['Event-level, TRAIN-fitted vocabulary','Approved seed02 split'],'#ffffff',20)
box(100,660,450,150,'Host classifier',['RF / XGBoost / LightGBM','Separate trained alternatives'],'#f2ddf5',22)
box(100,865,450,150,'Learned provenance context',['Causal GraphSAGE + cascade policy','Host event score / evidence'],'#f2ddf5',21)
line([(325,315),(325,343),(85,343),(85,540),(100,540)])
line([(325,605),(325,660)])
line([(325,810),(325,865)])
text(325,1060,'Graph also uses causal host/process context',18,color=muted)
# DL branch
rect(675,365,1290,730,'#dcefe2','#dcefe2',32)
text(1320,400,'Network Flow DL with Host-derived Context',28,True)
box(870,455,900,125,'UID Join + Feature Encoding',['Bro uid = eCAR-Bro bro_uid; retain matched flows','7 categorical + 7 numeric + numeric-missing masks + binary flag + delta time'],'#ffffff',19)
line([(985,315),(985,325),(785,325),(785,520),(870,520)]);line([(1655,315),(1655,325),(1850,325),(1850,520),(1770,520)])
box(870,625,900,125,'Fixed 15-minute Bins → Ordered Chunks',['Per hostname: floor(ts / 900) × 900; sort by (ts, uid)','Each chunk ≤ 512 flows; label = any malicious flow in that chunk'],'#ffffff',21)
line([(1320,580),(1320,625)])
box(715,820,565,170,'BiLSTM — trained independently',['Per-flow encoding → 64 dimensions','1 bidirectional layer, hidden 64 / direction','Final hidden states → binary head'],'#f2ddf5',21)
box(1340,820,585,170,'Mixed-Type — trained independently',['16 feature tokens → feature self-attention','Mean → 2 temporal attention layers','Masked mean → binary head'],'#f2ddf5',20)
line([(1120,750),(1120,787),(995,787),(995,820)])
line([(1510,750),(1510,787),(1630,787),(1630,820)])
text(1320,1030,'Two alternative predictors; no trained ensemble or BiLSTM → attention cascade',20)
text(1320,1065,'Current output: P(malicious chunk), binary decision; no unknown / multi-label head',20,color=muted)
# proposal integration clearly colored
rect(65,1155,1900,240,'#fff3d5','#d6aa43',28)
text(1015,1189,'PROPOSED INTEGRATION — shared window protocol and fusion still to implement',26,True)
box(100,1230,535,130,'Align Host / DL Evidence',['Host events + DL chunks → host / 15-min bin','Choose aggregation on validation'],'#ffffff',19)
box(735,1230,580,130,'Context-aware Fusion',['Gating + source masks; cross-attention option','Train / calibrate on aligned, leakage-safe data'],'#ffffff',20)
box(1415,1230,515,130,'APT Risk / Analyst Triage',['Evidence-backed risk and alerts','Unknown handling needs a separate policy'],'#ffffff',19)
line([(325,1095),(325,1230)],amber,True)
line([(1320,1095),(1320,1125),(520,1125),(520,1230)],amber,True)
line([(635,1295),(735,1295)],amber,True)
line([(1315,1295),(1415,1295)],amber,True)
# lifecycle
rect(65,1450,1900,210,'#fde8de','#e2ac93',28)
text(1015,1480,'PROPOSED LEARNING LOOP',25,True)
box(100,1515,520,110,'Monitor + Confirm Labels',['Drift / reviewed errors / sufficient new data'],'#ffffff',19)
box(735,1515,580,110,'Update Candidate',['Quality gate → retrain / fine-tune + replay'],'#ffffff',20)
box(1415,1515,515,110,'Validate + Version + Roll Out',['Check old/new domains; deploy if accepted'],'#ffffff',19)
line([(1670,1395),(1670,1425),(360,1425),(360,1515)],amber,True)
line([(620,1570),(735,1570)],amber,True);line([(1315,1570),(1415,1570)],amber,True)
line([(1930,1570),(1992,1570),(1992,338),(600,338),(600,700),(550,700)],blue,True)
line([(1200,338),(1200,365)],blue,True)
text(1260,351,'Validated model versions (proposed)',16,color=blue)
text(1020,1700,'Solid: code-grounded branch processing     •     Dashed amber: proposed integration / feedback     •     Dashed blue: rollout',21,color=muted)
text(1020,1737,'Current DL requires Zeek-origin fields. Endpoint-only collection and one-VM/container deployment require a separate implementation.',20,color=muted)
s.append('</svg>')
(O/'high_level_design.svg').write_text('\n'.join(s));im.save(O/'high_level_design.png')
