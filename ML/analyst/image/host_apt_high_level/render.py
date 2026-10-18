from pathlib import Path
import math, html, json
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parents[3]
OUT=(ROOT/'analyst/image/host_apt_high_level').resolve()
for n in ('host-begnin','host-malicious','ecar-bro','bro'):
    assert not OUT.is_relative_to((ROOT/n).resolve())
OUT.mkdir(parents=True,exist_ok=True)
W,H=2400,1770
INK='#183047'; MUTED='#4E6276'; LINE='#64778C'
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
nodes=[]; edges=[]; texts=[]; panels=[]
def box(id,x,y,w,h,title,body,kind='domain',size=22):
    nodes.append(dict(id=id,x=x,y=y,w=w,h=h,title=title,body=body,kind=kind,size=size))
def txt(id,x,y,w,h,value,size=20,bold=False,color=MUTED,bg=None):
    texts.append(dict(id=id,x=x,y=y,w=w,h=h,value=value,size=size,bold=bold,color=color,bg=bg))
def edge(id,src,dst,points,label=None,at=None,kind='schema'):
    edges.append(dict(id=id,src=src,dst=dst,points=points,kind=kind))
    if label: txt(id+'_label',*at,label,18,False,LINE,'white')
def panel(id,x,y,w,h,title,fill):
    panels.append(dict(id=id,x=x,y=y,w=w,h=h,title=title,fill=fill))

txt('title',70,20,2250,60,'Multi-source Host APT Detection — High-level Architecture',36,True,INK)
txt('subtitle',70,85,2250,40,'Target design • endpoint monitoring + central contextual analysis + validated model updates',24)
txt('status',70,133,2250,30,'Runtime integration is proposed; existing model experiments do not establish an operational deployment.',20)

panel('endpoint',60,210,620,875,'END HOST  ·  MONITOR, DETECT, SEND EVIDENCE', '#EAF3FA')
box('sources',90,270,560,170,'Multi-source host logs',[
 'OS / Security • Application / Service',
 'Orchestration / Audit where available',
 'Host-observed communication events',
 'No separate network sensor'],'support',21)
box('collector',90,490,560,140,'Collector & normalization',[
 'Source adapters • host/process identity • time',
 'Preserve provenance and availability masks',
 'Extract bounded, model-compatible features'],'exec',20)
box('ml',90,685,265,140,'Lightweight ML',[
 'RF / XGB / LightGBM',
 'Known-threat score',
 'Event-level evidence'],'exec',19)
box('ood',385,685,265,140,'Novelty / OOD detector',[
 'Unknown / suspicious score',
 'Separate calibrated policy',
 'Requires development'],'exec',18)
box('coordinator',90,885,560,155,'Agent coordinator',[
 'Benign / known malicious / unknown-suspicious',
 'Select and forward logs, scores and evidence',
 'Optional agentic investigation; unknown ≠ malicious'],'exec',19)

panel('central',760,210,1570,875,'ONE CENTRAL VM  ·  MULTIPLE SERVICES / CONTAINERS', '#EAF5EE')
box('ingest',795,270,1500,140,'Ingestion, correlation & sample building',[
 'Normalize source schemas; correlate host / process / time; retain source provenance',
 'Construct causal host/process context and ordered event sequences',
 'Window length and prediction target are explicit configuration; align evidence availability'],'shared',22)
box('graph',795,490,690,170,'Host / process provenance branch',[
 'Causal graph construction → learned GraphSAGE',
 'Host ML score + graph context / cascade',
 'Evidence from observed events only',
 'Map event-level output to the shared target'],'domain',21)
box('temporal',1605,490,690,170,'Temporal DL branch',[
 'Sequence encoding + masks',
 'BiLSTM OR Mixed-Type Self-Attention',
 'Independently trained alternatives',
 'Target source adapters require training / validation'],'domain',21)
box('fusion',1070,745,960,145,'Context-aware fusion',[
 'Align local ML, graph and sequence evidence to a shared host / time target',
 'Gating / cross-attention + source masks; calibrate on validation',
 'Produce APT assessment, confidence and supporting evidence'],'exec',21)
box('review',1070,950,960,100,'Analyst review & alert management',[
 'Investigate alerts / unknown cases → adjudicated labels and reviewed errors'],'exec',21)

edge('collect','sources','collector',[(370,440),(370,490)],kind='runtime')
edge('ml_input','collector','ml',[(222,630),(222,685)],kind='runtime')
edge('ood_input','collector','ood',[(517,630),(517,685)],kind='runtime')
edge('ml_triage','ml','coordinator',[(222,825),(222,885)],kind='runtime')
edge('ood_triage','ood','coordinator',[(517,825),(517,885)],kind='runtime')
edge('forward','coordinator','ingest',[(650,965),(720,965),(720,340),(795,340)],kind='runtime')
edge('graph_input','ingest','graph',[(1140,410),(1140,490)],kind='runtime')
edge('sequence_input','ingest','temporal',[(1950,410),(1950,490)],kind='runtime')
edge('graph_fuse','graph','fusion',[(1140,660),(1140,745)],kind='runtime')
edge('sequence_fuse','temporal','fusion',[(1950,660),(1950,745)],kind='runtime')
edge('local_score','ingest','fusion',[(1545,410),(1545,745)],'Local scores + masks',(1445,683,200,45),kind='runtime')
edge('alerts','fusion','review',[(1550,890),(1550,950)],kind='runtime')

panel('learning',60,1170,2270,290,'LEARNING LIFECYCLE  ·  SERVICES ON THE CENTRAL VM', '#FFF3E4')
box('monitor',90,1230,495,185,'Drift monitor & learning controller',[
 'Trigger: sustained drift OR reviewed decline',
 'OR sufficient confirmed new samples',
 'Apply label / quality / eligibility gates',
 'Drift alone does not create labels'],'exec',20)
box('train',655,1230,495,185,'Trainer',[
 'New verified TRAIN data + replay',
 'Retrain ML / fine-tune DL as appropriate',
 'Produce a candidate model',
 'Keep evaluation partitions held out'],'exec',20)
box('validate',1220,1230,495,185,'Model validator',[
 'Validate old and new domains',
 'Check detection and false-positive behavior',
 'Record validation report',
 'Promote only if policy is satisfied'],'exec',20)
box('deploy',1785,1230,515,185,'Registry & deployment',[
 'Approved version + schema + thresholds',
 'Roll out to eligible model services',
 'Monitor behavior after deployment',
 'Retain prior version for rollback'],'exec',20)
edge('feedback','review','monitor',[(1550,1050),(1550,1120),(337,1120),(337,1230)],'Reviewed labels / errors + operational drift metrics',(690,1100,800,35),kind='runtime')
edge('request','monitor','train',[(585,1322),(655,1322)],kind='update')
edge('candidate','train','validate',[(1150,1322),(1220,1322)],kind='update')
edge('approval','validate','deploy',[(1715,1322),(1785,1322)],kind='update')
edge('rollout','deploy','central',[(2300,1322),(2360,1322),(2360,700),(2330,700)],kind='update')
edge('endpoint_rollout','deploy','endpoint',[(2042,1415),(2042,1490),(30,1490),(30,755),(60,755)],kind='update')
txt('rollout_label',760,1473,900,30,'Approved model versions → endpoint and central inference services',19,False,'#B44C4C','white')

box('offline',60,1550,620,135,'Offline research datasets',[
 'OpTC + external datasets → adapters / label review',
 'Curate source-aware TRAIN / validation / TEST',
 'Additional data requires training to change weights'],'support',19)
box('storage',760,1550,1570,135,'Persistent storage / mounted volume attached to the Central VM',[
 'Raw logs • processed events / sequences • evidence and label provenance',
 'Verified datasets + replay buffer (trainer / validator) • model versions + metadata (registry)',
 'Ingestion / analysis / review services read and write their corresponding logical stores'],'support',21)
edge('dataset','offline','storage',[(680,1615),(760,1615)],kind='runtime')
edge('readwrite','learning','storage',[(1545,1460),(1545,1550)],kind='runtime')
txt('footer',60,1710,2270,35,'Amber dashed: data / evidence exchange   •   Red: update / rollout   •   Lam benchmark: Zeek-based inputs remain documented separately.',20)
PALETTE={'meta':('#FBE4E3','#BF6368'),'shared':('#DDF0E5','#4C9070'),
         'domain':('#E8E3FC','#7D71B4'),'exec':('#FFF4C8','#B99A40'),'support':('#E8EEF3','#8595A5')}
def font(s,b=False):return ImageFont.truetype(BOLD if b else FONT,s)
im=Image.new('RGB',(W,H),'white');d=ImageDraw.Draw(im)
svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img"><title>High-level multi-source host APT architecture</title><desc>Proposed functional architecture: endpoint multi-source logs, local ML and novelty triage, central graph and temporal analysis, fusion, analyst review, persistent storage, and a gated retraining and deployment loop.</desc><rect width="100%" height="100%" fill="white"/>']
mx=ET.Element('mxfile',host='app.diagrams.net',type='device')
dia=ET.SubElement(mx,'diagram',id='main',name='Target high-level architecture')
gm=ET.SubElement(dia,'mxGraphModel',page='1',pageWidth=str(W),pageHeight=str(H),grid='1',gridSize='10')
r=ET.SubElement(gm,'root');ET.SubElement(r,'mxCell',id='0');ET.SubElement(r,'mxCell',id='1',parent='0')
def vertex(id,value,style,x,y,w,h):
    c=ET.SubElement(r,'mxCell',id=id,value=value,style=style,vertex='1',parent='1')
    ET.SubElement(c,'mxGeometry',x=str(x),y=str(y),width=str(w),height=str(h),attrib={'as':'geometry'})
def textline(x,y,value,size,bold=False,color=INK):
    d.text((x,y),value,font=font(size,bold),fill=color,anchor='mm')
    svg.append(f'<text x="{x}" y="{y}" dominant-baseline="middle" text-anchor="middle" font-family="DejaVu Sans, sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}">{html.escape(value)}</text>')
def rect(x,y,w,h,fill,stroke,rad=10):
    d.rounded_rectangle((x,y,x+w,y+h),radius=rad,fill=fill,outline=stroke,width=2)
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rad}" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
for p in panels:
    rect(p['x'],p['y'],p['w'],p['h'],p['fill'],'#C5D1DC')
    textline(p['x']+p['w']/2,p['y']+25,p['title'],20,True)
    vertex(p['id'],p['title'],f'rounded=1;verticalAlign=top;spacingTop=15;fontSize=20;fontStyle=1;fillColor={p["fill"]};strokeColor=#C5D1DC;',p['x'],p['y'],p['w'],p['h'])

allnodes={n['id']:n for n in nodes+panels}
for e in edges:
    pts=e['points'];color={'schema':LINE,'runtime':'#B08536','update':'#C25050'}[e['kind']]
    dashed=e['kind']=='runtime'
    for a,b in zip(pts,pts[1:]):
        length=math.dist(a,b)
        if dashed:
            for k in range(0,int(length),15):
                u=k/length;v=min(k+9,length)/length
                d.line([(a[0]+(b[0]-a[0])*u,a[1]+(b[1]-a[1])*u),(a[0]+(b[0]-a[0])*v,a[1]+(b[1]-a[1])*v)],fill=color,width=2)
        else:d.line([a,b],fill=color,width=2)
    sd=' stroke-dasharray="9 6"' if dashed else ''
    svg.append('<polyline points="'+' '.join(f'{x},{y}' for x,y in pts)+f'" stroke="{color}" fill="none" stroke-width="2"{sd}/>')
    a,b=pts[-2:];theta=math.atan2(b[1]-a[1],b[0]-a[0]);sz=11
    tri=[b,(b[0]-sz*math.cos(theta)+sz/2*math.sin(theta),b[1]-sz*math.sin(theta)-sz/2*math.cos(theta)),(b[0]-sz*math.cos(theta)-sz/2*math.sin(theta),b[1]-sz*math.sin(theta)+sz/2*math.cos(theta))]
    d.polygon(tri,fill=color);svg.append('<polygon points="'+' '.join(f'{x},{y}' for x,y in tri)+f'" fill="{color}"/>')
    src,dst=allnodes[e['src']],allnodes[e['dst']]
    a,b=pts[0],pts[-1]
    ex,ey=(a[0]-src['x'])/src['w'],(a[1]-src['y'])/src['h']
    ix,iy=(b[0]-dst['x'])/dst['w'],(b[1]-dst['y'])/dst['h']
    style=f'edgeStyle=segmentEdgeStyle;endArrow=block;strokeWidth=2;strokeColor={color};exitX={ex};exitY={ey};entryX={ix};entryY={iy};'+('dashed=1;' if dashed else '')
    c=ET.SubElement(r,'mxCell',id=e['id'],style=style,edge='1',parent='1',source=e['src'],target=e['dst'])
    g=ET.SubElement(c,'mxGeometry',relative='1',attrib={'as':'geometry'})
    arr=ET.SubElement(g,'Array',attrib={'as':'points'})
    for x,y in pts[1:-1]:ET.SubElement(arr,'mxPoint',x=str(x),y=str(y))
for n in nodes:
    x,y,w,h=(n[k] for k in ['x','y','w','h']);fill,stroke=PALETTE[n['kind']]
    rect(x,y,w,h,fill,stroke)
    ts=24
    while d.textlength(n['title'],font=font(ts,True))>w-20:ts-=1
    textline(x+w/2,y+30,n['title'],ts,True)
    size=n['size'];step=30 if h>180 else (23 if h<=135 else 27)
    fitted_body=[]
    for j,line in enumerate(n['body']):
        fs=size
        while d.textlength(line,font=font(fs))>w-20:fs-=1
        yy=y+(58 if h<=135 else 65)+j*step
        assert yy<y+h-8,(n['id'],yy)
        textline(x+w/2,yy,line,fs,False,MUTED)
        fitted_body.append(f'<div style="font-size:{fs}px">'+html.escape(line)+'</div>')
    value='<div style="font-size:'+str(ts)+'px;font-weight:bold;margin-bottom:12px">'+html.escape(n['title'])+'</div><div style="font-size:'+str(size)+'px;line-height:1.35">'+''.join(fitted_body)+'</div>'
    vertex(n['id'],value,f'rounded=1;html=1;whiteSpace=wrap;spacing=10;fillColor={fill};strokeColor={stroke};strokeWidth=2;fontColor={INK};',x,y,w,h)
for t in texts:
    x,y,w,h=(t[k] for k in ['x','y','w','h'])
    if t['bg']:rect(x,y,w,h,t['bg'],t['bg'],5)
    lines=t['value'].split('\n');step=t['size']*1.4
    for j,line in enumerate(lines):
        assert d.textlength(line,font=font(t['size'],t['bold']))<=w-4,(t['id'],line)
        textline(x+w/2,y+h/2+(j-(len(lines)-1)/2)*step,line,t['size'],t['bold'],t['color'])
    vertex(t['id'],html.escape(t['value']).replace('\n','<br>'),f'text;html=1;align=center;verticalAlign=middle;whiteSpace=wrap;fontSize={t["size"]};fontStyle={1 if t["bold"] else 0};fontColor={t["color"]};fillColor={t["bg"] or "none"};strokeColor=none;',x,y,w,h)
svg.append('</svg>')
ET.indent(mx)
(OUT/'high_level_design.svg').write_text('\n'.join(svg))
ET.ElementTree(mx).write(OUT/'high_level_design.drawio',encoding='utf-8',xml_declaration=True)
im.save(OUT/'high_level_design.png')
ET.parse(OUT/'high_level_design.svg')
cells=ET.parse(OUT/'high_level_design.drawio').findall('.//mxCell');ids={c.get('id') for c in cells}
assert len(ids)==len(cells)
for c in cells:
    for attr in ['parent','source','target']:assert c.get(attr) is None or c.get(attr) in ids
print(json.dumps({'output':str(OUT),'size':[W,H],'nodes':len(nodes),'edges':len(edges),'files':[p.name for p in OUT.iterdir()]}))
