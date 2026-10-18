from pathlib import Path
import math, html, json
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parents[3]
OUT=(ROOT/'analyst/image/host_multisource_ontology_v2').resolve()
for n in ('host-begnin','host-malicious','ecar-bro','bro'):
    assert not OUT.is_relative_to((ROOT/n).resolve())
OUT.mkdir(parents=True,exist_ok=True)
W,H=2400,2130
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

txt('title',160,20,2050,55,'Ontology-based Architecture for Multi-source Host APT Detection',34,True,INK)
txt('subtitle',160,78,2050,38,'Target conceptual design • semantic relationships and deployment mapping',24)
txt('status',160,119,2050,30,'Proposed system; ontology specification, endpoint integration and learning lifecycle require implementation.',19)

box('meta_event',80,185,620,150,'Telemetry meta-model',[
    'Entity • Record • Source • Relation',
    'Identity • event time • observation time',
    'Schema and provenance constraints'],'meta')
box('meta_detection',780,185,620,150,'Detection meta-model',[
    'Task • Evidence • PredictionTarget • Label',
    'Prediction ≠ verified ground truth',
    'Confidence • uncertainty • label provenance'],'meta')
box('meta_ops',1480,185,620,150,'Deployment & learning meta-model',[
    'Host • VM • Container • Service • Agent',
    'Dataset • TrainingJob • ModelVersion',
    'Validation • promotion • rollback policy'],'meta')
box('telemetry',80,410,970,155,'Shared entity & observation ontology',[
    'Host • Process • Resource • LogSource • LogRecord',
    'LogRecord observedBy LogSource; Process runsOn Host',
    'Record hasEventTime / availableAt / sourceProvenance'],'shared')
box('analysis',1130,410,970,155,'Shared analysis & model-lifecycle ontology',[
    'Prediction aboutTarget / usesModel / supportedBy Evidence',
    'GroundTruth hasLabelSet / labelUnit / verifiedBy',
    'TrainingJob usesDataset / producesCandidateModel'],'shared')
edge('conform_t','telemetry','meta_event',[(390,410),(390,335)],'conforms to',(285,360,210,28))
edge('conform_a','analysis','meta_detection',[(1300,410),(1300,375),(1090,375),(1090,335)])
edge('conform_l','analysis','meta_ops',[(1790,410),(1790,335)],'conforms to',(1685,360,210,28))
box('host_domain',80,655,620,240,'Host activity ontology',[
    'Process • File • Registry • User • Service',
    'Process spawns Process; Event targets Resource',
    'Event performedBy Process / Principal',
    'CommunicationEvent associatedWith Host / Process',
    'Endpoint observations retain their source origin'],'domain')
box('log_domain',780,655,620,240,'Multi-source log ontology',[
    'OS / Security • Application / Service • Orchestration',
    'These source types are subclasses of LogSource',
    'LogRecord describes HostEvent / ServiceEvent',
    'LogRecord associatedWithHost; hasSourceSchema',
    'Adapters map source fields to shared concepts'],'domain')
box('target_domain',1480,655,620,240,'Temporal, prediction & learning ontology',[
    'TemporalWindow associatedWithHost',
    'EventSequence containsEvent; belongsTo Window',
    'PredictionTarget: Event / Sequence / Window',
    'TrainingJob uses VerifiedDataset + ReplayBuffer',
    'CandidateModel evaluatedBy ValidationReport'],'domain')
edge('import_h','host_domain','telemetry',[(390,655),(390,565)],'imports / extends',(265,601,250,28))
edge('import_s','log_domain','telemetry',[(1090,655),(1090,600),(890,600),(890,565)])
edge('import_w','target_domain','analysis',[(1790,655),(1790,565)],'imports / extends',(1665,601,250,28))
txt('mapping_note',80,920,2020,45,'Services instantiate these concepts; source adapters and schema checks enforce the mappings.',22,True)

panel('hosts',80,1025,480,675,'END HOST  ·  LOGICAL MODULES', '#F4F7FA')
box('collector',105,1080,430,140,'Log collector & source adapters',[
    'OS / security, application / service logs',
    'Orchestration / audit logs when available',
    'Normalize identity, timestamps and provenance'],'exec',19)
box('ml',105,1250,205,140,'Lightweight ML',[
    'RF / XGB / LGBM',
    'Known-threat score',
    'Evidence references'],'exec',17)
box('ood',330,1250,205,140,'Novelty / OOD',[
    'Unknown / suspicious',
    'Calibrated policy',
    'Needs validation'],'exec',17)
box('agent',105,1425,430,150,'Agent coordinator',[
    'Benign / known malicious / unknown-suspicious',
    'Collect evidence → send logs and scores',
    'Agentic investigation is an optional extension'],'exec',18)
txt('unknown_note',105,1590,430,85,'Unknown ≠ confirmed malicious\nReview and evidence are required',18,True)

panel('vm',620,1025,1480,675,'ONE CENTRAL VM  ·  MULTIPLE SERVICES / CONTAINERS', '#F4F7FA')
box('ingest',645,1080,430,140,'Ingestion & contextual analysis',[
    'Source adapters • correlation • graph context',
    'Host/process GraphSAGE + temporal DL',
    'BiLSTM OR Mixed-Type Self-Attention'],'exec',19)
box('fusion',1130,1080,430,140,'Context-aware fusion',[
    'Align prediction targets and available evidence',
    'Gating / cross-attention + source masks',
    'APT assessment • confidence • explanation'],'exec',18)
box('soc',1615,1080,460,140,'SOC review & evidence',[
    'Investigation • adjudicated labels',
    'Track false positives / negatives',
    'Unknown cases → review, not automatic labels'],'exec',19)
box('drift',645,1280,430,140,'Drift monitor & learning controller',[
    'Monitor drift and reviewed performance',
    'Check trigger + label / data-quality gates',
    'Create an eligible training request'],'exec',19)
box('trainer',1130,1280,430,140,'Trainer & model validator',[
    'New verified data + replay → TrainingJob',
    'Retrain ML / fine-tune DL → CandidateModel',
    'Evaluate on held-out old and new domains'],'exec',18)
box('registry',1615,1280,460,140,'Model registry & deployment',[
    'ValidationReport → approval → ModelVersion',
    'Versioned rollout to eligible model services',
    'Monitor deployment; rollback if needed'],'exec',19)
txt('trigger',645,1460,1430,85,'UPDATE TRIGGER: sustained drift OR reviewed degradation OR sufficient confirmed new samples\nController gates the request; drift alone never supplies ground-truth labels.',21,True,INK,'#FFF4DE')
txt('modules',645,1580,1430,65,'Logical responsibilities may share a container. Container placement is a deployment choice.\nSchema / ontology mappings are versioned with adapters, datasets and model metadata.',20)

edge('realize_h','hosts','host_domain',[(320,1025),(320,895)],'instantiates',(215,983,210,28))
edge('realize_l','ingest','log_domain',[(860,1080),(860,989),(1090,989),(1090,895)],'maps records to',(940,973,300,28))
edge('realize_p','fusion','target_domain',[(1345,1080),(1345,989),(1790,989),(1790,895)],'uses concepts from',(1505,973,300,28))
edge('collect_m','collector','ml',[(205,1220),(205,1250)],kind='runtime')
edge('collect_o','collector','ood',[(435,1220),(435,1250)],kind='runtime')
edge('score_m','ml','agent',[(205,1390),(205,1425)],kind='runtime')
edge('score_o','ood','agent',[(435,1390),(435,1425)],kind='runtime')
edge('uplink','agent','ingest',[(535,1500),(590,1500),(590,1150),(645,1150)],kind='runtime')
edge('infer','ingest','fusion',[(1075,1150),(1130,1150)],kind='runtime')
edge('review','fusion','soc',[(1560,1150),(1615,1150)],kind='runtime')
edge('monitoring','ingest','drift',[(860,1220),(860,1280)],kind='runtime')
edge('feedback','soc','drift',[(1845,1220),(1845,1245),(1020,1245),(1020,1280)],kind='runtime')
edge('train_request','drift','trainer',[(1075,1350),(1130,1350)],kind='update')
edge('promote','trainer','registry',[(1560,1350),(1615,1350)],kind='update')

panel('storage',620,1785,1480,215,'PERSISTENT STORAGE / MOUNTED VOLUME  ·  LOGICAL STORES', '#EDF3F8')
box('logs',645,1840,430,130,'Logs & processed observations',[
    'Raw logs • normalized events • sequences',
    'Evidence and verified label provenance',
    'Accessed by ingestion / analysis / SOC'],'support',18)
box('data',1130,1840,430,130,'Verified datasets & replay buffer',[
    'Curated labels • source-aware splits',
    'Training / validation / held-out evaluation',
    'Read by trainer and validator'],'support',18)
box('versions',1615,1840,460,130,'Model versions & metadata',[
    'Model artifacts • validation reports',
    'Schema versions • lineage • deployment state',
    'Managed by registry / deployment'],'support',18)
box('research',80,1800,480,175,'Offline research datasets',[
    'External datasets + OpTC benchmark',
    'Adapters • label mapping • quality review',
    'Dataset diversity requires evaluation',
    'Separate from live endpoint telemetry'],'support',19)
edge('curation','research','storage',[(560,1900),(620,1900)],kind='runtime')
edge('persistence','vm','storage',[(1360,1700),(1360,1785)],'mounted; services read / write',(1070,1731,580,28),kind='runtime')
edge('rollout','registry','hosts',[(2075,1380),(2125,1380),(2125,1730),(320,1730),(320,1700)],kind='update')
txt('rollout_label',660,1707,580,27,'Approved versions → endpoint + central services',18,False,'#B44C4C','white')

for ident,y,value in [('meta_layer',210,'META-MODEL'),('shared_layer',440,'SHARED\nONTOLOGY'),('domain_layer',710,'DOMAIN\nONTOLOGIES'),('runtime_layer',1250,'EXECUTABLE\nMAPPING &\nDEPLOYMENT')]:
    txt(ident,2160,y,225,140,value,20,True,INK)
txt('scope_note',80,2020,2020,40,'Current Lam benchmark uses Zeek-derived flow features; endpoint-only inputs need new adapters, retraining and validation.',20)
txt('legend',80,2070,2020,30,'Grey: semantic mappings   ·   Amber dashed: proposed data exchange   ·   Red: learning / deployment control   ·   All runtime integration is proposed.',18)

PALETTE={'meta':('#FBE4E3','#BF6368'),'shared':('#DDF0E5','#4C9070'),
         'domain':('#E8E3FC','#7D71B4'),'exec':('#FFF4C8','#B99A40'),'support':('#E8EEF3','#8595A5')}
def font(s,b=False):return ImageFont.truetype(BOLD if b else FONT,s)
im=Image.new('RGB',(W,H),'white');d=ImageDraw.Draw(im)
svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img"><title>Ontology-based multi-source host APT architecture</title><desc>Four layers describe meta-models, shared ontologies, domain ontologies and proposed deployment. Multi-source host logs, endpoint modules, central VM services, persistent storage and a gated model lifecycle are distinguished. This is a target conceptual ontology, not an implemented OWL reasoner.</desc><rect width="100%" height="100%" fill="white"/>']
mx=ET.Element('mxfile',host='app.diagrams.net',type='device')
dia=ET.SubElement(mx,'diagram',id='main',name='Main ontology architecture')
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
(OUT/'main_architecture.svg').write_text('\n'.join(svg))
ET.ElementTree(mx).write(OUT/'main_architecture.drawio',encoding='utf-8',xml_declaration=True)
im.save(OUT/'main_architecture.png')
ET.parse(OUT/'main_architecture.svg')
cells=ET.parse(OUT/'main_architecture.drawio').findall('.//mxCell');ids={c.get('id') for c in cells}
assert len(ids)==len(cells)
for c in cells:
    for attr in ['parent','source','target']:assert c.get(attr) is None or c.get(attr) in ids
print(json.dumps({'output':str(OUT),'size':[W,H],'nodes':len(nodes),'edges':len(edges),'files':[p.name for p in OUT.iterdir()]}))
