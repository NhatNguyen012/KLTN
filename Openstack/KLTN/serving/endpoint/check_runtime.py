"""Live endpoint checks, run by Ansible. Contains no model or synthetic scores."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import urllib.error
import urllib.request

p=argparse.ArgumentParser()
p.add_argument('--config',required=True)
p.add_argument('--marker',required=True)
p.add_argument('--phase',choices=['before','after'],required=True)
a=p.parse_args()
cfg=json.loads(Path(a.config).read_text())
base='http://127.0.0.1:18081'

def request(path,data=None,token=None):
    req=urllib.request.Request(base+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+(token or cfg['local_token'])})
    with urllib.request.urlopen(req,timeout=15) as r: return json.load(r)

health=request('/healthz')
assert health['inference']=='waiting_for_model' and health['score'] is None
try:
    request('/readyz')
except urllib.error.HTTPError as e:
    assert e.code==503
else:
    raise AssertionError('Inference readiness must not be true without a model')
raw={'marker':a.marker}
if a.phase=='before':
    try: request('/v1/raw/smoke',raw,'invalid')
    except urllib.error.HTTPError as e: assert e.code==401
    else: raise AssertionError('Invalid token accepted')
    assert request('/v1/raw/smoke',dict(raw,date=1))['accepted']==1
    assert request('/v1/raw/smoke',dict(raw,date=2))['inserted']==0
identity=hashlib.sha256(json.dumps([cfg['host_id'],'smoke',raw],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
with sqlite3.connect(cfg['database']) as db:
    rows=db.execute('SELECT state FROM inbox WHERE event_id=?',(identity,)).fetchall()
assert rows==[('waiting_for_model',)],rows
print(json.dumps({'phase':a.phase,'persisted_once':True,'inference':'waiting_for_model','runtime':health['runtime']}))
