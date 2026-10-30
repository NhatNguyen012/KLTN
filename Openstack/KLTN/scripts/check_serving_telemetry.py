#!/usr/bin/env python3
"""Verify that a real smoke marker is still archived from all seven sources."""
import argparse
import json
import subprocess
from prepare_central import ROOT, hosts
p=argparse.ArgumentParser()
p.add_argument('marker')
p.add_argument('--timeout', type=int, default=120)
a=p.parse_args()
expected = [(h['host_id'], s) for h in hosts().values() for s in
            (['audit','journal'] if h['os_type']=='ubuntu' else ['sysmon','security','powershell'])]
code='''
import json,sys,time
from common import db_connect
cfg=json.load(sys.stdin)
deadline=time.monotonic()+cfg['timeout']
while True:
    with db_connect() as db:
        rows=db.execute("SELECT host_id,source,count(*) FROM events WHERE strpos(payload::text,%s)>0 GROUP BY host_id,source",(cfg['marker'],)).fetchall()
    actual={(h,s):n for h,s,n in rows}
    missing=[(h,s) for h,s in cfg['expected'] if actual.get((h,s),0)==0]
    if not missing: break
    if time.monotonic() >= deadline: raise AssertionError(missing)
    time.sleep(3)
print(json.dumps({'marker':cfg['marker'],'archive_sources':[{'host_id':h,'source':s,'count':n} for h,s,n in rows]},indent=2))
'''
subprocess.run(['docker','compose','-f',str(ROOT/'central/compose.yaml'),'exec','-T','api','python','-c',code],
               input=json.dumps({'marker':a.marker,'expected':expected,'timeout':max(0,min(a.timeout,600))}),text=True,check=True)
