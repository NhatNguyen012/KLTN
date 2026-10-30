#!/usr/bin/env python3
"""Report central preparation health without printing credentials or telemetry."""
import subprocess
from prepare_central import ROOT

CODE = '''
import json
from common import db_connect
with db_connect() as db:
    rows=db.execute("SELECT service,state,pending,extract(epoch from now()-updated_at),runtime FROM serving_status").fetchall()
print(json.dumps([{'service':s,'state':st,'pending_events':p,'heartbeat_age_seconds':float(age),'runtime':r} for s,st,p,age,r in rows],indent=2))
'''
subprocess.run(['docker','compose','-f',str(ROOT/'central/compose.yaml'),'exec','-T','api','python','-c',CODE],check=True)
