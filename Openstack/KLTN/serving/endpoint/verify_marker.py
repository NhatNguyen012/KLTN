"""Verify real collector delivery without printing event content."""
import argparse
import json
import sqlite3
p=argparse.ArgumentParser()
p.add_argument('--database', required=True)
p.add_argument('--marker', required=True)
p.add_argument('--sources', nargs='+', required=True)
a=p.parse_args()
with sqlite3.connect(a.database) as db:
    rows=dict(db.execute('SELECT source,count(*) FROM inbox WHERE instr(raw,?)>0 GROUP BY source',(a.marker,)).fetchall())
assert set(a.sources) <= {s for s,n in rows.items() if n>0}, rows
print(json.dumps({'marker':a.marker,'local_sources':rows}))
