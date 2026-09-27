#!/usr/bin/env python3
"""Print auditable actor/parent/grandparent evidence; never assert a true attack root."""
import argparse
import json
from pathlib import Path
from common import DEFAULT_OUTPUT, sha, implementation
from graph import connect, Encoder, timestamp


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--graph',type=Path,default=DEFAULT_OUTPUT/'graph')
    p.add_argument('--source-id');p.add_argument('--source-line',type=int)
    p.add_argument('--host');p.add_argument('--actor');p.add_argument('--timestamp')
    args=p.parse_args();root=args.graph.resolve();meta=json.loads((root/'manifest.json').read_text())
    if sha(root/'graph.sqlite')!=meta['database_sha256'] or meta['config']['implementation']!=implementation():
        raise ValueError('graph integrity or implementation mismatch')
    db=connect(root/'graph.sqlite',readonly=True)
    try:
        if args.source_id and args.source_line:
            row=db.execute('SELECT host,proc,t FROM target WHERE source=? AND line=?',(args.source_id,args.source_line)).fetchone()
            if row is None:raise ValueError('target not in this graph scope')
        elif args.host and args.actor and args.timestamp:
            row=(args.host.lower().rstrip('.'),args.actor.lower(),timestamp(args.timestamp))
        else:raise ValueError('supply source-id/line or host/actor/timestamp')
        if not row[0] or not row[1] or row[2] is None:raise ValueError('target lacks valid identity or time')
        result=Encoder(db).explain(*row)
        sources={s['source_id']:s['source']['path'] for s in meta['config']['sources']}
        for edge in result['edges']:edge['source_path']=sources[edge['source_id']]
        result['pilot']=meta['config']['pilot']
        print(json.dumps(result,indent=2))
    finally:db.close()


if __name__=='__main__':main()
