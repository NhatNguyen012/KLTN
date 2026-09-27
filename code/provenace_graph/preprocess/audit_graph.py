#!/usr/bin/env python3
"""Read-only bounded audit/benchmark on real source prefixes; not detection evaluation."""
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import statistics
import time
import resource

from common import DEFAULT_OUTPUT, safe, sha, implementation, atomic_json
from graph import connect, Encoder, identity, FEATURES


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--graph',type=Path,default=DEFAULT_OUTPUT/'graph')
    p.add_argument('--output',type=Path,default=DEFAULT_OUTPUT/'graph_audit.json')
    p.add_argument('--sample-lines',type=int,default=1000)
    args=p.parse_args()
    if args.sample_lines<1:raise ValueError('positive sample size required')
    graph=args.graph.resolve();m=json.loads((graph/'manifest.json').read_text())
    if sha(graph/'graph.sqlite')!=m['database_sha256'] or m['config']['implementation']!=implementation():
        raise ValueError('graph integrity or code mismatch')
    destination=safe(args.output,[graph]);destination.parent.mkdir(parents=True,exist_ok=True)
    db=connect(graph/'graph.sqlite',readonly=True);encoder=Encoder(db);latencies=[];coverage=Counter();checked_edges=0
    try:
        for item in m['config']['sources']:
            source=Path(item['source']['path']);opener=gzip.open if source.suffix=='.gz' else open
            limit=min(args.sample_lines,m['sources'][item['source_id']]['lines'])
            with opener(source,'rt') as f:
                for line in range(limit):
                    record=json.loads(next(f));host,proc,t=identity(record)
                    before=time.perf_counter();columns=encoder.encode(host,proc,t);latencies.append(time.perf_counter()-before)
                    coverage.update(FEATURES[c] for c in columns)
                    if not host or not proc or t is None:continue
                    trace=encoder.explain(host,proc,t)
                    upper=trace['cutoff_us']
                    for edge in trace['edges']:
                        if edge['timestamp_us']>=upper:raise ValueError('future or impossible ancestor edge')
                        upper=edge['timestamp_us']+1;checked_edges+=1
        # Explicit domain checks: no arbitrary tokens or inherited labels in the graph facts.
        valid={f.split('::',2)[2] for f in FEATURES if f.startswith('graph::actor::')}
        if any(r[0] not in valid for r in db.execute('SELECT DISTINCT fact FROM fact')):
            raise ValueError('fact outside fixed schema')
    finally:db.close()
    ordered=sorted(latencies)
    atomic_json(destination,dict(scope=f'First up to {args.sample_lines} raw lines per indexed source; prefix-only, not a representative corpus sample',
                sampled_events=len(latencies),checked_ancestor_edges=checked_edges,feature_rows=coverage,
                median_encode_us=statistics.median(latencies)*1e6 if latencies else None,
                p95_encode_us=ordered[min(len(ordered)-1,int(len(ordered)*.95))]*1e6 if latencies else None,
                peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                graph_database_bytes=m['database_bytes'],graph_feature_columns=len(FEATURES),
                pilot=m['config']['pilot'],classification_metrics=None,
                note='No models trained or scored. Latency includes cache hits; full-corpus performance and FP/FN improvement are unmeasured.'))
    print(destination)


if __name__=='__main__':main()
