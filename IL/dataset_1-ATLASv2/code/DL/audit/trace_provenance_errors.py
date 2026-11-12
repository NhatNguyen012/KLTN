#!/usr/bin/env python3
"""Join model errors to observable provenance; supervision appears only in audits."""
import argparse
from collections import Counter,defaultdict
import csv
import json
from pathlib import Path
import sys

DL=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(DL/'model'))
from research_paths import validate_output_dir


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--context-dir',type=Path,default=DL/'output/provenance_context_20261111/data')
    ap.add_argument('--predictions',type=Path,default=DL/'output/research_20261111/audit/v5_test_errors.csv')
    ap.add_argument('--output-dir',type=Path,default=DL/'output/provenance_context_20261111/traceback_v5')
    args=ap.parse_args();out=validate_output_dir(args.output_dir);out.mkdir(parents=True,exist_ok=True)
    with args.predictions.open() as f:preds={r['sample_id']:r for r in csv.DictReader(f) if r['error_type']!='correct'}
    with (DL/'output/research_20261111/raw_audit/window_trace.csv').open() as f:
        windows={r['sample_id']:r for r in csv.DictReader(f) if r['sample_id'] in preds}
    wanted=defaultdict(set)
    for w in windows.values():wanted[w['source']].update(map(int,w['source_lines'].split('|')))
    events={}
    with (args.context_dir/'event_provenance.jsonl').open() as f:
        for line in f:
            r=json.loads(line)
            if r['line'] in wanted[r['source']]:events[(r['source'],r['line'])]=r
    with (DL/'output/research_20261111/raw_audit/positive_events.csv').open() as f:
        positive={(r['source'],int(r['line'])):r for r in csv.DictReader(f)}
    summaries=[]
    for sid,w in windows.items():
        records=[events[(w['source'],int(ln))] for ln in w['source_lines'].split('|')]
        targets=[r for r in records if (w['source'],r['line']) in positive]
        tokens=Counter(t for r in records for t in r['tokens'])
        evidence=Counter(e['kind'] for r in records for e in r['evidence'])
        labeled=[dict(positive[(r['source'],r['line'])]) for r in targets]
        # Entire bounded neighbourhood for the events that supplied the positive
        # target; FP windows retain every event. No truncation in machine artifact.
        focus=targets or records
        nodes={};edges=[]
        def node(e,which):
            guid=e[which];key=e['host']+':'+guid
            nodes[key]=dict(id=key,host=e['host'],guid=guid,path=e['actor_path'] if which=='actor' else e['target_path'])
            return key
        for r in focus:
            e=r['event'];node(e,'actor')
            if e['target'] and e['direction_known']:edges.append(dict(src=node(e,'actor'),dst=node(e,'target'),relation=e['relation'],timestamp=e['timestamp'],source=r['source'],line=e['line'],scope='current_event'))
            for entry in r['evidence']:
                p=entry['observation']
                if entry['kind']=='image_writer':
                    file_key=p['host']+':file:'+p['target_path']
                    nodes[file_key]=dict(id=file_key,host=p['host'],path=p['target_path'],type='file')
                    edges.append(dict(src=node(p,'actor'),dst=file_key,relation='file_write',timestamp=p['timestamp'],query_timestamp=e['timestamp'],source=r['source'],line=p['line'],scope='strictly_past_image_writer'))
                    if e['target']:
                        edges.append(dict(src=file_key,dst=node(e,'target'),relation='spawned_image_path_match',timestamp=e['timestamp'],source=r['source'],line=e['line'],scope='current_event_path_join'))
                else:
                    edges.append(dict(src=node(p,'actor'),dst=node(p,'target'),relation=p['relation'],timestamp=p['timestamp'],query_timestamp=e['timestamp'],source=r['source'],line=p['line'],scope='strictly_past_'+entry['kind']))
        unique={json.dumps(e,sort_keys=True):e for e in edges}
        graph=dict(sample_id=sid,prediction=preds[sid],window=w,positive_evidence_audit_only=labeled,
            token_counts=tokens,context_evidence_counts=evidence,nodes=list(nodes.values()),edges=list(unique.values()),focal_events=focus,
            interpretation='Bounded observed relations; graph inclusion is not proof of compromise. Labels are audit annotations only.')
        (out/f'{sid}.json').write_text(json.dumps(graph,indent=2))
        summaries.append(dict(sample_id=sid,**{k:v for k,v in preds[sid].items() if k!='sample_id'},source=w['source'],
            positive_events=len(targets),parent_edges=evidence['parent'],incoming_edges=evidence['incoming'],image_writer_edges=evidence['image_writer'],
            event_types='|'.join(sorted({r['event']['kind'] for r in targets})),
            positive_paths='|'.join(sorted({r['event']['actor_path'] for r in targets}))))
    with (out/'summary.csv').open('w') as f:
        writer=csv.DictWriter(f,fieldnames=list(summaries[0]));writer.writeheader();writer.writerows(summaries)
    print('Exported',len(summaries),'complete bounded error graphs',flush=True)


if __name__=='__main__':main()
