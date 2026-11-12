#!/usr/bin/env python3
"""Publish process-sequence graphs and a separate weak-label review ledger."""
import csv
import hashlib
import json
from pathlib import Path
import sys
from collections import defaultdict,Counter
import numpy as np
import torch

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/'model'),str(DL.parent)]
from research_paths import validate_output_dir
from process_graph_data import ObservationIndex,build_window_graph,review_targets


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    source=DL/'output/provenance_context_20261111/data'
    audit=DL/'output/research_20261111/raw_audit'
    base=DL/'preprocess/output'
    final=validate_output_dir(DL/'output/process_graph_20261111/data')
    if final.exists():raise FileExistsError(final)
    out=final.with_name(final.name+'.building')
    if out.exists():raise FileExistsError(out)
    out.mkdir(parents=True)
    with (base/'split/network_sample_manifest.csv').open() as f:rows=list(csv.DictReader(f))
    with (audit/'window_trace.csv').open() as f:traces={r['sample_id']:r for r in csv.DictReader(f)}
    positives={}
    with (audit/'positive_events.csv').open() as f:
        for row in csv.DictReader(f):positives[(row['source'],int(row['line']))]=row
    by_source=defaultdict(list);by_line=defaultdict(dict)
    with (source/'event_provenance.jsonl').open() as f:
        for line in f:
            record=json.loads(line);by_source[record['source']].append(record);by_line[record['source']][record['line']]=record
    maps=json.loads((base/'preprocessing/network_category_maps.json').read_text())['fields']
    fields=['app_family','proto','resp_port_class','image_dir_class']
    inverses=[{v:k for k,v in maps[field]['mapping'].items()} for field in fields]
    cache={};train_counts=Counter()
    # Preserve the existing encoded evidence as well as newly explicit source roles.
    # ID integers themselves do not become ordered/scalar model features.
    for row in rows:
        trace=traces[row['sample_id']];name=trace['source']
        path=row['shard_file']
        if path not in cache:
            with np.load(base/path) as z:cache[path]={k:z[k] for k in ['sample_offsets','x_cat']}
        z=cache[path];i=int(row['shard_sample_index']);lo,hi=z['sample_offsets'][i:i+2]
        lines=list(map(int,trace['source_lines'].split('|')))
        for ln,cat in zip(lines,z['x_cat'][int(lo):int(hi)]):
            record=by_line[name][ln]
            record['tokens']=sorted(set(record['tokens'])|{f'event::base_{field}={inv.get(int(value),"<UNK>")}' for field,inv,value in zip(fields,inverses,cat)})
    train_members=set()
    for row in rows:
        if row['split']!='train':continue
        tr=traces[row['sample_id']]
        train_members.update((tr['source'],int(ln)) for ln in tr['source_lines'].split('|'))
    for name,ln in train_members:train_counts.update(t for t in by_line[name][ln]['tokens'] if t.startswith('event::'))
    vocab={t:i for i,t in enumerate(sorted(t for t,c in train_counts.items() if c>=2))}
    indices={name:ObservationIndex(records) for name,records in by_source.items()}
    samples=defaultdict(list);ledger=[];edge_train=set();stats=defaultdict(Counter)
    for row in rows:
        sid=row['sample_id'];tr=traces[sid];name=tr['source'];lines=list(map(int,tr['source_lines'].split('|')))
        records=[by_line[name][ln] for ln in lines]
        # This call has no access to labels, stages, split IDs or review decisions.
        graph,info=build_window_graph(records,indices[name],vocab)
        pos=[positives[(name,ln)] for ln in lines if (name,ln) in positives]
        targets=review_targets(pos,scenario=tr['scenario'],original_label=int(row['label']))
        if row['split']=='train':edge_train.update(graph['edge_kind'])
        samples[row['split']].append(dict(features=graph,targets=targets,original_label=int(row['label']),
            original_stage=int(row['stage']),sample_id=sid,audit=info,source=name,source_lines=lines))
        ledger.append(dict(sample_id=sid,split=row['split'],source=name,original_binary=row['label'],original_stage=row['stage'],
            review_mask=targets['review_mask'],reason=targets['reason'],
            original_stage_set='|'.join(str(i+1) for i,v in enumerate(targets['original_stages']) if v),
            retained_stage_set='|'.join(str(i+1) for i,v in enumerate(targets['reviewed_stages']) if v),
            uncertain_source_lines='|'.join(map(str,targets['uncertain_source_lines']))))
        stats[row['split']]['windows']+=1;stats[row['split']]['retained_windows']+=int(targets['review_mask'])
        stats[row['split']]['original_positives']+=int(row['label']);stats[row['split']]['retained_positives']+=int(targets['review_mask'] and int(row['label']))
        stats[row['split']]['omitted_central']+=info['omitted_central'];stats[row['split']]['truncated_sequences']+=info['truncated_process_sequences']
    edge_vocab={'<UNK>':0,**{k:i+1 for i,k in enumerate(sorted(edge_train))}}
    for split,items in samples.items():
        for item in items:item['features']['edge_kind']=np.array([edge_vocab.get(k,0) for k in item['features']['edge_kind']],np.int64)
        torch.save(items,out/f'{split}.pt')
    with (out/'review_ledger.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(ledger[0]));w.writeheader();w.writerows(ledger)
    meta=dict(event_vocab=vocab,edge_vocab=edge_vocab,stats=stats,
        event_frequency_train={t:train_counts[t] for t in vocab},
        policy='process sequences + learned two-hop typed graph; weak multi-label stage presence',
        temporal_policy='window-end prediction; only edges and metadata with device timestamp <= final current event; snapshot history strictly prior to its query',
        caps=dict(central_processes=64,nodes=128,events_per_process=64,history_hops=2,incoming_per_kind=8,ttl_seconds=86400),
        supervision='Original labels preserved. Portal-only positive evidence and invalid S3 gate are masked, not reassigned to benign. Retained stages remain weak.',
        feature_boundary='No labels, review status, scenario, reputation, IOCs, source lines, GUIDs or stage names in model tensors. IDs only join/audit keys.',
        provenance={str(p):sha(p) for p in [source/'context_metadata.json',base/'split/network_sample_manifest.csv',audit/'positive_events.csv',Path(__file__),Path(__file__).with_name('process_graph_data.py')]})
    (out/'metadata.json').write_text(json.dumps(meta,indent=2));out.replace(final)
    print(json.dumps(meta['stats'],indent=2),flush=True);print('Published',final,flush=True)


if __name__=='__main__':main()
