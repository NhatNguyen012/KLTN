#!/usr/bin/env python3
"""Enrich the unchanged legacy DL samples with strictly past CBC graph context.

Source-line identities come from the independently reconstructed window trace.
No labeling/refinement code is used. Only train-member event tokens fit vocabulary.
"""
from collections import Counter, defaultdict
from dataclasses import asdict
from itertools import groupby
import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys
import numpy as np

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/"model"),str(DL.parent)]
from research_paths import ROOT,validate_output_dir
from preprocess.common_schema import parse_timestamp_micros
from provenance_context import observation,ProvenanceContext


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--data-dir",type=Path,default=DL/"preprocess/output")
    ap.add_argument("--raw-dir",type=Path,default=ROOT/"IL/dataset_1-ATLASv2/output/raw_cbc/atlasv2/data")
    ap.add_argument("--trace",type=Path,default=DL/"output/research_20261111/raw_audit/window_trace.csv")
    ap.add_argument("--output-dir",type=Path,default=DL/"output/provenance_context_20261111/data")
    ap.add_argument("--max-tokens",type=int,default=512)
    args=ap.parse_args();final=validate_output_dir(args.output_dir)
    if final.exists():raise FileExistsError(final)
    out=final.with_name(final.name+".building")
    if out.exists():raise FileExistsError(out)
    out.mkdir(parents=True)
    with (args.data_dir/"split/network_sample_manifest.csv").open() as f:manifest=list(csv.DictReader(f))
    wanted={r['sample_id']:r for r in manifest}
    with args.trace.open() as f:traces={r['sample_id']:r for r in csv.DictReader(f) if r['sample_id'] in wanted}
    if traces.keys()!=wanted.keys():raise ValueError("Trace does not cover frozen manifest")
    file_lines=defaultdict(dict);line_splits=defaultdict(lambda:defaultdict(set))
    for sid,row in traces.items():
        lines=[int(x) for x in row['source_lines'].split('|')]
        if len(lines)!=int(wanted[sid]['event_count']):raise ValueError(sid)
        file_lines[row['source']][sid]=lines
        for ln in lines:line_splits[row['source']][ln].add(wanted[sid]['split'])
    token_records={};train_counts=Counter();sources=[];stats={}
    with (out/'event_provenance.jsonl').open('w') as evidence_file:
        for path in sorted(args.raw_dir.rglob('*.jsonl')):
            if path.name not in file_lines or path.parent.name!='cbc-edr':continue
            events=[];digest=hashlib.sha256();count=0;directions=Counter()
            with path.open('rb') as f:
                for ln,line in enumerate(f,1):
                    digest.update(line);count+=1
                    raw=json.loads(line)
                    if raw.get('type') not in {'endpoint.event.procstart','endpoint.event.crossproc','endpoint.event.netconn','endpoint.event.filemod'}:continue
                    ts=parse_timestamp_micros(raw.get('device_timestamp'))
                    if ts<=0:continue
                    e=observation(raw,ts,ln)
                    if e:
                        events.append(e)
                        if e.kind=='crossproc':directions[str(raw.get('crossproc_target'))]+=1
            events.sort(key=lambda e:(e.timestamp,e.line))
            tracker=ProvenanceContext();records={};coverage=Counter()
            for ts,group in groupby(events,key=lambda e:e.timestamp):
                batch=list(group)
                for e in batch:
                    if e.line not in line_splits[path.name]:continue
                    tokens,evidence=tracker.features(e);records[e.line]=tokens
                    if 'train' in line_splits[path.name][e.line]:train_counts.update(tokens)
                    for kind,p in evidence:
                        if p.timestamp>=e.timestamp:raise AssertionError("Non-past evidence")
                        coverage[kind]+=1
                    evidence_file.write(json.dumps(dict(source=path.name,line=e.line,event=asdict(e),tokens=tokens,
                        evidence=[dict(kind=k,observation=asdict(p)) for k,p in evidence]))+'\n')
                tracker.observe_batch(batch)
            if records.keys()!=line_splits[path.name].keys():raise ValueError(f"Unmatched source lines in {path}")
            token_records[path.name]=records
            sources.append(dict(path=str(path.resolve()),sha256=digest.hexdigest(),raw_rows=count))
            stats[path.name]=dict(context_observations=len(events),query_events=len(records),evidence_counts=coverage,
                                  raw_crossproc_target= directions)
            print(path.name,stats[path.name],flush=True)
    selected=sorted((t for t,c in train_counts.items() if c>=2),key=lambda t:(-train_counts[t],t))[:args.max_tokens]
    vocab={t:i for i,t in enumerate(sorted(selected))}
    if not vocab:raise ValueError("Empty training vocabulary")
    if any(any(word in t.lower() for word in ['malicious','benign','attack','reputation','scenario','label','stage']) for t in vocab):
        raise AssertionError("Forbidden feature token")
    groups=defaultdict(list)
    for r in manifest:groups[r['shard_file']].append(r)
    for rel,rows in groups.items():
        with np.load(args.data_dir/rel) as z:payload={k:z[k] for k in z.files}
        context=np.zeros((len(payload['x_cat']),len(vocab)),dtype=np.uint8)
        for row in rows:
            idx=int(row['shard_sample_index']);lo,hi=payload['sample_offsets'][idx:idx+2]
            trace=traces[row['sample_id']];lines=file_lines[trace['source']][row['sample_id']]
            for offset,ln in enumerate(lines,int(lo)):
                ids=[vocab[t] for t in token_records[trace['source']][ln] if t in vocab]
                context[offset,ids]=1
        dest=out/rel;dest.parent.mkdir(parents=True,exist_ok=True)
        np.savez_compressed(dest,**payload,x_context=context)
    shutil.copytree(args.data_dir/'preprocessing',out/'preprocessing')
    shutil.copytree(args.data_dir/'split',out/'split')
    shutil.copy2(args.data_dir/'dataset_manifest.json',out/'dataset_manifest.json')
    config=dict(policy='label-blind CBC provenance context v1',fit_split='train',vocabulary=vocab,
        vocabulary_train_event_frequency={t:train_counts[t] for t in vocab},stats=stats,source_files=sources,
        manifest_sha256=sha(args.data_dir/'split/network_sample_manifest.csv'),trace_sha256=sha(args.trace),
        code_sha256={p.name:sha(p) for p in [Path(__file__),Path(__file__).with_name('provenance_context.py')]},
        temporal_policy='query all equal-time events before observing batch; context timestamp strictly earlier',
        scope='file/session + host; no PID fallback; max 8 per incoming kind; TTL 24h; processes 10000; files 20000',
        checkpoint_policy='atomic complete dataset publication; interrupted .building requires inspection; no partial resume',
        unchanged='sample IDs, labels, stages, splits, base feature tensors',feature_contract='x_context presence; groups event,parent,incoming,filectx')
    (out/'context_metadata.json').write_text(json.dumps(config,indent=2))
    out.replace(final);print('Published',final,'tokens',len(vocab),flush=True)


if __name__=='__main__':main()
