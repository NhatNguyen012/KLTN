#!/usr/bin/env python3
"""Re-score frozen XGB shards, export all errors and audit exact feature collisions.

No training, vocabulary fitting or threshold selection. Uses the recorded
validation threshold. Full TRAIN signature counts are not fitted-sample counts.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'preprocess'))
import numpy as np
import xgboost as xgb
from host_shards import HostShardDataset, decode_shard, sha256
from pipeline_contract import validate_output_path
from stratified_pipeline import atomic_json, digest, identity, work_directory, publish_directory


def classify_error(label, score, threshold):
    return ('FN' if label else 'FP') if (score >= threshold) != bool(label) else None


def collision_stats(groups, offset):
    mixed = [g for g in groups if g['counts'][offset] and g['counts'][offset+1]]
    return dict(mixed_signatures=len(mixed),
                rows_in_mixed_signatures=sum(sum(g['counts'][offset:offset+2]) for g in mixed),
                minimum_unavoidable_errors=sum(min(g['counts'][offset:offset+2]) for g in mixed))


def fixed_feature_f1_ceiling(groups, positive_count, offset):
    """Descriptive, label-informed oracle; never a fitted model or tuned threshold.

    groups must include every mixed-label vector in the evaluated partition.
    Pure-positive vectors are always included; sort mixed vectors by positive
    fraction and evaluate prefixes, since the F1-optimal set has such a cutoff.
    """
    mixed=[g['counts'][offset:offset+2] for g in groups
           if g['counts'][offset] and g['counts'][offset+1]]
    tp=positive_count-sum(p for b,p in mixed);fp=0
    if tp<0 or positive_count<=0:raise ValueError('invalid positive count')
    best=dict(f1=2*tp/(positive_count+tp),tp=tp,fp=fp,fn=positive_count-tp)
    for b,p in sorted(mixed,key=lambda counts:counts[1]/sum(counts),reverse=True):
        tp+=p;fp+=b;f1=2*tp/(positive_count+tp+fp)
        if f1>best['f1']:best=dict(f1=f1,tp=tp,fp=fp,fn=positive_count-tp)
    return best


def trace_raw(requests, sources, work):
    """Bounded one-pass per source, durable per-file receipts for expensive scans."""
    traced=[]
    for i,(sid,lines) in enumerate(sorted(requests.items()),1):
        source=sources[sid]['source']; path=Path(source['path'])
        if identity(path)!=source: raise ValueError(f'raw source identity changed: {path}')
        config=dict(source=source,lines=sorted(lines))
        receipt=validate_output_path(work/f'raw-{digest(config)}.json')
        if receipt.exists():
            rows=json.loads(receipt.read_text())
        else:
            wanted=set(lines); rows=[]
            with gzip.open(path,'rt',encoding='utf-8') as handle:
                for number,line in enumerate(handle,1):
                    if number in wanted:
                        rows.append(dict(source_id=sid,source_line=number,source_path=str(path),record=json.loads(line)))
                        wanted.remove(number)
                        if not wanted: break
            if wanted: raise ValueError(f'raw lines not found: {path}: {wanted}')
            if identity(path)!=source: raise ValueError('raw source changed during read')
            atomic_json(receipt,rows)
        traced.extend(rows)
        print(f'Raw source {i}/{len(requests)}: {len(rows)} records from {path.name}',flush=True)
    return traced


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--raw-top-groups',type=int,default=0,help='Trace representative errors and TRAIN counterparts for N largest test error signatures')
    parser.add_argument('--threads',type=int,default=4)
    args=parser.parse_args(argv)
    if args.threads<1 or args.raw_top_groups<0: raise ValueError('invalid thread/group limit')
    results=args.results.resolve(); metrics=json.loads((results/'results/xgb_metrics.json').read_text())
    dataset=HostShardDataset(args.manifest)
    for key in ('split_sha256','vocabulary_sha256'):
        if dataset.meta[key]!=metrics[key]: raise ValueError(f'run/shard mismatch: {key}')
    model_path=results/'results/model'/metrics['model_checkpoint']['path']
    if sha256(model_path)!=metrics['model_checkpoint']['sha256']: raise ValueError('model checksum mismatch')
    if metrics['test']['threshold']!=metrics['validation']['threshold']: raise ValueError('threshold mismatch')
    threshold=metrics['validation']['threshold']
    protected=[results,args.manifest.resolve().parent,*[Path(x) for x in dataset.meta['volumes'].values()]]
    output=validate_output_path(args.output_dir,protected)
    config=dict(model_sha256=sha256(model_path),manifest_sha256=sha256(args.manifest),
                metrics_sha256=sha256(results/'results/xgb_metrics.json'),threshold=threshold,
                audit_sha256=sha256(Path(__file__)),raw_top_groups=args.raw_top_groups,xgboost=xgb.__version__)
    output,work=work_directory(output,config)
    model=xgb.Booster();model.load_model(model_path);model.set_param(dict(device='cpu',nthread=args.threads))
    reverse={v:k for k,v in json.loads((results/'provenance/vocab.json').read_text()).items()}
    if sha256(results/'provenance/vocab.json')!=metrics['vocabulary_sha256']: raise ValueError('vocab checksum mismatch')
    # Key is the complete sorted sparse column vector, not a probabilistic hash.
    by_vector={}; groups=[];confusions={s:Counter() for s in ('val','test')}
    errors={s:[] for s in ('val','test')}; object_counts={s:Counter() for s in errors}
    for split_index,split in enumerate(('train','val','test')):
        parts=[p for p in dataset.meta['shards'] if p['split']==split]
        for part_index,part in enumerate(parts,1):
            X,y,lines=decode_shard(dataset.path_for(part),dataset.width,part)
            ids=np.empty(len(y),dtype=np.int64); new_rows=[]; new_ids=[]
            for row in range(len(y)):
                columns=X.indices[X.indptr[row]:X.indptr[row+1]]
                key=columns.astype('<u4',copy=False).tobytes()
                gid=by_vector.get(key)
                if gid is None:
                    gid=len(groups);by_vector[key]=gid
                    tokens=[reverse[int(c)] for c in columns]
                    groups.append(dict(signature_id=gid,columns=columns.tolist(),tokens=tokens,
                        counts=[0]*6,train_examples={},error_examples={},score=None))
                    new_rows.append(row);new_ids.append(gid)
                ids[row]=gid
            if new_rows:
                scores=model.predict(xgb.DMatrix(X[new_rows],nthread=args.threads))
                for gid,score in zip(new_ids,scores):groups[gid]['score']=float(score)
            for row,(gid,label,line) in enumerate(zip(ids,y,lines)):
                group=groups[int(gid)]; label=int(label);group['counts'][split_index*2+label]+=1
                ref=dict(source_id=part['source_id'],source_line=int(line),shard=part['path'],volume=part['volume'])
                if split=='train':
                    group['train_examples'].setdefault(str(label),ref)
                    continue
                score=group['score']; error=classify_error(label,score,threshold)
                confusions[split][error.lower() if error else ('tp' if label else 'tn')]+=1
                if error:
                    source=dataset.sources[part['source_id']]
                    rec=dict(**ref,source_path=source['source']['path'],host=source['file_host'],day=source['day'],
                             split=split,label=label,score=score,threshold=threshold,error=error,signature_id=int(gid))
                    errors[split].append(rec);group['error_examples'].setdefault(split,rec)
                    obj=next((t for t in group['tokens'] if t.startswith('object::')),'object::unknown')
                    object_counts[split][error+'/'+obj]+=1
            if part_index%20==0 or part_index==len(parts):
                print(f'{split}: {part_index}/{len(parts)} shards; {len(groups)} unique vectors',flush=True)
    for split in errors:
        if dict(confusions[split])!=metrics['validation' if split=='val' else 'test']['confusion']:
            raise ValueError(f'{split}: re-scored confusion differs from Kaggle: {dict(confusions[split])}; no complete audit published')
    error_groups=[g for g in groups if g['error_examples']]
    for group in error_groups:
        group['error_counts']={}
        for split,offset in [('val',2),('test',4)]:
            group['error_counts'][split]=dict(FP=group['counts'][offset] if group['score']>=threshold else 0,
                                             FN=group['counts'][offset+1] if group['score']<threshold else 0)
    ranked=sorted(error_groups,key=lambda g:sum(g['error_counts']['test'].values()),reverse=True)
    categories=Counter()
    for error in errors['test']:
        group=groups[error['signature_id']]; b,m=group['counts'][:2]
        category='mixed_label_train_vector' if b and m else 'unseen_train_vector' if not b and not m else 'opposite_label_only_train_vector' if not group['counts'][error['label']] else 'same_label_only_train_vector'
        categories[error['error']+'/'+category]+=1
    summary=dict(**config,counts=dict(confusions),training_population='full persisted TRAIN, not the fitted undersample',
        train_rows_not_in_fitted_sample=dataset.meta['splits']['train']['rows']-metrics['train_sampling']['rows'],
        signature_count=len(groups),error_signature_count=len(error_groups),test_error_train_categories=dict(categories),
        object_errors={s:dict(c) for s,c in object_counts.items()},
        exact_collision_limits={s:collision_stats(groups,i*2) for i,s in enumerate(('train','val','test'))},
        caveat='Collision lower bound is descriptive on observed labels, not deployment performance or evidence that labels are wrong.')
    atomic_json(work/'summary.json',summary)
    atomic_json(work/'error_signatures.json',ranked)
    for split,rows in errors.items():
        path=validate_output_path(work/f'{split}_all_errors.jsonl')
        temp=validate_output_path(path.with_suffix('.tmp'))
        with temp.open('w') as handle:
            for row in rows:handle.write(json.dumps(row)+'\n')
            handle.flush();os.fsync(handle.fileno())
        os.replace(temp,path)
    requests=defaultdict(set)
    for group in ranked[:args.raw_top_groups]:
        for ref in [group['error_examples'].get('test'),*group['train_examples'].values()]:
            if ref:requests[ref['source_id']].add(ref['source_line'])
    if requests:atomic_json(work/'representative_raw_events.json',trace_raw(requests,dataset.sources,work))
    publish_directory(work,output,dict(kind='frozen_xgb_error_audit',**config,complete=True))
    print(json.dumps(summary,indent=2),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
