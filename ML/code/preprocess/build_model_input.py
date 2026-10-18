#!/usr/bin/env python3
"""Full-data, binary sparse model input: compressed shards, multiple disks, resume.

Uses the already-published split and vocabulary. No global matrix or JSONL
sidecar is constructed, and no event is sampled or aggregated away.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

from ML.code.preprocess.ecar_tokenizer import flatten_tokens,token_layers,tokenize_record
from ML.code.preprocess.pipeline_contract import PROJECT_ROOT,load_vocabulary,validate_output_path,code_hashes,sync_directory
from ML.code.preprocess.stratified_pipeline import (BASE,load_manifest,checked_manifest,checked_sources,split_rows,
                                 bounded_map,digest,atomic_json,file_hash,stamp)
from ML.code.preprocess.shard_storage import exclusive_lock,load_volumes,initialize_ledger,write_shard
from ML.code.preprocess.host_shards import FORMAT,SCHEMA,SPLITS,ShardBuffer


def builder_identity():
    return code_hashes(('build_model_input.py','host_shards.py','shard_storage.py'))


def receipt_valid(receipt,entry,run_id,volumes):
    if receipt.get('run_id')!=run_id or receipt.get('entry_sha256')!=digest(entry):
        return False
    roots={v['id']:Path(v['path']).resolve() for v in volumes}
    counts={s:Counter() for s in SPLITS}
    lines={s:0 for s in SPLITS}
    seen=set()
    for part in receipt['shards']:
        split=part['split']
        root=roots[part['volume']]
        path=(root/part['path']).resolve()
        if not path.is_relative_to(root) or part['path'] in seen:
            return False
        seen.add(part['path'])
        if (part['source_line_first']<=lines[split] or part['source_line_last']<part['source_line_first']
                or part['source_line_last']>entry['counts'].get('lines',0)):
            return False
        lines[split]=part['source_line_last']
        if path.stat().st_size!=part['bytes'] or file_hash(path)!=part['sha256']:
            return False
        for k in ('rows','nnz','label_0','label_1','bytes'):counts[split][k]+=part[k]
    for i,s in enumerate(SPLITS):
        if (counts[s]['label_0']!=entry['allocation']['1'][i]
                or counts[s]['label_1']!=entry['allocation']['2'][i]
                or counts[s]['rows']!=counts[s]['label_0']+counts[s]['label_1']):
            return False
    return True


def process_source(entry,split_dir,vocab,control,run_id,volumes,rows_per_shard,buffer_bytes):
    source_id=digest(entry['source'])
    receipt_path=control/'checkpoints'/run_id/f'{source_id}.json'
    checked_sources([entry])
    if receipt_path.exists():
        try:
            receipt=json.loads(receipt_path.read_text())
            if receipt_valid(receipt,entry,run_id,volumes):
                return dict(receipt,resumed=True)
        except (OSError,ValueError,KeyError,TypeError):
            pass
    buffers={s:ShardBuffer(len(vocab)) for s in SPLITS}
    numbers=Counter();stats=Counter();parts=[]
    started=time.monotonic()
    def flush(s):
        buffer=buffers[s]
        if not len(buffer):return
        payload,info=buffer.encode()
        relative=f'{run_id}/{source_id}/{s}_{numbers[s]:06d}.npz'
        location=write_shard(control,relative,payload)
        parts.append(dict(info,**location,split=s,source_id=source_id))
        numbers[s]+=1
        buffers[s]=ShardBuffer(len(vocab))
    for code,line,record in split_rows(entry,split_dir):
        split=SPLITS[code-1]
        grouped,audit=tokenize_record(record)
        if not audit['eligible']:raise ValueError('split/tokenizer eligibility mismatch')
        tokens=set(flatten_tokens(grouped))
        columns=[]
        for token in tokens:
            if token in vocab:columns.append(vocab[token])
            for layer in token_layers(token):
                stats[f'candidate_unique_{layer}']+=1
                if token not in vocab:stats[f'oov_unique_{layer}']+=1
        if not columns:stats['empty_vectors']+=1
        buffers[split].append(columns,record['label'],line)
        stats['rows']+=1
        if len(buffers[split])>=rows_per_shard or buffers[split].nbytes>=buffer_bytes:flush(split)
    for s in SPLITS:flush(s)
    checked_sources([entry])
    receipt=dict(run_id=run_id,entry_sha256=digest(entry),source_id=source_id,
                 shards=parts,stats=dict(stats),elapsed_seconds=time.monotonic()-started)
    if not receipt_valid(receipt,entry,run_id,volumes):
        raise ValueError('new shard receipt failed count/checksum validation')
    atomic_json(receipt_path,receipt)
    return dict(receipt,resumed=False)


def copy_asset(source,target):
    target=validate_output_path(target)
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        if file_hash(source)!=file_hash(target):
            raise ValueError(f'existing output asset differs; use a separate output directory: {target}')
        return
    temporary=target.with_name('.'+target.name+'.tmp')
    shutil.copyfile(source,temporary)
    with temporary.open('rb') as handle:os.fsync(handle.fileno())
    os.replace(temporary,target);sync_directory(target.parent)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split',type=Path,default=BASE/'split/manifest.json')
    parser.add_argument('--vocab',type=Path,default=BASE/'vocab.json')
    parser.add_argument('--vocab-metadata',type=Path,default=BASE/'vocab_metadata.json')
    parser.add_argument('--output-dir',type=Path,default=BASE/'model_input')
    parser.add_argument('--storage-config',type=Path,default=Path(__file__).resolve().parents[1]/'others/model_input_volumes.json')
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--rows-per-shard',type=int,default=100000)
    parser.add_argument('--buffer-mib',type=int,default=32)
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args(argv)
    if min(args.workers,args.rows_per_shard,args.buffer_mib)<1:raise ValueError('positive worker/buffer sizes required')
    split,split_sha=load_manifest(args.split,'host_random_split')
    vocab,vm=load_vocabulary(args.vocab,args.vocab_metadata,split_sha256=split_sha)
    protected=[args.split.resolve().parent]+[Path(e['source']['path']).parent for e in split['entries']]
    control=validate_output_path(args.output_dir,protected)
    volumes=load_volumes(args.storage_config,protected,create=False)
    config=dict(format=FORMAT,schema=SCHEMA,split_sha256=split_sha,vocabulary_sha256=vm['vocabulary_sha256'],
                builder_sha256=builder_identity(),rows_per_shard=args.rows_per_shard,buffer_bytes=args.buffer_mib*2**20)
    run_id=digest(config)
    if args.dry_run:
        print(json.dumps(dict(run_id=run_id,sources=len(split['entries']),counts=split['counts'],
            vocab_size=len(vocab),output_dir=str(control),volumes=volumes,
            note='Full corpus; compression size is unknown until shards are measured. No output writes.'),indent=2))
        return 0
    control.mkdir(parents=True,exist_ok=True)
    with exclusive_lock(control/'builder.lock',nonblocking=True), ExitStack() as locks:
        final=control/'manifest.json'
        if final.exists():
            existing=json.loads(final.read_text())
            if existing.get('run_id')==run_id and existing.get('complete'):
                print(f'Already complete: {final}. Use verify_model_input.py to verify shards.');return 0
            raise ValueError('completed output has a different configuration; preserving it')
        volumes=load_volumes(args.storage_config,protected,create=True)
        for volume in sorted(volumes,key=lambda v:v['path']):
            locks.enter_context(exclusive_lock(Path(volume['path'])/'volume_owner.lock',nonblocking=True))
        initialize_ledger(control,volumes)
        atomic_json(control/'run_config.json',dict(config,run_id=run_id,volumes=volumes))
        copy_asset(args.split,control/'assets/split_manifest.json')
        copy_asset(args.vocab,control/'assets/vocab.json')
        copy_asset(args.vocab_metadata,control/'assets/vocab_metadata.json')
        copy_asset(Path(__file__).with_name('host_shards.py'),control/'host_shards.py')
        copy_asset(Path(__file__).with_name('shard_metrics.py'),control/'shard_metrics.py')
        notebook_dir=Path(__file__).resolve().parents[1]/'kaggle/notebooks'
        for p in sorted(notebook_dir.glob('host_*_shards.ipynb')):copy_asset(p,control/p.name)
        parts=[];stats=Counter();resumed=0
        tasks=[(e,args.split.resolve().parent,vocab,control,run_id,volumes,args.rows_per_shard,args.buffer_mib*2**20) for e in split['entries']]
        for i,result in enumerate(bounded_map(process_source,tasks,args.workers),1):
            parts.extend(result['shards']);stats.update(result['stats']);resumed+=int(result['resumed'])
            saved=sum(p['bytes'] for p in result['shards'])
            print(f'[{i}/{len(tasks)}] {"RESUME" if result["resumed"] else "WROTE"} {result["source_id"][:12]}: '
                  f'{result["stats"].get("rows",0):,} rows, {saved/2**20:.1f} MiB; total {stats.get("rows",0):,} rows',flush=True)
        checked_manifest(args.split,split_sha,split)
        totals={s:{k:sum(p[k] for p in parts if p['split']==s) for k in ('rows','nnz','label_0','label_1','bytes')} for s in SPLITS}
        for s in SPLITS:
            if any(totals[s][k]!=v for k,v in split['counts'][s].items()):
                raise ValueError('output class totals differ from original split')
        if file_hash(args.vocab)!=vm['vocabulary_sha256']:
            raise ValueError('vocabulary changed during processing')
        manifest=dict(config,run_id=run_id,complete=True,created_utc=stamp(),vocab_size=len(vocab),
            seed=split['seed'],splits=totals,volumes={v['id']:v['path'] for v in volumes},
            sources=[dict(source_id=digest(e['source']),source=e['source'],file_host=e['host'],day=e['day']) for e in split['entries']],
            shards=parts,assets_sha256={p.name:file_hash(p) for p in (control/'assets').iterdir()},
            statistics=dict(stats),resumed_files=resumed,representation='binary sparse presence; no row aggregation or sampling',
            row_identity='source_id + source_line; raw provenance remains in read-only source records',
            stage_compatibility='original split/tokenizer/vocabulary checked without modifying upstream artifacts')
        atomic_json(final,manifest)
        print(json.dumps(dict(manifest=str(final),splits=totals,total_shard_bytes=sum(p['bytes'] for p in parts)),indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
