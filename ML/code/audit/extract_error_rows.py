#!/usr/bin/env python3
"""Resolve complete error JSONL exports to untouched raw Host events by source ID.

Streams each gzip once; resumes expensive source reads via per-source receipts.
Accepts files emitted by audit_xgb_run.py, using one-based source_line values.
"""
import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'preprocess'))
from pipeline_contract import validate_output_path
from stratified_pipeline import digest, file_hash, work_directory, publish_directory
from ML.code.audit.audit_xgb_run import trace_raw


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--errors',type=Path,nargs='+',required=True)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args(argv)
    manifest=json.loads(args.manifest.read_text())
    sources={s['source_id']:s for s in manifest['sources']}
    output=validate_output_path(args.output_dir,[args.manifest.resolve().parent,*[p.resolve().parent for p in args.errors]])
    config=dict(manifest_sha256=file_hash(args.manifest),errors_sha256={str(p.resolve()):file_hash(p) for p in args.errors},
                implementation_sha256=file_hash(Path(__file__)),reader_sha256=file_hash(Path(__file__).with_name('audit_xgb_run.py')))
    output,work=work_directory(output,config)
    requests=defaultdict(set);errors=[]; seen=set()
    for path in args.errors:
        with path.open() as handle:
            for line in handle:
                row=json.loads(line);sid=row['source_id'];number=row['source_line']
                if sid not in sources or type(number) is not int or number<1:raise ValueError('invalid provenance')
                key=(sid,number)
                if key in seen:raise ValueError('duplicate source row across error exports')
                seen.add(key);requests[sid].add(number);errors.append(row)
    raw={(r['source_id'],r['source_line']):r['record'] for r in trace_raw(requests,sources,work)}
    counts={};handles={}
    try:
        for row in errors:
            event=raw[(row['source_id'],row['source_line'])]
            if event.get('label',0)!=row['label']:raise ValueError('raw/error label mismatch')
            split=row['split']
            if split not in ('val','test'):raise ValueError('unexpected error split')
            if split not in handles:
                handles[split]=validate_output_path(work/f'{split}_all_errors_raw.jsonl').open('w')
            handles[split].write(json.dumps(dict(**row,raw_event=event))+'\n')
            counts[split]=counts.get(split,0)+1
    finally:
        for h in handles.values():h.flush();os.fsync(h.fileno());h.close()
    publish_directory(work,output,dict(kind='raw_error_trace',complete=True,counts=counts,**config))
    print(json.dumps(dict(output=str(output),counts=counts),indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
