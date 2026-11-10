#!/usr/bin/env python3
"""Validate canonical preprocessing output and atomically replace Kaggle input.tar."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import tarfile
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[3]
sys.path.insert(0, str(WORKSPACE))
from ML.code.preprocess.host_shards import decode_shard


def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
    return h.hexdigest()


def validate_shards(root):
    manifest=json.loads((root/'manifest.json').read_text())
    if not manifest['complete']:raise ValueError('Incomplete manifest')
    for name, digest in manifest.get('assets_sha256', {}).items():
        if sha(root/'assets'/name) != digest:raise ValueError('Asset checksum mismatch')
    totals={s:[0,0] for s in ('train','val','test')}
    for part in manifest['shards']:
        p=(root/part['path']).resolve()
        if root.resolve() not in p.parents:raise ValueError('Shard escapes package')
        if sha(p)!=part['sha256']:raise ValueError(f'Bad shard hash: {p}')
        X,y,lines=decode_shard(p,manifest['vocab_size'],part)
        if "provenance_path" in part:
            from cohort_metrics import load_provenance
            load_provenance(root, part, lines)
        if X.shape[0]!=part['rows']:raise ValueError('Row mismatch')
        totals[part['split']][0]+=len(y);totals[part['split']][1]+=int(y.sum())
    for s,(rows,positives) in totals.items():
        if rows != manifest['splits'][s]['rows'] or positives != manifest['splits'][s]['label_1']:
            raise ValueError('Split totals mismatch')
    return totals


def main():
    staging=ROOT/'preprocess/output'
    archive=ROOT/'output/kaggle_input/input.tar'
    if not (staging/'manifest.json').exists():raise ValueError('Build preprocessing output first')
    if WORKSPACE/'DATASET' in staging.resolve().parents:raise ValueError('Read-only destination')
    archive.parent.mkdir(parents=True,exist_ok=True)
    original_sha=sha(archive) if archive.exists() else None
    # Frozen dependencies live alongside canonical shards and are never regenerated here.
    for required in ('optc_test/manifest.json','atlasv2_test/manifest.json',
                     'optc_replay_buffer.npz','pretrained_optc_model/composition.json'):
        if not (staging/required).is_file():raise ValueError(f'Missing frozen dependency: {required}')
    from frozen_atlas import FrozenAtlasModel
    FrozenAtlasModel(staging/'pretrained_optc_model/model-slot-0.txt')
    shutil.copy2(ROOT/'notebook/lgbm_atlasv2_theia.ipynb',staging/'lgbm_atlasv2_theia.ipynb')
    source=staging/'source'
    if source.exists():shutil.rmtree(source)
    for p in [*sorted((ROOT/'preprocess').glob('*.py')),*sorted((ROOT.parent/'preprocess').glob('*.py')),
              *sorted((ROOT/'audit').glob('*.py')),*sorted((ROOT/'test').glob('*.py')),*sorted((ROOT/'docs').glob('*.md'))]:
        rel=p.relative_to(ROOT.parent)
        dest=source/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
    base=json.loads((staging/'assets/vocab.json').read_text())
    extended=json.loads((staging/'assets/vocab_extended.json').read_text())
    if any(extended[t]!=i for t,i in base.items()):raise ValueError('Frozen column changed')
    if sorted(extended.values())!=list(range(len(extended))):raise ValueError('Invalid vocab indices')
    if any(t.startswith('flow::') for t in extended if t not in base):raise ValueError('New socket features')
    totals={str(p.relative_to(staging)) or '.':validate_shards(p) for p in [staging,staging/'optc_test',staging/'atlasv2_test']}
    # Verify the replay shape and old-domain vocabularies against the frozen prefix.
    with np.load(staging/'optc_replay_buffer.npz', allow_pickle=False) as replay:
        shape=tuple(replay['shape'])
        if shape[1] > len(base) or shape[0] != len(replay['labels']):
            raise ValueError('Replay incompatible with frozen base')
    for domain in ('optc_test', 'atlasv2_test'):
        old_vocab=json.loads((staging/domain/'assets/vocab.json').read_text())
        if any(base.get(t) != i for t,i in old_vocab.items()):
            raise ValueError('Old-domain column meanings differ from base')
    # No raw network token is activated, including dormant inherited columns.
    flow_columns=np.array([i for t,i in extended.items() if t.startswith('flow::')],dtype=np.int64)
    manifest=json.loads((staging/'manifest.json').read_text())
    if len(flow_columns):
        for part in manifest['shards']:
            X,_,_=decode_shard(staging/part['path'],manifest['vocab_size'],part)
            if X[:,flow_columns].nnz:raise ValueError('Raw flow features activated in host rows')
    files={str(p.relative_to(staging)):sha(p) for p in sorted(staging.rglob('*')) if p.is_file() and "__pycache__" not in p.parts and p.name != "package_receipt.json" and not p.name.endswith(".sqlite")}
    receipt=dict(previous_package_sha256=original_sha,files_sha256=files,validated_totals=totals,
                 training_executed_by_packager=False,calibration='validation negative histogram FPR <= 0.005; secondary 0.01',
                 limitations=['Legacy heuristic labels and positive loop cap retained',
                              'Test-informed development: exploratory comparison, not independent confirmation',
                              'Context uses already observed events with timestamps <= query; late arrivals are not retroactive'])
    (staging/'package_receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    # All contents are validated before either publication.
    temporary=archive.with_suffix('.tar.partial')
    with tarfile.open(temporary,'w') as tar:
        for p in sorted(staging.rglob('*')):
            if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".sqlite"):tar.add(p,arcname=str(p.relative_to(staging)),recursive=False)
    with tarfile.open(temporary) as tar:
        for member in tar:
            if member.name in files:
                if hashlib.sha256(tar.extractfile(member).read()).hexdigest()!=files[member.name]:
                    raise ValueError('Packaged bytes differ')
    digest=sha(temporary)
    with temporary.open('rb') as f:os.fsync(f.fileno())
    os.replace(temporary,archive)
    archive.with_suffix('.tar.sha256').write_text(f'{digest}  {archive.name}\n')
    print(json.dumps(dict(archive=str(archive),sha256=digest,bytes=archive.stat().st_size,totals=totals),indent=2))

if __name__=='__main__':main()
