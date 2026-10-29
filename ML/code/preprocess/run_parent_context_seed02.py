#!/usr/bin/env python3
"""Build the full frozen seed02 parent-context experiment once, verify and package.

No split rebuild, model training or long duplicate continuous/resume experiment.
Rerunning resumes production file checkpoints and reuses completed phases.
"""
from pathlib import Path
import argparse
import gzip
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from ML.code.preprocess.pipeline_contract import validate_output_path, code_hashes
from ML.code.preprocess.stratified_pipeline import file_hash, atomic_json, load_manifest, checked_manifest, digest
from ML.code.preprocess.host_shards import HostShardDataset, decode_shard


def verify_frozen_labels(manifest, split_path, index_path):
    """Independent target membership + frozen index-label fidelity, per source."""
    import numpy as np
    data = HostShardDataset(manifest)
    split, sha = load_manifest(split_path, 'host_random_split')
    if sha != data.meta['split_sha256']:
        raise ValueError('split mismatch')
    index = json.loads(index_path.read_text())
    indexed = {e['source']['path']: e for e in index['entries']}
    summary = []
    for e in split['entries']:
        sid = digest(e['source'])
        ie = indexed[e['source']['path']]
        label_path = index_path.parent/ie['artifact']
        if file_hash(label_path) != ie['sha256']:
            raise ValueError('index label checksum mismatch')
        with gzip.open(label_path, 'rb') as h:
            labels = np.frombuffer(h.read(), dtype=np.uint8)
        with gzip.open(split_path.parent/e['artifact'], 'rb') as h:
            mask = np.frombuffer(h.read(), dtype=np.uint8)
        if len(mask) != e['counts']['lines'] or len(labels) != len(mask):
            raise ValueError('index/mask length mismatch')
        if np.any(mask > 3):
            raise ValueError('invalid split code')
        seen = np.zeros(len(mask), dtype=np.bool_)
        rows = 0
        for part in data.meta['shards']:
            if part['source_id'] != sid:
                continue
            _, y, lines = decode_shard(data.path_for(part), data.meta['vocab_size'], part)
            pos = lines.astype(np.int64)-1
            if np.any(pos < 0) or np.any(pos >= len(mask)):
                raise ValueError('source line out of range')
            if len(np.unique(pos)) != len(pos) or np.any(seen[pos]):
                raise ValueError('duplicate target')
            code = {'train':1, 'val':2, 'test':3}[part['split']]
            if not np.all(mask[pos] == code):
                raise ValueError('split membership mismatch')
            if not np.all((labels[pos] == 1) | (labels[pos] == 2)) or not np.array_equal(y, labels[pos]-1):
                raise ValueError('frozen index label mismatch')
            seen[pos] = True
            rows += len(pos)
        if not np.array_equal(seen, mask != 0):
            raise ValueError('missing/extra targets')
        summary.append(dict(source_id=sid, host=e['host'], day=e['day'], rows=rows,
                            index_sha256=ie['sha256'], mask_sha256=e['sha256']))
    checked_manifest(split_path, sha, split)
    return dict(status='VERIFIED', method='all shard rows vs frozen masks and independent index labels',
                raw_labels_rescanned=False, scope='label fidelity to frozen index; not a new raw-label audit',
                total_rows=sum(x['rows'] for x in summary), sources=summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT/'ML/code/output/host_ml_parent_incoming_seed02')
    parser.add_argument('--workers', type=int, default=6)
    args = parser.parse_args()
    if args.workers < 1: raise ValueError('positive workers required')
    out = validate_output_path(args.output_dir, protect_baseline=True)
    split_path = ROOT/'ML/code/output/host_ml_seed02/split/manifest.json'
    index_path = ROOT/'ML/code/output/host_ml_seed02/index/manifest.json'
    split, split_sha = load_manifest(split_path, 'host_random_split')
    checked_manifest(split_path, split_sha, split)
    identity = dict(split_sha256=split_sha, implementation=code_hashes((
        'process_context_tracker.py','stratified_pipeline.py','ecar_tokenizer.py',
        'command_syntax.py','pipeline_contract.py','build_vocab.py','build_model_input.py')),
        parent_context=True, max_processes=10000, ttl_seconds=86400,
        min_frequency=2, min_document_frequency=1)
    out.mkdir(parents=True, exist_ok=True)
    receipt = out/'experiment_identity.json'
    if receipt.exists() and json.loads(receipt.read_text()) != identity:
        raise ValueError('Existing namespace implementation/config differs; use a fresh output directory')
    atomic_json(receipt, identity)
    logs = out/'logs'; logs.mkdir(exist_ok=True)
    atomic_json(out/'scope.json', dict(hosts=len({e['host'] for e in split['entries']}),
        sources=len(split['entries']), raw_lines_per_pass=sum(e['counts']['lines'] for e in split['entries']),
        counts=split['counts'], workers=args.workers, pid=os.getpid()))
    volumes = out/'storage_config.json'
    atomic_json(volumes, dict(volumes=[dict(id='ssd',path=str(out/'model_input/volumes/ssd'),
        max_bytes=100*2**30,reserve_free_bytes=20*2**30)]))
    def step(name, command):
        print(f'START {name}: {command}', flush=True)
        t = time.monotonic()
        with (logs/f'{name}.log').open('a') as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        atomic_json(logs/f'{name}_exit.json',dict(command=command,exit_code=result.returncode,elapsed_seconds=time.monotonic()-t))
        if result.returncode: raise RuntimeError(f'{name} failed: inspect {logs/name}.log')
        print(f'DONE {name} in {time.monotonic()-t:.1f}s', flush=True)
    py = [sys.executable, '-u']
    vocab, metadata = out/'vocab.json', out/'vocab_metadata.json'
    if not (vocab.is_file() and metadata.is_file()):
        step('vocabulary',py+[str(ROOT/'ML/code/preprocess/build_vocab.py'),'--split',str(split_path),
            '--output',str(vocab),'--metadata-output',str(metadata),'--checkpoint-dir',str(out/'vocab_checkpoints'),
            '--enable-parent-context','--workers',str(args.workers),'--min-frequency','2','--min-document-frequency','1'])
    model_input = out/'model_input'
    step('shards',py+[str(ROOT/'ML/code/preprocess/build_model_input.py'),'--split',str(split_path),
        '--vocab',str(vocab),'--vocab-metadata',str(metadata),'--output-dir',str(model_input),
        '--storage-config',str(volumes),'--enable-parent-context','--workers',str(args.workers)])
    step('decode_verify',py+[str(ROOT/'ML/code/preprocess/verify_model_input.py'),'--manifest',str(model_input/'manifest.json'),'--decode'])
    atomic_json(out/'frozen_label_membership_verification.json',verify_frozen_labels(model_input/'manifest.json',split_path,index_path))
    package = out/'kaggle_upload'
    if not package.exists():
        step('package',py+[str(ROOT/'ML/code/kaggle/scripts/package_host_shards.py'),'--manifest',str(model_input/'manifest.json'),
            '--output-dir',str(package),'--notebook','lgbm.ipynb'])
    atomic_json(out/'completion.json',dict(status='COMPLETE',identity=identity,
        manifest=str(model_input/'manifest.json'),archive=str(package/'host-input.tar'),
        notebook=str(ROOT/'ML/code/kaggle/notebooks/lgbm.ipynb'),training_run=False))
    print('COMPLETE:',out,flush=True)

if __name__ == '__main__':
    main()
