#!/usr/bin/env python3
"""Publish immutable v4 cascade input with exact-time causal graph extraction."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import shutil

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT = ROOT / 'code/output/provenace_graph/kaggle_upload_cascade_v4'

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def frozen_graph_weights(output):
    """Recover the exact frozen GraphSAGE weights from immutable v3 input."""
    previous = ROOT / 'code/output/provenace_graph/kaggle_upload_cascade_v3'
    record = json.loads((previous / 'package_manifest.json').read_text())
    archive = previous / record['archive']
    if sha(archive) != record['sha256']:
        raise ValueError('Frozen v3 archive checksum mismatch')
    expected = record['contents']['files']['provenance/model_numpy.npz']['sha256']
    target = output / 'model_numpy.npz'
    if target.exists():
        if sha(target) != expected: raise ValueError('Staged GraphSAGE weights mismatch')
        return target
    tmp = target.with_suffix('.npz.tmp')
    try:
        with tarfile.open(archive, 'r:gz') as tar, tmp.open('wb') as stream:
            shutil.copyfileobj(tar.extractfile('provenance/model_numpy.npz'), stream)
            stream.flush(); os.fsync(stream.fileno())
        if sha(tmp) != expected: raise ValueError('Archived GraphSAGE weights mismatch')
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)
    return target

def package(output=DEFAULT_OUTPUT):
    output = Path(output).resolve()
    if set(output.parts) & {'host-begnin', 'host-malicious', 'ecar-bro', 'bro'}:
        raise ValueError('Output inside a read-only dataset root')
    output.mkdir(parents=True, exist_ok=True)
    graph = ROOT / 'code/output/provenace_graph'
    baseline = ROOT / 'code/output/host_ml_seed02/kaggle_ouput'
    files = {
        'provenance/graph.sqlite': graph / 'graph/graph.sqlite',
        'provenance/model_numpy.npz': frozen_graph_weights(output),
        'code/cascade_runtime.py': ROOT / 'code/provenace_graph/model/cascade_runtime.py',
        'code/ego.py': ROOT / 'code/provenace_graph/model/ego.py',
        'code/relational_sage.py': ROOT / 'code/provenace_graph/model/relational_sage.py',
        'code/graph.py': ROOT / 'code/provenace_graph/preprocess/graph.py',
        'code/host_shards.py': ROOT / 'code/preprocess/host_shards.py',
    }
    suffix = {'rf': 'pkl', 'xgb': 'ubj', 'lgbm': 'txt'}
    names = {'rf': 'rf_model.pkl', 'xgb': 'xgb_model.ubj', 'lgbm': 'lgbm_model.txt'}
    identities = {}
    for model in ('rf', 'xgb', 'lgbm'):
        result = baseline / f'{model}_kaggle_results/results'
        receipt = json.loads((result / 'model/latest.json').read_text())
        checkpoint = result / 'model' / receipt['path']
        if sha(checkpoint) != receipt['sha256']:
            raise ValueError(f'{model} frozen checkpoint hash mismatch')
        metrics = result / f'{model}_metrics.json'
        data = json.loads(metrics.read_text())
        if data['model_checkpoint']['sha256'] != receipt['sha256']:
            raise ValueError(f'{model} metrics/checkpoint mismatch')
        files[f'models/{names[model]}'] = checkpoint
        files[f'models/{model}_metrics.json'] = metrics
        identities[model] = {'checkpoint': receipt['sha256'], 'split': data['split_sha256'],
                             'vocabulary': data['vocabulary_sha256'],
                             'library_version': receipt['identity']['library_version']}
    if len({v['split'] for v in identities.values()}) != 1 or len({v['vocabulary'] for v in identities.values()}) != 1:
        raise ValueError('Host models do not use the same frozen split/vocabulary')
    for rel, p in files.items():
        if not p.is_file(): raise FileNotFoundError(f'{rel}: {p}')
    manifest = {'schema': 4,
                'context_policy': {'timestamp_quantum_us': 1,
                                   'edge_rule': 'strictly earlier than target event',
                                   'checkpoint_training_quantum_us': 1000000,
                                   'checkpoint_retrained': False},
                'model_identities': identities,
                'files': {rel: {'sha256': sha(p), 'bytes': p.stat().st_size} for rel,p in files.items()}}
    archive = output / 'provenance-cascade-bundle-v4.tar.gz'
    if archive.exists(): raise FileExistsError(archive)
    tmp = archive.with_suffix('.tar.gz.tmp')
    try:
        with tarfile.open(tmp, 'w:gz') as tar:
            for rel, src in files.items():
                tar.add(src, arcname=rel, recursive=False)
                print('Added', rel, flush=True)
            payload = json.dumps(manifest, indent=2).encode()
            entry = tarfile.TarInfo('bundle_manifest.json'); entry.size = len(payload)
            tar.addfile(entry, io.BytesIO(payload))
        os.replace(tmp, archive)
    finally:
        tmp.unlink(missing_ok=True)
    (output / 'package_manifest.json').write_text(json.dumps({'archive': archive.name,
        'sha256': sha(archive), 'bytes': archive.stat().st_size, 'contents': manifest}, indent=2) + '\n')
    print('Published', archive, 'sha256', sha(archive))
    return archive

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    package(parser.parse_args().output)
