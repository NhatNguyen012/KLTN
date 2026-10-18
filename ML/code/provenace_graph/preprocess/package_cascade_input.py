#!/usr/bin/env python3
"""Publish immutable, integrity-checked cascade inference assets for Kaggle."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / 'code/output/provenace_graph/kaggle_upload_cascade_v2'

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()

def make(out):
    out = Path(out).resolve()
    if set(out.parts) & {'host-begnin', 'host-malicious', 'bro', 'ecar-bro'}:
        raise ValueError('Output inside read-only data root')
    out.mkdir(parents=True, exist_ok=True)
    baseline = ROOT / 'code/output/host_ml_seed02/kaggle_ouput/lgbm_kaggle_results/results'
    graph = ROOT / 'code/output/provenace_graph'
    files = {
        'provenance/graph.sqlite': graph / 'graph/graph.sqlite',
        'provenance/model_numpy.npz': graph / 'kaggle_output/provenance-gpu-model/model_numpy.npz',
        'models/lgbm_model.txt': baseline / 'model/model-slot-1.txt',
        'models/baseline_metrics.json': baseline / 'lgbm_metrics.json',
        'code/cascade_runtime.py': ROOT / 'code/provenace_graph/model/cascade_runtime.py',
        'code/ego.py': ROOT / 'code/provenace_graph/model/ego.py',
        'code/relational_sage.py': ROOT / 'code/provenace_graph/model/relational_sage.py',
        'code/graph.py': ROOT / 'code/provenace_graph/preprocess/graph.py',
        'code/host_shards.py': ROOT / 'code/preprocess/host_shards.py',
    }
    for rel, p in files.items():
        if not p.is_file(): raise FileNotFoundError(f'{rel}: {p}')
    latest = json.loads((baseline / 'model/latest.json').read_text())
    if sha(files['models/lgbm_model.txt']) != latest['sha256']:
        raise ValueError('LightGBM checkpoint hash mismatch')
    manifest = {'schema': 2, 'files': {rel: {'sha256': sha(p), 'bytes': p.stat().st_size} for rel,p in files.items()},
                'lightgbm_checkpoint': latest, 'graph_metrics_sha256': sha(graph / 'kaggle_output/provenance-gpu-model/metrics.json')}
    archive = out / 'provenance-cascade-bundle-v2.tar.gz'
    if archive.exists():
        raise FileExistsError(f'Bundle exists: {archive}; use a fresh output directory')
    tmp = archive.with_suffix(archive.suffix + '.tmp')
    try:
        with tarfile.open(tmp, 'w:gz') as tar:
            for rel,p in files.items():
                tar.add(p, arcname=rel, recursive=False)
                print(f'Added {rel}', flush=True)
            payload = json.dumps(manifest, indent=2).encode()
            import io
            info = tarfile.TarInfo('bundle_manifest.json'); info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        os.replace(tmp, archive)
    finally:
        tmp.unlink(missing_ok=True)
    receipt = {'archive': archive.name, 'sha256': sha(archive), 'bytes': archive.stat().st_size, 'contents': manifest}
    (out / 'package_manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (out / 'README.txt').write_text(
        'Upload provenance-cascade-bundle-v2.tar.gz as one Kaggle Dataset. '
        'Also attach the existing host_ml_seed02 shard Dataset, then import '
        'code/kaggle/notebooks/host_two_stage_cascade.ipynb. '
        'The notebook uses frozen LightGBM and GraphSAGE weights, calibrates on all '
        'validation events routed to GraphSAGE, and evaluates the full test set.\n')
    print(f'{archive} sha256={receipt["sha256"]}', flush=True)
    return archive

if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--output', type=Path, default=DEFAULT_OUT)
    make(p.parse_args().output)
