"""Shared safety and reproducibility contracts for the separate graph experiment."""
from pathlib import Path
import hashlib
import json
import os
import sys

CODE = Path(__file__).resolve().parents[2]
ROOT = CODE.parent
sys.path.insert(0, str(CODE / 'preprocess'))
from pipeline_contract import validate_output_path, sync_directory
from shard_storage import exclusive_lock

BASELINE = CODE / 'output/host_ml_seed02'
DEFAULT_OUTPUT = CODE / 'output/provenace_graph'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def safe(path, protected=()):
    p = validate_output_path(Path(path), [BASELINE, *protected])
    if any(x in p.parts for x in ('host-begnin', 'host-malicious', 'bro', 'ecar-bro')):
        raise ValueError('output is inside a dataset root')
    return p


def atomic_json(path, value):
    path = safe(path)
    temporary = path.with_name(path.name + '.tmp')
    if path.is_symlink() or temporary.is_symlink():
        raise ValueError('atomic output must not be a symlink')
    safe(temporary)
    with temporary.open('w') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def implementation():
    return {p.name: sha(p) for p in sorted(Path(__file__).parent.glob('*.py'))}
