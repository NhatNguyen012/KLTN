"""Portable, static two-hop ego-graph cache format.

The cache is deliberately NumPy NPZ rather than torch pickle: it can be built
on a local CPU-only machine, verified without executing code, and converted to
PyTorch tensors only inside the Kaggle GPU trainer.  Node IDs and raw telemetry
are absent; provenance is retained as source ID index plus raw source line.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

import numpy as np

FORMAT = 'optc_two_hop_ego_npz'
SCHEMA = 1
RELATIONS = ('creates', 'communicates', 'communicates_reverse', 'hosts')
RELATION_ID = {name: index for index, name in enumerate(RELATIONS)}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def manifest_digest(meta: dict) -> str:
    """Hash manifest contents while excluding its self-referential digest field."""
    value = dict(meta)
    value.pop('manifest_sha256', None)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def safe_relative(value: str) -> Path:
    path = PurePosixPath(value)
    if (path.is_absolute() or '..' in path.parts or '\\' in value or not path.parts
            or path.as_posix() != value):
        raise ValueError(f'unsafe cache relative path: {value!r}')
    return Path(*path.parts)


def load_manifest(root: Path):
    root = Path(root).resolve()
    manifest_path = root / 'manifest.json'
    meta = json.loads(manifest_path.read_text())
    if meta.get('format') != FORMAT or meta.get('schema') != SCHEMA or meta.get('complete') is not True:
        raise ValueError('expected complete ego-graph cache manifest')
    if tuple(meta.get('relations', ())) != RELATIONS or not meta.get('attributes'):
        raise ValueError('unsupported ego-graph cache schema')
    if manifest_digest(meta) != meta.get('manifest_sha256'):
        raise ValueError('ego-graph cache manifest checksum mismatch')
    return root, meta


def part_path(root: Path, part: dict) -> Path:
    path = (Path(root) / safe_relative(part['path'])).resolve()
    if not path.is_relative_to(Path(root).resolve()):
        raise ValueError('cache part path escapes root')
    return path


def decode_part(root: Path, part: dict, attributes: int):
    """Load one verified cache part with no pickle/object arrays."""
    path = part_path(root, part)
    if not path.is_file() or path.stat().st_size != part['bytes'] or sha256(path) != part['sha256']:
        raise ValueError(f'cache part checksum/size mismatch: {path}')
    with np.load(path, allow_pickle=False) as data:
        required = {'x', 'node_ptr', 'edge_index', 'edge_type', 'root', 'host_root',
                    'label', 'source_index', 'source_line', 'cutoff_us'}
        if set(data.files) != required:
            raise ValueError('invalid cache part members')
        arrays = {name: data[name].copy() for name in required}
    x = arrays['x']; node_ptr = arrays['node_ptr']; edge_index = arrays['edge_index']
    edge_type = arrays['edge_type']; root_index = arrays['root']; host_root = arrays['host_root']
    label = arrays['label']; source_index = arrays['source_index']; source_line = arrays['source_line']
    cutoff = arrays['cutoff_us']
    graphs = len(label)
    if (x.dtype != np.float32 or x.ndim != 2 or x.shape[1] != attributes
            or node_ptr.ndim != 1 or len(node_ptr) != graphs + 1
            or edge_index.dtype.kind not in 'iu' or edge_index.shape[0] != 2 or edge_index.ndim != 2
            or edge_type.dtype.kind not in 'iu' or len(edge_type) != edge_index.shape[1]
            or any(a.ndim != 1 or len(a) != graphs for a in
                   (root_index, host_root, label, source_index, source_line, cutoff))):
        raise ValueError('invalid cache part array shapes')
    if (len(node_ptr) == 0 or int(node_ptr[0]) != 0 or int(node_ptr[-1]) != len(x)
            or np.any(node_ptr[1:] <= node_ptr[:-1]) or np.any(label > 1)
            or np.any(edge_type >= len(RELATIONS))):
        raise ValueError('invalid cache part ranges')
    if len(edge_type) and (np.any(edge_index < 0) or np.any(edge_index >= len(x))):
        raise ValueError('cache edge outside node array')
    for index, (start, end) in enumerate(zip(node_ptr[:-1], node_ptr[1:])):
        if not (int(start) <= int(root_index[index]) < int(end)
                and int(start) <= int(host_root[index]) < int(end)):
            raise ValueError('cache graph root outside graph nodes')
    if graphs != part['graphs'] or len(x) != part['nodes'] or len(edge_type) != part['edges']:
        raise ValueError('cache part disagrees with manifest')
    return arrays


def examples(root: Path, part: dict, attributes: int):
    """Yield independent local-index graph arrays from one cache part."""
    arrays = decode_part(root, part, attributes)
    for index, (start, end) in enumerate(zip(arrays['node_ptr'][:-1], arrays['node_ptr'][1:])):
        start, end = int(start), int(end)
        edges = arrays['edge_index']
        keep = ((edges[0] >= start) & (edges[0] < end)
                & (edges[1] >= start) & (edges[1] < end))
        yield dict(
            x=arrays['x'][start:end],
            edge_index=edges[:, keep].astype(np.int64, copy=False) - start,
            edge_type=arrays['edge_type'][keep].astype(np.int64, copy=False),
            root=int(arrays['root'][index] - start),
            host_root=int(arrays['host_root'][index] - start),
            label=int(arrays['label'][index]),
            source_index=int(arrays['source_index'][index]),
            source_line=int(arrays['source_line'][index]),
            cutoff_us=int(arrays['cutoff_us'][index]),
        )
