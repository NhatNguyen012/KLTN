#!/usr/bin/env python3
"""Package a complete static provenance ego-graph cache for Kaggle upload.

The archive contains only cache tensors, source-line provenance, cache metadata
and the GPU trainer/notebook.  It never copies graph.sqlite or raw telemetry.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parents[1]
CODE = HERE.parents[0]
sys.path.insert(0, str(HERE / 'model'))

from ego_cache import load_manifest, part_path, safe_relative, sha256, require_exact_time
from ML.code.provenace_graph.preprocess.common import DEFAULT_OUTPUT, safe
from pipeline_contract import sync_directory


class HashReader:
    def __init__(self, handle):
        self.handle = handle
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        value = self.handle.read(size)
        self.digest.update(value)
        return value


def archive_name(value: str) -> str:
    path = PurePosixPath(value)
    if (path.is_absolute() or '..' in path.parts or '\\' in value or not path.parts
            or path.as_posix() != value):
        raise ValueError(f'unsafe archive member: {value!r}')
    return value


def header(name, size):
    info = tarfile.TarInfo(archive_name(name))
    info.size = size
    info.mode = 0o644
    info.mtime = 0
    return info


def add_checked(archive, name, path, size, expected):
    path = Path(path)
    if not path.is_file() or path.stat().st_size != size:
        raise ValueError(f'cache file missing or size changed: {path}')
    with path.open('rb') as handle:
        reader = HashReader(handle)
        archive.addfile(header(name, size), reader)
    if reader.digest.hexdigest() != expected:
        raise ValueError(f'cache file checksum changed: {path}')


def collect(root, meta):
    files = []
    for name in ('manifest.json', 'selection.json'):
        path = root / name
        files.append((name, path, path.stat().st_size, sha256(path)))
    for part in meta['parts']:
        relative = safe_relative(part['path']).as_posix()
        files.append((relative, part_path(root, part), part['bytes'], part['sha256']))
    for relative in ('model/ego_cache.py', 'model/train_gpu.py',
                     'notebook/provenance_graph_exact_time_gpu.ipynb'):
        path = HERE / relative
        archive_path = Path(relative).name if relative.startswith('model/') else relative
        files.append((archive_path, path, path.stat().st_size, sha256(path)))
    names = [entry[0] for entry in files]
    if len(names) != len(set(names)):
        raise ValueError('duplicate Kaggle archive member')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=DEFAULT_OUTPUT / 'seed02_ego_cache')
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--reserve-free-gib', type=int, default=2)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if args.reserve_free_gib < 0:
        raise ValueError('free-space reserve must be nonnegative')
    root, meta = load_manifest(args.cache)
    require_exact_time(meta)
    output = safe(args.output_dir or root.parent / f'kaggle_upload_{root.name}', [root])
    if output.exists():
        raise ValueError(f'output already exists; preserving it: {output}')
    files = collect(root, meta)
    estimated = sum(len(header(name, size).tobuf(format=tarfile.USTAR_FORMAT)) + ((size + 511) // 512) * 512
                    for name, _, size, _ in files) + 2**20
    summary = dict(output_dir=str(output), archive='provenance-exact-time-graphsage.tar', archive_format='ustar',
                   cache_manifest_sha256=meta['manifest_sha256'], parts=len(meta['parts']),
                   graphs=meta['splits'], payload_bytes=sum(size for _, _, size, _ in files),
                   estimated_archive_bytes=estimated)
    print(json.dumps(summary, indent=2), flush=True)
    if args.dry_run:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(output.parent).free < estimated + args.reserve_free_gib * 2**30:
        raise OSError('insufficient free space for provenance cache archive plus reserve')
    stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
    try:
        archive_path = stage / summary['archive']
        with archive_path.open('xb') as handle:
            with tarfile.open(fileobj=handle, mode='w', format=tarfile.USTAR_FORMAT, copybufsize=2**20) as archive:
                for index, (name, file_path, size, expected) in enumerate(files, 1):
                    add_checked(archive, name, file_path, size, expected)
                    print(f'[{index}/{len(files)}] packaged and SHA256 checked: {name}', flush=True)
                readme = f"""# OpTC exact-time static provenance ego-graph cache

Cache format: `{meta['format']}` schema `{meta['schema']}`.

This archive contains {sum(value['graphs'] for value in meta['splits'].values()):,} precomputed,
label-blind, strict-past two-hop Host/Process ego graphs. Every target cutoff
is its exact microsecond timestamp (`quantum_us=1`); evidence timestamps must be
strictly less than that cutoff. It contains no raw
telemetry and does not require graph.sqlite, source datasets, or Host ML shards
on Kaggle.

Enable a GPU accelerator. Extract `provenance-exact-time-graphsage.tar`, then run:

```bash
python train_gpu.py --cache . --output /kaggle/working/provenance-gpu-model --evaluate-test
```

`train_gpu.py` verifies the exact-time cache policy, uses PyTorch CUDA, and only
reads sequential cache shards. `notebook/provenance_graph_exact_time_gpu.ipynb` performs secure extraction and
runs the same command. Validation selects the threshold; test is evaluated once.
The split is seed02 contextual random-event, so it is not unseen-host/process
validation.
""".encode()
                archive.addfile(header('README.md', len(readme)), io.BytesIO(readme))
            handle.flush(); os.fsync(handle.fileno())
        summary.update(archive_bytes=archive_path.stat().st_size, archive_sha256=sha256(archive_path))
        with (stage / 'package_report.json').open('x') as handle:
            json.dump(summary, handle, indent=2); handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
        sync_directory(stage)
        os.rename(stage, output)
        sync_directory(output.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print(json.dumps(dict(summary, ready_for_upload=True), indent=2), flush=True)


if __name__ == '__main__':
    main()
