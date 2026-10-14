#!/usr/bin/env python3
"""Package the frozen Event-only v5a cache and GPU trainer for Kaggle."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'model'))
from event_ego_cache import load_manifest, part_path, sha256
from common import DEFAULT_OUTPUT, safe


def add_file(archive, name, path, expected):
    path = Path(path)
    if sha256(path) != expected:
        raise ValueError(f'Input checksum changed: {path}')
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode = 0o644
    info.mtime = 0
    with path.open('rb') as stream:
        archive.addfile(info, stream)


def package(cache, output):
    root, meta = load_manifest(cache)
    output = safe(Path(output).resolve(), [root])
    if output.exists():
        raise ValueError(f'Output already exists: {output}')
    files = [(name, root/name) for name in ('manifest.json', 'selection.json')]
    files += [(part['path'], part_path(root, part)) for part in meta['parts']]
    files += [(name, HERE/'model'/name) for name in
              ('event_ego_cache.py', 'train_event_gpu.py', 'event_relational_sage.py',
               'event_ego.py', 'ego.py')]
    files.append(('graph.py', HERE/'preprocess/graph.py'))
    files.append(('provenance_event_v5a_gpu.ipynb', HERE/'notebook/provenance_event_v5a_gpu.ipynb'))
    names = [name for name,_ in files]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate archive path')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
    try:
        archive_path = stage/'provenance-event-v5a-cache.tar'
        with archive_path.open('xb') as handle:
            with tarfile.open(fileobj=handle, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, path in files:
                    add_file(archive, name, path, sha256(path))
            handle.flush(); os.fsync(handle.fileno())
        report = dict(archive=archive_path.name, archive_sha256=sha256(archive_path),
                      archive_bytes=archive_path.stat().st_size,
                      cache_manifest_sha256=meta['manifest_sha256'],
                      splits=meta['splits'], relations=meta['relations'],
                      attributes=len(meta['attributes']), files=len(files))
        (stage/'package_report.json').write_text(json.dumps(report, indent=2)+'\n')
        os.rename(stage, output)
        return report
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=DEFAULT_OUTPUT/'seed02_event_v5a_cache')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT/'kaggle_upload_event_v5a')
    args = parser.parse_args()
    print(json.dumps(package(args.cache, args.output), indent=2))


if __name__ == '__main__':
    main()
