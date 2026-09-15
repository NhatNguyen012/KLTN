#!/usr/bin/env python3
"""Package an existing full Host shard manifest for upload; never fit or upload.

Stream only referenced shards into one uncompressed USTAR, checking their SHA256
while writing. NPZ payloads stay compressed. Publish the upload directory only
after success; interrupted packaging can be rerun without rebuilding input.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile

CODE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CODE))
from host_shards import HostShardDataset, sha256
from pipeline_contract import sync_directory, validate_output_path

BASE = CODE / 'output/host_ml'
NOTEBOOKS = tuple(f'host_{model}_shards.ipynb' for model in ('rf', 'xgb', 'lgbm'))


class HashReader:
    def __init__(self, handle):
        self.handle = handle
        self.digest = hashlib.sha256()

    def read(self, size):
        data = self.handle.read(size)
        self.digest.update(data)
        return data


def safe_name(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or '..' in path.parts or '\\' in name
            or not path.parts or path.as_posix() != name):
        raise ValueError(f'unsafe archive path: {name}')
    return name


def header(name, size):
    info = tarfile.TarInfo(safe_name(name))
    info.size = size
    info.mode = 0o644
    # Stable headers, no local ownership or absolute paths in TAR member names.
    info.mtime = 0
    return info


def add_file(archive, name, path, size, expected_sha):
    with path.open('rb') as handle:
        before = os.fstat(handle.fileno())
        if before.st_size != size:
            raise ValueError(f'size mismatch: {path}')
        reader = HashReader(handle)
        archive.addfile(header(name, size), reader)
        after = os.fstat(handle.fileno())
        if (reader.digest.hexdigest() != expected_sha
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError(f'checksum mismatch or file changed: {path}')


def collect(data):
    """Explicit allowlist: no checkpoints, orphan shards or source telemetry."""
    base = data.manifest_path.parent
    files = [('manifest.json', data.manifest_path,
              data.manifest_path.stat().st_size, sha256(data.manifest_path))]
    for name in ('vocab.json', 'vocab_metadata.json'):
        path = base / 'assets' / name
        files.append((f'assets/{name}', path, path.stat().st_size,
                      data.meta['assets_sha256'][name]))
    # Preserve the reader that accompanied the completed preprocessing run.
    # Notebook path setup comes from the current Kaggle templates.
    for name in ('host_shards.py', 'shard_metrics.py'):
        path = base / name
        digest = sha256(path)
        expected = data.meta.get('builder_sha256', {}).get(name)
        if expected and digest != expected:
            raise ValueError(f'published reader differs from builder identity: {name}')
        files.append((name, path, path.stat().st_size, digest))
    for name in NOTEBOOKS:
        path = Path(__file__).parent / name
        files.append((name, path, path.stat().st_size, sha256(path)))
    for part in data.meta['shards']:
        if not re.fullmatch(r'[A-Za-z0-9_]+', part['volume']):
            raise ValueError('unsafe volume ID')
        relative = safe_name(part['path'])
        name = safe_name(f'volumes/{part["volume"]}/{relative}')
        path = data.path_for(part)
        if not path.is_file() or path.stat().st_size != part['bytes']:
            raise ValueError(f'missing shard or size mismatch: {path}')
        files.append((name, path, part['bytes'], part['sha256']))
    if len({f[0] for f in files}) != len(files):
        raise ValueError('duplicate archive member')
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=BASE/'model_input/manifest.json')
    parser.add_argument('--output-dir', type=Path, default=BASE/'kaggle_upload')
    parser.add_argument('--reserve-free-gib', type=int, default=20)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    if args.reserve_free_gib < 0:
        raise ValueError('free-space reserve must be nonnegative')
    manifest_sha = sha256(args.manifest)
    data = HostShardDataset(args.manifest)
    protected = [data.manifest_path.parent, *data.roots.values()]
    output = validate_output_path(args.output_dir, protected)
    if output.exists():
        raise ValueError(f'output already exists; preserving it: {output}')
    files = collect(data)
    if files[0][3] != manifest_sha:
        raise ValueError('manifest changed during package planning')
    total_bytes = sum(f[2] for f in files)
    # Encode long paths in USTAR's prefix/name fields. PAX extended paths can
    # be ignored by upload extractors, exposing identical truncated raw names.
    # Fail before writing if any path or individual file exceeds USTAR limits.
    required_bytes = sum(len(header(n, size).tobuf(format=tarfile.USTAR_FORMAT))
                         + ((size+511)//512)*512 for n, _, size, _ in files) + 2**20
    summary = dict(output_dir=str(output), archive='host-input.tar', archive_format='ustar',
                   shards=len(data.meta['shards']), payload_bytes=total_bytes,
                   estimated_archive_bytes=required_bytes,
                   split_sha256=data.meta['split_sha256'],
                   vocabulary_sha256=data.meta['vocabulary_sha256'],
                   source_manifest_sha256=files[0][3],
                   splits=data.meta['splits'])
    print(json.dumps(summary, indent=2), flush=True)
    if args.dry_run:
        return 0
    # Resolve and guard paths before any mkdir/temp/archive writes.
    output.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(output.parent).free < required_bytes + args.reserve_free_gib*2**30:
        raise OSError('insufficient free space for archive plus reserve')
    stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
    try:
        archive_path = stage / 'host-input.tar'
        with archive_path.open('xb') as handle:
            with tarfile.open(fileobj=handle, mode='w', format=tarfile.USTAR_FORMAT,
                              copybufsize=2**20) as archive:
                for i, (name, path, size, expected) in enumerate(files, 1):
                    add_file(archive, name, path, size, expected)
                    if i % 1000 == 0 or i == len(files):
                        print(f'[{i}/{len(files)}] packaged and SHA256 checked', flush=True)
                readme = (
                    '# OpTC Host ML input\n\n'
                    'Full binary features; persisted 75/10/15 event split, seed 1.\n'
                    'Vocabulary fitted on benign and malicious TRAIN only.\n'
                    'Attach this dataset, import one host_*_shards.ipynb, then run its setup.\n'
                    'The notebook locates manifest.json and maps volumes relative to it.\n'
                    'All three models share the same data; there is no automatic sampling.\n'
                    'Compressed disk size is not training RAM: full TRAIN CSR needs '
                    f'{data.csr_bytes("train")/2**30:.1f} GiB before estimator overhead.\n'
                    'RF/LightGBM templates guard RAM; XGBoost external-memory feasibility '
                    'must be measured in the target runtime.\n'
                    'The random-event split does not establish temporal/campaign generalization.\n'
                    'Source and split identities, labels and shard checksums are in manifest.json.\n'
                ).encode()
                archive.addfile(header('README.md', len(readme)), io.BytesIO(readme))
            handle.flush()
            os.fsync(handle.fileno())
        print('Computing archive SHA256...', flush=True)
        summary.update(archive_bytes=archive_path.stat().st_size,
                       archive_sha256=sha256(archive_path), checksum_checked_shards=len(data.meta['shards']))
        report = stage / 'package_report.json'
        with report.open('x') as handle:
            json.dump(summary, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        sync_directory(stage)
        if output.exists():
            raise ValueError('output appeared concurrently; preserving it')
        os.rename(stage, output)
        sync_directory(output.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print(json.dumps(dict(summary, ready_for_upload=True), indent=2), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
