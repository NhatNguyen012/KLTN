#!/usr/bin/env python3
"""Offline verifier for an immutable KLTN model bundle."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify(root: Path, branch: str | None = None, require_eligible: bool = False) -> dict:
    root = root.resolve()
    manifest_path = root / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('schema_version') != 'bundle.v1':
        raise ValueError('unsupported bundle schema')
    if branch and manifest.get('branch') != branch:
        raise ValueError(f"expected branch {branch}, got {manifest.get('branch')}")
    if require_eligible:
        if not manifest.get('activation', {}).get('eligible'):
            raise ValueError('bundle is not activation eligible')
        if manifest.get('domain_validation') != 'validated':
            raise ValueError('eligible deployment requires validated domain')
        parity = manifest.get('parity')
        if not isinstance(parity, dict) or parity.get('passed') is not True:
            raise ValueError('eligible deployment requires a passed parity report')
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > 100:
        raise ValueError('invalid artifact inventory')
    for relative, metadata in artifacts.items():
        if not isinstance(relative, str) or not isinstance(metadata, dict):
            raise ValueError('invalid artifact entry')
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f'artifact escapes bundle: {relative}') from exc
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'artifact missing or symlinked: {relative}')
        expected = metadata.get('sha256')
        if not isinstance(expected, str) or not hmac.compare_digest(sha256(path), expected):
            raise ValueError(f'artifact checksum mismatch: {relative}')
        if metadata.get('bytes') != path.stat().st_size:
            raise ValueError(f'artifact size mismatch: {relative}')
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--branch', choices=['host_ml', 'network_dl', 'fusion'])
    parser.add_argument('--require-eligible', action='store_true')
    args = parser.parse_args()
    try:
        manifest = verify(args.bundle, args.branch, args.require_eligible)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'bundle verification failed: {exc}', file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps({'bundle_id': manifest['bundle_id'], 'branch': manifest['branch'],
                      'eligible': manifest.get('activation', {}).get('eligible', False),
                      'artifacts_verified': len(manifest['artifacts'])}, indent=2))


if __name__ == '__main__':
    main()
