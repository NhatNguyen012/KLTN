#!/usr/bin/env python3
"""Promote validated candidate bundles to active-eligible production bundles.

Publishes immutable releases:
  - host-ml-run12-v1 (LightGBM)
  - network-dl-run12-v1 (BiLSTM)

Updates manifests to:
  "domain_validation": "validated"
  "parity": {"passed": true, ...}
  "activation": {"eligible": true, "blockers": []}
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_model_bundle import verify


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def promote_bundle(candidate_dir: Path, target_dir: Path, new_bundle_id: str):
    candidate_dir = candidate_dir.resolve()
    target_dir = target_dir.resolve()
    if target_dir.exists():
        manifest_file = target_dir / 'manifest.json'
        if manifest_file.is_file():
            print(f"Target bundle already exists: {target_dir}")
            return
        raise FileExistsError(f"Target path exists but is not a bundle: {target_dir}")

    candidate_manifest = json.loads((candidate_dir / 'manifest.json').read_text(encoding='utf-8'))
    
    # Check that candidate has parity evidence
    evidence_dir = candidate_dir / 'evidence'
    parity_file = None
    for candidate_name in ('lightgbm_parity_fixture.json', 'bilstm_sequence_parity_fixture.json'):
        candidate_path = evidence_dir / candidate_name
        if candidate_path.is_file():
            parity_file = candidate_path
            break
    if parity_file is None:
        raise RuntimeError(f"Candidate {candidate_dir} lacks parity evidence fixture!")

    # Check that candidate has domain validation evidence
    domain_file = evidence_dir / 'windows_domain_validation.json'
    if not domain_file.is_file():
        raise RuntimeError(f"Candidate {candidate_dir} lacks windows_domain_validation.json!")
    
    domain_doc = json.loads(domain_file.read_text(encoding='utf-8'))
    if domain_doc.get('domain_validation') != 'validated':
        raise RuntimeError(f"Domain validation status is not validated in {domain_file}!")

    with tempfile.TemporaryDirectory(prefix='promote.', dir=target_dir.parent) as temp_str:
        temp_path = Path(temp_str)
        # Copy entire candidate structure
        for item in candidate_dir.iterdir():
            if item.name == 'manifest.json':
                continue
            dest = temp_path / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        # Build new artifacts dictionary
        artifacts = {}
        for file_path in temp_path.rglob('*'):
            if file_path.is_file():
                rel = str(file_path.relative_to(temp_path))
                artifacts[rel] = {
                    'sha256': sha256_file(file_path),
                    'bytes': file_path.stat().st_size,
                }

        parity_report = json.loads(parity_file.read_text(encoding='utf-8'))
        
        new_manifest = dict(candidate_manifest)
        new_manifest['bundle_id'] = new_bundle_id
        new_manifest['promoted_from'] = candidate_manifest['bundle_id']
        new_manifest['promoted_at'] = datetime.now(timezone.utc).isoformat()
        new_manifest['domain_validation'] = 'validated'
        new_manifest['parity'] = {
            'passed': True,
            'fixture': parity_file.name,
            'parity_hash': parity_report.get('parity_hash'),
            'verified_at': parity_report.get('verified_at'),
        }
        new_manifest['activation'] = {
            'eligible': True,
            'blockers': [],
        }
        new_manifest['artifacts'] = artifacts

        (temp_path / 'manifest.json').write_text(json.dumps(new_manifest, indent=2), encoding='utf-8')
        temp_path.rename(target_dir)

    print(f"Successfully promoted bundle to: {target_dir}")
    # Verify the new bundle
    verify(target_dir, require_eligible=True)
    print(f"Verified eligible release: {new_bundle_id}")


def main():
    releases_dir = ROOT / 'runtime/releases'
    host_candidate = releases_dir / 'host-ml-run12-candidate'
    host_target = releases_dir / 'host-ml-run12-v1'
    promote_bundle(host_candidate, host_target, 'optc-atlasv2-lgbm-run12-v1')

    net_candidate = releases_dir / 'network-dl-run12-candidate'
    net_target = releases_dir / 'network-dl-run12-v1'
    promote_bundle(net_candidate, net_target, 'optc-atlasv2-bilstm-run12-v1')


if __name__ == '__main__':
    main()

