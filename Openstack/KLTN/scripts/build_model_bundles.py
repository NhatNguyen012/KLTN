#!/usr/bin/env python3
"""Package the selected run-12 artifacts as immutable shadow candidates.

This command does not activate, deploy or modify the trained source artifacts.
Candidates remain ineligible until raw-to-feature-to-score parity fixtures and
live-domain validation are supplied by a later, explicit promotion workflow.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
IL = WORKSPACE / 'IL/dataset_1-ATLASv2/code'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def copy_artifact(source: Path, root: Path, relative: str, artifacts: dict):
    if not source.is_file():
        raise FileNotFoundError(source)
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    artifacts[relative] = {'sha256': sha256(destination), 'bytes': destination.stat().st_size}


def publish(destination: Path, builder):
    if destination.exists():
        manifest = destination / 'manifest.json'
        if manifest.is_file():
            print(f'Existing immutable candidate preserved: {destination}')
            return
        raise FileExistsError(f'refusing non-bundle destination: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=destination.name + '.', dir=destination.parent) as temp:
        staging = Path(temp)
        builder(staging)
        staging.rename(destination)
    print(f'Published candidate: {destination}')


def host_builder(staging: Path):
    output = IL / 'ML/output/kaggle_output/12'
    latest = read_json(output / 'results/incremental/model/latest.json')
    metrics = read_json(output / 'results/incremental/lgbm_metrics.json')
    model = output / 'results/incremental/model' / latest['path']
    if sha256(model) != latest['sha256']:
        raise RuntimeError('selected LightGBM checkpoint hash does not match latest.json')
    artifacts = {}
    copy_artifact(model, staging, 'model/model.txt', artifacts)
    copy_artifact(output / 'provenance/vocab_extended.json', staging,
                  'preprocess/vocab.json', artifacts)
    copy_artifact(output / 'provenance/vocab_metadata.json', staging,
                  'preprocess/vocab_metadata.json', artifacts)
    copy_artifact(output / 'results/incremental/lgbm_metrics.json', staging,
                  'evidence/lgbm_metrics.json', artifacts)
    tokenizer_sources = {
        'ecar_tokenizer.py': WORKSPACE / 'ML/code/preprocess/ecar_tokenizer.py',
        'command_syntax.py': WORKSPACE / 'ML/code/preprocess/command_syntax.py',
    }
    for name, source in tokenizer_sources.items():
        copy_artifact(source, staging, f'preprocess/{name}', artifacts)
    requirements = staging / 'runtime/requirements.lock'
    requirements.parent.mkdir(parents=True, exist_ok=True)
    requirements.write_text('lightgbm==4.6.0\nnumpy==2.2.6\nscipy==1.15.3\n', encoding='utf-8')
    artifacts['runtime/requirements.lock'] = {'sha256': sha256(requirements),
                                              'bytes': requirements.stat().st_size}
    manifest = {
        'schema_version': 'bundle.v1',
        'bundle_id': 'optc-atlasv2-lgbm-run12-candidate',
        'branch': 'host_ml', 'algorithm': 'lightgbm',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'training_corpora': ['DARPA OpTC base', 'ATLASv2 incremental'],
        'supported_domains': ['windows-sysmon'],
        'domain_validation': 'shadow_unvalidated',
        'adapter_version': 'kltn-live-windows-v1',
        'feature_contract': {'representation': 'binary_sparse_presence',
                             'width': 12337, 'unknown_tokens': 'drop',
                             'tokenizer': 'host_ml_structure_anchor_syntax-v5'},
        'runtime_code_sha256': {
            f'ML/code/preprocess/{name}': sha256(source)
            for name, source in tokenizer_sources.items()
        },
        'policy': {'threshold': metrics['validation']['threshold'],
                   'threshold_source': 'ATLASv2 validation only', 'positive_class': 1},
        'artifacts': artifacts,
        'activation': {
            'eligible': False,
            'blockers': [
                'live Sysmon raw-to-feature parity fixture is not published',
                'service probability/decision parity is not published',
                'representative live Windows domain validation is pending',
            ],
        },
        'linux_theia': {'supported': False,
                        'reason': 'THEIA/Linux adapter and validation are unfinished'},
    }
    (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


def dl_builder(staging: Path):
    output = IL / 'DL/output/kaggle_output/12'
    preprocess = IL / 'DL/preprocess/output/preprocessing'
    artifacts = {}
    copy_artifact(output / 'results/incremental/incremental_best.pt', staging,
                  'model/weights.pt', artifacts)
    for name in ('network_category_maps.json', 'network_preprocess_spec.json',
                 'feature_subset.json', 'preprocess_spec.json'):
        copy_artifact(preprocess / name, staging, f'preprocess/{name}', artifacts)
    copy_artifact(output / 'results/bwt_metrics.json', staging,
                  'evidence/bwt_metrics.json', artifacts)
    manifest = {
        'schema_version': 'bundle.v1',
        'bundle_id': 'optc-atlasv2-bilstm-run12-candidate',
        'branch': 'network_dl', 'algorithm': 'bilstm',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'training_corpora': ['DARPA OpTC base', 'ATLASv2 incremental'],
        'supported_domains': ['windows-network'],
        'domain_validation': 'shadow_unvalidated',
        'adapter_version': 'network-sequence-live-v1',
        'model_config': {'event_dim': 64, 'hidden_dim': 64, 'lstm_layers': 1,
                         'dropout': 0.2, 'maximum_sequence': 512,
                         'window_seconds': 900, 'stride_seconds_training': 180},
        'feature_contract': {
            'categorical': ['app_family', 'proto', 'resp_port_class', 'image_dir_class'],
            'numeric': [], 'binary': 'constant_zero', 'temporal': 'delta_t_log1p',
        },
        'policy': {'threshold': 0.245, 'threshold_source': 'incremental validation',
                   'positive_class': 1},
        'artifacts': artifacts,
        'activation': {
            'eligible': False,
            'blockers': [
                'live sequence-builder parity fixture is not published',
                'checkpoint service-load parity is not published',
                'live network domain validation and delay measurement are pending',
            ],
        },
        'linux_theia': {'supported': False,
                        'reason': 'THEIA/Linux feature semantics and validation are unfinished'},
    }
    (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'runtime/releases')
    args = parser.parse_args()
    output = args.output.resolve()
    runtime = (ROOT / 'runtime').resolve()
    try:
        output.relative_to(runtime)
    except ValueError as exc:
        raise SystemExit('candidate output must remain under Openstack/KLTN/runtime') from exc
    publish(output / 'host-ml-run12-candidate', host_builder)
    publish(output / 'network-dl-run12-candidate', dl_builder)


if __name__ == '__main__':
    main()
