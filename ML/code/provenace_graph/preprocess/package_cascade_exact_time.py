#!/usr/bin/env python3
"""Publish a separate full LightGBM + exact-time GraphSAGE Kaggle bundle."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT = ROOT / 'code/output/provenace_graph/kaggle_upload_cascade_exact_time_graphsage'
GRAPH_DIR = ROOT / 'code/output/provenace_graph/exact_time_graph'
SAGE_RESULTS = ROOT / 'code/output/provenace_graph/exact_time_graphsage_results.zip'
HOST_BASE = ROOT / 'code/output/host_ml_seed02/kaggle_ouput/lgbm_kaggle_results/results'
ARCHIVE = 'provenance-cascade-exact-time-graphsage.tar.gz'


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def archive_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != name or '\\' in name:
        raise ValueError(f'Unsafe archive member: {name!r}')
    return name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if set(output.parts) & {'host-begnin', 'host-malicious', 'ecar-bro', 'bro'}:
        raise ValueError('Output inside a read-only dataset root')

    graph_manifest_path = GRAPH_DIR / 'manifest.json'
    graph_manifest = json.loads(graph_manifest_path.read_text())
    if not graph_manifest.get('complete') or graph_manifest.get('config', {}).get('pilot'):
        raise ValueError('A complete non-pilot exact-time graph index is required')
    graph_db = GRAPH_DIR / 'graph.sqlite'
    if sha(graph_db) != graph_manifest['database_sha256']:
        raise ValueError('Exact-time graph database checksum mismatch')

    cache_manifest_path = ROOT / 'code/output/provenace_graph/exact_time_ego_cache/manifest.json'
    cache_manifest = json.loads(cache_manifest_path.read_text())
    if (cache_manifest.get('time_policy', {}).get('quantum_us') != 1 or
            not cache_manifest.get('time_audit', {}).get('all_evidence_strictly_before_target') or
            not cache_manifest.get('time_audit', {}).get('cutoff_equals_target_timestamp')):
        raise ValueError('Exact-time ego cache audit is incomplete')
    if cache_manifest['config']['graph_database_sha256'] != graph_manifest['database_sha256']:
        raise ValueError('Graph DB and ego-cache identities differ')

    result_zip = zipfile.ZipFile(SAGE_RESULTS)
    model_member = 'exact-time-graphsage-model/model_numpy.npz'
    model_metrics = json.loads(result_zip.read('exact-time-graphsage-model/metrics.json'))
    model_config = json.loads(result_zip.read('exact-time-graphsage-model/config.json'))
    result_cache_manifest = json.loads(result_zip.read('provenance/exact_time_cache_manifest.json'))
    if result_cache_manifest['manifest_sha256'] != cache_manifest['manifest_sha256']:
        raise ValueError('Trained GraphSAGE checkpoint does not match local exact-time cache')
    if (model_config['cache_manifest_sha256'] != cache_manifest['manifest_sha256'] or
            model_config['time_policy']['quantum_us'] != 1 or
            model_metrics['time_policy']['quantum_us'] != 1):
        raise ValueError('GraphSAGE result was not trained with the audited exact-time cache')
    sage_weights = result_zip.read(model_member)
    sage_sha = hashlib.sha256(sage_weights).hexdigest()

    receipt = json.loads((HOST_BASE / 'model/latest.json').read_text())
    host_model = HOST_BASE / 'model' / receipt['path']
    host_metrics_path = HOST_BASE / 'lgbm_metrics.json'
    host_metrics = json.loads(host_metrics_path.read_text())
    if sha(host_model) != receipt['sha256'] or host_metrics['model_checkpoint']['sha256'] != receipt['sha256']:
        raise ValueError('Frozen LightGBM checkpoint identity mismatch')
    if host_metrics['validation']['threshold'] != 0.94016:
        raise ValueError('Unexpected frozen LightGBM threshold')

    source_files = {
        'provenance/graph.sqlite': graph_db,
        'provenance/graph_manifest.json': graph_manifest_path,
        'provenance/ego_cache_manifest.json': cache_manifest_path,
        'provenance/model_training_metrics.json': None,
        'provenance/model_training_config.json': None,
        'models/lgbm_model.txt': host_model,
        'models/lgbm_metrics.json': host_metrics_path,
        'code/cascade_runtime.py': ROOT / 'code/provenace_graph/model/cascade_runtime.py',
        'code/ego.py': ROOT / 'code/provenace_graph/model/ego.py',
        'code/relational_sage.py': ROOT / 'code/provenace_graph/model/relational_sage.py',
        'code/graph.py': ROOT / 'code/provenace_graph/preprocess/graph.py',
        'code/host_shards.py': ROOT / 'code/preprocess/host_shards.py',
    }
    with tempfile.TemporaryDirectory(prefix='exact-time-bundle-metadata-') as tmp_name:
        tmp_dir = Path(tmp_name)
        metrics_path = tmp_dir / 'model_training_metrics.json'
        config_path = tmp_dir / 'model_training_config.json'
        metrics_path.write_text(json.dumps(model_metrics, indent=2, sort_keys=True) + '\n')
        config_path.write_text(json.dumps(model_config, indent=2, sort_keys=True) + '\n')
        source_files['provenance/model_training_metrics.json'] = metrics_path
        source_files['provenance/model_training_config.json'] = config_path
        for rel, path in source_files.items():
            if path is not None and not path.is_file():
                raise FileNotFoundError(f'{rel}: {path}')

        identities = {'lgbm': {
            'checkpoint': receipt['sha256'],
            'split': host_metrics['split_sha256'],
            'vocabulary': host_metrics['vocabulary_sha256'],
            'library_version': receipt['identity']['library_version'],
        }}
        manifest = {
            'schema': 5,
            'experiment': 'exact_time_graphsage_full_cascade',
            'context_policy': {
                'timestamp_quantum_us': 1,
                'edge_rule': 'evidence_timestamp_us < exact target_timestamp_us',
                'checkpoint_training_quantum_us': 1,
                'checkpoint_retrained': True,
                'graph_manifest_sha256': sha(graph_manifest_path),
                'graph_database_sha256': graph_manifest['database_sha256'],
                'ego_cache_manifest_sha256': cache_manifest['manifest_sha256'],
            },
            'model_identities': identities,
            'files': {},
        }
        file_data = {}
        for rel, path in source_files.items():
            manifest['files'][rel] = {'sha256': sha(path), 'bytes': path.stat().st_size}
            file_data[rel] = ('path', path)
        manifest['files']['provenance/model_numpy.npz'] = {
            'sha256': sage_sha, 'bytes': len(sage_weights)}
        file_data['provenance/model_numpy.npz'] = ('bytes', sage_weights)
        readme = (
            '# LightGBM + exact-time GraphSAGE cascade input\n\n'
            'This is a full-corpus graph index and a newly trained GraphSAGE checkpoint. '
            'Every target cutoff retains its exact microsecond timestamp; only evidence '
            'strictly earlier than the target is visible. The graph schema and node/edge '
            'types are unchanged. Attach the separate frozen Host input dataset for its '
            'shards and feature assets. Do not attach or use a v4 GraphSAGE score cache: '
            'those scores belong to a different checkpoint.\n'
        ).encode()

        report = {
            'archive': ARCHIVE,
            'format': 'tar.gz',
            'schema': manifest['schema'],
            'model_identities': identities,
            'context_policy': manifest['context_policy'],
            'files': manifest['files'],
        }
        estimated_payload = sum(item['bytes'] for item in manifest['files'].values())
        print(json.dumps({'output_dir': str(output), 'archive': ARCHIVE,
                          'file_count': len(file_data), 'uncompressed_payload_bytes': estimated_payload,
                          'graph_database_bytes': graph_db.stat().st_size,
                          'new_graphsage_sha256': sage_sha,
                          'validation_sample_f1': model_metrics['validation']['f1'],
                          'test_sample_f1': model_metrics['test']['f1']}, indent=2))
        if args.dry_run:
            return
        if output.exists():
            raise FileExistsError(f'Preserving existing full input directory: {output}')
        output.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
        try:
            archive_path = stage / ARCHIVE
            tmp_archive = stage / (ARCHIVE + '.tmp')
            with tarfile.open(tmp_archive, 'w:gz', compresslevel=1) as tar:
                for rel, (kind, value) in file_data.items():
                    info = tarfile.TarInfo(archive_name(rel))
                    info.mode = 0o644
                    if kind == 'path':
                        path = Path(value)
                        info.size = path.stat().st_size
                        with path.open('rb') as stream:
                            tar.addfile(info, stream)
                    else:
                        info.size = len(value)
                        tar.addfile(info, io.BytesIO(value))
                    print('Added', rel, flush=True)
                info = tarfile.TarInfo('bundle_manifest.json')
                payload = json.dumps(manifest, indent=2, sort_keys=True).encode()
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
                info = tarfile.TarInfo('README.md')
                info.size = len(readme)
                tar.addfile(info, io.BytesIO(readme))
            os.replace(tmp_archive, archive_path)
            report.update(bytes=archive_path.stat().st_size, sha256=sha(archive_path),
                          uncompressed_payload_bytes=estimated_payload)
            (stage / 'package_manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
            os.rename(stage, output)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    print('Published', output / ARCHIVE, 'sha256', sha(output / ARCHIVE))


if __name__ == '__main__':
    main()
