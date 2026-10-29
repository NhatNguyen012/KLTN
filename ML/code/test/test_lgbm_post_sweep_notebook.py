"""Regression checks for the executable runtime embedded in lgbm.ipynb."""
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import numpy as np
from scipy.sparse import csr_matrix

CODE = Path(__file__).resolve().parents[1]
ROOT = CODE.parents[1]
sys.path.insert(0, str(CODE / 'provenace_graph/model'))
sys.path.insert(0, str(CODE / 'provenace_graph/preprocess'))
NOTEBOOK = CODE / 'kaggle/notebooks/lgbm_graphsage_post_sweep_archived.ipynb'
DOCUMENT = json.loads(NOTEBOOK.read_text())
SOURCE = next(''.join(c['source']).split('\n', 1)[1] for c in DOCUMENT['cells']
              if ''.join(c['source']).startswith('%%writefile'))
runtime = types.ModuleType('tested_frozen_lgbm_runtime')
runtime.__file__ = str(NOTEBOOK.with_suffix('.py'))
exec(compile(SOURCE, str(NOTEBOOK), 'exec'), runtime.__dict__)
RESULTS = CODE / 'output/provenace_graph/kaggle_output/lgbm_exact_time_middle_threshold_sweep_results'


class PostSweepTests(unittest.TestCase):
    def test_all_python_cells_compile(self):
        for i, cell in enumerate(DOCUMENT['cells']):
            if cell['cell_type'] != 'code':
                continue
            source = ''.join(cell['source'])
            if source.startswith('%%writefile'):
                source = source.split('\n', 1)[1]
            compile(source, f'cell-{i}', 'exec')
        self.assertNotIn('def select_policy(', SOURCE)
        self.assertNotIn('def per_vector_audit(', SOURCE)

    def test_swept_middle_applies_to_noncollisions_and_boundaries(self):
        p = runtime.FROZEN_POLICY
        below = np.nextafter(p['middle_threshold'], -np.inf)
        ml = [.30, .50, .95999, .96, .29999]
        graph = [p['middle_threshold'], below, .80, np.nan, np.nan]
        old, new, reasons = runtime.predict(ml, graph, [False] * 5, p)
        np.testing.assert_array_equal(old, [False, False, False, True, False])
        np.testing.assert_array_equal(new, [True, False, True, True, False])
        self.assertEqual(reasons[0], 'swept_middle')

    def test_collision_thresholds_are_inclusive(self):
        p = runtime.FROZEN_POLICY
        g = [p['low_threshold'], np.nextafter(p['low_threshold'], -np.inf),
             p['high_threshold'], np.nextafter(p['high_threshold'], -np.inf)]
        _, new, _ = runtime.predict([.1, .1, .99, .99], g, [True] * 4, p)
        np.testing.assert_array_equal(new, [True, False, True, False])

    def test_missing_required_graph_scores_fail(self):
        for ml, collision in [(.5, False), (.1, True), (.99, True)]:
            with self.assertRaises(ValueError):
                runtime.predict([ml], [np.nan], [collision], runtime.FROZEN_POLICY)

    def test_bad_shapes_and_probabilities_fail(self):
        for ml, graph, collision in [([.5], [], [False]), ([np.nan], [.9], [False]),
                                     ([.5], [1.1], [False])]:
            with self.assertRaises(ValueError):
                runtime.predict(ml, graph, collision, runtime.FROZEN_POLICY)

    def test_default_backend_matches_archived_numpy_reference(self):
        self.assertFalse(runtime.USE_CUDA)
        self.assertEqual(runtime.inference_backend_name(), 'numpy_cpu_reference')
        model = types.SimpleNamespace(predict=lambda g: {'probability': g})
        scorer = runtime.DenseCudaGraphSAGE(model)
        self.assertFalse(scorer.enabled)
        np.testing.assert_array_equal(scorer.score([.1, .8]), [.1, .8])

    @unittest.skipUnless(RESULTS.is_dir(), 'Archived results not present')
    def test_policy_and_reference_identity_match_archived_run(self):
        saved = json.loads((RESULTS / 'frozen_policy.json').read_text())
        self.assertEqual(runtime.REFERENCE_IDENTITY, saved['identity'])
        for name in ('low_threshold', 'middle_threshold', 'high_threshold'):
            self.assertEqual(runtime.FROZEN_POLICY[name], saved['policy'][name])
        for split in ('validation', 'test'):
            d = json.loads((RESULTS / f'{split}_metrics.json').read_text())
            runtime.assert_reference_counts(split, d['legacy'], d['selected'])
        self.assertEqual(runtime.REFERENCE_PROVENANCE['frozen_policy_sha256'],
                         runtime.sha(RESULTS / 'frozen_policy.json'))

    @unittest.skipUnless(RESULTS.is_dir(), 'Archived results not present')
    def test_replay_every_archived_error_and_transition(self):
        for filename in ('test_errors_full_scores.jsonl', 'event_transition_audit.jsonl'):
            rows = [json.loads(line) for line in (RESULTS / filename).read_text().splitlines()]
            ml = [r['ml_score'] for r in rows]
            graph = [r['graph_score'] if r['graph_score'] is not None else np.nan for r in rows]
            collision = [r['collision'] for r in rows]
            old, new, _ = runtime.predict(ml, graph, collision, runtime.FROZEN_POLICY)
            old_key = 'legacy_prediction' if filename.startswith('test_errors') else 'old_prediction'
            new_key = 'prediction' if filename.startswith('test_errors') else 'new_prediction'
            np.testing.assert_array_equal(old, [r[old_key] for r in rows])
            np.testing.assert_array_equal(new, [r[new_key] for r in rows])

    def test_reproduction_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            runtime.assert_reference_counts('test', runtime.metrics([1, 0, 0, 1]),
                                            runtime.metrics([1, 0, 0, 1]))

    def test_compute_export_resume_and_reject_stale_policy_cache(self):
        """Exercise real run/checkpoint/export control flow with tiny fake model/data IO."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host, bundle, out = [root / name for name in ('host', 'bundle', 'out')]
            for path in (host / 'assets', bundle / 'models', out):
                path.mkdir(parents=True)
            manifest = host / 'manifest.json'
            manifest.write_text('{}')
            for name in ('vocab.json', 'split_manifest.json'):
                (host / 'assets' / name).write_text('{}')
            bmeta = dict(schema=5, context_policy=dict(timestamp_quantum_us=1,
                checkpoint_training_quantum_us=1), files={
                    key: {'sha256': key} for key in ('provenance/graph.sqlite',
                    'provenance/model_numpy.npz', 'models/lgbm_model.txt')},
                model_identities={'lgbm': {'library_version': 'fake'}})
            (bundle / 'bundle_manifest.json').write_text(json.dumps(bmeta))
            (bundle / 'models/lgbm_metrics.json').write_text(json.dumps(dict(
                validation={'threshold': runtime.BASELINE},
                vocabulary_sha256=runtime.sha(host / 'assets/vocab.json'),
                split_sha256=runtime.sha(host / 'assets/split_manifest.json'))))
            shards = []
            for split in ('val', 'test'):
                path = host / f'{split}.npz'
                path.write_bytes(split.encode())
                shards.append(dict(split=split, source_id=split, rows=5,
                                   path=str(path), sha256=runtime.sha(path)))
            x = csr_matrix([[.2, 1, 0], [.5, 0, 1], [.99, 1, 0], [.99, 0, 0], [.2, 0, 0]])
            y = np.array([1, 1, 0, 1, 0], dtype=np.uint8)
            graph = [1., .8, .001, 0., 0.]
            class Dataset:
                width = 3
                meta = dict(shards=shards, sources=[], splits={'val': {'rows': 5}, 'test': {'rows': 5}})
                def __init__(self, *args, **kwargs): pass
                def path_for(self, shard): return Path(shard['path'])
            class DB:
                def execute(self, query, args=()):
                    if query.startswith('PRAGMA'): return []
                    return [(line, 'host', 'proc', graph[line - 1]) for line in args[1:]]
                def close(self): pass
            class Ego:
                def __init__(self, db): pass
                def build(self, host, proc, score): return score
            class Scorer:
                enabled = False
                def __init__(self, model): pass
                def score(self, graphs): return np.array(graphs)
            identity = dict(runtime.REFERENCE_IDENTITY)
            identity.update(manifest_sha256=runtime.sha(manifest),
                bundle_sha256=runtime.sha(bundle / 'bundle_manifest.json'),
                graph_sha256='provenance/graph.sqlite', graph_model_sha256='provenance/model_numpy.npz',
                host_model_sha256='models/lgbm_model.txt', feature_width=3,
                schema_sha256=runtime.sha(host / 'assets/vocab.json'))
            key = runtime.key_for_row(x, 0).hex()
            (out / 'collision_registry.jsonl').write_text(json.dumps(dict(
                vector_key=key, labels=[0, 1], train_label_counts=[1, 1])) + '\n')
            (out / 'collision_registry_summary.json').write_text(json.dumps({'identity': identity}))
            old_counts = runtime.metrics([1, 1, 2, 1])['confusion']
            new_counts = runtime.metrics([3, 0, 0, 2])['confusion']
            expected = {s: dict(legacy=old_counts, selected=new_counts) for s in ('validation', 'test')}
            fake_host_module = types.ModuleType('host_shards')
            fake_host_module.HostShardDataset = Dataset
            with patch.dict(sys.modules, {'host_shards': fake_host_module}), \
                 patch.multiple(runtime, REFERENCE_IDENTITY=identity,
                    REFERENCE_MANIFEST_SHA=identity['manifest_sha256'], REFERENCE_CONFUSIONS=expected,
                    GRAPH_CPU_WORKERS=1, EgoGraphs=Ego, DenseCudaGraphSAGE=Scorer), \
                 patch.object(runtime, 'verify_bundle', return_value=bmeta), \
                 patch.object(runtime, 'load_host_model', return_value=(lambda m: m[:, 0].toarray().ravel(), 'fake')), \
                 patch.object(runtime, 'get_shard', return_value=(x, y, np.arange(1, 6))) as decode, \
                 patch.object(runtime.sqlite3, 'connect', return_value=DB()), \
                 patch.object(runtime.RelationalSAGE, 'load', return_value=object()):
                result = runtime.run(manifest, bundle, out)
                self.assertEqual(result['test']['confusion'], new_counts)
                self.assertEqual(decode.call_count, 2)
                changes = [json.loads(line) for line in (out / 'event_transition_audit.jsonl').read_text().splitlines()]
                middle = next(row for row in changes if row['reason'] == 'swept_middle')
                self.assertFalse(middle['collision'])
                self.assertTrue((out / 'test_errors_full_scores.jsonl').is_file())
                self.assertFalse((out / 'test_errors_full_scores.jsonl.tmp').exists())
                (root / 'frozen_lgbm_runtime.py').write_text(SOURCE)
                export_source = next(''.join(c['source']) for c in DOCUMENT['cells']
                                     if 'import json, zipfile' in ''.join(c['source']))
                exec(compile(export_source, 'notebook-export', 'exec'),
                     {'OUTPUT': out, 'WORK': root, 'os': os})
                self.assertTrue((root / 'lgbm_post_sweep_reproduction_results.zip').is_file())
                # Legacy v1 validation payloads contain unused vector-key bytes.
                val_receipt = next((out / 'validation_shards').glob('*.receipt.json'))
                val_payload = val_receipt.with_name(val_receipt.name.replace('.receipt.json', '.npz'))
                with np.load(val_payload, allow_pickle=False) as data:
                    arrays = {name: data[name].copy() for name in data.files}
                arrays.update(key_offsets=np.array([0, 8, 16]), key_bytes=np.zeros(16, dtype=np.uint8))
                runtime.atomic_npz(val_payload, **arrays)
                val_saved = json.loads(val_receipt.read_text())
                val_saved.update(version=1, payload_sha256=runtime.sha(val_payload))
                val_receipt.write_text(json.dumps(val_saved))
                runtime.run(manifest, bundle, out)
                self.assertEqual(decode.call_count, 2, 'Valid checkpoints should avoid rescoring')
                receipt = next((out / 'test_shards').glob('*.receipt.json'))
                saved = json.loads(receipt.read_text())
                saved['policy_sha256'] = 'old-conditional-policy'
                receipt.write_text(json.dumps(saved))
                with self.assertRaisesRegex(ValueError, 'TEST shard checkpoint identity/hash'):
                    runtime.run(manifest, bundle, out)


if __name__ == '__main__':
    unittest.main()
