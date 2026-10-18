import json
from pathlib import Path
import sys
import tempfile
import unittest

import numpy as np

HERE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(HERE / 'model'), str(HERE / 'preprocess'), str(HERE.parents[0] / 'preprocess')]
from build_ego_cache import write_part
from ego import ATTRIBUTES
from ego_cache import (FORMAT, RELATIONS, examples, load_manifest,
                       manifest_digest, require_exact_time)


class EgoCacheTests(unittest.TestCase):
    def test_static_part_round_trip_and_manifest_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = dict(x=np.eye(2, len(ATTRIBUTES), dtype=np.float32),
                         edges=((0, 1, 'creates'),), root=1, host_root=0, cutoff_us=100)
            second = dict(x=np.ones((2, len(ATTRIBUTES)), dtype=np.float32),
                          edges=(), root=0, host_root=1, cutoff_us=None)
            rows = [(first, ('h', 'p', 100, 1, 'source-a', 10)),
                    (second, ('h', 'q', 200, 0, 'source-b', 20))]
            part = write_part(root / 'train/graph_00000.npz', rows, {'source-a': 0, 'source-b': 1})
            part.update(path='train/graph_00000.npz', split='train', start=0, stop=2)
            policy = dict(timestamp_unit='microseconds', quantum_us=1,
                          cutoff='exact target timestamp in microseconds',
                          evidence='evidence_timestamp_us < cutoff_us')
            audit = dict(targets_checked=2, explicit_evidence_items_checked=1,
                         cutoff_equals_target_timestamp=True,
                         all_evidence_strictly_before_target=True)
            meta = dict(format=FORMAT, schema=1, complete=True,
                        config={'ego': {'quantum_us': 1}}, time_policy=policy,
                        time_audit=audit, attributes=ATTRIBUTES,
                        relations=list(RELATIONS), source_ids=['source-a', 'source-b'],
                        splits={'train': {'graphs': 2, 'label_0': 1, 'label_1': 1, 'parts': 1},
                                'val': {'graphs': 0, 'label_0': 0, 'label_1': 0, 'parts': 0},
                                'test': {'graphs': 0, 'label_0': 0, 'label_1': 0, 'parts': 0}},
                        parts=[part], cache_bytes=part['bytes'])
            meta['manifest_sha256'] = manifest_digest(meta)
            (root / 'manifest.json').write_text(json.dumps(meta))
            loaded_root, loaded = load_manifest(root)
            require_exact_time(loaded)
            decoded = list(examples(loaded_root, loaded['parts'][0], len(ATTRIBUTES)))
            self.assertEqual([item['label'] for item in decoded], [1, 0])
            self.assertEqual(decoded[0]['edge_index'].tolist(), [[0], [1]])
            self.assertEqual(decoded[0]['edge_type'].tolist(), [0])
            self.assertEqual(decoded[1]['cutoff_us'], -1)

    def test_exact_time_policy_rejects_second_quantized_cache(self):
        with self.assertRaisesRegex(ValueError, 'quantum_us=1'):
            require_exact_time({'config': {'ego': {'quantum_us': 1_000_000}},
                                'time_policy': {'timestamp_unit': 'microseconds',
                                                'quantum_us': 1_000_000}})


if __name__ == '__main__':
    unittest.main()
