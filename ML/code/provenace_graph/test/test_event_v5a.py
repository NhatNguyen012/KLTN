import json
from pathlib import Path
import sys
import tempfile
import unittest

import numpy as np

HERE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(HERE/'model'), str(HERE/'preprocess'),
                str(HERE.parent/'preprocess')]

from ego import ATTRIBUTES as BASE_ATTRIBUTES
from event_ego import EventSchema, RELATIONS
from event_ego_cache import FORMAT, SCHEMA, examples, load_manifest, manifest_digest
from event_relational_sage import RelationalSAGE
from build_event_ego_cache import encode_part


class EventV5aTests(unittest.TestCase):
    def setUp(self):
        self.vocab = {'action::create': 1, 'action::load': 2,
                      'object::process': 3, 'object::module': 4}
        self.schema = EventSchema(self.vocab)
        self.base = dict(x=np.eye(2, len(BASE_ATTRIBUTES), dtype=np.float32),
                         edges=((1, 0, 'hosts'),), root=0, host_root=1,
                         node_keys=(('h', 'p'), ('h', None)), cutoff_us=100)

    def test_one_event_node_preserves_backbone_and_changes_target_type(self):
        first = self.schema.augment(self.base, 'action::load', 'object::module')
        second = self.schema.augment(self.base, 'action::create', 'object::process')
        self.assertEqual(len(first['x']), len(self.base['x']) + 1)
        np.testing.assert_array_equal(first['x'][:2, :len(BASE_ATTRIBUTES)], self.base['x'])
        self.assertTrue(set(self.base['edges']).issubset(first['edges']))
        self.assertIn((0, 2, 'performs'), first['edges'])
        self.assertIn((2, 0, 'performs_reverse'), first['edges'])
        self.assertNotEqual(first['x'].tobytes(), second['x'].tobytes())
        self.assertEqual(len(first['node_keys']), 3)
        self.assertEqual(len(self.schema.attributes), len(BASE_ATTRIBUTES) + 1 + len(self.vocab))

    def test_exact_host_column_join_and_record_mapping(self):
        self.assertEqual(self.schema.from_columns([2, 4, 99]), ('action::load', 'object::module'))
        self.assertEqual(self.schema.from_record({'action': 'LOAD', 'object': 'MODULE'}),
                         ('action::load', 'object::module'))
        with self.assertRaises(ValueError):
            self.schema.from_columns([1, 2, 3])
        with self.assertRaises(ValueError):
            self.schema.from_record({'action': 'LOAD', 'object': 'FILE'})

    def test_event_cache_and_new_relation_model_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base_meta = {'relations': ['creates', 'communicates', 'communicates_reverse', 'hosts'],
                         'source_ids': ['s']}
            row = dict(x=self.base['x'], edge_index=np.asarray([[1], [0]], dtype=np.int64),
                       edge_type=np.asarray([3], dtype=np.int64), root=0, host_root=1,
                       label=1, source_index=0, source_line=7, cutoff_us=100)
            path = root/'train/graph_00000.npz'
            part = encode_part(path, [row], base_meta, self.schema,
                               {('s', 7): ('action::load', 'object::module')})
            part.update(path='train/graph_00000.npz', split='train')
            meta = dict(format=FORMAT, schema=SCHEMA, complete=True, config={},
                        attributes=list(self.schema.attributes), relations=list(RELATIONS),
                        source_ids=['s'], splits={}, parts=[part])
            meta['manifest_sha256'] = manifest_digest(meta)
            (root/'manifest.json').write_text(json.dumps(meta))
            _, loaded = load_manifest(root)
            item = next(examples(root, loaded['parts'][0], len(self.schema.attributes)))
            self.assertEqual(sorted(item['edge_type'].tolist()), [3, 4, 5])
            self.assertEqual(item['label'], 1)
            model = RelationalSAGE(len(self.schema.attributes), seed=4)
            graph = dict(x=item['x'], edges=tuple((int(a), int(b), RELATIONS[int(t)])
                         for (a, b), t in zip(item['edge_index'].T, item['edge_type'])),
                         root=item['root'], host_root=item['host_root'])
            self.assertTrue(0 <= model.predict(graph)['probability'] <= 1)


if __name__ == '__main__':
    unittest.main()
