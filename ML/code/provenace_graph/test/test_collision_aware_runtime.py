"""Focused collision-key and routing regression checks."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np
from scipy.sparse import csr_matrix

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'model'))
import collision_aware_runtime as runtime
from collision_aware_runtime import key_for_row, route_predictions


class CollisionAwareTests(unittest.TestCase):
    def test_exact_vector_key_and_all_score_bands(self):
        x = csr_matrix(np.asarray([[1, 0, 1, 0], [1, 0, 1, 0],
                                   [1, 1, 0, 0]], dtype=np.float32))
        self.assertEqual(key_for_row(x, 0), key_for_row(x, 1))
        self.assertNotEqual(key_for_row(x, 0), key_for_row(x, 2))
        ml = np.asarray([.20, .50, .97, .20, .50, .97])
        graph = np.asarray([.99, .10, .10, np.nan, .99, np.nan])
        collision = np.asarray([True, True, True, False, False, False])
        old, new, band, routed = route_predictions(ml, graph, collision)
        self.assertEqual(old.tolist(), [False, False, True, False, True, True])
        self.assertEqual(new.tolist(), [True, False, False, False, True, True])
        self.assertEqual(band.tolist(), [False, True, False, False, True, False])
        self.assertEqual(routed.tolist(), [True, True, True, False, True, False])

    def test_missing_required_graph_score_is_error(self):
        with self.assertRaisesRegex(ValueError, 'GraphSAGE score missing'):
            route_predictions(np.asarray([.1]), np.asarray([np.nan]), np.asarray([True]))

    def test_registry_reads_train_labels_only(self):
        shared = [1, 0, 1]
        train_x = csr_matrix(np.asarray([shared, shared, [0, 1, 0]], dtype=np.float32))
        val_x = csr_matrix(np.asarray([[1, 1, 1]], dtype=np.float32))
        class Data:
            meta = {'splits': {'train': {'label_0': 2, 'label_1': 1}},
                    'shards': [{'split': 'train'}, {'split': 'val'}]}
        with patch.object(runtime, 'get_shard', side_effect=[
                (train_x, np.asarray([0, 1, 0]), None),
                (val_x, np.asarray([1]), None)]) as mocked:
            full, fit, full_rows, fit_rows, full_occ, fit_occ = runtime.build_registry(
                Data(), expected_fit_counts=None)
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(full[key_for_row(train_x, 0)], 3)
        self.assertNotIn(key_for_row(val_x, 0), full)
        self.assertEqual(full_rows[0], 2)
        self.assertEqual(fit_rows[1], 1)
        self.assertEqual(full_occ[key_for_row(train_x, 0)], [1, 1])


if __name__ == '__main__':
    unittest.main()
