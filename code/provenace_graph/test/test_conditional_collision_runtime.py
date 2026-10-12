"""Focused routing and validation-budget regressions."""
from pathlib import Path
import sys
import unittest

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'model'))
from conditional_collision_runtime import predict, threshold_options, select_policy


class ConditionalRoutingTest(unittest.TestCase):
    def test_candidate_budgets_and_frozen_selection(self):
        low = ([0, 0, 1, 1], [0.1, 0.8, 0.9, 0.4])
        high = ([0, 0, 1, 1], [0.1, 0.8, 0.9, 0.4])
        self.assertTrue(all(x['fp'] <= 10 for x in threshold_options(*low, band='low')))
        self.assertTrue(all(x['fn'] <= 10 for x in threshold_options(*high, band='high')))
        selected = select_policy([10, 2, 2, 100], low, high)
        self.assertIn(selected['selected'], ('conditional', 'legacy'))

    def test_middle_and_noncollision_are_unchanged(self):
        ml = np.array([.1, .1, .5, .5, .99, .99])
        graph = np.array([.99, .99, .94, .96, .01, .01])
        collision = np.array([True, False, True, False, True, False])
        policy = dict(accepted=True, low_threshold=.98, high_threshold=.02)
        old, new, _ = predict(ml, graph, collision, policy)
        np.testing.assert_array_equal(old, [False, False, False, True, True, True])
        np.testing.assert_array_equal(new, [True, False, False, True, False, True])

    def test_missing_routed_score_is_explicit(self):
        with self.assertRaisesRegex(ValueError, 'Required GraphSAGE score missing'):
            predict(np.array([.1]), np.array([np.nan]), np.array([True]),
                    dict(accepted=True, low_threshold=.9, high_threshold=.1))


if __name__ == '__main__':
    unittest.main()
