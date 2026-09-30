import sys
import unittest
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'model'))
from cascade_runtime import choose, counts, metrics, policies, predictions

class CascadeRuntimeTest(unittest.TestCase):
    def test_validation_uses_all_routed_rows_and_fallback(self):
        ml = np.array([.05, .4, .8, .995])
        graph = np.array([np.nan, .9, np.nan, np.nan])
        p = dict(mode='cascade', low=.1, high=.99, graph=.7, baseline_threshold=.94)
        np.testing.assert_array_equal(predictions(ml, graph, p), [False, True, False, True])
        c = counts(np.array([0, 0, 1, 1]), predictions(ml, graph, p))
        self.assertEqual(metrics(c)['confusion'], dict(tp=1, fp=1, fn=1, tn=1))

    def test_baseline_wins_tie(self):
        opts = policies(.94)
        c = np.tile(np.array([1, 0, 0, 9]), (len(opts), 1))
        self.assertEqual(choose(opts, c)['mode'], 'baseline')

if __name__ == '__main__': unittest.main()
