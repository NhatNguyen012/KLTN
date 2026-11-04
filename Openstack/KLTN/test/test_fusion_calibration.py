import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'central/app'))
sys.path.insert(0, str(ROOT / 'scripts'))

from framework import FUSION_POLICY, fuse_scores, validate_score
from calibrate_fusion import evaluate_policy, generate_paired_dataset, grid_search_calibration


class FusionCalibrationTests(unittest.TestCase):
    def test_calibrated_fusion_policy_contract(self):
        self.assertEqual(FUSION_POLICY['version'], 'fusion-calibrated-v1')
        self.assertIn('host_ml', FUSION_POLICY['weights'])
        self.assertIn('network_dl', FUSION_POLICY['weights'])
        self.assertAlmostEqual(sum(FUSION_POLICY['weights'].values()), 1.0)
        self.assertTrue(0.0 < FUSION_POLICY['threshold'] < 1.0)

    def test_grid_search_optimizes_f1_with_bounded_fpr(self):
        val_set, test_set = generate_paired_dataset(n_samples=500, seed=123)
        calibrated = grid_search_calibration(val_set, max_fpr=0.01)
        self.assertIsNotNone(calibrated)
        self.assertGreaterEqual(calibrated['f1'], 0.90)
        self.assertLessEqual(calibrated['fpr'], 0.01)

        # Test evaluation with frozen weights
        test_res = evaluate_policy(test_set, calibrated['w_host'], calibrated['w_net'], calibrated['threshold'])
        self.assertGreaterEqual(test_res['f1'], 0.85)


if __name__ == '__main__':
    unittest.main()

