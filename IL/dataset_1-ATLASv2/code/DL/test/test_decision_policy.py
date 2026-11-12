import sys
import unittest
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "model"))
from decision_policy import attack_macro_f1, select_binary_threshold
from research_paths import ROOT, validate_output_dir


class DecisionPolicyTests(unittest.TestCase):
    def test_benign_false_alarms_reduce_attack_f1(self):
        self.assertAlmostEqual(attack_macro_f1([0, 1, 2, 3, 4], [1, 1, 2, 3, 4]), 11 / 12)

    def test_all_thresholds_above_half_are_considered(self):
        y, s = np.array([0, 0, 1]), np.array([0.7, 0.8, 0.9])
        t = select_binary_threshold(y, s, 0)
        self.assertEqual(t, 0.9)

    def test_infeasible_detection_emits_no_alerts(self):
        y, s = np.array([0, 0, 1]), np.array([0.9, 0.9, 0.1])
        self.assertTrue(select_binary_threshold(y, s, 0) > s.max())

    def test_tied_scores_are_not_split(self):
        self.assertGreater(select_binary_threshold([0, 1], [0.8, 0.8], 0), 0.8)

    def test_dataset_outputs_rejected(self):
        with self.assertRaises(ValueError):
            validate_output_dir(ROOT / "DATASET" / "ATLASv2" / "cache")


if __name__ == "__main__":
    unittest.main()
