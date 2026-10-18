import unittest
import numpy as np
from evaluation_metrics import fixed_threshold_metrics, select_validation_threshold


class EvaluationTests(unittest.TestCase):
    def test_test_labels_cannot_change_validation_threshold(self):
        threshold = select_validation_threshold([0, 0, 1, 1], [0.1, 0.2, 0.7, 0.8])
        self.assertEqual(threshold, 0.7)
        # Optimizing on this test split would pick 0.4. The fixed threshold misses it.
        metrics = fixed_threshold_metrics([0, 1], [0.1, 0.4], threshold)
        self.assertEqual(metrics['threshold'], 0.7)
        self.assertEqual(metrics['recall'], 0.0)

    def test_false_positive_budget_does_not_round_up(self):
        y = np.array([0] * 50 + [1])
        probabilities = np.array([0.9] + [0.1] * 49 + [0.8])
        metrics = fixed_threshold_metrics(y, probabilities, 0.5)
        self.assertEqual(metrics['recall_at_1pct_fpr'], 0.0)
        self.assertEqual(metrics['observed_fpr'], 0.02)

    def test_one_class_smoke_data_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'both benign and malicious'):
            select_validation_threshold([0, 0], [0.2, 0.3])


if __name__ == '__main__':
    unittest.main()
