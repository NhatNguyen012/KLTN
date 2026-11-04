import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from verify_lightgbm_parity import verify_bundle_parity


class LightGBMParityTests(unittest.TestCase):
    def setUp(self):
        self.bundle_dir = ROOT / 'runtime/releases/host-ml-run12-candidate'

    def test_golden_parity_end_to_end(self):
        report = verify_bundle_parity(self.bundle_dir, output_fixture=False)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['vocabulary_width'], 12337)
        self.assertEqual(report['model_features'], 12337)
        self.assertAlmostEqual(report['threshold'], 0.97917, places=5)
        self.assertGreaterEqual(report['fixtures_evaluated'], 5)

        for res in report['results']:
            self.assertGreater(res['tokens_count'], 0)
            self.assertGreater(res['matched_columns_count'], 0)
            self.assertTrue(0.0 <= res['probability'] <= 1.0)
            self.assertIn(res['decision'], (0, 1))
            self.assertEqual(res['decision'], int(res['probability'] >= report['threshold']))


if __name__ == '__main__':
    unittest.main()

