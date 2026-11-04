import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from verify_bilstm_parity import verify_bundle_parity


class BiLSTMParityTests(unittest.TestCase):
    def setUp(self):
        self.bundle_dir = ROOT / 'runtime/releases/network-dl-run12-candidate'

    def test_golden_sequence_parity_end_to_end(self):
        report = verify_bundle_parity(self.bundle_dir, output_fixture=False)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['categorical_cardinalities'], [141, 4, 11, 10])
        self.assertEqual(report['maximum_sequence'], 512)
        self.assertEqual(report['window_seconds'], 900)
        self.assertAlmostEqual(report['threshold'], 0.245, places=3)
        self.assertGreaterEqual(report['fixtures_evaluated'], 3)

        for res in report['results']:
            self.assertGreater(res['event_count'], 0)
            self.assertEqual(len(res['event_refs']), res['event_count'])
            self.assertTrue(0.0 <= res['probability'] <= 1.0)
            self.assertIn(res['decision'], (0, 1))
            self.assertEqual(res['decision'], int(res['probability'] >= report['threshold']))


if __name__ == '__main__':
    unittest.main()

