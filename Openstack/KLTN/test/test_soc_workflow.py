import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'central/app'))
import api
from framework import REVIEW_DECISIONS, canonical_hash


class SocWorkflowTests(unittest.TestCase):
    def test_review_decisions_supported(self):
        self.assertIn('confirmed', REVIEW_DECISIONS)
        self.assertIn('false_positive', REVIEW_DECISIONS)
        self.assertIn('dismissed', REVIEW_DECISIONS)

    def test_soc_dashboard_renders_components(self):
        html = api.SOC_HTML
        self.assertIn('KLTN Unified SOC Portal', html)
        self.assertIn('Evidence & Review Drill-down', html)
        self.assertIn('Host ML (LightGBM)', html)
        self.assertIn('Network DL (BiLSTM)', html)
        self.assertIn('Confirmed Incident', html)
        self.assertIn('False Positive', html)
        self.assertIn('Audit History', html)
        self.assertIn('/v1/soc/verified-dataset', html)


if __name__ == '__main__':
    unittest.main()

