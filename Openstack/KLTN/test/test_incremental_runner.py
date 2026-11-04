import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'central/app'))

from incremental_runner import IncrementalRunner


class IncrementalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.runner = IncrementalRunner()

    def test_runner_initialization_and_paths(self):
        self.assertTrue(self.runner.work_dir.exists())
        self.assertTrue(self.runner.releases_dir.exists())

    def test_active_model_discovery(self):
        try:
            res = self.runner.get_active_model('host_ml')
            if res:
                bundle_id, bundle_path, manifest = res
                self.assertTrue(bundle_path.is_dir())
                self.assertEqual(manifest['branch'], 'host_ml')
        except Exception as e:
            # When postgres daemon is not running on 15432, verify graceful connection refusal
            self.assertTrue('connect' in str(e).lower() or 'connection' in str(e).lower())


if __name__ == '__main__':
    unittest.main()
