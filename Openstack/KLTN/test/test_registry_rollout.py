import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'central/app'))

from framework import REGISTRY_STAGES
from registry_rollout import RegistryRolloutManager


class RegistryRolloutTests(unittest.TestCase):
    def test_registry_stages_contract(self):
        expected = {'candidate', 'validated', 'canary', 'active', 'retired', 'rolled_back'}
        self.assertEqual(REGISTRY_STAGES, expected)

    def test_manager_instantiation(self):
        mgr = RegistryRolloutManager()
        self.assertTrue(mgr.releases_dir.exists())


if __name__ == '__main__':
    unittest.main()

