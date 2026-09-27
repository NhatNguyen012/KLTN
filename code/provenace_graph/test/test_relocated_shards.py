import tempfile
import unittest
from pathlib import Path

from model.train import resolve_volume_roots


class RelocatedShardTests(unittest.TestCase):
    def test_discovers_volume_from_nested_manifest_relative_shard(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mounted-dataset'
            manifest = mount / 'manifest.json'
            relative = Path('source-id') / 'split-id' / 'train_000000.npz'
            shard = mount / 'payload' / 'ssd' / relative
            shard.parent.mkdir(parents=True)
            shard.touch()
            meta = {'volumes': {'ssd': '/old/machine/ssd'},
                    'shards': [{'volume': 'ssd', 'path': str(relative)}]}
            roots = resolve_volume_roots(manifest, meta)
            self.assertEqual(roots['ssd'], (mount / 'payload' / 'ssd').resolve())

    def test_prefers_standard_volume_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mounted-dataset'
            root = mount / 'volumes' / 'ssd'
            shard = root / 'id' / 'train.npz'
            shard.parent.mkdir(parents=True)
            shard.touch()
            meta = {'volumes': {'ssd': '/old/machine/ssd'},
                    'shards': [{'volume': 'ssd', 'path': 'id/train.npz'}]}
            roots = resolve_volume_roots(mount / 'manifest.json', meta)
            self.assertEqual(roots['ssd'], root.resolve())

    def test_unused_configured_volume_does_not_need_to_be_mounted(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mounted-dataset'
            root = mount / 'volumes' / 'ssd'
            shard = root / 'id' / 'train.npz'
            shard.parent.mkdir(parents=True)
            shard.touch()
            meta = {'volumes': {'ssd': '/old/machine/ssd', 'hdd': '/old/machine/hdd'},
                    'shards': [{'volume': 'ssd', 'path': 'id/train.npz'}]}
            roots = resolve_volume_roots(mount / 'manifest.json', meta)
            self.assertEqual(roots['ssd'], root.resolve())
            self.assertEqual(roots['hdd'], Path('/old/machine/hdd'))


if __name__ == '__main__':
    unittest.main()
