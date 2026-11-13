import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'serving/endpoint'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'serving'))
import agent  # noqa: E402


class Inbox(unittest.TestCase):
    def test_order_dedup_mark_and_prune(self):
        with tempfile.TemporaryDirectory() as d:
            box = agent.Inbox(Path(d) / 'i.sqlite', 'h1', retention_hours=0)
            recs = [{'log': f'line {i}', 'date': i} for i in (3, 1, 2)]
            self.assertEqual(box.put('audit', recs), 3)
            self.assertEqual(box.put('audit', [{'log': 'line 1', 'date': 99}]), 0)   # transport time is not identity
            rows = box.waiting('audit')
            self.assertEqual([r[2]['log'] for r in rows], ['line 3', 'line 1', 'line 2'])   # arrival order
            box.mark([r[0] for r in rows], 'processed')
            self.assertEqual(box.waiting('audit'), [])
            box.prune()
            self.assertEqual(box.status()['inbox_rows'], 0)

    def test_capacity_and_identity(self):
        with tempfile.TemporaryDirectory() as d:
            box = agent.Inbox(Path(d) / 'i.sqlite', 'h1', max_rows=1)
            box.put('audit', [{'log': 'a'}])
            with self.assertRaises(agent.CapacityError):
                box.put('audit', [{'log': 'b'}])
            with self.assertRaises(ValueError):
                agent.Inbox(Path(d) / 'i.sqlite', 'other-host')

    def test_bundle_gates(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'm.txt').write_text('x')
            man = {'schema_version': 'bundle.v2', 'branch': 'host_ml', 'activation': {'eligible': True},
                   'parity': {'passed': False}, 'artifacts': {'m.txt': {'sha256': agent.sha256_file(root / 'm.txt'), 'bytes': 1}}}
            (root / 'manifest.json').write_text(json.dumps(man))
            with self.assertRaisesRegex(agent.BundleError, 'parity'):
                agent.verify_manifest(root)
            man['parity']['passed'] = True
            man['artifacts']['m.txt']['bytes'] = 2
            (root / 'manifest.json').write_text(json.dumps(man))
            with self.assertRaisesRegex(agent.BundleError, 'checksum'):
                agent.verify_manifest(root)


if __name__ == '__main__':
    unittest.main()
