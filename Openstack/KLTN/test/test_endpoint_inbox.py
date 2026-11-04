import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
import sqlite3

try:
    import fastapi  # noqa: F401
except ModuleNotFoundError:
    module = types.ModuleType('fastapi')
    class FastAPI:
        def __init__(self, *args, **kwargs):
            pass
        def get(self, *args, **kwargs):
            return lambda function: function
        def post(self, *args, **kwargs):
            return lambda function: function
    class HTTPException(Exception):
        pass
    class Request:
        pass
    module.FastAPI, module.HTTPException, module.Request = FastAPI, HTTPException, Request
    sys.modules['fastapi'] = module

# Allows running both in this repository and in a container with /src mounted.
source = Path(__file__).resolve().parents[1] / 'serving/endpoint/agent.py'
if not source.exists():
    source = Path('/src/agent.py')
spec = importlib.util.spec_from_file_location('endpoint_agent', source)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'inbox.sqlite'

    def tearDown(self):
        self.tmp.cleanup()

    def inbox(self, **kwargs):
        return agent.Inbox(self.path, 'host-1', min_free_bytes=0, **kwargs)

    def test_bundle_requires_all_promotion_gates(self):
        root = Path(self.tmp.name) / 'bundle'
        artifact = root / 'model/model.txt'
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b'model')
        manifest = {
            'schema_version': 'bundle.v1', 'branch': 'host_ml',
            'algorithm': 'lightgbm', 'domain_validation': 'shadow_unvalidated',
            'activation': {'eligible': False},
            'artifacts': {'model/model.txt': {
                'sha256': hashlib.sha256(b'model').hexdigest(), 'bytes': 5,
            }},
        }
        manifest_path = root / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(agent.BundleError, 'bundle_not_activation_eligible'):
            agent.verify_manifest(root)
        manifest['activation']['eligible'] = True
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(agent.BundleError, 'bundle_domain_not_validated'):
            agent.verify_manifest(root)
        manifest['domain_validation'] = 'validated'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(agent.BundleError, 'bundle_parity_not_passed'):
            agent.verify_manifest(root)
        manifest['parity'] = {'passed': True}
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        self.assertEqual(agent.verify_manifest(root)['domain_validation'], 'validated')

    def test_replay_is_deduplicated_across_reopen(self):
        self.assertEqual(self.inbox().put('sysmon', [{'date':1,'EventRecordID':42}]), 1)
        reopened = self.inbox()
        self.assertEqual(reopened.put('sysmon', [{'date':2,'EventRecordID':42}]), 0)
        self.assertEqual(reopened.status()['pending_events'], 1)
        self.assertEqual(reopened.put('security', [{'date':1,'EventRecordID':42}]), 1)

    def test_full_batch_rolls_back_and_existing_retry_is_acked(self):
        inbox = self.inbox(max_rows=1)
        with self.assertRaises(agent.CapacityError):
            inbox.put('audit', [{'log':'first'},{'log':'second'}])
        self.assertEqual(inbox.status()['pending_events'], 0)
        self.assertEqual(inbox.put('audit', [{'log':'first'}]), 1)
        self.assertEqual(inbox.put('audit', [{'log':'first'}]), 0)
        with self.assertRaises(agent.CapacityError):
            inbox.put('audit', [{'log':'second'}])
        self.assertEqual(inbox.status()['pending_events'], 1)

    def test_byte_limit_and_host_identity(self):
        inbox = self.inbox(max_bytes=8)
        with self.assertRaises(agent.CapacityError):
            inbox.put('journal', [{'message':'too long'}])
        with self.assertRaises(ValueError):
            agent.Inbox(self.path, 'different-host', min_free_bytes=0)

    def test_pending_records_have_no_fake_score(self):
        self.inbox().put('sysmon', [{'EventRecordID':1}])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT state FROM inbox').fetchone()[0], 'waiting_for_model')
            self.assertIsNone(db.execute('SELECT score_id FROM inbox').fetchone()[0])
            self.assertEqual(db.execute('SELECT count(*) FROM score_outbox').fetchone()[0], 0)

    def test_score_and_outbox_commit_atomically(self):
        inbox = self.inbox()
        inbox.put('sysmon', [{'EventRecordID': 1}])
        identity = agent.event_id('host-1', 'sysmon', {'EventRecordID': 1})
        score = {'score_id': 'score-1', 'score': 0.9}
        inbox.store_score(identity, {'event_type': 'PROCESS_START'}, score)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT state FROM inbox').fetchone()[0], 'scored_shadow')
            self.assertEqual(db.execute('SELECT score_id FROM inbox').fetchone()[0], 'score-1')
            self.assertEqual(db.execute('SELECT score_id FROM score_outbox').fetchone()[0], 'score-1')

    def test_permanent_inference_error_does_not_starve_queue(self):
        inbox = self.inbox()
        inbox.put('sysmon', [{'EventRecordID': 1}])
        identity = agent.event_id('host-1', 'sysmon', {'EventRecordID': 1})
        for _ in range(3):
            inbox.mark_error(identity, 'fixture_error')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT state,attempts FROM inbox').fetchone(), ('error', 3))

if __name__ == '__main__':
    unittest.main()
