import importlib.util
from pathlib import Path
import tempfile
import unittest
import sqlite3

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
            self.assertNotIn('score', [row[1] for row in db.execute('PRAGMA table_info(inbox)')])

if __name__ == '__main__':
    unittest.main()
