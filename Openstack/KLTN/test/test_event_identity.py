import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central/app'))
from common import event_record


class EventIdentityTests(unittest.TestCase):
    def test_delivery_timestamp_does_not_duplicate_source_event(self):
        a = event_record('host-a', 'audit', {'date': 1, 'log': 'audit(1:27)'})
        b = event_record('host-a', 'audit', {'date': 2, 'log': 'audit(1:27)'})
        self.assertEqual(a['event_id'], b['event_id'])
        self.assertNotEqual(a['raw'], b['raw'])

    def test_host_source_and_record_are_identity_boundaries(self):
        original = event_record('a', 'audit', {'log': 'audit(1:27)'})['event_id']
        for host, source, raw in [('b', 'audit', {'log': 'audit(1:27)'}), ('a', 'journal', {'log': 'audit(1:27)'}), ('a', 'audit', {'log': 'audit(1:28)'})]:
            self.assertNotEqual(original, event_record(host, source, raw)['event_id'])

    def test_json_key_order_is_not_identity(self):
        self.assertEqual(event_record('a','audit',{'x':1,'y':2})['event_id'],event_record('a','audit',{'y':2,'x':1})['event_id'])

if __name__ == '__main__':
    unittest.main()
