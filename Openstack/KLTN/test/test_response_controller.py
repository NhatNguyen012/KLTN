import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'central/app'))
from response_controller import Controller, OpenStackExecutor  # noqa: E402


class ResponseControllerTests(unittest.TestCase):
    def test_quarantine_then_release_restores_groups(self):
        x = OpenStackExecutor(simulation=True)
        q = x.quarantine('server-1')
        self.assertEqual(q['status'], 'quarantined')
        port = next(iter(q['initial_state']))
        self.assertEqual(x.groups(port), ['sg-quarantine'])
        r = x.release('server-1', q['initial_state'])
        self.assertEqual(x.groups(port), sorted(q['initial_state'][port]))
        self.assertEqual(r['status'], 'released')

    def test_release_without_snapshot_fails(self):
        with self.assertRaises(RuntimeError):
            OpenStackExecutor(simulation=True).release('server-1', None)

    def test_network_action_requires_confirmed_alert(self):
        ctrl = Controller(OpenStackExecutor(simulation=True))
        with self.assertRaises(PermissionError):
            ctrl.process({'request_id': 'r', 'alert_id': 'a', 'host_id': 'h', 'action': 'quarantine_network',
                          'alert_state': 'needs_review'})

    def test_quarantine_group_with_extra_rule_is_refused(self):
        x = OpenStackExecutor(simulation=False, cli='/bin/false')
        rules = [{'Direction': 'egress', 'IP Protocol': 'tcp', 'Port Range': '18443:18443'},
                 {'Direction': 'egress', 'IP Protocol': None, 'Port Range': ''}]   # default allow-all egress
        with patch.object(OpenStackExecutor, 'os', side_effect=[{'id': 'sg'}, rules]):
            with self.assertRaisesRegex(RuntimeError, 'non-allowed'):
                x.quarantine_group()


if __name__ == '__main__':
    unittest.main()
