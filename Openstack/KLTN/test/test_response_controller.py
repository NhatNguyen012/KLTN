import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'central/app'))

from framework import RESPONSE_ACTIONS
from response_controller import OpenStackResponseExecutor, ResponseController


class ResponseControllerTests(unittest.TestCase):
    def test_response_actions_contract(self):
        self.assertIn('quarantine_network', RESPONSE_ACTIONS)
        self.assertIn('release_network', RESPONSE_ACTIONS)

    def test_simulation_quarantine_and_release(self):
        executor = OpenStackResponseExecutor(simulation=True)
        res_q = executor.apply_quarantine("test-server-01")
        self.assertEqual(res_q['status'], 'quarantined')
        self.assertIn('initial_state', res_q)
        self.assertIn('security_group_ids', res_q['initial_state'])

        res_r = executor.apply_release("test-server-01", res_q['initial_state'])
        self.assertEqual(res_r['status'], 'released')
        self.assertEqual(res_r['restored_secgroups'], res_q['initial_state']['security_group_ids'])

    @patch('response_controller.db_connect')
    def test_safety_check_blocks_unconfirmed_alert(self, mock_db):
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        executor = OpenStackResponseExecutor(simulation=True)
        ctrl = ResponseController(executor)
        unconfirmed_req = {
            'request_id': 'req-01',
            'alert_id': 'alert-shadow-01',
            'host_id': 'host-01',
            'action': 'quarantine_network',
            'alert_state': 'needs_review',  # Not confirmed!
        }
        # Must fail safety check
        processed = ctrl.process_request(unconfirmed_req)
        self.assertFalse(processed)


if __name__ == '__main__':
    unittest.main()
