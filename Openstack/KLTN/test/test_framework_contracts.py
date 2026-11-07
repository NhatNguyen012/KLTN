import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'central/app'))
from framework import ContractError, fuse_scores, validate_score
from normalization import normalize_record

NORMALIZATION = ROOT / 'serving/endpoint/endpoint_normalization.py'
spec = importlib.util.spec_from_file_location('endpoint_normalization', NORMALIZATION)
endpoint_normalization = importlib.util.module_from_spec(spec)
spec.loader.exec_module(endpoint_normalization)


SYSMON_PROCESS = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
<TimeCreated SystemTime="2026-11-01T02:03:04.000000Z"/></System><EventData>
<Data Name="ProcessGuid">{A}</Data><Data Name="ParentProcessGuid">{P}</Data>
<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
<Data Name="CommandLine">cmd.exe /c whoami</Data><Data Name="User">LAB\\User</Data>
</EventData></Event>'''


class NormalizationTests(unittest.TestCase):
    def test_sysmon_process_fields_match_endpoint_view(self):
        raw = {'xml': SYSMON_PROCESS, 'date': 1}
        record = {'event_id': 'e1', 'host_id': 'h1', 'source': 'sysmon', 'raw': raw}
        central = normalize_record(record, datetime(2026, 11, 1, tzinfo=timezone.utc))
        endpoint = endpoint_normalization.normalize_endpoint_event('h1', 'e1', 'sysmon', raw)
        for key in ('event_type', 'process_id', 'parent_process_id', 'process_path',
                    'parent_path', 'command_line', 'principal'):
            self.assertEqual(central[key], endpoint[key])
        self.assertEqual(central['event_type'], 'PROCESS_START')


class ScoreContractTests(unittest.TestCase):
    def score(self, **changes):
        value = {
            'schema_version': 'score.v1', 'host_id': 'h1', 'branch': 'host_ml',
            'bundle_id': 'bundle-1', 'event_refs': ['event-1'], 'window': None,
            'status': 'ready_shadow', 'score': 0.8, 'threshold': 0.75,
            'prediction': 1, 'domain': 'windows-sysmon',
            'domain_validation': 'shadow_unvalidated',
            'processed_at': '2026-11-01T00:00:00Z', 'evidence': {},
        }
        value.update(changes)
        return value

    def test_score_identity_and_host_ownership(self):
        score = validate_score(self.score(), 'h1')
        self.assertEqual(score['prediction'], 1)
        self.assertEqual(len(score['score_id']), 64)
        with self.assertRaises(ContractError):
            validate_score(self.score(host_id='h2'), 'h1')

    def test_unavailable_is_null_not_benign(self):
        value = self.score(status='unsupported_domain', score=None, threshold=None, prediction=None)
        self.assertIsNone(validate_score(value, 'h1')['score'])
        with self.assertRaises(ContractError):
            validate_score(self.score(status='unsupported_domain', score=0.0,
                                      threshold=None, prediction=0), 'h1')

    def test_prediction_boundary_is_enforced(self):
        with self.assertRaises(ContractError):
            validate_score(self.score(score=0.4, prediction=1), 'h1')

    def test_only_two_detection_branches_are_accepted(self):
        validate_score(self.score(branch='host_ml'), 'h1')
        validate_score(self.score(branch='network_dl'), 'h1')
        with self.assertRaises(ContractError):
            validate_score(self.score(branch='provenance'), 'h1')

    def test_fusion_source_mask_preserves_missing_branch(self):
        row = validate_score(self.score(), 'h1')
        fused = fuse_scores([row], datetime(2026, 11, 1, tzinfo=timezone.utc))
        self.assertEqual(set(fused['source_mask']), {'host_ml', 'network_dl'})
        self.assertTrue(fused['source_mask']['host_ml'])
        self.assertFalse(fused['source_mask']['network_dl'])
        self.assertAlmostEqual(fused['risk_score'], 0.8)


if __name__ == '__main__':
    unittest.main()
