import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central/app'))
from framework import (ContractError, FUSION_POLICY, approval_allowed, fuse_bucket, margin, population_stability_index,  # noqa: E402
                       validate_score, validate_summary)

T = '2026-11-14T01:00:00+00:00'


def score(**kw):
    s = {'schema_version': 'score.v1', 'host_id': 'h1', 'branch': 'host_ml', 'bundle_id': 'b', 'event_refs': ['e1'],
         'window': None, 'status': 'ready_shadow', 'score': 0.9, 'threshold': 0.8, 'prediction': 1,
         'domain': 'linux-audit', 'domain_validation': 'validated', 'processed_at': T,
         'evidence': {'event_time': '2026-11-14T00:59:00+00:00'}}
    s.update(kw)
    return s


class ScoreContract(unittest.TestCase):
    def test_host_ownership_and_event_time(self):
        v = validate_score(score(), 'h1')
        self.assertEqual(v['event_time'].minute, 59)
        with self.assertRaises(ContractError):
            validate_score(score(), 'h2')

    def test_prediction_must_match_threshold(self):
        with self.assertRaises(ContractError):
            validate_score(score(score=0.5, prediction=1))

    def test_branches(self):
        validate_score(score(branch='host_dl', window={'start': T, 'end': '2026-11-14T01:03:00+00:00'}))
        with self.assertRaises(ContractError):
            validate_score(score(branch='network_dl'))

    def test_unavailable_is_null(self):
        validate_score(score(status='waiting_for_model', score=None, threshold=None, prediction=None))
        with self.assertRaises(ContractError):
            validate_score(score(status='waiting_for_model'))

    def test_summary(self):
        s = validate_summary({'schema_version': 'summary.v1', 'host_id': 'h1', 'bundle_id': 'b', 'domain': 'linux-audit',
                              'period_start': T, 'period_end': T}, 'h1')
        self.assertEqual(len(s['summary_id']), 64)


class Fusion(unittest.TestCase):
    def row(self, branch, p, th, pred=None, val='validated', stage=None):
        return {'score_id': f'{branch}{p}', 'branch': branch, 'bundle_id': 'b', 'status': 'ready_shadow', 'score': p,
                'threshold': th, 'prediction': int(p >= th) if pred is None else pred, 'domain': 'd', 'domain_validation': val,
                'event_refs': ['x'], 'score_window': None, 'evidence': {'stage_last': stage},
                'event_time': datetime(2026, 11, 14, tzinfo=timezone.utc)}

    def test_margin_maps_threshold_to_half(self):
        self.assertAlmostEqual(margin(0.8, 0.8), 0.5, places=6)
        self.assertGreater(margin(0.9, 0.8), 0.5)

    def test_single_branch_alerts_exactly_at_its_threshold(self):
        b = datetime(2026, 11, 14, tzinfo=timezone.utc)
        self.assertEqual(fuse_bucket('h', b, [self.row('host_ml', 0.95, 0.9)], {})['prediction'], 1)
        self.assertEqual(fuse_bucket('h', b, [self.row('host_ml', 0.85, 0.9)], {})['prediction'], 0)

    def test_agreement_of_weak_signals_and_severity(self):
        b = datetime(2026, 11, 14, tzinfo=timezone.utc)
        weak = fuse_bucket('h', b, [self.row('host_ml', 0.85, 0.9), self.row('host_dl', 0.85, 0.9)], {})
        self.assertEqual(weak['prediction'], 1)          # two independent near-threshold views
        both = fuse_bucket('h', b, [self.row('host_ml', 0.99, 0.9), self.row('host_dl', 0.99, 0.9)], {})
        self.assertEqual(both['severity'], 'critical')
        stage = fuse_bucket('h', b, [self.row('host_dl', 0.99, 0.9, stage='lateral_movement')], {})
        self.assertEqual(stage['severity'], 'critical')

    def test_missing_branch_is_not_benign_and_shadow_flag(self):
        b = datetime(2026, 11, 14, tzinfo=timezone.utc)
        f = fuse_bucket('h', b, [self.row('host_ml', 0.99, 0.9, val='shadow_unvalidated')], {})
        self.assertEqual(f['source_mask'], {'host_ml': True, 'host_dl': False})
        self.assertTrue(f['shadow'])
        with self.assertRaises(ContractError):
            fuse_bucket('h', b, [], {})

    def test_policy_and_psi(self):
        self.assertEqual(FUSION_POLICY['bucket_seconds'], 300)
        self.assertAlmostEqual(population_stability_index({'a': 1}, {'a': 5}), 0.0)
        self.assertIsNone(population_stability_index({}, {'a': 1}))



class ApprovalPolicy(unittest.TestCase):
    def test_two_person_and_single_operator(self):
        self.assertFalse(approval_allowed('two_person', 'Alice', ' alice '))
        self.assertTrue(approval_allowed('two_person', 'alice', 'bob'))
        self.assertTrue(approval_allowed('single_operator', 'alice', 'Alice'))
        with self.assertRaises(ContractError):
            approval_allowed('anyone', 'a', 'b')


if __name__ == '__main__':
    unittest.main()
