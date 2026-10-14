import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "model"))
from evidence_veto_runtime import evidence, gate, revised_counts, select_rule

import numpy as np


class EvidenceVetoTests(unittest.TestCase):
    def test_graph_evidence_and_gate(self):
        graph = dict(x=np.zeros((2, 3), dtype=np.float32),
                     edges=((1, 0, "creates"),), root=0,
                     flags=("unresolved_relation", "truncated"))
        item = evidence(graph)
        self.assertEqual(item["create_edges"], 1)
        self.assertTrue(gate("any_create", item))
        self.assertTrue(gate("root_create", item))
        self.assertFalse(gate("any_create_resolved", item))
        self.assertFalse(gate("any_create_untruncated", item))
        item["create_edges"] = 0
        self.assertFalse(gate("any_create", item))

    def test_reversion_reconciles_fp_fn(self):
        base = dict(tp=10, fp=2, fn=3, tn=100)
        weak = dict(create_edges=0, root_create=False, unresolved=True,
                    truncated=True, missing_identity=False, graph_input_sha256="weak")
        strong = dict(create_edges=1, root_create=True, unresolved=False,
                      truncated=False, missing_identity=False, graph_input_sha256="strong")
        rows = [dict(label=0, evidence=weak, source_id="a"),
                dict(label=1, evidence=weak, source_id="b"),
                dict(label=0, evidence=strong, source_id="c")]
        result, audit = revised_counts(base, rows, "any_create")
        self.assertEqual(result["confusion"], dict(tp=11, fp=3, fn=2, tn=99))
        self.assertEqual(audit["rescued_fn"], 1)
        self.assertEqual(audit["vetoed_fp"], 1)

    def test_validation_falls_back_on_unclear_gain(self):
        base = dict(tp=100, fp=2, fn=2, tn=1000)
        choice = select_rule(base, [])
        self.assertFalse(choice["accepted"])
        self.assertEqual(choice["selected"], "conditional_unchanged")


if __name__ == "__main__":
    unittest.main()
