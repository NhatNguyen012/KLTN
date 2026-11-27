"""Tests for OptcEcarFeaturizer and endpoint OpTC Seed-02 parity."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "serving"))
sys.path.insert(0, str(WORKSPACE / "Docker"))

from kltn_features.optc_ecar import OptcEcarFeaturizer  # noqa: E402
from shared.causal_runtime import extract_stream_features  # noqa: E402


def _sysmon(eid: int, rid: int, ts: str, **fields) -> dict:
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return {
        "System": (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="Microsoft-Windows-Sysmon"/><EventID>{eid}</EventID>'
            f'<EventRecordID>{rid}</EventRecordID><Computer>kltn-windows-1</Computer>'
            f'<TimeCreated SystemTime="{ts}"/></System><EventData>{data}</EventData></Event>'
        )
    }


class OptcEcarTests(unittest.TestCase):
    def test_endpoint_featurizer_matches_docker_causal_runtime(self):
        vocab_path = WORKSPACE / "ML/code/output/host_ml_parent_incoming_seed02/vocab.json"
        if not vocab_path.is_file():
            self.skipTest("Seed-02 vocab not present")
        vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
        events = [
            _sysmon(
                1, 1, "2026-11-27T00:00:01.000Z",
                ProcessGuid="{00000001-0000-0000-0000-000000000001}", ProcessId="100",
                Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /c whoami",
                User="WORKGROUP\\SYSTEM", ParentProcessGuid="{00000001-0000-0000-0000-000000000000}",
                ParentImage="C:\\Windows\\System32\\services.exe",
            ),
            _sysmon(
                1, 2, "2026-11-27T00:00:02.000Z",
                ProcessGuid="{00000001-0000-0000-0000-000000000002}", ProcessId="200",
                Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell -NoP -Enc UABvAHcAZQByAA==",
                User="kltn-windows-1\\Admin", ParentProcessGuid="{00000001-0000-0000-0000-000000000001}",
                ParentImage="C:\\Windows\\System32\\cmd.exe",
            ),
        ]
        fz = OptcEcarFeaturizer("windows-sysmon", vocab, "kltn-windows-1")
        rows = []
        for idx, ev in enumerate(events):
            rows.extend(fz.feed(ev, ref=f"r-{idx}"))
        X_ep = fz.matrix(rows)

        feats = extract_stream_features(events, adapt_external=True)
        self.assertEqual(len(rows), len(feats))
        for i, feat in enumerate(feats):
            expected_cols = sorted({vocab[t] for t in feat.ml_tokens if t in vocab})
            self.assertEqual(X_ep[i].indices.tolist(), expected_cols)


if __name__ == "__main__":
    unittest.main()
