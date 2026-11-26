#!/usr/bin/env python3
"""Focused regression tests for THEIA labeling, exclusions, directionality, and OpTC vocab alignment."""

from __future__ import annotations

from pathlib import Path
import sys
import tarfile
import io
import csv
import json
import unittest

PREPROCESS_DIR = Path(__file__).resolve().parents[1] / "preprocess"
PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PREPROCESS_DIR))

from theia_schema import (
    EDGE_REVERSED_OPS,
    SCENARIO_NAMES,
    STAGE_NAMES,
    classify_path_dir,
    ip_scope,
    is_os_shared_library,
    port_class,
)
from theia_stage_mapper import TheiaGroundTruthResolver


class TestTheiaLabelingAndSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tar_path = PROJECT_ROOT / "DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3/theia_edge_labels.tar.gz"
        cls.csv_path = PROJECT_ROOT / "DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3/theia_labels.csv"
        cls.resolver = TheiaGroundTruthResolver(cls.tar_path, cls.csv_path)

    def test_scenario_and_stage_schema(self) -> None:
        self.assertEqual(set(SCENARIO_NAMES.keys()), {0, 1, 2})
        self.assertEqual(set(STAGE_NAMES.keys()), {0, 1, 2, 3, 4})
        self.assertIn("EVENT_OPEN", EDGE_REVERSED_OPS)
        self.assertIn("EVENT_RECVFROM", EDGE_REVERSED_OPS)
        self.assertNotIn("EVENT_CONNECT", EDGE_REVERSED_OPS)
        self.assertNotIn("EVENT_CLONE", EDGE_REVERSED_OPS)

    def test_fail_and_contaminated_exclusions(self) -> None:
        # Both contaminated edges overlapping fail + success must be excluded, never labeled 1 or 0
        contam_uuids = {
            "6E78BB15-00BE-2415-2964-620200000010",
            "F773529B-4EBE-2415-46F6-620200000010",
        }
        for u in contam_uuids:
            self.assertIn(u, self.resolver.excluded_edge_uuids)
            self.assertNotIn(u, self.resolver.included_edge_scenario)

        # Sample one edge from each excluded fail chain directly from REAPr archive
        fail_samples = {}
        with tarfile.open(self.tar_path, "r:gz") as tf:
            raw = tf.extractfile("edge_labels.csv").read().decode("utf-8", errors="ignore")
            for row in csv.DictReader(io.StringIO(raw)):
                c = {k.strip(): (v or "").strip() for k, v in row.items() if k is not None}
                ch = c["attack_chain"]
                if ch.endswith("_fail") or "_fail_" in ch:
                    fail_samples.setdefault(ch, c["edge_uuid"])
        self.assertEqual(len(fail_samples), 4)
        for ch, euuid in fail_samples.items():
            self.assertIn(euuid, self.resolver.excluded_edge_uuids, msg=f"Missing fail chain {ch}")
            self.assertNotIn(euuid, self.resolver.included_edge_scenario)

        # Common Threat 4.6 phishing IP must be excluded
        self.assertEqual(
            self.resolver.get_exclusion_reason("unlabeled-edge", 1, 2, "/bin/bash", "", "128.55.12.110", "208.75.117.3"),
            "common_threat_4_6",
        )

    def test_os_shared_library_vs_attacker_memtrace(self) -> None:
        self.assertTrue(is_os_shared_library("/etc/ld.so.cache"))
        self.assertTrue(is_os_shared_library("/lib/x86_64-linux-gnu/libc-2.15.so"))
        self.assertTrue(is_os_shared_library("/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.22"))
        # Must NOT exclude attacker shared object payload `/tmp/memtrace.so`
        self.assertFalse(is_os_shared_library("/tmp/memtrace.so"))
        self.assertEqual(
            self.resolver.get_exclusion_reason("clean-edge", 1, 2, "/var/log/mail", "/lib/x86_64-linux-gnu/libc-2.15.so"),
            "os_shared_lib_noise",
        )
        self.assertIsNone(
            self.resolver.get_exclusion_reason("clean-edge", 1, 2, "/etc/firefox/native-messaging-hosts/gtcache", "/tmp/memtrace.so")
        )

    def test_stage_resolution_on_clean_success_patterns(self) -> None:
        s33_uuid = next(u for u, s in self.resolver.included_edge_scenario.items() if s == 1)
        s311_uuid = next(u for u, s in self.resolver.included_edge_scenario.items() if s == 2)

        # Initial compromise delivery & extension launch
        self.assertEqual(self.resolver.resolve_3heads(s33_uuid, "EVENT_RECVFROM", "/usr/bin/fluxbox", "", "128.55.12.110", "141.43.176.203"), (1, 1, 1))
        self.assertEqual(self.resolver.resolve_3heads(s311_uuid, "EVENT_EXECUTE", "/home/admin/Downloads/firefox/firefox", "/etc/firefox/native-messaging-hosts/pass_mgr"), (1, 2, 1))
        # Execution & Privilege Escalation
        self.assertEqual(self.resolver.resolve_3heads(s33_uuid, "EVENT_WRITE", "/home/admin/Downloads/firefox/firefox", "/dev/glx_alsa_675"), (1, 1, 2))
        self.assertEqual(self.resolver.resolve_3heads(s311_uuid, "EVENT_WRITE", "/etc/firefox/native-messaging-hosts/gtcache", "/tmp/memtrace.so"), (1, 2, 2))
        # Discovery & Reconnaissance
        self.assertEqual(self.resolver.resolve_3heads(s311_uuid, "EVENT_CONNECT", "/var/log/mail", "", "128.55.12.110", "NA"), (1, 2, 3))
        self.assertEqual(self.resolver.resolve_3heads(s33_uuid, "EVENT_READ", "/home/admin/profile (deleted)", "/etc/passwd"), (1, 1, 3))
        # C2 Communication
        self.assertEqual(self.resolver.resolve_3heads(s33_uuid, "EVENT_SENDTO", "/home/admin/profile (deleted)", "", "128.55.12.110", "161.116.88.72"), (1, 1, 4))
        self.assertEqual(self.resolver.resolve_3heads(s311_uuid, "EVENT_RECVFROM", "/var/log/mail", "", "128.55.12.110", "149.52.198.23"), (1, 2, 4))

    def test_optc_token_compatibility(self) -> None:
        vocab_path = PROJECT_ROOT / "DL/code/output/dl_vocab.json"
        if not vocab_path.is_file():
            self.skipTest("dl_vocab.json not present")
        with vocab_path.open("r", encoding="utf-8") as f:
            v = json.load(f)
        self.assertIn(f"net::dest_scope={ip_scope('141.43.176.203')}", v)
        self.assertIn(f"net::dest_scope={ip_scope('128.55.12.110')}", v)
        self.assertIn(f"net::dest_scope={ip_scope('NA')}", v)
        self.assertIn(f"net::dest_port_role={port_class(80)}", v)
        self.assertIn(f"net::dest_port_role={port_class(22)}", v)
        self.assertIn(f"image_path::category={classify_path_dir('/usr/bin/firefox')}", v)
        self.assertIn(f"image_path::category={classify_path_dir('/home/admin/profile')}", v)


if __name__ == "__main__":
    unittest.main()
