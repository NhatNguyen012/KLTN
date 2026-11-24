#!/usr/bin/env python3
"""Unit and Integration Tests for Decoupled Sidecar Multi-Task Labeling."""

import gzip
import json
import os
import sys
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from DATASET.Preprocess.generate_multitask_labels import generate_multitask_labels, classify_event_semantics
from DATASET.Preprocess.label_catalog import MultiTaskLabelCatalog, SCENARIO_MAP, STAGE_MAP


class TestMultiTaskLabeling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gt_path = PROJECT_ROOT / "DATASET/DARPA-OPTC/a_new_hope_for_darpa_optc/labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz"
        cls.output_dir = PROJECT_ROOT / "DATASET/Preprocess/output"
        cls.catalog_file = cls.output_dir / "optc_multitask_labels_v1.json.gz"
        
        # Generate catalog if it doesn't exist
        if not cls.catalog_file.exists():
            generate_multitask_labels(cls.gt_path, cls.output_dir, version="v1")
        cls.catalog = MultiTaskLabelCatalog(cls.catalog_file)

    def test_catalog_size_and_loading(self):
        self.assertEqual(len(self.catalog), 360567, "Should load exactly 360,567 malicious events")

    def test_benign_event_defaults(self):
        # Unseen event id must default to 0, 0, 0
        is_mal, sc_id, st_id = self.catalog.lookup("non-existent-uuid")
        self.assertEqual(is_mal, 0)
        self.assertEqual(sc_id, 0)
        self.assertEqual(st_id, 0)

        is_mal, sc_id, st_id = self.catalog.lookup(None)
        self.assertEqual(is_mal, 0)
        self.assertEqual(sc_id, 0)
        self.assertEqual(st_id, 0)

    def test_semantic_mapping_rules(self):
        # 1. Thread Remote Create -> Stage 2 (Defense Evasion / Injection)
        ev_inj = {
            "timestamp": "2019-09-23T14:44:53.000-04:00",
            "hostname": "sysclient0104",
            "object": "THREAD",
            "action": "REMOTE_CREATE",
            "properties": {"image_path": "powershell.exe"}
        }
        sc, st = classify_event_semantics(ev_inj)
        self.assertEqual(sc, 1, "Day 23 should be SC1")
        self.assertEqual(st, 2, "Remote create should be Defense_Evasion_Injection")

        # 2. Ping sweep -> Stage 4 (Discovery)
        ev_ping = {
            "timestamp": "2019-09-23T13:15:48.000-04:00",
            "hostname": "sysclient0201",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "C:\\Windows\\System32\\ping.exe", "command_line": "ping 142.20.56.1"}
        }
        sc, st = classify_event_semantics(ev_ping)
        self.assertEqual(sc, 1)
        self.assertEqual(st, 4, "ping.exe should be Discovery")

        # 3. RDP Lateral Movement -> Stage 6 (Lateral Movement)
        ev_rdp = {
            "timestamp": "2019-09-24T13:46:00.000-04:00",
            "hostname": "sysclient0501",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "C:\\Windows\\System32\\mstsc.exe"}
        }
        sc, st = classify_event_semantics(ev_rdp)
        self.assertEqual(sc, 2, "Day 24 should be SC2")
        self.assertEqual(st, 6, "mstsc.exe should be Lateral_Movement")

        # 4. Net user admin /add -> Stage 7 (Persistence)
        ev_admin = {
            "timestamp": "2019-09-25T11:07:41.000-04:00",
            "hostname": "sysclient0051",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"command_line": "net user admin supersecret /add"}
        }
        sc, st = classify_event_semantics(ev_admin)
        self.assertEqual(sc, 3, "Day 25 on sysclient0051 should be SC3")
        self.assertEqual(st, 7, "net user admin should be Persistence")


if __name__ == "__main__":
    unittest.main()
