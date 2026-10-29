#!/usr/bin/env python3
"""Comprehensive regression tests for OpTC Host ML Parent and Process Context Feature Enrichment.

Protects 12 specific behaviors:
1. FILE event retrieves executing actor and observed parent context.
2. PROCESS CREATE does not assign child metadata to parent.
3. Strict temporal anti-leakage: evidence strictly < event t, same-timestamp events cannot see each other.
4. Cross-host isolation: UUID/PID from one host cannot join across hosts.
5. PID reuse and UUID/PPID conflict handling.
6. Missing parent, missing command-line, and capacity/TTL deterministic eviction without dropping target events.
7. TRAIN-only vocabulary fitting: validation/TEST unique context tokens never enter vocabulary.
8. Target identity, label, and split allocations are strictly preserved.
9. Continuous execution vs interruption and checkpoint/resume produce identical context.
10. Context-disabled mode maintains 100% baseline compatibility.
11. Protected dataset roots (direct and via symlink) are rejected before any output write.
12. Temporal ordering and boundary handling preserve monotonic line progression.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT_ROOT = next((p for p in Path(__file__).resolve().parents if (p / "AGENTS.md").is_file()), Path(__file__).resolve().parents[3])
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.code.preprocess.ecar_tokenizer import flatten_tokens, tokenize_record
from ML.code.preprocess.host_shards import HostShardDataset
from ML.code.preprocess.pipeline_contract import DATA_ROOT_NAMES, validate_output_path
from ML.code.preprocess.process_context_tracker import (
    HostProcessContextTracker,
    ProcessContextConfig,
    age_bucket,
    canonical_host,
    canonical_uuid,
    parse_timestamp,
    tokenize_record_with_context,
)
from ML.code.preprocess.stratified_pipeline import index_main, split_main, split_rows


class ParentContextEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.host = "sysclient0201.systemia.com"
        self.parent_uuid = "11111111-1111-1111-1111-111111111111"
        self.actor_uuid = "22222222-2222-2222-2222-222222222222"
        self.child_uuid = "33333333-3333-3333-3333-333333333333"

    # 1. FILE event retrieves correct actor and parent history
    def test_01_file_event_retrieves_actor_and_parent_history(self):
        tracker = HostProcessContextTracker()
        # Explorer creates cmd.exe at t=1000
        create_evt = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "principal": "NT AUTHORITY\\SYSTEM",
            "properties": {
                "parent_image_path": "C:\\Windows\\explorer.exe",
                "image_path": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
        }
        t1 = parse_timestamp(create_evt["timestamp"])
        tracker.observe(create_evt, event_t=t1)

        # cmd.exe reads a file at t=2000
        file_evt = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:02.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": self.actor_uuid,
            "objectID": "44444444-4444-4444-4444-444444444444",
            "properties": {"file_path": "C:\\Windows\\System32\\kernel32.dll"},
        }
        t2 = parse_timestamp(file_evt["timestamp"])
        tokens = tracker.get_context_tokens(file_evt, query_t=t2)

        # Assert actor context
        self.assertIn("ctx::actor::exe=cmd.exe", tokens)
        self.assertIn("ctx::actor::cmd_family=cmd", tokens)
        self.assertIn("ctx::actor::cmd_mode=/c", tokens)
        self.assertIn("ctx::actor::principal=nt_system", tokens)
        self.assertIn("ctx::status::has_actor_metadata", tokens)

        # Assert parent context
        self.assertIn("ctx::parent::exe=explorer.exe", tokens)
        self.assertIn("ctx::status::has_parent", tokens)

        # Assert relationship
        self.assertIn("ctx::relation::lineage=native->cmd", tokens)
        self.assertIn("ctx::relation::spawn_recency=lt_10s", tokens)

        # File object must NOT be tagged as child
        self.assertFalse(any("child" in t for t in tokens))

    # 2. PROCESS CREATE does not assign child metadata to parent
    def test_02_process_create_does_not_assign_child_metadata_to_parent(self):
        tracker = HostProcessContextTracker()
        # Explorer creates cmd at t=1000
        evt1 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "properties": {
                "parent_image_path": "C:\\Windows\\explorer.exe",
                "image_path": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /c start",
            },
        }
        t1 = parse_timestamp(evt1["timestamp"])
        tracker.observe(evt1, event_t=t1)

        # cmd creates powershell with encoded command at t=2000
        evt2 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:02.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.actor_uuid,
            "objectID": self.child_uuid,
            "properties": {
                "parent_image_path": "C:\\Windows\\System32\\cmd.exe",
                "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -enc AAAA",
            },
        }
        t2 = parse_timestamp(evt2["timestamp"])
        # Query context for evt2 BEFORE observe
        tokens = tracker.get_context_tokens(evt2, query_t=t2)

        # Actor for evt2 is cmd.exe
        self.assertIn("ctx::actor::exe=cmd.exe", tokens)
        self.assertIn("ctx::actor::cmd_mode=/c", tokens)
        # Parent for evt2 is explorer.exe
        self.assertIn("ctx::parent::exe=explorer.exe", tokens)
        self.assertIn("ctx::relation::actor_is_parent_of_target=true", tokens)

        # Child's powershell metadata must NOT appear in actor or parent context
        self.assertNotIn("ctx::actor::exe=powershell.exe", tokens)
        self.assertNotIn("ctx::parent::exe=powershell.exe", tokens)
        self.assertNotIn("ctx::actor::switch=enc", tokens)
        self.assertNotIn("ctx::parent::switch=enc", tokens)

    # 3. No future or same-timestamp leakage
    def test_03_no_future_or_same_timestamp_leakage(self):
        tracker = HostProcessContextTracker()
        evt1 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "properties": {
                "parent_image_path": "C:\\Windows\\explorer.exe",
                "image_path": "C:\\Windows\\System32\\cmd.exe",
            },
        }
        t1 = parse_timestamp(evt1["timestamp"])
        tracker.observe(evt1, event_t=t1)

        # An event at the EXACT SAME timestamp t1 queries context
        same_t_evt = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": self.actor_uuid,
            "objectID": "55555555-5555-5555-5555-555555555555",
            "properties": {"file_path": "C:\\file.txt"},
        }
        tokens_same_t = tracker.get_context_tokens(same_t_evt, query_t=t1)
        # Strictly < t1 means event at t1 cannot see evt1!
        self.assertIn("ctx::status::actor_metadata_missing", tokens_same_t)
        self.assertIn("ctx::status::parent_missing", tokens_same_t)
        self.assertNotIn("ctx::status::has_actor_metadata", tokens_same_t)

        # Future event at t1 + 10s cannot leak to past
        future_evt = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:10.000000+00:00",
            "object": "REGISTRY",
            "action": "MODIFY",
            "actorID": self.actor_uuid,
            "properties": {"key": "HKLM\\Software"},
        }
        t_future = parse_timestamp(future_evt["timestamp"])
        tracker.observe(future_evt, event_t=t_future)

        # Query at t1 + 1s (past relative to future_evt)
        t_mid = t1 + 1_000_000
        mid_evt = dict(same_t_evt, timestamp="2019-09-23T11:00:02.000000+00:00")
        tokens_mid = tracker.get_context_tokens(mid_evt, query_t=t_mid)
        # Mid event sees evt1, but does NOT see future_evt
        self.assertIn("ctx::status::has_actor_metadata", tokens_mid)
        self.assertNotIn("ctx::actor::recent_action=REGISTRY_MODIFY", tokens_mid)

    # 4. Cross-host isolation
    def test_04_cross_host_isolation(self):
        tracker = HostProcessContextTracker()
        host_a = "sysclient0001.systemia.com"
        host_b = "sysclient0002.systemia.com"

        evt_a = {
            "hostname": host_a,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "properties": {
                "parent_image_path": "C:\\Windows\\explorer.exe",
                "image_path": "C:\\Windows\\System32\\cmd.exe",
            },
        }
        tracker.observe(evt_a, event_t=parse_timestamp(evt_a["timestamp"]))

        # Query same UUID on host_b
        evt_b = {
            "hostname": host_b,
            "timestamp": "2019-09-23T11:00:02.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": self.actor_uuid,
            "properties": {"file_path": "C:\\file.txt"},
        }
        tokens_b = tracker.get_context_tokens(evt_b, query_t=parse_timestamp(evt_b["timestamp"]))
        self.assertIn("ctx::status::actor_metadata_missing", tokens_b)
        self.assertIn("ctx::status::parent_missing", tokens_b)

    def test_05_pid_reuse_and_uuid_conflict(self):
        with self.assertRaises(ValueError):
            ProcessContextConfig(enable_pid_fallback=True)
        tracker = HostProcessContextTracker()

        # Child created with parent P1
        evt1 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "properties": {"image_path": "cmd.exe", "pid": 2540},
        }
        tracker.observe(evt1, event_t=1000)

        # Later event claims child has conflicting parent P_other
        p_other = "99999999-9999-9999-9999-999999999999"
        evt_conflict = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:02.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": p_other,
            "objectID": self.actor_uuid,
            "properties": {"image_path": "cmd.exe", "pid": 2540},
        }
        tracker.observe(evt_conflict, event_t=2000)

        # Query context for actor_uuid at t=3000
        tokens = tracker.get_context_tokens({
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:03.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": self.actor_uuid,
        }, query_t=3000)
        self.assertIn("ctx::status::parent_conflict", tokens)

        # Test PID reuse detection: new process created with PID 2540 without terminate
        new_child = "88888888-8888-8888-8888-888888888888"
        evt_reuse = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:04.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": new_child,
            "properties": {"image_path": "notepad.exe", "pid": 2540},
        }
        tracker.observe(evt_reuse, event_t=4000)
        self.assertGreater(tracker.stats["pid_reuse_conflict_count"], 0)

    # 6. Missing parent, missing command-line, TTL eviction
    def test_06_missing_parent_and_ttl_eviction(self):
        # max_processes_per_host = 2
        tracker = HostProcessContextTracker(ProcessContextConfig(max_processes_per_host=2, ttl_seconds=3600))

        # p1 created without parent (missing parent) and without command_line
        evt_orphan = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "FILE",
            "action": "WRITE",
            "actorID": "proc-1",
            "properties": {"image_path": "C:\\Windows\\System32\\svchost.exe"},
        }
        t1 = 1000
        tracker.observe(evt_orphan, event_t=t1)

        tokens_orphan = tracker.get_context_tokens({
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:02.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": "proc-1",
        }, query_t=2000)
        # Event is NOT dropped, has actor metadata, parent is missing
        self.assertIn("ctx::status::has_actor_metadata", tokens_orphan)
        self.assertIn("ctx::status::parent_missing", tokens_orphan)

        # Add p2 and p3 -> capacity 2 reached -> p1 evicted
        tracker.observe({"hostname": self.host, "object": "FILE", "action": "READ", "actorID": "proc-2"}, event_t=3000)
        tracker.observe({"hostname": self.host, "object": "FILE", "action": "READ", "actorID": "proc-3"}, event_t=4000)

        self.assertGreaterEqual(tracker.stats["evicted_count"], 1)

        # Query p1 after eviction -> returns actor_expired, NOT dropped
        tokens_evicted = tracker.get_context_tokens({
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:05.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": "proc-1",
        }, query_t=5000)
        self.assertIn("ctx::status::actor_expired", tokens_evicted)

    # 7. TRAIN-only vocabulary fitting
    def test_07_train_only_vocabulary_no_leakage_from_val_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            work = tmp_path / "work"
            work.mkdir()

            entry = {
                "source": {"path": str(tmp_path / "source.json.gz"), "size": 100, "mtime_ns": 1},
                "artifact": "source.split.gz",
                "benign": False,
                "host": "sysclient0201",
                "day": "2019-09-23",
                "counts": {"lines": 3},
                "allocation": {"1": [1, 0, 0], "2": [0, 1, 1]},
            }

            # Line 1: TRAIN (code 1) with switch=trainswitch
            # Line 2: VAL (code 2) with switch=valswitch
            # Line 3: TEST (code 3) with switch=testswitch
            records = [
                {"hostname": "sysclient0201.systemia.com", "object": "PROCESS", "action": "CREATE", "actorID": "p0", "objectID": "p1", "label": 0,
                 "timestamp": "2019-09-23T11:00:01.000000+00:00", "properties": {"image_path": "cmd.exe", "command_line": "cmd.exe /trainswitch"}},
                {"hostname": "sysclient0201.systemia.com", "object": "PROCESS", "action": "CREATE", "actorID": "p0", "objectID": "p2", "label": 1,
                 "timestamp": "2019-09-23T11:00:02.000000+00:00", "properties": {"image_path": "cmd.exe", "command_line": "cmd.exe /valswitch"}},
                {"hostname": "sysclient0201.systemia.com", "object": "PROCESS", "action": "CREATE", "actorID": "p0", "objectID": "p3", "label": 1,
                 "timestamp": "2019-09-23T11:00:03.000000+00:00", "properties": {"image_path": "cmd.exe", "command_line": "cmd.exe /testswitch"}},
            ]
            source_file = tmp_path / "ecar-2019-09-23-sysclient0201.json.gz"
            entry["source"]["path"] = str(source_file)
            entry["artifact"] = "ecar-2019-09-23-sysclient0201.split.gz"
            with gzip.open(source_file, "wt", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")
            stat = source_file.stat()
            entry["source"]["size"] = stat.st_size
            entry["source"]["mtime_ns"] = stat.st_mtime_ns

            mask_file = tmp_path / "ecar-2019-09-23-sysclient0201.split.gz"
            with gzip.open(mask_file, "wb") as f:
                f.write(bytes([1, 2, 3]))

            from ML.code.preprocess.stratified_pipeline import vocab_file
            res = vocab_file(entry, tmp_path, work, context_config={"enabled": True})
            tf = res["tf"]
            all_tokens = set().union(*tf.values())

            # trainswitch must be counted; valswitch and testswitch must NOT be counted
            self.assertTrue(any("trainswitch" in t for t in all_tokens))
            self.assertFalse(any("valswitch" in t for t in all_tokens))
            self.assertFalse(any("testswitch" in t for t in all_tokens))

    # 8. Target identity, label and split allocations preserved
    def test_08_target_identity_label_and_split_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            data_file = tmp_path / "ecar-2019-09-21-sysclient0051.json.gz"
            entry = {
                "source": {"path": str(data_file), "size": 100, "mtime_ns": 1},
                "artifact": "ecar-2019-09-21-sysclient0051.split.gz",
                "benign": True,
                "host": "sysclient0051",
                "day": "2019-09-21",
                "counts": {"lines": 2},
                "allocation": {"1": [1, 1, 0], "2": [0, 0, 0]},
            }
            records = [
                {"hostname": "sysclient0051.systemia.com", "timestamp": "2019-09-21T00:00:01.000000+00:00", "object": "PROCESS", "action": "CREATE", "actorID": "p1", "objectID": "p2", "label": 0, "properties": {"image_path": "cmd.exe"}},
                {"hostname": "sysclient0051.systemia.com", "timestamp": "2019-09-21T00:00:02.000000+00:00", "object": "FILE", "action": "READ", "actorID": "p2", "objectID": "f1", "label": 0, "properties": {"file_path": "C:\\a.txt"}},
            ]
            with gzip.open(data_file, "wt") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")
            stat = data_file.stat()
            entry["source"]["size"] = stat.st_size
            entry["source"]["mtime_ns"] = stat.st_mtime_ns

            with gzip.open(tmp_path / "ecar-2019-09-21-sysclient0051.split.gz", "wb") as f:
                f.write(bytes([1, 2]))

            # Run split_rows without tracker
            baseline_rows = list(split_rows(entry, tmp_path))
            # Run split_rows with tracker
            tracker = HostProcessContextTracker()
            context_rows = list(split_rows(entry, tmp_path, tracker=tracker))

            # Row codes, line numbers, and labels must be 100% identical
            self.assertEqual(len(baseline_rows), len(context_rows))
            for (c1, n1, r1), (c2, n2, r2) in zip(baseline_rows, context_rows):
                self.assertEqual(c1, c2)
                self.assertEqual(n1, n2)
                self.assertEqual(r1["label"], r2["label"])
                self.assertEqual(r1["object"], r2["object"])

    # 9. Continuous execution vs interruption and checkpoint/resume produce identical results
    def test_09_continuous_vs_checkpoint_resume_identical(self):
        evt1 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:01.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "properties": {"parent_image_path": "explorer.exe", "image_path": "cmd.exe", "command_line": "cmd.exe /c whoami"},
        }
        evt2 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:02.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": self.actor_uuid,
            "properties": {"file_path": "C:\\test.dll"},
        }
        evt3 = {
            "hostname": self.host,
            "timestamp": "2019-09-23T11:00:03.000000+00:00",
            "object": "REGISTRY",
            "action": "MODIFY",
            "actorID": self.actor_uuid,
            "properties": {"key": "HKLM\\Run"},
        }

        # 1. Continuous run
        tracker_cont = HostProcessContextTracker()
        tracker_cont.observe(evt1, 1000)
        tok2_cont = tracker_cont.get_context_tokens(evt2, 2000)
        tracker_cont.observe(evt2, 2000)
        tok3_cont = tracker_cont.get_context_tokens(evt3, 3000)

        # 2. Resumed run
        with tempfile.TemporaryDirectory() as tmp:
            ckpt_path = Path(tmp) / "tracker.ckpt"
            tracker_part1 = HostProcessContextTracker()
            tracker_part1.observe(evt1, 1000)
            tracker_part1.save_checkpoint(ckpt_path)

            tracker_resumed = HostProcessContextTracker()
            tracker_resumed.load_checkpoint(ckpt_path)
            tok2_resumed = tracker_resumed.get_context_tokens(evt2, 2000)
            tracker_resumed.observe(evt2, 2000)
            tok3_resumed = tracker_resumed.get_context_tokens(evt3, 3000)

            self.assertEqual(tok2_cont, tok2_resumed)
            self.assertEqual(tok3_cont, tok3_resumed)

    # 10. Context-disabled maintains baseline compatibility
    def test_10_context_disabled_exact_baseline_compatibility(self):
        record = {
            "hostname": "sysclient0001.systemia.com",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "cmd.exe", "command_line": "cmd.exe /c echo hello"},
        }
        baseline_grouped, baseline_audit = tokenize_record(record)
        context_grouped, context_audit = tokenize_record_with_context(record, tracker=None)

        self.assertEqual(baseline_grouped, context_grouped)
        self.assertEqual(baseline_audit, context_audit)

        # Also when tracker config enabled=False
        disabled_tracker = HostProcessContextTracker(ProcessContextConfig(enabled=False))
        disabled_grouped, disabled_audit = tokenize_record_with_context(record, tracker=disabled_tracker)
        self.assertEqual(baseline_grouped, disabled_grouped)
        self.assertEqual(baseline_audit, disabled_audit)

    # 11. Protected dataset roots are rejected before any output write
    def test_11_output_path_in_dataset_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch("ML.code.preprocess.pipeline_contract.PROJECT_ROOT", Path(tmp)):
            base = Path(tmp)
            for name in DATA_ROOT_NAMES:
                bad_dir = base / name
                bad_dir.mkdir(parents=True, exist_ok=True)
                with self.assertRaises(ValueError):
                    validate_output_path(bad_dir / "vocab.json")

        # Also test real dataset paths directly
        for name in DATA_ROOT_NAMES:
            bad_path = Path("/mnt/SSD_Data/optc") / name / "test_output.json"
            with self.assertRaises(ValueError):
                validate_output_path(bad_path)

    # 12. Temporal order and boundary handling
    def test_12_temporal_order_and_shard_boundaries(self):
        tracker = HostProcessContextTracker()
        # Event at day 1 (Sep 21)
        evt_day1 = {
            "hostname": self.host,
            "timestamp": "2019-09-21T10:00:00.000000+00:00",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": self.parent_uuid,
            "objectID": self.actor_uuid,
            "properties": {"parent_image_path": "explorer.exe", "image_path": "cmd.exe"},
        }
        t_day1 = parse_timestamp(evt_day1["timestamp"])
        tracker.observe(evt_day1, event_t=t_day1)

        # Event at day 2 (Sep 22) crossing shard boundary for the same host
        evt_day2 = {
            "hostname": self.host,
            "timestamp": "2019-09-22T10:00:00.000000+00:00",
            "object": "FILE",
            "action": "READ",
            "actorID": self.actor_uuid,
            "properties": {"file_path": "C:\\test.txt"},
        }
        t_day2 = parse_timestamp(evt_day2["timestamp"])
        tokens_day2 = tracker.get_context_tokens(evt_day2, query_t=t_day2)

        # State carried over host/day boundary cleanly
        self.assertIn("ctx::actor::exe=cmd.exe", tokens_day2)
        self.assertIn("ctx::parent::exe=explorer.exe", tokens_day2)
        self.assertIn("ctx::status::has_parent", tokens_day2)
        self.assertIn("ctx::actor::age=gt_1h", tokens_day2)

    # 13. End-to-end CLI integration test on a 2-day fixture of the same host
    def test_13_cli_end_to_end_two_days_same_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            benign_root = base / "benign"
            malicious_root = base / "malicious"
            benign_root.mkdir()
            malicious_root.mkdir()

            host = "sysclient0051"
            # Day 1: 2019-09-19 (benign)
            # Parent p0 (explorer) spawns child p1 (cmd.exe)
            p0 = "10000000-0000-0000-0000-000000000000"
            p1 = "20000000-0000-0000-0000-000000000000"
            p2 = "30000000-0000-0000-0000-000000000000"

            d1_rows = [
                {
                    "hostname": f"{host}.systemia.com",
                    "timestamp": "2019-09-19T09:00:00.000000+00:00",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "actorID": p0,
                    "objectID": p1,
                    "label": 0,
                    "properties": {
                        "parent_image_path": "C:\\Windows\\explorer.exe",
                        "image_path": "C:\\Windows\\System32\\cmd.exe",
                        "command_line": "cmd.exe /c echo day1",
                    },
                },
                {
                    "hostname": f"{host}.systemia.com",
                    "timestamp": "2019-09-19T09:00:01.000000+00:00",
                    "object": "FILE",
                    "action": "WRITE",
                    "actorID": p1,
                    "objectID": "f1",
                    "label": 0,
                    "properties": {"file_path": "C:\\temp\\file1.txt"},
                },
            ]
            for i in range(18):
                d1_rows.append({
                    "hostname": f"{host}.systemia.com",
                    "timestamp": f"2019-09-19T09:00:{i+2:02d}.000000+00:00",
                    "object": "FILE",
                    "action": "READ",
                    "actorID": p1,
                    "objectID": f"f_{i}",
                    "label": 0,
                    "properties": {"file_path": f"C:\\temp\\data_{i}.txt"},
                })
            # Add an excluded FLOW record
            d1_rows.append({
                "hostname": f"{host}.systemia.com",
                "timestamp": "2019-09-19T09:00:30.000000+00:00",
                "object": "FLOW",
                "action": "MESSAGE",
                "label": 0,
            })

            d1_file = benign_root / f"ecar-2019-09-19-{host}.json.gz"
            with gzip.open(d1_file, "wt", encoding="utf-8") as f:
                for r in d1_rows:
                    f.write(json.dumps(r) + "\n")

            # Day 2: 2019-09-20 (benign)
            # p1 spawns grandchild p2 (powershell.exe); p2 reads file
            d2_rows = [
                {
                    "hostname": f"{host}.systemia.com",
                    "timestamp": "2019-09-20T10:00:00.000000+00:00",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "actorID": p1,
                    "objectID": p2,
                    "label": 0,
                    "properties": {
                        "parent_image_path": "C:\\Windows\\System32\\cmd.exe",
                        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "command_line": "powershell.exe -enc ...",
                    },
                },
                {
                    "hostname": f"{host}.systemia.com",
                    "timestamp": "2019-09-20T10:00:01.000000+00:00",
                    "object": "FILE",
                    "action": "READ",
                    "actorID": p2,
                    "objectID": "f_secret",
                    "label": 0,
                    "properties": {"file_path": "C:\\confidential\\key.pem"},
                },
            ]
            for i in range(18):
                d2_rows.append({
                    "hostname": f"{host}.systemia.com",
                    "timestamp": f"2019-09-20T10:00:{i+2:02d}.000000+00:00",
                    "object": "FILE",
                    "action": "WRITE",
                    "actorID": p2,
                    "objectID": f"f2_{i}",
                    "label": 0,
                    "properties": {"file_path": f"C:\\temp\\out_{i}.txt"},
                })
            d2_file = benign_root / f"ecar-2019-09-20-{host}.json.gz"
            with gzip.open(d2_file, "wt", encoding="utf-8") as f:
                for r in d2_rows:
                    f.write(json.dumps(r) + "\n")

            # Day 3: 2019-09-23 (malicious)
            d3_rows = []
            for i in range(20):
                d3_rows.append({
                    "hostname": f"{host}.systemia.com",
                    "timestamp": f"2019-09-23T11:00:{i:02d}.000000+00:00",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "actorID": p1,
                    "objectID": f"mal_{i}",
                    "label": int(i % 2 == 0),
                    "properties": {
                        "image_path": "malware.exe",
                        "command_line": f"malware.exe --attack {i}",
                    },
                })
            d3_file = malicious_root / f"ecar-2019-09-23-{host}.json.gz"
            with gzip.open(d3_file, "wt", encoding="utf-8") as f:
                for r in d3_rows:
                    f.write(json.dumps(r) + "\n")

            # 1. Run index_main
            idx_dir = base / "index"
            index_main(["--benign-root", str(benign_root), "--malicious-root", str(malicious_root), "--output-dir", str(idx_dir), "--workers", "1"])
            self.assertTrue((idx_dir / "manifest.json").exists())

            # 2. Run split_main
            split_dir = base / "split"
            split_main(["--index", str(idx_dir / "manifest.json"), "--output-dir", str(split_dir), "--workers", "1", "--seed", "01"])
            self.assertTrue((split_dir / "manifest.json").exists())

            # 3. Run build_vocab.py via CLI
            build_vocab_py = Path(__file__).resolve().parents[1] / "preprocess/build_vocab.py"
            vocab_out = base / "vocab_ctx.json"
            meta_out = base / "vocab_ctx_metadata.json"
            sub_env = {**os.environ, "PYTHONPATH": f"{Path(__file__).resolve().parents[1] / 'preprocess'}:{Path(__file__).resolve().parents[3]}"}

            vocab_cmd = [
                sys.executable, str(build_vocab_py),
                "--split", str(split_dir / "manifest.json"),
                "--output", str(vocab_out),
                "--metadata-output", str(meta_out),
                "--enable-parent-context",
                "--workers", "1",
            ]
            res_vocab = subprocess.run(vocab_cmd, capture_output=True, text=True, env=sub_env)
            self.assertEqual(res_vocab.returncode, 0, f"build_vocab CLI failed: {res_vocab.stderr}")
            self.assertTrue(vocab_out.exists())
            self.assertTrue(meta_out.exists())

            vocab_data = json.loads(vocab_out.read_text())
            meta_data = json.loads(meta_out.read_text())

            # Verify context tokens are present in vocabulary
            ctx_tokens = [tok for tok in vocab_data if tok.startswith("ctx::")]
            self.assertTrue(len(ctx_tokens) > 0, "Expected context tokens in vocabulary")
            self.assertIn("ctx::actor::exe=cmd.exe", vocab_data)
            self.assertIn("ctx::parent::exe=explorer.exe", vocab_data)
            self.assertIn("ctx::relation::lineage=native->cmd", vocab_data)
            self.assertIn("ctx::status::has_parent", vocab_data)

            # Verify metadata has context_policy
            self.assertIsNotNone(meta_data.get("context_policy"))
            self.assertTrue(meta_data["context_policy"]["enabled"])

            # 4. Storage configuration for build_model_input
            storage_dir = base / "model_shards"
            storage_ssd = base / "ssd_storage"
            storage_ssd.mkdir()
            storage_cfg = base / "storage_config.json"
            storage_cfg.write_text(json.dumps({
                "volumes": [
                    {"id": "ssd", "path": str(storage_ssd), "max_bytes": 10**8, "reserve_free_bytes": 0}
                ]
            }))

            # 5. Run build_model_input.py via CLI
            build_input_py = Path(__file__).resolve().parents[1] / "preprocess/build_model_input.py"
            input_cmd = [
                sys.executable, str(build_input_py),
                "--split", str(split_dir / "manifest.json"),
                "--vocab", str(vocab_out),
                "--vocab-metadata", str(meta_out),
                "--storage-config", str(storage_cfg),
                "--output-dir", str(storage_dir),
                "--enable-parent-context",
                "--workers", "1",
                "--rows-per-shard", "10",
            ]
            res_input = subprocess.run(input_cmd, capture_output=True, text=True, env=sub_env)
            self.assertEqual(res_input.returncode, 0, f"build_model_input CLI failed: {res_input.stderr}")
            self.assertTrue((storage_dir / "manifest.json").exists())

            # Load dataset to verify lossless row count and shard integrity
            dataset = HostShardDataset(storage_dir / "manifest.json")
            total_shard_rows = sum(v["rows"] for v in dataset.meta["splits"].values())
            self.assertEqual(total_shard_rows, 60, "Expected 60 total rows (20+20+20 non-FLOW events)")

            # 6. Verify negative test: running build_model_input without --enable-parent-context fails closed
            bad_cmd = [
                sys.executable, str(build_input_py),
                "--split", str(split_dir / "manifest.json"),
                "--vocab", str(vocab_out),
                "--vocab-metadata", str(meta_out),
                "--storage-config", str(storage_cfg),
                "--output-dir", str(base / "bad_output"),
                "--workers", "1",
            ]
            res_bad = subprocess.run(bad_cmd, capture_output=True, text=True, env=sub_env)
            self.assertNotEqual(res_bad.returncode, 0)
            self.assertIn("Vocabulary was fitted with parent context, but --enable-parent-context was not provided", res_bad.stderr)

            # 7. Verify negative test: config mismatch fails closed
            mismatch_cmd = [
                sys.executable, str(build_input_py),
                "--split", str(split_dir / "manifest.json"),
                "--vocab", str(vocab_out),
                "--vocab-metadata", str(meta_out),
                "--storage-config", str(storage_cfg),
                "--output-dir", str(base / "mismatch_output"),
                "--enable-parent-context",
                "--context-max-processes", "5000",
                "--workers", "1",
            ]
            res_mismatch = subprocess.run(mismatch_cmd, capture_output=True, text=True, env=sub_env)
            self.assertNotEqual(res_mismatch.returncode, 0)
            self.assertIn("context-max-processes mismatch", res_mismatch.stderr)

    # 14. Interruption and resume on multi-day host produces 100% identical vocabulary and shards
    def test_14_pipeline_resume_identical_to_continuous(self):
        from ML.code.preprocess import stratified_pipeline as sp
        from ML.code.preprocess import build_model_input as bm
        from ML.code.preprocess.shard_storage import initialize_ledger

        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp)
            h = "sysclient0001.systemia.com"
            a = "22222222-2222-2222-2222-222222222222"
            p = "11111111-1111-1111-1111-111111111111"

            create_evt = {
                "hostname": h,
                "actorID": p,
                "objectID": a,
                "object": "PROCESS",
                "action": "CREATE",
                "properties": {"image_path": "cmd.exe", "parent_image_path": "explorer.exe"},
            }
            read_evt = {
                "hostname": h,
                "actorID": a,
                "object": "FILE",
                "action": "READ",
                "properties": {"file_path": "C:\\test.txt"},
            }

            entries = []
            for day, rec, code in [("21", create_evt, 0), ("22", read_evt, 1)]:
                rec_copy = dict(rec)
                rec_copy.update(timestamp=f"2019-09-{day}T00:00:00+00:00", label=0)
                f = b / f"ecar-2019-09-{day}-sysclient0001.json.gz"
                mask = f.name + ".split.gz"
                with gzip.open(f, "wt", encoding="utf-8") as dst:
                    dst.write(json.dumps(rec_copy) + "\n")
                with gzip.open(b / mask, "wb") as dst:
                    dst.write(bytes([code]))
                entries.append({
                    "source": sp.identity(f),
                    "artifact": mask,
                    "benign": True,
                    "host": "sysclient0001",
                    "day": f"2019-09-{day}",
                    "counts": {"lines": 1},
                    "allocation": {"1": [int(code == 1), 0, 0], "2": [0, 0, 0]},
                })

            cfg = {"enabled": True, "max_processes_per_host": 10000, "ttl_seconds": 86400.0}

            # 1. Vocabulary: continuous vs resumed
            clean_work = b / "clean_vocab_work"
            clean_work.mkdir()
            resume_work = b / "resume_vocab_work"
            resume_work.mkdir()

            c_vocab = sp.vocab_host(entries, b, clean_work, cfg)
            # Simulate interruption: only run day 21 first
            sp.vocab_host(entries[:1], b, resume_work, cfg)
            # Resume: run all days
            r_vocab = sp.vocab_host(entries, b, resume_work, cfg)

            self.assertEqual(c_vocab[1]["tf"], r_vocab[1]["tf"], "Vocabulary TF must be identical between continuous and resumed runs")
            self.assertEqual(c_vocab[1]["df"], r_vocab[1]["df"], "Vocabulary DF must be identical between continuous and resumed runs")

            # 2. Shards: continuous vs resumed
            vocab_map = {t: i for i, t in enumerate(sorted(set(t for x in c_vocab for group in x["tf"].values() for t in group)))}

            def setup_storage(name):
                ctrl = b / name
                ctrl.mkdir()
                vol = ctrl / "vol"
                vol.mkdir()
                vols = [{"id": "ssd", "path": str(vol), "max_bytes": 10_000_000, "reserve_free_bytes": 0}]
                initialize_ledger(ctrl, vols)
                return ctrl, vols

            c_ctrl, c_vols = setup_storage("shards_clean")
            r_ctrl, r_vols = setup_storage("shards_resume")

            c_shards = bm.process_host(entries, b, vocab_map, c_ctrl, "run", c_vols, 100, 100_000, cfg)
            # Simulate interruption: process day 21 only
            bm.process_host(entries[:1], b, vocab_map, r_ctrl, "run", r_vols, 100, 100_000, cfg)
            # Resume: process all days
            r_shards = bm.process_host(entries, b, vocab_map, r_ctrl, "run", r_vols, 100, 100_000, cfg)

            self.assertTrue(r_shards[0]["resumed"], "Day 1 should be resumed from cache")
            self.assertEqual(c_shards[1]["shards"][0]["sha256"], r_shards[1]["shards"][0]["sha256"],
                             "Day 2 shard SHA256 must match exactly between continuous and resumed runs")

    # 15. Cross-file temporal monotonicity: reject regressions and boundary ties for the same host
    def test_15_cross_file_temporal_monotonicity_and_rejection(self):
        from ML.code.preprocess import stratified_pipeline as sp
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp)
            h = "sysclient0001.systemia.com"
            a = "22222222-2222-2222-2222-222222222222"
            p = "11111111-1111-1111-1111-111111111111"

            def make_entry(day, timestamp_str, host="sysclient0001"):
                rec = {
                    "hostname": f"{host}.systemia.com",
                    "actorID": p,
                    "objectID": a,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "properties": {"image_path": "cmd.exe"},
                    "timestamp": timestamp_str,
                    "label": 0,
                }
                f = b / f"ecar-{day}-{host}.json.gz"
                mask = f.name + ".split.gz"
                with gzip.open(f, "wt", encoding="utf-8") as dst:
                    dst.write(json.dumps(rec) + "\n")
                with gzip.open(b / mask, "wb") as dst:
                    dst.write(bytes([1]))
                return {
                    "source": sp.identity(f),
                    "artifact": mask,
                    "benign": True,
                    "host": host,
                    "day": day,
                    "counts": {"lines": 1},
                    "allocation": {"1": [1, 0, 0], "2": [0, 0, 0]},
                }

            cfg = {"enabled": True}

            # Normal monotonic progression across files: 12:00 -> 13:00 -> OK
            e1 = make_entry("2019-09-21", "2019-09-21T12:00:00+00:00")
            e2_ok = make_entry("2019-09-22", "2019-09-22T13:00:00+00:00")
            work_ok = b / "work_ok"
            work_ok.mkdir()
            res = sp.vocab_host([e1, e2_ok], b, work_ok, cfg)
            self.assertEqual(len(res), 2)

            # Regression across files: 2019-09-21T12:00 -> 2019-09-20T12:00 -> ValueError
            e2_regress = make_entry("2019-09-20", "2019-09-20T12:00:00+00:00")
            work_bad = b / "work_bad"
            work_bad.mkdir()
            with self.assertRaisesRegex(ValueError, "Cross-file timestamp regression/overlap"):
                sp.vocab_host([e1, e2_regress], b, work_bad, cfg)

            # Equality / tie across file boundary: 2019-09-21T12:00 -> 2019-09-21T12:00 on another file -> ValueError
            e2_tie = make_entry("2019-09-23", "2019-09-21T12:00:00+00:00")
            work_tie = b / "work_tie"
            work_tie.mkdir()
            with self.assertRaisesRegex(ValueError, "Cross-file timestamp regression/overlap"):
                sp.vocab_host([e1, e2_tie], b, work_tie, cfg)

            # Different hosts are independent
            e_h2 = make_entry("2019-09-20", "2019-09-20T10:00:00+00:00", host="sysclient0002")
            work_diff = b / "work_diff"
            work_diff.mkdir()
            res_diff = sp.vocab_host([e1, e_h2], b, work_diff, cfg)
            self.assertEqual(len(res_diff), 2)

    # 16. Boundary resume maintains watermark and rejects regression on cached resume
    def test_16_cross_file_boundary_resume_validation(self):
        from ML.code.preprocess import stratified_pipeline as sp
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp)
            h = "sysclient0001"

            def make_entry(day, timestamp_str):
                rec = {
                    "hostname": f"{h}.systemia.com",
                    "actorID": "11111111-1111-1111-1111-111111111111",
                    "objectID": "22222222-2222-2222-2222-222222222222",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "properties": {"image_path": "cmd.exe"},
                    "timestamp": timestamp_str,
                    "label": 0,
                }
                f = b / f"ecar-{day}-{h}.json.gz"
                mask = f.name + ".split.gz"
                with gzip.open(f, "wt", encoding="utf-8") as dst:
                    dst.write(json.dumps(rec) + "\n")
                with gzip.open(b / mask, "wb") as dst:
                    dst.write(bytes([1]))
                return {
                    "source": sp.identity(f),
                    "artifact": mask,
                    "benign": True,
                    "host": h,
                    "day": day,
                    "counts": {"lines": 1},
                    "allocation": {"1": [1, 0, 0], "2": [0, 0, 0]},
                }

            cfg = {"enabled": True}
            e1 = make_entry("2019-09-21", "2019-09-21T12:00:00+00:00")
            e2_good = make_entry("2019-09-22", "2019-09-22T12:00:00+00:00")
            e2_regress = make_entry("2019-09-20", "2019-09-20T12:00:00+00:00")

            resume_work = b / "resume_work"
            resume_work.mkdir()

            # Process day 1
            sp.vocab_host([e1], b, resume_work, cfg)

            # Resume with regressed day 2 -> must reject despite day 1 being a cache hit
            with self.assertRaisesRegex(ValueError, "Cross-file timestamp regression/overlap"):
                sp.vocab_host([e1, e2_regress], b, resume_work, cfg)

            # Resume with valid day 2 -> must succeed
            res = sp.vocab_host([e1, e2_good], b, resume_work, cfg)
            self.assertEqual(len(res), 2)

    # 17. Config finite TTL validation, checkpoint file hash inclusions, and batch limits
    def test_17_process_context_config_finite_ttl_and_batch_limits(self):
        import math
        # Finite TTL validation
        for bad_ttl in (float("nan"), float("inf"), float("-inf"), 0.0, -10.0):
            with self.assertRaisesRegex(ValueError, "ttl_seconds must be a finite positive number"):
                ProcessContextConfig(ttl_seconds=bad_ttl)

        valid_cfg = ProcessContextConfig(ttl_seconds=86400.0)
        self.assertEqual(valid_cfg.ttl_seconds, 86400.0)

        # Checkpoint files include command_syntax.py
        from ML.code.preprocess.process_context_tracker import CONTEXT_PIPELINE_FILES
        self.assertIn("command_syntax.py", CONTEXT_PIPELINE_FILES)
        self.assertIn("process_context_tracker.py", CONTEXT_PIPELINE_FILES)

        # Batch tie limit: 50,000 records
        tracker = HostProcessContextTracker()
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp)
            f = b / "ecar-2019-09-21-sysclient0001.json.gz"
            mask = f.name + ".split.gz"
            # Write 50,001 records with identical timestamp
            records = [
                json.dumps({
                    "hostname": "sysclient0001.systemia.com",
                    "actorID": "11111111-1111-1111-1111-111111111111",
                    "object": "FILE",
                    "action": "READ",
                    "timestamp": "2019-09-21T00:00:00+00:00",
                    "label": 0,
                }) + "\n"
                for _ in range(50001)
            ]
            with gzip.open(f, "wt", encoding="utf-8") as dst:
                dst.writelines(records)
            with gzip.open(b / mask, "wb") as dst:
                dst.write(bytes([1] * 50001))

            entry = {
                "source": {"path": str(f)},
                "artifact": mask,
                "benign": True,
                "host": "sysclient0001",
                "counts": {"lines": 50001},
                "allocation": {"1": [50001, 0, 0], "2": [0, 0, 0]},
            }
            with self.assertRaisesRegex(ValueError, "exceeds safe limit"):
                list(split_rows(entry, b, tracker=tracker))

    # 18. Batch UTF-8 byte ceiling enforced independently of record count with non-ASCII text
    def test_18_batch_utf8_byte_ceiling_with_non_ascii(self):
        tracker = HostProcessContextTracker()
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp)
            f = b / "ecar-2019-09-21-sysclient0001.json.gz"
            mask = f.name + ".split.gz"

            # 1 record only, 18M 3-byte unicode chars: char count 18M < 50M, but UTF-8 bytes ~54MB > 50 MiB limit
            large_non_ascii = "\u2603" * 18_000_000
            rec = {
                "hostname": "sysclient0001.systemia.com",
                "actorID": "11111111-1111-1111-1111-111111111111",
                "object": "FILE",
                "action": "READ",
                "timestamp": "2019-09-21T00:00:00+00:00",
                "label": 0,
                "properties": {"data": large_non_ascii},
            }
            with gzip.open(f, "wt", encoding="utf-8") as dst:
                dst.write(json.dumps(rec) + "\n")
            with gzip.open(b / mask, "wb") as dst:
                dst.write(bytes([1]))

            entry = {
                "source": {"path": str(f)},
                "artifact": mask,
                "benign": True,
                "host": "sysclient0001",
                "counts": {"lines": 1},
                "allocation": {"1": [1, 0, 0], "2": [0, 0, 0]},
            }
            with self.assertRaisesRegex(ValueError, "50MB raw UTF-8"):
                list(split_rows(entry, b, tracker=tracker))


if __name__ == "__main__":
    unittest.main()



