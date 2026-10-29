#!/usr/bin/env python3
"""Comprehensive behavioral regression tests for production checkpoint/resume (Schema v3).

Covers all 9 required production scenarios without compatibility adapters:
1. Prefix CREATE with PID -> save -> fresh tracker load -> suffix CREATE with PID.
2. PID reassigned across checkpoint boundary (PID reuse detection).
3. PID audit counters and state equivalence with continuous run.
4. Multi-host independence (no cross-host leakage).
5. TTL and capacity eviction on saved state.
6. Watermark, config, schema version, and code-hash mismatch rejections.
7. Interrupted->resume for vocab and shards via production workers (TF/DF and sparse row equivalence).
8. Absence of compatibility adapter in production functions.
9. Independent label verification detects tampered labels.
"""
from __future__ import annotations

from collections import deque
import copy
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = next((p for p in Path(__file__).resolve().parents if (p / "AGENTS.md").is_file()), Path(__file__).resolve().parents[3])
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.code.preprocess.process_context_tracker import (
    HostProcessContextTracker,
    ProcessContextConfig,
    ProcessNode,
    tokenize_record_with_context,
)
from ML.code.preprocess import stratified_pipeline as sp
from ML.code.preprocess import build_model_input as bm
from ML.code.preprocess.build_model_input import initialize_ledger
from ML.code.preprocess.host_shards import ShardBuffer, decode_shard
from ML.code.preprocess.run_pilot_sysclient0201 import run_independent_label_verification


class ProductionCheckpointResumeTests(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.b = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    # 1. Prefix CREATE có PID → save → fresh tracker load → suffix CREATE có PID
    def test_01_prefix_create_with_pid_save_fresh_load_suffix_create_with_pid(self):
        """Prefix CREATE with PID -> save checkpoint -> fresh tracker load -> suffix CREATE with PID.

        Must resolve actor metadata, maintain PID in child process node, and generate context tokens
        without any KeyError or external compatibility adapter.
        """
        cfg = ProcessContextConfig()
        tracker1 = HostProcessContextTracker(cfg)
        host = "sysclient0201"
        actor_uuid = "11111111-1111-1111-1111-111111111111"
        child_uuid = "22222222-2222-2222-2222-222222222222"
        grandchild_uuid = "33333333-3333-3333-3333-333333333333"

        # Prefix: root process CREATE
        ev1 = {
            "hostname": host,
            "actorID": "00000000-0000-0000-0000-000000000000",
            "objectID": actor_uuid,
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "C:\\Windows\\System32\\services.exe", "pid": 500},
            "timestamp": "2019-09-21T10:00:00.000000Z",
        }
        tokens1, _ = tokenize_record_with_context(ev1, tracker=tracker1, query_t=100_000, update_tracker=True)

        # Prefix: child process CREATE by actor
        ev2 = {
            "hostname": host,
            "actorID": actor_uuid,
            "objectID": child_uuid,
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "C:\\Windows\\System32\\cmd.exe", "pid": 1002},
            "timestamp": "2019-09-21T10:01:00.000000Z",
        }
        tokens2, _ = tokenize_record_with_context(ev2, tracker=tracker1, query_t=100_100, update_tracker=True)

        # Save checkpoint
        chk_path = self.b / "chk_v3.json"
        tracker1.save_checkpoint(chk_path)

        # Verify checkpoint has schema_version 3 and pid_tracker
        saved_data = json.loads(chk_path.read_text())
        self.assertEqual(saved_data.get("schema_version"), 3)
        self.assertIn("pid_tracker", saved_data)
        self.assertIn(host, saved_data["pid_tracker"])
        self.assertIn("1002", saved_data["pid_tracker"][host])

        # Fresh tracker load
        tracker2 = HostProcessContextTracker(cfg)
        tracker2.load_checkpoint(chk_path)

        # Suffix: grandchild CREATE by child
        ev3 = {
            "hostname": host,
            "actorID": child_uuid,
            "objectID": grandchild_uuid,
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "C:\\Windows\\System32\\whoami.exe", "pid": 1003},
            "timestamp": "2019-09-22T10:02:00.000000Z",
        }
        # Execute suffix without any adapter
        tokens3, _ = tokenize_record_with_context(ev3, tracker=tracker2, query_t=200_000, update_tracker=True)

        # Verify child process node and PID are preserved
        child_node = tracker2.hosts[host].get(child_uuid)
        self.assertIsNotNone(child_node)
        self.assertEqual(child_node.pid, 1002)
        self.assertEqual(child_node.image_path, "C:\\Windows\\System32\\cmd.exe")

        # Verify grandchild was created and tracked in pid_tracker
        self.assertIn(1003, tracker2.pid_tracker[host])
        self.assertEqual(tracker2.pid_tracker[host][1003][0], grandchild_uuid)

        # Verify context tokens include actor metadata and relation
        struct_tokens = tokens3["structure_semantic"]
        self.assertTrue(any("ctx::actor::exe=" in t for t in struct_tokens))
        self.assertTrue(any("ctx::relation::actor_is_parent_of_target=true" in t for t in struct_tokens))

    # 2. PID được cấp lại cho UUID khác qua checkpoint boundary
    def test_02_pid_reassigned_across_checkpoint_boundary(self):
        """PID reassigned to another process UUID across checkpoint boundary must increment pid_reuse_conflict_count."""
        cfg = ProcessContextConfig()
        tracker1 = HostProcessContextTracker(cfg)
        host = "sysclient0201"
        reused_pid = 2048
        uuid_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        uuid_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

        # Prefix: PID 2048 assigned to uuid_a
        ev1 = {
            "hostname": host,
            "actorID": "00000000-0000-0000-0000-000000000000",
            "objectID": uuid_a,
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "first.exe", "pid": reused_pid},
            "timestamp": "2019-09-21T08:00:00.000000Z",
        }
        tokenize_record_with_context(ev1, tracker=tracker1, query_t=1000, update_tracker=True)
        self.assertEqual(tracker1.stats["pid_reuse_conflict_count"], 0)
        self.assertEqual(tracker1.pid_tracker[host][reused_pid][0], uuid_a)

        # Save checkpoint
        chk_path = self.b / "chk_pid_reuse.json"
        tracker1.save_checkpoint(chk_path)

        # Fresh tracker load
        tracker2 = HostProcessContextTracker(cfg)
        tracker2.load_checkpoint(chk_path)
        self.assertEqual(tracker2.stats["pid_reuse_conflict_count"], 0)

        # Suffix: PID 2048 reassigned to uuid_b
        ev2 = {
            "hostname": host,
            "actorID": "00000000-0000-0000-0000-000000000000",
            "objectID": uuid_b,
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "second.exe", "pid": reused_pid},
            "timestamp": "2019-09-22T09:00:00.000000Z",
        }
        tokenize_record_with_context(ev2, tracker=tracker2, query_t=2000, update_tracker=True)

        # Conflict count must increment
        self.assertEqual(tracker2.stats["pid_reuse_conflict_count"], 1)
        # Updated mapping points to uuid_b
        self.assertEqual(tracker2.pid_tracker[host][reused_pid][0], uuid_b)

    # 3. So sánh PID audit counters/state theo contract mới với continuous
    def test_03_pid_audit_counters_and_state_equivalence_with_continuous(self):
        """Continuous execution vs. interrupted-then-resumed run must produce identical stats, PID state, and tokens."""
        cfg = ProcessContextConfig()
        host = "sysclient0201"

        events = [
            # Event 0: create p1 (pid 100)
            {
                "hostname": host,
                "actorID": "00000000-0000-0000-0000-000000000000",
                "objectID": "11111111-1111-1111-1111-111111111111",
                "object": "PROCESS",
                "action": "CREATE",
                "properties": {"image_path": "init.exe", "pid": 100},
                "timestamp": "2019-09-21T01:00:00.000000Z",
            },
            # Event 1: create p2 (pid 200) by p1
            {
                "hostname": host,
                "actorID": "11111111-1111-1111-1111-111111111111",
                "objectID": "22222222-2222-2222-2222-222222222222",
                "object": "PROCESS",
                "action": "CREATE",
                "properties": {"image_path": "worker.exe", "pid": 200},
                "timestamp": "2019-09-21T02:00:00.000000Z",
            },
            # --- CHECKPOINT BOUNDARY BETWEEN EVENT 1 AND EVENT 2 ---
            # Event 2: file write by p2
            {
                "hostname": host,
                "actorID": "22222222-2222-2222-2222-222222222222",
                "objectID": "file-uuid-001",
                "object": "FILE",
                "action": "WRITE",
                "properties": {"file_path": "C:\\temp\\log.txt"},
                "timestamp": "2019-09-22T03:00:00.000000Z",
            },
            # Event 3: pid 200 reused by p3
            {
                "hostname": host,
                "actorID": "11111111-1111-1111-1111-111111111111",
                "objectID": "33333333-3333-3333-3333-333333333333",
                "object": "PROCESS",
                "action": "CREATE",
                "properties": {"image_path": "recycled.exe", "pid": 200},
                "timestamp": "2019-09-22T04:00:00.000000Z",
            },
            # Event 4: action by p3
            {
                "hostname": host,
                "actorID": "33333333-3333-3333-3333-333333333333",
                "objectID": "file-uuid-002",
                "object": "FILE",
                "action": "READ",
                "properties": {"file_path": "C:\\temp\\log.txt"},
                "timestamp": "2019-09-22T05:00:00.000000Z",
            },
        ]

        # 1. Run Continuous
        tr_continuous = HostProcessContextTracker(cfg)
        cont_tokens = []
        for i, ev in enumerate(events):
            t = (i + 1) * 100_000
            toks, _ = tokenize_record_with_context(ev, tracker=tr_continuous, query_t=t, update_tracker=True)
            cont_tokens.append(toks["structure_semantic"])

        # 2. Run Interrupted -> Resume
        tr_prefix = HostProcessContextTracker(cfg)
        for i in range(2):
            ev = events[i]
            t = (i + 1) * 100_000
            tokenize_record_with_context(ev, tracker=tr_prefix, query_t=t, update_tracker=True)

        chk_path = self.b / "equivalence_chk.json"
        tr_prefix.save_checkpoint(chk_path)

        # Resume in fresh tracker
        tr_resumed = HostProcessContextTracker(cfg)
        tr_resumed.load_checkpoint(chk_path)

        resumed_tokens = []
        for i in range(2, len(events)):
            ev = events[i]
            t = (i + 1) * 100_000
            toks, _ = tokenize_record_with_context(ev, tracker=tr_resumed, query_t=t, update_tracker=True)
            resumed_tokens.append(toks["structure_semantic"])

        # Compare stats: exactly identical
        self.assertEqual(tr_continuous.stats, tr_resumed.stats)
        self.assertEqual(tr_continuous.stats["pid_reuse_conflict_count"], 1)
        self.assertEqual(tr_resumed.stats["pid_reuse_conflict_count"], 1)

        # Compare PID tracker mapping
        self.assertEqual(tr_continuous.pid_tracker, tr_resumed.pid_tracker)

        # Compare generated tokens for suffix events (events 2, 3, 4)
        self.assertEqual(cont_tokens[2:], resumed_tokens)

    # 4. Nhiều host độc lập
    def test_04_multi_host_independence(self):
        """Tracker must cleanly partition state and watermarks across multiple independent hosts."""
        cfg = ProcessContextConfig()
        tr = HostProcessContextTracker(cfg)
        hosts = ["sysclient0201", "sysclient0051", "sysclient0104"]

        for idx, h in enumerate(hosts):
            ev = {
                "hostname": h,
                "actorID": "00000000-0000-0000-0000-000000000000",
                "objectID": f"proc-uuid-{h}",
                "object": "PROCESS",
                "action": "CREATE",
                "properties": {"image_path": f"{h}.exe", "pid": 1000 + idx},
                "timestamp": f"2019-09-21T1{idx}:00:00.000000Z",
            }
            tokenize_record_with_context(ev, tracker=tr, query_t=(idx + 1) * 100_000, update_tracker=True)

        chk_path = self.b / "multi_host_chk.json"
        tr.save_checkpoint(chk_path)

        # Fresh tracker load
        tr2 = HostProcessContextTracker(cfg)
        tr2.load_checkpoint(chk_path)

        self.assertEqual(set(tr2.hosts.keys()), set(hosts))
        self.assertEqual(set(tr2.pid_tracker.keys()), set(hosts))
        for idx, h in enumerate(hosts):
            self.assertIn(1000 + idx, tr2.pid_tracker[h])
            self.assertEqual(tr2.pid_tracker[h][1000 + idx][0], f"proc-uuid-{h}")
            # Ensure no cross-host pollution
            for other_idx, other_h in enumerate(hosts):
                if other_h != h:
                    self.assertNotIn(1000 + other_idx, tr2.pid_tracker[h])

    # 5. TTL/capacity eviction liên quan đến state được lưu
    def test_05_ttl_and_capacity_eviction_on_saved_state(self):
        """TTL expiration and capacity bounding must prune pid_tracker consistently and preserve bounds across checkpoints."""
        # Config with 5 second TTL and capacity of 3
        cfg = ProcessContextConfig(max_processes_per_host=3, ttl_seconds=5.0)
        tr = HostProcessContextTracker(cfg)
        host = "sysclient0201"

        # 1. Test Capacity Eviction: Add 5 processes within TTL
        for i in range(5):
            ev = {
                "hostname": host,
                "actorID": "00000000-0000-0000-0000-000000000000",
                "objectID": f"proc-uuid-{i}",
                "object": "PROCESS",
                "action": "CREATE",
                "properties": {"image_path": f"p{i}.exe", "pid": 100 + i},
                "timestamp": "2019-09-21T01:00:00.000000Z",
            }
            # t separated by 10 us (well within 5s TTL)
            tokenize_record_with_context(ev, tracker=tr, query_t=1_000_000 + i * 10, update_tracker=True)

        # Capacity is 3, so oldest 2 (proc-uuid-0, proc-uuid-1) must be evicted
        self.assertEqual(len(tr.hosts[host]), 3)
        self.assertEqual(len(tr.pid_tracker[host]), 3)
        self.assertNotIn("proc-uuid-0", tr.hosts[host])
        self.assertNotIn(100, tr.pid_tracker[host])
        self.assertIn("proc-uuid-4", tr.hosts[host])
        self.assertIn(104, tr.pid_tracker[host])

        # 2. Test TTL Eviction: Advance time by 10 seconds (> 5s TTL)
        ev_new = {
            "hostname": host,
            "actorID": "00000000-0000-0000-0000-000000000000",
            "objectID": "proc-uuid-new",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "new.exe", "pid": 999},
            "timestamp": "2019-09-21T01:00:10.000000Z",
        }
        # Advance current_t to 10 seconds later
        tokenize_record_with_context(ev_new, tracker=tr, query_t=11_000_000, update_tracker=True)

        # Old processes should have expired under TTL
        self.assertEqual(len(tr.hosts[host]), 1)
        self.assertEqual(len(tr.pid_tracker[host]), 1)
        self.assertIn("proc-uuid-new", tr.hosts[host])
        self.assertIn(999, tr.pid_tracker[host])

        # 3. Save and load into fresh tracker: bounds preserved
        chk_path = self.b / "eviction_chk.json"
        tr.save_checkpoint(chk_path)

        tr_loaded = HostProcessContextTracker(cfg)
        tr_loaded.load_checkpoint(chk_path)
        self.assertEqual(len(tr_loaded.hosts[host]), 1)
        self.assertEqual(len(tr_loaded.pid_tracker[host]), 1)
        self.assertIn(999, tr_loaded.pid_tracker[host])
        self.assertTrue(len(tr_loaded.evicted_uuids[host]) > 0)

    # 6. Watermark, config/schema/code-hash mismatch rejection
    def test_06_watermark_config_schema_codehash_rejections(self):
        """load_checkpoint must strictly reject schema v2, code hash tampering, and config mismatch."""
        cfg = ProcessContextConfig()
        tr = HostProcessContextTracker(cfg)
        host = "sysclient0201"
        ev = {
            "hostname": host,
            "actorID": "00000000-0000-0000-0000-000000000000",
            "objectID": "proc-uuid-test",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "test.exe", "pid": 1234},
            "timestamp": "2019-09-21T01:00:00.000000Z",
        }
        tokenize_record_with_context(ev, tracker=tr, query_t=1000, update_tracker=True)

        valid_chk = self.b / "valid_chk.json"
        tr.save_checkpoint(valid_chk)

        # 1. Strict rejection of schema version 2
        chk_v2 = self.b / "chk_v2.json"
        data_v2 = json.loads(valid_chk.read_text())
        data_v2["schema_version"] = 2
        del data_v2["pid_tracker"]
        chk_v2.write_text(json.dumps(data_v2))

        tr_test = HostProcessContextTracker(cfg)
        with self.assertRaises(ValueError) as cm:
            tr_test.load_checkpoint(chk_v2)
        self.assertIn("unsupported checkpoint schema version: 2", str(cm.exception))
        self.assertIn("expected 3", str(cm.exception))

        # 2. Strict rejection of tampered code hash
        chk_tampered_hash = self.b / "chk_tampered_hash.json"
        data_bad_hash = json.loads(valid_chk.read_text())
        data_bad_hash["code_hashes"]["process_context_tracker.py"] = "0" * 64
        chk_tampered_hash.write_text(json.dumps(data_bad_hash))

        with self.assertRaises(ValueError) as cm:
            tr_test.load_checkpoint(chk_tampered_hash)
        self.assertIn("code_hashes mismatch", str(cm.exception))

        # 3. Strict rejection of config mismatch
        chk_bad_cfg = self.b / "chk_bad_cfg.json"
        data_bad_cfg = json.loads(valid_chk.read_text())
        data_bad_cfg["config"]["ttl_seconds"] = 1234.5
        chk_bad_cfg.write_text(json.dumps(data_bad_cfg))

        with self.assertRaises(ValueError) as cm:
            tr_test.load_checkpoint(chk_bad_cfg)
        self.assertIn("configuration mismatch for ttl_seconds", str(cm.exception))

        # 4. Strict rejection of missing pid_tracker section in Schema v3
        chk_no_pid = self.b / "chk_no_pid.json"
        data_no_pid = json.loads(valid_chk.read_text())
        del data_no_pid["pid_tracker"]
        chk_no_pid.write_text(json.dumps(data_no_pid))

        with self.assertRaises(ValueError) as cm:
            tr_test.load_checkpoint(chk_no_pid)
        self.assertIn("checkpoint missing required 'pid_tracker' section for Schema v3", str(cm.exception))

        # 5. Strict rejection of missing host mapping in pid_tracker in Schema v3
        chk_missing_host_pid = self.b / "chk_missing_host_pid.json"
        data_missing_host_pid = json.loads(valid_chk.read_text())
        del data_missing_host_pid["pid_tracker"][host]
        chk_missing_host_pid.write_text(json.dumps(data_missing_host_pid))

        with self.assertRaises(ValueError) as cm:
            tr_test.load_checkpoint(chk_missing_host_pid)
        self.assertIn("checkpoint missing required pid_tracker mapping for host", str(cm.exception))

    # 7. Interrupted→resume cho vocab và shards qua production workers: TF/DF, source lines, labels và sparse features khớp continuous
    def test_07_interrupted_resume_for_vocab_and_shards_via_production_workers(self):
        """Production workers (vocab_host and process_host) must produce 100% identical TF/DF, lines, labels, and features."""
        b = self.b
        host = "sysclient0001"
        entries = []

        # Construct a 2-day synthetic telemetry fixture with parent-child process relationships
        for day_num, day_str in enumerate(["2019-09-21", "2019-09-22"]):
            raw_file = b / f"ecar-{day_str}-{host}.json.gz"
            mask_file = b / f"ecar-{day_str}-{host}.json.gz.split.gz"

            actor_uuid = f"root-{day_num}-uuid"
            child_uuid = f"child-{day_num}-uuid"

            records = [
                # Line 1: Root CREATE (train target, code 1)
                {
                    "hostname": f"{host}.systemia.com",
                    "actorID": "00000000-0000-0000-0000-000000000000",
                    "objectID": actor_uuid,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "properties": {"image_path": f"C:\\srv{day_num}.exe", "pid": 100 + day_num},
                    "timestamp": f"{day_str}T08:00:00.000000Z",
                    "label": 0,
                },
                # Line 2: Child CREATE by Root (val target, code 2)
                {
                    "hostname": f"{host}.systemia.com",
                    "actorID": actor_uuid,
                    "objectID": child_uuid,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "properties": {"image_path": f"C:\\worker{day_num}.exe", "pid": 200 + day_num},
                    "timestamp": f"{day_str}T09:00:00.000000Z",
                    "label": 0,
                },
                # Line 3: Action by Child (test target, code 3)
                {
                    "hostname": f"{host}.systemia.com",
                    "actorID": child_uuid,
                    "objectID": f"file-{day_num}",
                    "object": "FILE",
                    "action": "WRITE",
                    "properties": {"file_path": f"C:\\temp\\log{day_num}.txt"},
                    "timestamp": f"{day_str}T10:00:00.000000Z",
                    "label": 0,
                },
            ]

            with gzip.open(raw_file, "wt", encoding="utf-8") as rf:
                for r in records:
                    rf.write(json.dumps(r) + "\n")

            with gzip.open(mask_file, "wb") as mf:
                mf.write(bytes([1, 2, 3]))

            entries.append({
                "source": sp.identity(raw_file),
                "artifact": mask_file.name,
                "benign": True,
                "host": host,
                "day": day_str,
                "counts": {"lines": 3, "0": 0, "1": 1, "2": 1, "3": 1},
                "allocation": {"1": [1, 1, 1], "2": [0, 0, 0]},
            })

        cfg = {"enabled": True, "max_processes_per_host": 10000, "ttl_seconds": 86400.0}

        # 1. Vocab: Continuous vs. Resumed
        clean_vocab_work = b / "clean_vocab_work"
        clean_vocab_work.mkdir()
        resume_vocab_work = b / "resume_vocab_work"
        resume_vocab_work.mkdir()

        # Continuous vocab
        cont_vocab = sp.vocab_host(entries, b, clean_vocab_work, cfg)
        # Interrupted vocab: run day 1 only
        sp.vocab_host(entries[:1], b, resume_vocab_work, cfg)
        # Resume vocab: run day 1 + day 2
        resumed_vocab = sp.vocab_host(entries, b, resume_vocab_work, cfg)

        self.assertEqual(cont_vocab[1]["tf"], resumed_vocab[1]["tf"], "Vocab TF must match exactly between continuous and resumed")
        self.assertEqual(cont_vocab[1]["df"], resumed_vocab[1]["df"], "Vocab DF must match exactly between continuous and resumed")

        # Build vocabulary mapping
        all_tokens = set()
        for x in cont_vocab:
            for grp in x["tf"].values():
                all_tokens.update(grp.keys())
        vocab_map = {t: i for i, t in enumerate(sorted(all_tokens))}

        # 2. Shards: Continuous vs. Resumed
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

        cont_shards = bm.process_host(entries, b, vocab_map, c_ctrl, "run", c_vols, 100, 100_000, cfg)
        # Interrupted shards: run day 1 only
        bm.process_host(entries[:1], b, vocab_map, r_ctrl, "run", r_vols, 100, 100_000, cfg)
        # Resume shards: run day 1 + day 2
        resumed_shards = bm.process_host(entries, b, vocab_map, r_ctrl, "run", r_vols, 100, 100_000, cfg)

        self.assertTrue(resumed_shards[0]["resumed"], "Day 1 must be resumed from receipt")
        # Compare day 2 shards
        c_part = cont_shards[1]["shards"][0]
        r_part = resumed_shards[1]["shards"][0]
        self.assertEqual(c_part["sha256"], r_part["sha256"], "Day 2 shard SHA256 must match exactly between continuous and resumed")

        # Decode both shards and compare X, y, lines
        c_vol_path = Path(c_vols[0]["path"]) / c_part["path"]
        r_vol_path = Path(r_vols[0]["path"]) / r_part["path"]
        X_c, y_c, lines_c = decode_shard(c_vol_path, len(vocab_map), c_part)
        X_r, y_r, lines_r = decode_shard(r_vol_path, len(vocab_map), r_part)

        self.assertEqual(lines_c.tolist(), lines_r.tolist(), "Source lines must match exactly")
        self.assertEqual(y_c.tolist(), y_r.tolist(), "Labels must match exactly")
        self.assertEqual(X_c.nnz, X_r.nnz, "Sparse NNZ must match exactly")
        self.assertEqual((X_c != X_r).nnz, 0, "Sparse matrix values must match bit-for-bit")

    # 8. Không sử dụng compatibility adapter để làm tests production pass
    def test_08_no_compatibility_adapter_used_in_production_functions(self):
        """Production tracker load_checkpoint must initialize pid_tracker without external adapters."""
        cfg = ProcessContextConfig()
        tr = HostProcessContextTracker(cfg)
        host = "sysclient0201"
        ev = {
            "hostname": host,
            "actorID": "00000000-0000-0000-0000-000000000000",
            "objectID": "proc-uuid-no-adapter",
            "object": "PROCESS",
            "action": "CREATE",
            "properties": {"image_path": "no_adapter.exe", "pid": 4321},
            "timestamp": "2019-09-21T01:00:00.000000Z",
        }
        tokenize_record_with_context(ev, tracker=tr, query_t=1000, update_tracker=True)

        chk_path = self.b / "no_adapter_chk.json"
        tr.save_checkpoint(chk_path)

        # Fresh tracker load
        tr2 = HostProcessContextTracker(cfg)
        tr2.load_checkpoint(chk_path)

        # Assert pid_tracker is directly populated for host
        self.assertIn(host, tr2.pid_tracker)
        self.assertIn(4321, tr2.pid_tracker[host])
        self.assertEqual(tr2.pid_tracker[host][4321][0], "proc-uuid-no-adapter")

        # Ensure no external adapter attribute or function is present on tracker
        self.assertFalse(hasattr(tr2, "adapter_applied"))
        self.assertFalse(hasattr(tr2, "_compatibility_adapter"))

    # 9. Tampered label phải bị label verification phát hiện
    def test_09_tampered_label_detected_by_label_verification(self):
        """run_independent_label_verification must detect tampered shard labels and fail closed."""
        b = self.b
        host = "sysclient0201"
        day_str = "2019-09-21"

        raw_file = b / f"AIA-201-225.ecar-{day_str}-{host}.json.gz"
        mask_file = b / f"AIA-201-225.ecar-{day_str}-{host}.json.gz.split.gz"
        index_label_file = b / f"AIA-201-225.ecar-{day_str}-{host}.json.gz.labels.gz"

        records = [
            {"hostname": f"{host}.systemia.com", "actorID": "a1", "objectID": "o1", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T08:00:00Z", "label": 0},
            {"hostname": f"{host}.systemia.com", "actorID": "a2", "objectID": "o2", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T09:00:00Z", "label": 0},
        ]

        with gzip.open(raw_file, "wt", encoding="utf-8") as rf:
            for r in records:
                rf.write(json.dumps(r) + "\n")

        with gzip.open(mask_file, "wb") as mf:
            # Lines 1 and 2 are train (code 1)
            mf.write(bytes([1, 1]))

        with gzip.open(index_label_file, "wb") as lf:
            # Code 1 in .labels.gz means benign (label 0)
            lf.write(bytes([1, 1]))

        entries = [{
            "source": sp.identity(raw_file),
            "artifact": mask_file.name,
            "benign": True,
            "host": host,
            "day": day_str,
            "counts": {"lines": 2, "1": 2, "2": 0, "3": 0},
            "allocation": {"1": [2, 0, 0], "2": [0, 0, 0]},
        }]

        manifest = {"entries": entries, "counts": {"train": 2, "val": 0, "test": 0}}
        source_id = sp.digest(entries[0]["source"])

        # Create valid shard using ShardBuffer
        vol_dir = b / "vol"
        vol_dir.mkdir()
        shard_path = vol_dir / "shard_0.bin"

        buf_clean = ShardBuffer(width=2)
        buf_clean.append([0], 0, 1)
        buf_clean.append([1], 0, 2)
        payload_clean, meta_clean = buf_clean.encode()
        shard_path.write_bytes(payload_clean)

        part_info = {
            "volume": "ssd",
            "path": "shard_0.bin",
            "source_id": source_id,
            "split": "train",
            "compression": "none",
            **meta_clean,
        }
        roots = {"ssd": vol_dir}

        # Create index manifest mapping raw_file to index_label_file
        idx_manifest_file = b / "index_manifest.json"
        idx_manifest_data = {
            "schema": 1,
            "kind": "host_label_index",
            "entries": [
                {
                    "source": {"path": str(raw_file)},
                    "artifact": index_label_file.name,
                }
            ],
        }
        idx_manifest_file.write_text(json.dumps(idx_manifest_data))

        # 1. Verification on pristine shards: must pass across all 3 sources
        report_clean, _ = run_independent_label_verification(
            pilot_manifest=manifest,
            split_dir=b,
            all_shard_parts=[part_info],
            roots=roots,
            vocab_width=2,
            output_dir=b / "clean_verif",
            index_manifest_path=idx_manifest_file,
        )
        self.assertEqual(report_clean["status"], "VERIFIED")
        self.assertEqual(report_clean["overall_summary"]["membership_parity_status"], "VERIFIED (100% PARITY WITH FROZEN MASK)")
        self.assertEqual(report_clean["overall_summary"]["raw_source_label_status"], "VERIFIED (100% MATCH WITH RAW SOURCE TELEMETRY)")
        self.assertEqual(report_clean["overall_summary"]["frozen_index_label_status"], "VERIFIED (100% MATCH WITH FROZEN INDEX .labels.gz)")
        self.assertEqual(report_clean["overall_summary"]["index_stream_integrity_status"], "VERIFIED (EXACT STREAM LENGTH MATCH)")
        self.assertEqual(report_clean["overall_summary"]["raw_label_mismatches"], 0)
        self.assertEqual(report_clean["overall_summary"]["index_label_mismatches"], 0)

        # 2. Verification on tampered shard (label flipped 0 -> 1 on line 2): must fail closed
        buf_tampered = ShardBuffer(width=2)
        buf_tampered.append([0], 0, 1)
        buf_tampered.append([1], 1, 2)
        payload_tampered, meta_tampered = buf_tampered.encode()
        shard_path.write_bytes(payload_tampered)
        part_info.update(meta_tampered)

        report_tampered, _ = run_independent_label_verification(
            pilot_manifest=manifest,
            split_dir=b,
            all_shard_parts=[part_info],
            roots=roots,
            vocab_width=2,
            output_dir=b / "tampered_verif",
            index_manifest_path=idx_manifest_file,
        )
        self.assertEqual(report_tampered["status"], "FAILED")
        self.assertEqual(report_tampered["overall_summary"]["raw_label_mismatches"], 1)
        self.assertEqual(report_tampered["overall_summary"]["index_label_mismatches"], 1)
        self.assertTrue(len(report_tampered["mismatch_examples"]) >= 1)
        m_types = [ex.get("type") for ex in report_tampered["mismatch_examples"]]
        self.assertIn("raw_label_mismatch", m_types)
        self.assertIn("index_label_mismatch", m_types)

    # 10. Verifier tự chứng minh không thiếu target từ split mask
    def test_10_missing_target_from_mask_detected_by_label_verification(self):
        """run_independent_label_verification must detect when a shard omits targets specified by the mask."""
        b = self.b
        host = "sysclient0201"
        day_str = "2019-09-21"

        raw_file = b / f"ecar-missing-{day_str}-{host}.json.gz"
        mask_file = b / f"ecar-missing-{day_str}-{host}.json.gz.split.gz"
        idx_file = b / f"ecar-missing-{day_str}-{host}.json.gz.labels.gz"

        # Raw file has 3 lines
        records = [
            {"hostname": f"{host}.systemia.com", "actorID": "a1", "objectID": "o1", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T08:00:00Z", "label": 0},
            {"hostname": f"{host}.systemia.com", "actorID": "a2", "objectID": "o2", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T09:00:00Z", "label": 0},
            {"hostname": f"{host}.systemia.com", "actorID": "a3", "objectID": "o3", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T10:00:00Z", "label": 0},
        ]
        with gzip.open(raw_file, "wt", encoding="utf-8") as rf:
            for r in records:
                rf.write(json.dumps(r) + "\n")

        # Mask declares lines 1, 2, 3 as targets
        with gzip.open(mask_file, "wb") as mf:
            mf.write(bytes([1, 1, 1]))

        # Index labels for 3 lines
        with gzip.open(idx_file, "wb") as lf:
            lf.write(bytes([1, 1, 1]))

        idx_manifest_file = b / "idx_manifest_missing.json"
        idx_manifest_file.write_text(json.dumps({
            "schema": 1,
            "kind": "host_label_index",
            "entries": [{"source": {"path": str(raw_file)}, "artifact": idx_file.name}],
        }))

        entries = [{
            "source": sp.identity(raw_file),
            "artifact": mask_file.name,
            "benign": True,
            "host": host,
            "day": day_str,
            "counts": {"lines": 3, "1": 3, "2": 0, "3": 0},
            "allocation": {"1": [3, 0, 0], "2": [0, 0, 0]},
        }]
        manifest = {"entries": entries, "counts": {"train": 3, "val": 0, "test": 0}}
        source_id = sp.digest(entries[0]["source"])

        # Shard only contains lines 1 and 2 (line 3 is MISSING)
        vol_dir = b / "vol_missing"
        vol_dir.mkdir()
        shard_path = vol_dir / "shard_missing.bin"

        buf_incomplete = ShardBuffer(width=2)
        buf_incomplete.append([0], 0, 1)
        buf_incomplete.append([1], 0, 2)
        payload, meta = buf_incomplete.encode()
        shard_path.write_bytes(payload)

        part_info = {
            "volume": "ssd",
            "path": "shard_missing.bin",
            "source_id": source_id,
            "split": "train",
            "compression": "none",
            **meta,
        }
        roots = {"ssd": vol_dir}

        report, _ = run_independent_label_verification(
            pilot_manifest=manifest,
            split_dir=b,
            all_shard_parts=[part_info],
            roots=roots,
            vocab_width=2,
            output_dir=b / "verif_missing",
            index_manifest_path=idx_manifest_file,
        )

        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["overall_summary"]["membership_parity_status"], "FAILED")
        self.assertEqual(report["overall_summary"]["missing_from_shards"], 1)
        self.assertEqual(report["overall_summary"]["total_mask_targets"], 3)
        self.assertEqual(report["overall_summary"]["total_shard_targets"], 2)

    # 11. Phát hiện index artifact bị thiếu, hết sớm hoặc có mã không hợp lệ
    def test_11_index_stream_length_and_code_mismatch_detected(self):
        """run_independent_label_verification must fail when index is missing, truncated, or contains invalid codes."""
        b = self.b
        host = "sysclient0201"
        day_str = "2019-09-21"

        raw_file = b / f"ecar-idx-test-{day_str}-{host}.json.gz"
        mask_file = b / f"ecar-idx-test-{day_str}-{host}.json.gz.split.gz"

        records = [
            {"hostname": f"{host}.systemia.com", "actorID": "a1", "objectID": "o1", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T08:00:00Z", "label": 0},
            {"hostname": f"{host}.systemia.com", "actorID": "a2", "objectID": "o2", "object": "FILE", "action": "WRITE", "timestamp": f"{day_str}T09:00:00Z", "label": 0},
        ]
        with gzip.open(raw_file, "wt", encoding="utf-8") as rf:
            for r in records:
                rf.write(json.dumps(r) + "\n")

        with gzip.open(mask_file, "wb") as mf:
            mf.write(bytes([1, 1]))

        entries = [{
            "source": sp.identity(raw_file),
            "artifact": mask_file.name,
            "benign": True,
            "host": host,
            "day": day_str,
            "counts": {"lines": 2, "1": 2, "2": 0, "3": 0},
            "allocation": {"1": [2, 0, 0], "2": [0, 0, 0]},
        }]
        manifest = {"entries": entries, "counts": {"train": 2, "val": 0, "test": 0}}
        source_id = sp.digest(entries[0]["source"])

        vol_dir = b / "vol_idx_test"
        vol_dir.mkdir()
        shard_path = vol_dir / "shard.bin"

        buf = ShardBuffer(width=2)
        buf.append([0], 0, 1)
        buf.append([1], 0, 2)
        payload, meta = buf.encode()
        shard_path.write_bytes(payload)

        part_info = {
            "volume": "ssd",
            "path": "shard.bin",
            "source_id": source_id,
            "split": "train",
            "compression": "none",
            **meta,
        }
        roots = {"ssd": vol_dir}

        # Subtest A: Missing index artifact -> must fail closed
        empty_manifest_file = b / "empty_idx_manifest.json"
        empty_manifest_file.write_text(json.dumps({"schema": 1, "kind": "host_label_index", "entries": []}))

        report_missing, _ = run_independent_label_verification(
            pilot_manifest=manifest,
            split_dir=b,
            all_shard_parts=[part_info],
            roots=roots,
            vocab_width=2,
            output_dir=b / "verif_no_idx",
            index_manifest_path=empty_manifest_file,
        )
        self.assertEqual(report_missing["status"], "FAILED")
        self.assertEqual(report_missing["overall_summary"]["frozen_index_label_status"], "FAILED")
        self.assertEqual(report_missing["overall_summary"]["index_stream_integrity_status"], "FAILED")

        # Subtest B: Index stream premature EOF (only 1 byte for 2 lines)
        short_idx_file = b / "short.labels.gz"
        with gzip.open(short_idx_file, "wb") as lf:
            lf.write(bytes([1]))  # Only 1 byte instead of 2

        short_idx_manifest = b / "short_idx_manifest.json"
        short_idx_manifest.write_text(json.dumps({
            "schema": 1, "kind": "host_label_index",
            "entries": [{"source": {"path": str(raw_file)}, "artifact": short_idx_file.name}],
        }))

        report_short, _ = run_independent_label_verification(
            pilot_manifest=manifest,
            split_dir=b,
            all_shard_parts=[part_info],
            roots=roots,
            vocab_width=2,
            output_dir=b / "verif_short_idx",
            index_manifest_path=short_idx_manifest,
        )
        self.assertEqual(report_short["status"], "FAILED")
        self.assertEqual(report_short["overall_summary"]["index_stream_integrity_status"], "FAILED")

        # Subtest C: Invalid index code (byte is 0 or 5 instead of 1 or 2)
        invalid_idx_file = b / "invalid.labels.gz"
        with gzip.open(invalid_idx_file, "wb") as lf:
            lf.write(bytes([1, 5]))  # Byte 2 has code 5 (invalid)

        invalid_idx_manifest = b / "invalid_idx_manifest.json"
        invalid_idx_manifest.write_text(json.dumps({
            "schema": 1, "kind": "host_label_index",
            "entries": [{"source": {"path": str(raw_file)}, "artifact": invalid_idx_file.name}],
        }))

        report_invalid, _ = run_independent_label_verification(
            pilot_manifest=manifest,
            split_dir=b,
            all_shard_parts=[part_info],
            roots=roots,
            vocab_width=2,
            output_dir=b / "verif_invalid_idx",
            index_manifest_path=invalid_idx_manifest,
        )
        self.assertEqual(report_invalid["status"], "FAILED")
        self.assertEqual(report_invalid["overall_summary"]["frozen_index_label_status"], "FAILED")
        m_types = [ex.get("type") for ex in report_invalid["mismatch_examples"]]
        self.assertIn("index_code_invalid", m_types)


if __name__ == "__main__":
    unittest.main()
