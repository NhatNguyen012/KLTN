#!/usr/bin/env python3
"""Comprehensive production-calling tests for Pilot Publication, Manifest Contract, and Verification.

Calls production functions directly on synthetic fixtures to protect:
1. Volume-relative path resolution and strict escape/unknown volume rejection.
2. Receipt without 'index' field publishes and verifies cleanly via HostShardDataset.
3. Incompatible existing manifest/assets rejected with all existing files preserved bit-for-bit.
4. Matching rerun reuses existing artifacts without rewriting.
5. Split hash mismatch rejected; missing hash requires explicit provenance migration with backup and manifest verification.
6. Verify-only mode is strictly read-only and never modifies or adds files in fixture namespace.
7. Mask and target parity verification: validates uniqueness, completeness, and split codes; separates labels.
8. Event illustrations decoded accurately from shard row vectors (source-line, label, split, columns).
9. Suffix resume verification truly executes suffix under recovered state, matching continuous TF/DF and shards without reading prefix raw data.
10. Suffix verification failure handling: corrupt prefix, cache hit on suffix, and metric mismatch all fail cleanly.
11. execute_pilot truthful report status: provenance mismatch fails, pending suffix marks PARTIAL_VERIFIED.
"""
from __future__ import annotations

from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

# Ensure project root is on sys.path
PROJECT_ROOT = next((p for p in Path(__file__).resolve().parents if (p / "AGENTS.md").is_file()), Path(__file__).resolve().parents[3])
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.code.preprocess.command_syntax import Lexeme
from ML.code.preprocess.ecar_tokenizer import GROUPS, flatten_tokens, tokenize_record
from ML.code.preprocess.host_shards import FORMAT, SCHEMA, SPLITS, HostShardDataset, ShardBuffer, decode_shard
from ML.code.preprocess.pipeline_contract import code_hashes, validate_output_path
from ML.code.preprocess.process_context_tracker import HostProcessContextTracker, ProcessContextConfig, parse_timestamp
from ML.code.preprocess.shard_storage import initialize_ledger, load_volumes
from ML.code.preprocess.stratified_pipeline import digest, file_hash, identity, vocab_file, vocab_host
from ML.code.preprocess import build_model_input as bm
from ML.code.preprocess.run_pilot_sysclient0201 import (
    CONTEXT_CONFIG,
    execute_pilot,
    extract_event_illustrations_from_shards,
    main as pilot_main,
    migrate_provenance_split_sha256,
    publish_shard_manifest,
    run_suffix_resume_verification,
    validate_and_resolve_shard_parts,
    validate_continuous_reference,
    validate_prefix_checkpoints,
    verify_mask_and_target_parity,
    verify_shards_dataset,
)


class PilotPublicationContractTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = Path(self.tmp)
        self.vol_dir = self.base / "volumes/ssd"
        self.vol_dir.mkdir(parents=True, exist_ok=True)
        self.volumes = [{"id": "ssd", "path": str(self.vol_dir)}]
        self.roots = {"ssd": self.vol_dir.resolve()}

        # Create dummy vocabulary
        self.vocab = {"action::read": 0, "ctx::actor::exe=cmd.exe": 1, "object::file": 2}
        self.vocab_dir = self.base / "vocab"
        self.vocab_dir.mkdir(parents=True, exist_ok=True)
        self.vocab_file = self.vocab_dir / "vocab.json"
        self.vocab_file.write_text(json.dumps(self.vocab))
        self.vocab_sha = file_hash(self.vocab_file)

        # Create fake source file and compute real identity
        source_file = self.base / "fake_source.json.gz"
        with gzip.open(source_file, "wt", encoding="utf-8") as f:
            for i in range(25):
                f.write(json.dumps({"timestamp": f"2019-09-21T10:00:{i:02d}+00:00", "hostname": "sysclient0201.systemia.com"}) + "\n")
        self.source_obj = identity(source_file)
        self.source_id = digest(self.source_obj)

        # Create fake split manifest and compute real hash
        self.split_dir = self.base / "split"
        self.split_dir.mkdir(parents=True, exist_ok=True)
        self.split_manifest_file = self.split_dir / "manifest.json"
        self.mask_name = f"{self.source_id}.split.gz"
        mask_path = self.split_dir / self.mask_name
        # Mask has 25 lines: line 10 has code 1 (train), line 20 has code 1 (train)
        mask_bytes = bytearray([0] * 25)
        mask_bytes[9] = 1  # 1-based line 10
        mask_bytes[19] = 1 # 1-based line 20
        with gzip.open(mask_path, "wb") as f:
            f.write(mask_bytes)

        mask_sha = file_hash(mask_path)
        self.pilot_manifest = {
            "schema": 1,
            "kind": "host_random_split",
            "seed": 2,
            "tokenizer_sha256": code_hashes(),
            "implementation": {"pipeline": "test"},
            "entries": [{
                "source": self.source_obj,
                "host": "sysclient0201",
                "day": "2019-09-21",
                "artifact": self.mask_name,
                "sha256": mask_sha,
                "counts": {"lines": 25, "0": 23, "1": 2},
                "allocation": {"1": [2, 0, 0], "2": [0, 0, 0]},
            }],
            "counts": {
                "train": {"label_0": 1, "label_1": 1},
                "val": {"label_0": 0, "label_1": 0},
                "test": {"label_0": 0, "label_1": 0},
            },
        }
        self.split_manifest_file.write_text(json.dumps(self.pilot_manifest, indent=2))
        self.split_sha = file_hash(self.split_manifest_file)

        self.vocab_meta = {
            "schema_version": 7,
            "vocab_size": len(self.vocab),
            "vocabulary_sha256": self.vocab_sha,
            "split_sha256": self.split_sha,
        }
        self.vocab_meta_file = self.vocab_dir / "vocab_metadata.json"
        self.vocab_meta_file.write_text(json.dumps(self.vocab_meta))

        # Create a valid fixture shard
        buf = ShardBuffer(len(self.vocab))
        buf.append([0, 1, 2], 0, 10)
        buf.append([0, 2], 1, 20)
        payload, meta = buf.encode()
        shard_rel_path = f"run1/{self.source_id}/train_000000.npz"
        shard_abs_path = self.vol_dir / shard_rel_path
        shard_abs_path.parent.mkdir(parents=True, exist_ok=True)
        shard_abs_path.write_bytes(payload)

        self.shard_part = {
            "source_id": self.source_id,
            "split": "train",
            "volume": "ssd",
            "path": shard_rel_path,
            "rows": meta["rows"],
            "nnz": meta["nnz"],
            "label_0": meta["label_0"],
            "label_1": meta["label_1"],
            "bytes": meta["bytes"],
            "source_line_first": meta["source_line_first"],
            "source_line_last": meta["source_line_last"],
            "sha256": meta["sha256"],
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # 1. Volume-relative path resolution and strict escape/unknown volume rejection
    def test_01_volume_relative_paths_and_escape_rejection(self):
        # Valid part succeeds
        valid = validate_and_resolve_shard_parts([self.shard_part], self.roots)
        self.assertEqual(len(valid), 1)

        # Escape path fails
        escape_part = dict(self.shard_part, path="../../../etc/passwd")
        with self.assertRaisesRegex(ValueError, "escapes volume root"):
            validate_and_resolve_shard_parts([escape_part], self.roots)

        # Unknown volume fails
        unknown_part = dict(self.shard_part, volume="hdd_other")
        with self.assertRaisesRegex(ValueError, "Unknown or missing volume"):
            validate_and_resolve_shard_parts([unknown_part], self.roots)

    # 2. Receipt without 'index' field publishes and verifies cleanly
    def test_02_receipt_without_index_field_publishes_and_verifies(self):
        shards_dir = self.base / "shards_t2"
        shards_dir.mkdir(parents=True, exist_ok=True)
        self.assertNotIn("index", self.shard_part)

        mpath = publish_shard_manifest(
            shards_dir=shards_dir,
            volumes=self.volumes,
            pilot_manifest=self.pilot_manifest,
            split_sha=self.split_sha,
            vocab_file_path=self.vocab_file,
            vocab_meta_path=self.vocab_meta_file,
            vocabulary=self.vocab,
            shard_parts=[self.shard_part],
            stats={"rows": 2},
            context_config=CONTEXT_CONFIG,
        )
        self.assertTrue(mpath.is_file())
        metrics = verify_shards_dataset(mpath)
        self.assertEqual(metrics["verified_shards"], 1)
        self.assertEqual(metrics["total_rows"], 2)

    # 3. Existing incompatible manifest/assets rejected and checksum of all files unchanged
    def test_03_existing_incompatible_manifest_rejected_and_files_unchanged(self):
        shards_dir = self.base / "shards_t3"
        shards_dir.mkdir(parents=True, exist_ok=True)

        # First publish valid manifest
        mpath = publish_shard_manifest(
            shards_dir=shards_dir,
            volumes=self.volumes,
            pilot_manifest=self.pilot_manifest,
            split_sha=self.split_sha,
            vocab_file_path=self.vocab_file,
            vocab_meta_path=self.vocab_meta_file,
            vocabulary=self.vocab,
            shard_parts=[self.shard_part],
            stats={"rows": 2},
            context_config=CONTEXT_CONFIG,
        )
        self.assertTrue(mpath.is_file())

        # Snapshot every file in shards_dir and volume
        before_manifest_state = {str(p): file_hash(p) for p in shards_dir.rglob("*") if p.is_file()}
        before_vol_state = {str(p): file_hash(p) for p in self.vol_dir.rglob("*") if p.is_file()}

        # Now attempt to republish with incompatible split_sha
        with self.assertRaisesRegex(ValueError, "incompatible with new publication request"):
            publish_shard_manifest(
                shards_dir=shards_dir,
                volumes=self.volumes,
                pilot_manifest=self.pilot_manifest,
                split_sha="0000000000000000000000000000000000000000000000000000000000000000",
                vocab_file_path=self.vocab_file,
                vocab_meta_path=self.vocab_meta_file,
                vocabulary=self.vocab,
                shard_parts=[self.shard_part],
                stats={"rows": 2},
                context_config=CONTEXT_CONFIG,
            )

        # Verify that all files remain bit-for-bit unchanged
        after_manifest_state = {str(p): file_hash(p) for p in shards_dir.rglob("*") if p.is_file()}
        after_vol_state = {str(p): file_hash(p) for p in self.vol_dir.rglob("*") if p.is_file()}
        self.assertEqual(before_manifest_state, after_manifest_state)
        self.assertEqual(before_vol_state, after_vol_state)

    # 4. Matching rerun reuses existing artifacts
    def test_04_matching_rerun_reuses_existing_artifacts(self):
        shards_dir = self.base / "shards_t4"
        shards_dir.mkdir(parents=True, exist_ok=True)

        mpath1 = publish_shard_manifest(
            shards_dir=shards_dir,
            volumes=self.volumes,
            pilot_manifest=self.pilot_manifest,
            split_sha=self.split_sha,
            vocab_file_path=self.vocab_file,
            vocab_meta_path=self.vocab_meta_file,
            vocabulary=self.vocab,
            shard_parts=[self.shard_part],
            stats={"rows": 2},
            context_config=CONTEXT_CONFIG,
        )
        mtime1 = mpath1.stat().st_mtime_ns

        mpath2 = publish_shard_manifest(
            shards_dir=shards_dir,
            volumes=self.volumes,
            pilot_manifest=self.pilot_manifest,
            split_sha=self.split_sha,
            vocab_file_path=self.vocab_file,
            vocab_meta_path=self.vocab_meta_file,
            vocabulary=self.vocab,
            shard_parts=[self.shard_part],
            stats={"rows": 2},
            context_config=CONTEXT_CONFIG,
        )
        self.assertEqual(mpath1, mpath2)
        self.assertEqual(mtime1, mpath2.stat().st_mtime_ns)

    # 5. Split hash mismatch rejected; missing hash requires migration
    def test_05_split_sha_mismatch_rejected_missing_requires_migration(self):
        meta_test_file = self.base / "vocab_meta_test.json"
        manifest_file = self.split_manifest_file

        # Case A: Mismatch rejected
        meta_mismatch = {"split_sha256": "aaaa"}
        meta_test_file.write_text(json.dumps(meta_mismatch))
        with self.assertRaisesRegex(ValueError, "Provenance mismatch"):
            migrate_provenance_split_sha256(meta_test_file, self.split_sha, manifest_file)

        # Case B: Missing hash successfully migrated with backup and verified evidence
        meta_missing = {"vocab_size": 3, "vocabulary_sha256": self.vocab_sha}
        meta_test_file.write_text(json.dumps(meta_missing))
        # Also copy vocab.json beside it
        shutil.copy2(self.vocab_file, self.base / "vocab.json")

        migrated = migrate_provenance_split_sha256(meta_test_file, self.split_sha, manifest_file)
        self.assertTrue(migrated)

        updated = json.loads(meta_test_file.read_text())
        self.assertEqual(updated["split_sha256"], self.split_sha)
        self.assertTrue(meta_test_file.with_suffix(".json.pre_migration.bak").is_file())
        self.assertTrue((self.base / "provenance_migration.json").is_file())

    # 6. Verify-only is strictly read-only on fixture: zero files added, modified, or deleted
    def test_06_verify_only_is_strictly_readonly(self):
        pilot_ns = self.base / "pilot_ro_fixture"
        split_dir = pilot_ns / "split"
        vocab_dir = pilot_ns / "vocab"
        shards_dir = pilot_ns / "shards"
        vol_ssd = shards_dir / "volumes/ssd"
        for d in (split_dir, vocab_dir, shards_dir, vol_ssd):
            d.mkdir(parents=True, exist_ok=True)

        manifest_data = dict(self.pilot_manifest)
        manifest_path_f = split_dir / "manifest.json"
        manifest_path_f.write_text(json.dumps(manifest_data, indent=2))
        split_sha_f = file_hash(manifest_path_f)
        (vocab_dir / "vocab.json").write_text(json.dumps(self.vocab))
        f_vocab_meta = dict(self.vocab_meta, split_sha256=split_sha_f)
        (vocab_dir / "vocab_metadata.json").write_text(json.dumps(f_vocab_meta))
        vols_config = {
            "volumes": [{
                "id": "ssd",
                "path": str(vol_ssd),
                "max_bytes": 10_000_000_000,
                "reserve_free_bytes": 1_000_000_000,
            }]
        }
        (pilot_ns / "volumes.json").write_text(json.dumps(vols_config))

        chk_dir = shards_dir / "checkpoints/pilot_continuous"
        chk_dir.mkdir(parents=True, exist_ok=True)

        # Copy shard into volume
        dest_shard = vol_ssd / self.shard_part["path"]
        dest_shard.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.vol_dir / self.shard_part["path"], dest_shard)

        receipt = {
            "source_id": self.source_id,
            "stats": {"rows": 2},
            "shards": [self.shard_part],
        }
        (chk_dir / f"{self.source_id}.json").write_text(json.dumps(receipt))

        # Copy split mask
        shutil.copy2(self.split_dir / self.mask_name, split_dir / self.mask_name)

        # Snapshot exact file tree and hashes before
        before_state = {str(p.relative_to(pilot_ns)): file_hash(p) for p in pilot_ns.rglob("*") if p.is_file()}

        # Call production execute_pilot in verify-only mode
        report = execute_pilot(mode="verify-only", pilot_base=pilot_ns, save_report=False)
        self.assertIsInstance(report, dict)
        self.assertEqual(report["mode"], "verify-only")

        # Snapshot exact file tree and hashes after
        after_state = {str(p.relative_to(pilot_ns)): file_hash(p) for p in pilot_ns.rglob("*") if p.is_file()}

        # Assert zero files were added, deleted, or modified
        self.assertEqual(before_state, after_state, "Verify-only mode MUST NOT add, delete, or modify any files!")
        self.assertFalse((pilot_ns / "pilot_report.json").exists())
        self.assertFalse((pilot_ns / ".pilot_report.json.tmp").exists())

    # 7. Mask parity verification detects duplicates, missing rows, and separates labels
    def test_07_mask_parity_verification_logic(self):
        # Case A: Valid mask parity
        res_valid = verify_mask_and_target_parity(
            pilot_manifest=self.pilot_manifest,
            split_dir=self.split_dir,
            all_shard_parts=[self.shard_part],
            roots=self.roots,
            vocab_width=len(self.vocab),
        )
        self.assertEqual(res_valid["mask_parity_status"], "VERIFIED (100% PARITY)")
        self.assertEqual(res_valid["label_parity_status"], "NOT_VERIFIED (MASK_CONTAINS_SPLIT_CODES_ONLY)")

        # Case B: Duplicate line in shards causes failure
        dup_part = dict(self.shard_part)
        res_dup = verify_mask_and_target_parity(
            pilot_manifest=self.pilot_manifest,
            split_dir=self.split_dir,
            all_shard_parts=[self.shard_part, dup_part],
            roots=self.roots,
            vocab_width=len(self.vocab),
        )
        self.assertEqual(res_dup["mask_parity_status"], "FAILED")
        self.assertIn("Duplicate", res_dup.get("reason", ""))

        # Case C: Missing target row from shards causes count mismatch failure
        empty_manifest = dict(self.pilot_manifest)
        # Create mask with 3 targets instead of 2
        bad_mask_path = self.split_dir / "bad.split.gz"
        b_bytes = bytearray([0] * 25)
        b_bytes[5] = 1
        with gzip.open(bad_mask_path, "wb") as f:
            f.write(b_bytes)
        bad_manifest = {
            "entries": [{
                "source": self.source_obj,
                "artifact": "bad.split.gz",
                "counts": {"lines": 25},
            }]
        }
        res_mismatch = verify_mask_and_target_parity(
            pilot_manifest=bad_manifest,
            split_dir=self.split_dir,
            all_shard_parts=[self.shard_part],
            roots=self.roots,
            vocab_width=len(self.vocab),
        )
        self.assertEqual(res_mismatch["mask_parity_status"], "FAILED")

    # 8. Event illustrations decoded accurately from shard
    def test_08_event_illustrations_decoded_from_shard(self):
        X, y, lines = decode_shard(self.vol_dir / self.shard_part["path"], len(self.vocab))
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], 10)
        self.assertEqual(y[0], 0)
        self.assertEqual(lines[1], 20)
        self.assertEqual(y[1], 1)

        inv_vocab = {v: k for k, v in self.vocab.items()}
        row0_tokens = [inv_vocab[c] for c in X.getrow(0).indices]
        self.assertIn("ctx::actor::exe=cmd.exe", row0_tokens)
        self.assertIn("action::read", row0_tokens)

    # 9. Suffix resume verification executes suffix under recovered state and matches continuous TF/DF and shards
    def test_09_suffix_resume_verification_production_orchestration(self):
        from ML.code.preprocess import stratified_pipeline as sp

        verif_base = self.base / "verif_orch_test"
        verif_base.mkdir()

        # Build 2-day synthetic telemetry with PROCESS CREATE and PID recycling
        # Day 21 (prefix): PROCESS CREATE with PID 1001 (code 0: background)
        f21 = verif_base / "telemetry_21.json.gz"
        evt21 = {
            "hostname": "sysclient0201.systemia.com",
            "actorID": "11111111-1111-1111-1111-111111111111",
            "objectID": "22222222-2222-2222-2222-222222222222",
            "object": "PROCESS",
            "action": "CREATE",
            "pid": 1001,
            "properties": {"image_path": "C:\\Windows\\System32\\cmd.exe"},
            "timestamp": "2019-09-21T10:00:00+00:00",
            "label": 0,
        }
        with gzip.open(f21, "wt", encoding="utf-8") as dst:
            dst.write(json.dumps(evt21) + "\n")
        mask21 = f21.name + ".split.gz"
        with gzip.open(verif_base / mask21, "wb") as dst:
            dst.write(bytes([0]))

        # Day 22 (suffix):
        # 1. PROCESS CREATE where old PID 1001 is reassigned to new UUID 33333333... (recycled PID)
        # 2. PROCESS CREATE with new PID 1002
        f22 = verif_base / "telemetry_22.json.gz"
        evt22_1 = {
            "hostname": "sysclient0201.systemia.com",
            "actorID": "11111111-1111-1111-1111-111111111111",
            "objectID": "33333333-3333-3333-3333-333333333333",
            "object": "PROCESS",
            "action": "CREATE",
            "pid": 1001,
            "properties": {"image_path": "C:\\Windows\\System32\\powershell.exe"},
            "timestamp": "2019-09-22T10:00:00+00:00",
            "label": 0,
        }
        evt22_2 = {
            "hostname": "sysclient0201.systemia.com",
            "actorID": "22222222-2222-2222-2222-222222222222",
            "objectID": "44444444-4444-4444-4444-444444444444",
            "object": "PROCESS",
            "action": "CREATE",
            "pid": 1002,
            "properties": {"image_path": "C:\\Windows\\System32\\notepad.exe"},
            "timestamp": "2019-09-22T10:05:00+00:00",
            "label": 0,
        }
        with gzip.open(f22, "wt", encoding="utf-8") as dst:
            dst.write(json.dumps(evt22_1) + "\n" + json.dumps(evt22_2) + "\n")
        mask22 = f22.name + ".split.gz"
        with gzip.open(verif_base / mask22, "wb") as dst:
            dst.write(bytes([1, 1]))

        entries = [
            {
                "source": sp.identity(f21),
                "artifact": mask21,
                "benign": True,
                "host": "sysclient0201",
                "day": "2019-09-21",
                "counts": {"lines": 1, "0": 1, "1": 0},
                "allocation": {"1": [0, 0, 0], "2": [0, 0, 0]},
            },
            {
                "source": sp.identity(f22),
                "artifact": mask22,
                "benign": True,
                "host": "sysclient0201",
                "day": "2019-09-22",
                "counts": {"lines": 2, "0": 0, "1": 2},
                "allocation": {"1": [2, 0, 0], "2": [0, 0, 0]},
            },
        ]

        pilot_manifest = {
            "schema": 1,
            "kind": "host_random_split",
            "seed": 2,
            "tokenizer_sha256": code_hashes(),
            "entries": entries,
            "counts": {"train": {"label_0": 2, "label_1": 0}, "val": {"label_0": 0, "label_1": 0}, "test": {"label_0": 0, "label_1": 0}},
        }
        (verif_base / "manifest.json").write_text(json.dumps(pilot_manifest))

        cfg = {"enabled": True, "max_processes_per_host": 1000, "ttl_seconds": 86400.0}

        # 1. Continuous run to produce ground-truth continuous checkpoints
        cont_shards_dir = verif_base / "shards"
        cont_vol = cont_shards_dir / "volumes/ssd"
        cont_vol.mkdir(parents=True, exist_ok=True)
        initialize_ledger(cont_shards_dir, [{"id": "ssd", "path": str(cont_vol), "max_bytes": 1000000000, "reserve_free_bytes": 0}])

        # Continuous vocab
        cont_vocab_dir = verif_base / "checkpoints/vocab_continuous"
        cont_vocab_dir.mkdir(parents=True, exist_ok=True)
        cont_vocab_res = sp.vocab_host(entries, verif_base, cont_vocab_dir, cfg)

        # Continuous shards
        cont_shard_res = bm.process_host(
            entries,
            split_dir=verif_base,
            vocab=self.vocab,
            control=cont_shards_dir,
            run_id="pilot_continuous",
            volumes=[{"id": "ssd", "path": str(cont_vol)}],
            rows_per_shard=100,
            buffer_bytes=1024 * 1024,
            context_config=cfg,
        )

        # 2. Call production run_suffix_resume_verification with execute_suffix=True
        # To prove that Day 21 raw telemetry is NOT read during suffix resume, delete the Day 21 raw file!
        d21_raw = Path(entries[0]["source"]["path"])
        d21_raw.unlink()
        self.assertFalse(d21_raw.exists(), "Day 21 raw file deleted to prove resume does not read it")

        verif_output_dir = verif_base / "verification_ns"
        resume_res = run_suffix_resume_verification(
            pilot_dir=verif_base,
            host_entries=entries,
            split_dir=verif_base,
            vocabulary=self.vocab,
            context_config=cfg,
            execute_suffix=True,
            verif_namespace=verif_output_dir,
        )

        self.assertEqual(resume_res["prefix_checkpoint_restoration_status"], "VERIFIED")
        self.assertEqual(resume_res["real_data_suffix_equivalence_status"], "VERIFIED")
        self.assertFalse(resume_res["day21_resumed_from_cache"])

        # Check native Schema v3 resume reporting (no adapter)
        self.assertFalse(resume_res["compatibility_adapter_applied"])
        self.assertIsNone(resume_res["adapter"])
        self.assertTrue(resume_res["pid_audit_history_restored"])
        self.assertEqual(resume_res["pid_reuse_counter_equivalence"], "VERIFIED")
        self.assertEqual(
            resume_res["feature_equivalence_verdict"],
            "Production schema v3 native resume VERIFIED on SysClient0201 Day 22",
        )

        self.assertEqual(resume_res["replayed_lines"]["expected_source_lines"], 2)
        self.assertEqual(resume_res["replayed_lines"]["measured_vocab_train_rows"], 2)
        self.assertEqual(resume_res["replayed_lines"]["measured_shard_target_rows"], 2)
        # Raw lines counter is not instrumented by process_source; verify it is None (null) and not erroneously reported as 0
        self.assertIsNone(
            resume_res["replayed_lines"]["measured_shard_lines_read"],
            "measured_shard_lines_read must be None (JSON null) when process_source lacks line counter",
        )
        self.assertNotEqual(
            resume_res["replayed_lines"]["measured_shard_lines_read"],
            0,
            "Must not report 0 as a measured line count when process_source does not instrument line counter",
        )
        self.assertEqual(
            resume_res["replayed_lines"].get("measured_shard_lines_read_reason"),
            "not instrumented",
            "Must provide explicit reason 'not instrumented' for null measured_shard_lines_read",
        )
        self.assertTrue(resume_res["comparisons"]["tf_matches"])
        self.assertTrue(resume_res["comparisons"]["df_matches"])
        self.assertTrue(resume_res["comparisons"]["lines_and_labels_match"])
        self.assertTrue(resume_res["comparisons"]["sparse_feature_columns_match"])
        self.assertTrue(resume_res["comparisons"]["shard_sha256_match"])

    # 10. Suffix verification failure cases: corrupt prefix or suffix failure
    def test_10_suffix_verification_failure_handling(self):
        cfg = {"enabled": True, "max_processes_per_host": 1000, "ttl_seconds": 86400.0}
        bad_base = self.base / "bad_verif_base"
        bad_base.mkdir()

        # Prefix missing -> returns FAILED
        res = run_suffix_resume_verification(
            pilot_dir=bad_base,
            host_entries=self.pilot_manifest["entries"],
            split_dir=self.split_dir,
            vocabulary=self.vocab,
            context_config=cfg,
            execute_suffix=True,
        )
        self.assertEqual(res["prefix_checkpoint_restoration_status"], "FAILED")
        self.assertEqual(res["real_data_suffix_equivalence_status"], "FAILED")

    # 11. execute_pilot truthful report status on provenance mismatch
    def test_11_execute_pilot_truthful_report_provenance_failure(self):
        pilot_ns = self.base / "pilot_mismatch_fixture"
        split_dir = pilot_ns / "split"
        vocab_dir = pilot_ns / "vocab"
        shards_dir = pilot_ns / "shards"
        vol_ssd = shards_dir / "volumes/ssd"
        for d in (split_dir, vocab_dir, shards_dir, vol_ssd):
            d.mkdir(parents=True, exist_ok=True)

        manifest_data = dict(self.pilot_manifest)
        (split_dir / "manifest.json").write_text(json.dumps(manifest_data, indent=2))
        (vocab_dir / "vocab.json").write_text(json.dumps(self.vocab))

        # Intentionally mismatch split_sha256 in vocabulary metadata
        bad_vocab_meta = dict(self.vocab_meta, split_sha256="mismatch_hash_12345")
        (vocab_dir / "vocab_metadata.json").write_text(json.dumps(bad_vocab_meta))
        vols_config = {
            "volumes": [{
                "id": "ssd",
                "path": str(vol_ssd),
                "max_bytes": 10_000_000_000,
                "reserve_free_bytes": 1_000_000_000,
            }]
        }
        (pilot_ns / "volumes.json").write_text(json.dumps(vols_config))

        chk_dir = shards_dir / "checkpoints/pilot_continuous"
        chk_dir.mkdir(parents=True, exist_ok=True)
        dest_shard = vol_ssd / self.shard_part["path"]
        dest_shard.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.vol_dir / self.shard_part["path"], dest_shard)
        receipt = {"source_id": self.source_id, "stats": {"rows": 2}, "shards": [self.shard_part]}
        (chk_dir / f"{self.source_id}.json").write_text(json.dumps(receipt))
        shutil.copy2(self.split_dir / self.mask_name, split_dir / self.mask_name)

        # Call execute_pilot directly
        report = execute_pilot(mode="verify-only", pilot_base=pilot_ns, save_report=False)
        self.assertEqual(report["component_statuses"]["vocabulary_status"], "FAILED (PROVENANCE_MISMATCH)")
        self.assertEqual(report["status"], "FAILED")
        self.assertNotEqual(report["status"], "COMPLETED")

    # 12. Intentional label tampering detection and rejection of fake verification
    def test_12_intentional_label_tampering_and_oracle_rejection(self):
        # Create a tampered shard: lines and split are identical to mask (10 and 20 are train),
        # but label for line 10 is intentionally tampered from 0 to 1
        tampered_buf = ShardBuffer(len(self.vocab))
        tampered_buf.append([0, 1, 2], 1, 10)  # Tampered! Original was label 0
        tampered_buf.append([0, 2], 1, 20)
        payload, meta = tampered_buf.encode()
        tampered_rel = f"tampered/{self.source_id}/train_000000.npz"
        tampered_abs = self.vol_dir / tampered_rel
        tampered_abs.parent.mkdir(parents=True, exist_ok=True)
        tampered_abs.write_bytes(payload)

        tampered_part = dict(
            self.shard_part,
            path=tampered_rel,
            bytes=len(payload),
            sha256=file_hash(tampered_abs),
            rows=meta["rows"],
            nnz=meta["nnz"],
            label_0=meta["label_0"],
            label_1=meta["label_1"],
            source_line_first=meta["source_line_first"],
            source_line_last=meta["source_line_last"],
        )

        # Ground truth oracle where line 10 is expected to be 0
        reference_oracle = {
            (self.source_id, 10): 0,
            (self.source_id, 20): 1,
        }

        # 1. Authentic cross-referencing detects mismatch
        res = verify_mask_and_target_parity(
            pilot_manifest=self.pilot_manifest,
            split_dir=self.split_dir,
            all_shard_parts=[tampered_part],
            roots=self.roots,
            vocab_width=len(self.vocab),
            reference_labels=reference_oracle,
        )
        self.assertEqual(res["mask_parity_status"], "VERIFIED (100% PARITY)")
        self.assertEqual(res["label_parity_status"], "FAILED")
        self.assertIn("Label mismatch", res["reason"])

        # 2. cross_reference_labels=True without reference_labels is rejected (NOT_VERIFIED)
        res_rejected = verify_mask_and_target_parity(
            pilot_manifest=self.pilot_manifest,
            split_dir=self.split_dir,
            all_shard_parts=[self.shard_part],
            roots=self.roots,
            vocab_width=len(self.vocab),
            cross_reference_labels=True,
        )
        self.assertEqual(res_rejected["mask_parity_status"], "VERIFIED (100% PARITY)")
        self.assertEqual(res_rejected["label_parity_status"], "NOT_VERIFIED (REJECTED_WITHOUT_INDEPENDENT_LABEL_ORACLE)")
        self.assertIn("Refusing fake verification", res_rejected["reason"])

    # 13. Strict prefix checkpoint validation rejections
    def test_13_strict_prefix_checkpoint_validation_rejections(self):
        cfg = {"enabled": True, "max_processes_per_host": 1000, "ttl_seconds": 86400.0}
        prefix_base = self.base / "prefix_test_base"
        shards_chk = prefix_base / "shards/checkpoints/pilot_continuous"
        vocab_chk = prefix_base / "checkpoints/vocab_continuous"
        shards_chk.mkdir(parents=True, exist_ok=True)
        vocab_chk.mkdir(parents=True, exist_ok=True)

        d21_entry = self.pilot_manifest["entries"][0]
        d21_source_id = digest(d21_entry["source"])
        d21_vocab_key = digest(dict(entry=d21_entry, context_config=cfg))

        def make_chk(path, host="sysclient0201", watermark=1569124799000000):
            t = HostProcessContextTracker(ProcessContextConfig.from_dict(cfg))
            t.hosts[host] = {}
            from ML.code.preprocess.process_context_tracker import ProcessNode
            t.hosts[host]["uuid1"] = ProcessNode(uuid="uuid1", host=host, last_seen_t=watermark)
            t.set_watermark(host, watermark)
            t.save_checkpoint(path)
            return file_hash(path)

        s_chk_file = shards_chk / f"tracker_{d21_source_id}.json"
        s_sha = make_chk(s_chk_file)
        v_chk_file = vocab_chk / f"tracker_{d21_vocab_key}.json"
        v_sha = make_chk(v_chk_file)

        # Baseline valid receipts
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": s_sha,
        }))
        (vocab_chk / f"{d21_vocab_key}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": v_chk_file.name,
            "checkpoint_sha256": v_sha,
        }))

        # Valid baseline passes
        valid, details = validate_prefix_checkpoints(prefix_base, d21_entry, cfg)
        self.assertTrue(valid)

        # Subtest a: Checkpoint checksum mismatch
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": "corrupted_sha_12345",
        }))
        valid, details = validate_prefix_checkpoints(prefix_base, d21_entry, cfg)
        self.assertFalse(valid)
        self.assertIn("checksum mismatch", details["error"])
        # Restore valid
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": s_sha,
        }))

        # Subtest b: Wrong host in checkpoint
        bad_host_file = shards_chk / "bad_host.json"
        bad_host_sha = make_chk(bad_host_file, host="sysclient9999")
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": bad_host_file.name,
            "checkpoint_sha256": bad_host_sha,
        }))
        valid, details = validate_prefix_checkpoints(prefix_base, d21_entry, cfg)
        self.assertFalse(valid)
        self.assertIn("not present in Day 21", details["error"])
        # Restore valid
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": s_sha,
        }))

        # Subtest c: Wrong source_id in receipt
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": "wrong_source_id",
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": s_sha,
        }))
        valid, details = validate_prefix_checkpoints(prefix_base, d21_entry, cfg)
        self.assertFalse(valid)
        self.assertIn("source_id mismatch", details["error"])
        # Restore valid
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": s_sha,
        }))

        # Subtest d: Watermark mismatch between shard and vocab
        diff_wm_file = vocab_chk / "diff_wm.json"
        diff_wm_sha = make_chk(diff_wm_file, watermark=1569120000000000)
        (vocab_chk / f"{d21_vocab_key}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": diff_wm_file.name,
            "checkpoint_sha256": diff_wm_sha,
        }))
        valid, details = validate_prefix_checkpoints(prefix_base, d21_entry, cfg)
        self.assertFalse(valid)
        self.assertIn("watermark mismatch", details["error"])

        # Subtest e: Both checkpoints have matching watermark, but exceeding Day 21 boundary
        exceed_wm_s = shards_chk / "exceed_wm_s.json"
        exceed_wm_v = vocab_chk / "exceed_wm_v.json"
        exceed_sha_s = make_chk(exceed_wm_s, watermark=1569130000000000)  # In Day 22
        exceed_sha_v = make_chk(exceed_wm_v, watermark=1569130000000000)  # In Day 22
        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": exceed_wm_s.name,
            "checkpoint_sha256": exceed_sha_s,
        }))
        (vocab_chk / f"{d21_vocab_key}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": exceed_wm_v.name,
            "checkpoint_sha256": exceed_sha_v,
        }))
        valid, details = validate_prefix_checkpoints(prefix_base, d21_entry, cfg)
        self.assertFalse(valid)
        self.assertIn("exceeds end of 2019-09-21", details["error"])

    # 14. Existing suffix cache refusal
    def test_14_existing_suffix_cache_refusal(self):
        cfg = {"enabled": True, "max_processes_per_host": 1000, "ttl_seconds": 86400.0}
        v_base = self.base / "cache_refusal_base"
        shards_chk = v_base / "shards/checkpoints/pilot_continuous"
        vocab_chk = v_base / "checkpoints/vocab_continuous"
        shards_chk.mkdir(parents=True, exist_ok=True)
        vocab_chk.mkdir(parents=True, exist_ok=True)

        d21_entry = self.pilot_manifest["entries"][0]
        d21_source_id = digest(d21_entry["source"])
        d21_vocab_key = digest(dict(entry=d21_entry, context_config=cfg))

        t = HostProcessContextTracker(ProcessContextConfig.from_dict(cfg))
        t.hosts["sysclient0201"] = {}
        from ML.code.preprocess.process_context_tracker import ProcessNode
        t.hosts["sysclient0201"]["uuid1"] = ProcessNode(uuid="uuid1", host="sysclient0201", last_seen_t=1569124799000000)
        t.set_watermark("sysclient0201", 1569124799000000)

        s_file = shards_chk / f"tracker_{d21_source_id}.json"
        t.save_checkpoint(s_file)
        v_file = vocab_chk / f"tracker_{d21_vocab_key}.json"
        t.save_checkpoint(v_file)

        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_file.name,
            "checkpoint_sha256": file_hash(s_file),
        }))
        (vocab_chk / f"{d21_vocab_key}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": v_file.name,
            "checkpoint_sha256": file_hash(v_file),
        }))

        d22_entry = dict(d21_entry, day="2019-09-22")
        entries = [d21_entry, d22_entry]
        d22_vocab_key = digest(dict(entry=d22_entry, context_config=cfg))

        # In verification namespace, pre-populate old vocab cache
        verif_ns = v_base / "verif_ns"
        (verif_ns / "vocab_resume").mkdir(parents=True, exist_ok=True)
        (verif_ns / f"vocab_resume/{d22_vocab_key}.json").write_text(json.dumps({"tf": {}, "df": {}}))

        res = run_suffix_resume_verification(
            pilot_dir=v_base,
            host_entries=entries,
            split_dir=self.split_dir,
            vocabulary=self.vocab,
            context_config=cfg,
            execute_suffix=True,
            verif_namespace=verif_ns,
        )
        self.assertEqual(res["real_data_suffix_equivalence_status"], "FAILED")
        self.assertIn("already contains cached suffix artifacts", res["reason"])

    # 15. Preflight aborts before replay on corrupt continuous reference
    def test_15_preflight_aborts_before_replay_on_corrupt_continuous_reference(self):
        cfg = {"enabled": True, "max_processes_per_host": 1000, "ttl_seconds": 86400.0}
        v_base = self.base / "preflight_abort_base"
        shards_chk = v_base / "shards/checkpoints/pilot_continuous"
        vocab_chk = v_base / "checkpoints/vocab_continuous"
        shards_chk.mkdir(parents=True, exist_ok=True)
        vocab_chk.mkdir(parents=True, exist_ok=True)

        d21_entry = self.pilot_manifest["entries"][0]
        d21_source_id = digest(d21_entry["source"])
        d21_vocab_key = digest(dict(entry=d21_entry, context_config=cfg))

        t = HostProcessContextTracker(ProcessContextConfig.from_dict(cfg))
        t.hosts["sysclient0201"] = {}
        from ML.code.preprocess.process_context_tracker import ProcessNode
        t.hosts["sysclient0201"]["uuid1"] = ProcessNode(uuid="uuid1", host="sysclient0201", last_seen_t=1569124799000000)
        t.set_watermark("sysclient0201", 1569124799000000)

        s_file = shards_chk / f"tracker_{d21_source_id}.json"
        t.save_checkpoint(s_file)
        v_file = vocab_chk / f"tracker_{d21_vocab_key}.json"
        t.save_checkpoint(v_file)

        (shards_chk / f"{d21_source_id}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": s_file.name,
            "checkpoint_sha256": file_hash(s_file),
        }))
        (vocab_chk / f"{d21_vocab_key}.json").write_text(json.dumps({
            "source_id": d21_source_id,
            "checkpoint_file": v_file.name,
            "checkpoint_sha256": file_hash(v_file),
        }))

        d22_entry = dict(d21_entry, day="2019-09-22")
        entries = [d21_entry, d22_entry]
        d22_vocab_key = digest(dict(entry=d22_entry, context_config=cfg))

        # Intentionally corrupt continuous reference receipt
        (vocab_chk / f"{d22_vocab_key}.json").write_text(json.dumps({
            "sha256": "missing_or_corrupt_cache_file",
        }))

        verif_ns = v_base / "verif_ns"
        res = run_suffix_resume_verification(
            pilot_dir=v_base,
            host_entries=entries,
            split_dir=self.split_dir,
            vocabulary=self.vocab,
            context_config=cfg,
            execute_suffix=True,
            verif_namespace=verif_ns,
        )
        self.assertEqual(res["real_data_suffix_equivalence_status"], "FAILED")
        self.assertIn("Preflight failed", res["reason"])
        # Verify no suffix replay files were created in verif_ns
        self.assertFalse((verif_ns / "vocab_resume").exists())

    # 16. Truthful overall status reporting and CLI nonzero exit codes
    def test_16_report_status_and_cli_exit_codes(self):
        # 1. execute_pilot status with label pending is PARTIAL_VERIFIED, not COMPLETED
        pilot_ns = self.base / "pilot_status_fixture"
        split_dir = pilot_ns / "split"
        vocab_dir = pilot_ns / "vocab"
        shards_dir = pilot_ns / "shards"
        vol_ssd = shards_dir / "volumes/ssd"
        for d in (split_dir, vocab_dir, shards_dir, vol_ssd):
            d.mkdir(parents=True, exist_ok=True)

        (split_dir / "manifest.json").write_text(json.dumps(self.pilot_manifest, indent=2))
        (vocab_dir / "vocab.json").write_text(json.dumps(self.vocab))
        (vocab_dir / "vocab_metadata.json").write_text(json.dumps(self.vocab_meta))
        vols_config = {"volumes": [{"id": "ssd", "path": str(vol_ssd), "max_bytes": 10_000_000_000, "reserve_free_bytes": 1_000_000_000}]}
        (pilot_ns / "volumes.json").write_text(json.dumps(vols_config))

        chk_dir = shards_dir / "checkpoints/pilot_continuous"
        chk_dir.mkdir(parents=True, exist_ok=True)
        v_chk_dir = pilot_ns / "checkpoints/vocab_continuous"
        v_chk_dir.mkdir(parents=True, exist_ok=True)

        d21_entry = self.pilot_manifest["entries"][0]
        d21_vocab_key = digest(dict(entry=d21_entry, context_config=CONTEXT_CONFIG))

        t = HostProcessContextTracker(ProcessContextConfig.from_dict(CONTEXT_CONFIG))
        t.hosts["sysclient0201"] = {}
        from ML.code.preprocess.process_context_tracker import ProcessNode
        t.hosts["sysclient0201"]["uuid1"] = ProcessNode(uuid="uuid1", host="sysclient0201", last_seen_t=1569124799000000)
        t.set_watermark("sysclient0201", 1569124799000000)

        s_chk_file = chk_dir / f"tracker_{self.source_id}.json"
        t.save_checkpoint(s_chk_file)
        v_chk_file = v_chk_dir / f"tracker_{d21_vocab_key}.json"
        t.save_checkpoint(v_chk_file)

        dest_shard = vol_ssd / self.shard_part["path"]
        dest_shard.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.vol_dir / self.shard_part["path"], dest_shard)
        receipt = {
            "source_id": self.source_id,
            "stats": {"rows": 2},
            "shards": [self.shard_part],
            "checkpoint_file": s_chk_file.name,
            "checkpoint_sha256": file_hash(s_chk_file),
        }
        (chk_dir / f"{self.source_id}.json").write_text(json.dumps(receipt))
        (v_chk_dir / f"{d21_vocab_key}.json").write_text(json.dumps({
            "source_id": self.source_id,
            "checkpoint_file": v_chk_file.name,
            "checkpoint_sha256": file_hash(v_chk_file),
        }))
        shutil.copy2(self.split_dir / self.mask_name, split_dir / self.mask_name)

        # Publish shard manifest
        publish_shard_manifest(
            shards_dir=shards_dir,
            volumes=vols_config["volumes"],
            pilot_manifest=self.pilot_manifest,
            split_sha=self.split_sha,
            vocab_file_path=vocab_dir / "vocab.json",
            vocab_meta_path=vocab_dir / "vocab_metadata.json",
            vocabulary=self.vocab,
            shard_parts=[self.shard_part],
            stats={"rows": 2},
            context_config=CONTEXT_CONFIG,
        )

        # In verify-only without oracle, label verification is NOT_VERIFIED, suffix is PENDING
        rep = execute_pilot(mode="verify-only", pilot_base=pilot_ns, save_report=False)
        self.assertEqual(rep["component_statuses"]["vocabulary_status"], "VERIFIED")
        self.assertEqual(rep["component_statuses"]["shard_integrity_status"], "VERIFIED")
        self.assertEqual(rep["component_statuses"]["mask_row_parity_status"], "VERIFIED (100% PARITY)")
        self.assertTrue(rep["component_statuses"]["label_verification_status"].startswith("NOT_VERIFIED"))
        self.assertEqual(rep["status"], "PARTIAL_VERIFIED (SUFFIX_AND_LABEL_PENDING)")
        self.assertNotEqual(rep["status"], "COMPLETED")

        # 2. CLI exits nonzero on failure
        # Case A: CLI with provenance mismatch -> exit 1
        bad_meta = dict(self.vocab_meta, split_sha256="bad_sha")
        (vocab_dir / "vocab_metadata.json").write_text(json.dumps(bad_meta))
        with self.assertRaises(SystemExit) as cm:
            pilot_main(["--pilot-base", str(pilot_ns), "--verify-only"])
        self.assertEqual(cm.exception.code, 1)

        # Restore valid
        (vocab_dir / "vocab_metadata.json").write_text(json.dumps(self.vocab_meta))

        # Case B: CLI with resume-verification failure -> exit 1
        with self.assertRaises(SystemExit) as cm:
            pilot_main(["--pilot-base", str(pilot_ns), "--resume-verification"])
        self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()

