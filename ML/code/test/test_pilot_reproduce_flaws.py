#!/usr/bin/env python3
"""Reproduction tests for existing flaws in pilot publication, verification, and report.

These tests call production functions directly and reproduce the flaws identified by the reviewer:
1. execute_pilot("verify-only") unconditionally writes pilot_report.json to disk (not read-only).
2. execute_pilot hardcodes vocabulary_status="VERIFIED" even when split_sha256 is missing or mismatched.
3. execute_pilot hardcodes mask_row_label_parity_status="VERIFIED (100% PARITY)" without verifying masks.
4. run_suffix_resume_verification does not perform TF/DF comparison or sparse row decoding.
5. run_suffix_resume_verification copies receipt to simulate cache hit instead of loading prefix checkpoint into worker.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

PROJECT_ROOT = next((p for p in Path(__file__).resolve().parents if (p / "AGENTS.md").is_file()), Path(__file__).resolve().parents[3])
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import ML.code.preprocess.run_pilot_sysclient0201 as pilot_prod


class PilotFlawReproductionTests(unittest.TestCase):

    def test_01_verify_only_must_not_write_report_file(self):
        """Flaw 1: execute_pilot('verify-only') currently writes .tmp and replaces pilot_report.json."""
        report_file = pilot_prod.PILOT_BASE / "pilot_report.json"
        self.assertTrue(report_file.is_file())
        mtime_before = report_file.stat().st_mtime_ns

        time.sleep(0.01)
        # Call production execute_pilot in verify-only mode
        report = pilot_prod.execute_pilot(mode="verify-only")

        # In true verify-only mode, report_file must NOT be modified or written
        mtime_after = report_file.stat().st_mtime_ns
        self.assertEqual(
            mtime_before,
            mtime_after,
            "Flaw reproduced: execute_pilot('verify-only') modified pilot_report.json on disk!"
        )

    def test_02_vocabulary_status_must_fail_on_provenance_mismatch(self):
        """Flaw 2: execute_pilot currently hardcodes vocabulary_status='VERIFIED' even when provenance_status is MISSING_OR_MISMATCH."""
        # Check current implementation in execute_pilot
        import inspect
        source = inspect.getsource(pilot_prod.execute_pilot)
        # Look for hardcoded '"vocabulary_status": "VERIFIED"'
        self.assertNotIn(
            '"vocabulary_status": "VERIFIED"',
            source,
            "Flaw reproduced: execute_pilot hardcodes '\"vocabulary_status\": \"VERIFIED\"'!"
        )

    def test_03_mask_parity_must_not_be_hardcoded_string(self):
        """Flaw 3: execute_pilot currently hardcodes mask_row_label_parity_status='VERIFIED (100% PARITY)'."""
        import inspect
        source = inspect.getsource(pilot_prod.execute_pilot)
        self.assertNotIn(
            '"mask_row_label_parity_status": "VERIFIED (100% PARITY)"',
            source,
            "Flaw reproduced: execute_pilot hardcodes '\"mask_row_label_parity_status\": \"VERIFIED (100% PARITY)\"'!"
        )

    def test_04_run_suffix_resume_verification_must_include_tf_df_and_sparse_checks(self):
        """Flaw 4: run_suffix_resume_verification lacks TF, DF, and sparse row comparison logic."""
        import inspect
        source = inspect.getsource(pilot_prod.run_suffix_resume_verification)
        # Current implementation does not check tf or df or sparse feature columns
        self.assertIn(
            "vocab_file",
            source,
            "Flaw reproduced: run_suffix_resume_verification does not call vocab_file for suffix replay!"
        )
        self.assertIn(
            "cont_vocab",
            source,
            "Flaw reproduced: run_suffix_resume_verification does not compare continuous TF/DF!"
        )

    def test_05_run_suffix_resume_verification_must_not_copy_receipt_for_cache_hit(self):
        """Flaw 5: run_suffix_resume_verification copies receipt to simulate cache hit instead of running suffix."""
        import inspect
        source = inspect.getsource(pilot_prod.run_suffix_resume_verification)
        self.assertNotIn(
            "d21_receipt",
            source,
            "Flaw reproduced: run_suffix_resume_verification copies d21_receipt to fake cache hit!"
        )

    def test_06_mixing_monotonic_and_mtime_clock_domains_flaw(self):
        """Flaw 6: Comparing filesystem st_mtime with time.monotonic() mixes clock domains.

        st_mtime is in POSIX epoch seconds (~1.7e9), whereas monotonic is seconds since boot (~1e4).
        If code compares `st_mtime < t_monotonic`, it always evaluates to False, failing to catch
        a pre-existing stale cache file!
        """
        import os
        import time

        with tempfile.NamedTemporaryFile() as tf:
            # Simulate a stale cache file created 100 seconds ago in wall clock time
            now_wall = time.time()
            stale_mtime = now_wall - 100.0
            os.utime(tf.name, (stale_mtime, stale_mtime))

            actual_mtime = Path(tf.name).stat().st_mtime
            mono_now = time.monotonic()

            # Buggy check: compares mtime against monotonic time
            # actual_mtime (~1.76e9) < mono_now (~50,000) is FALSE!
            buggy_detected = actual_mtime < mono_now - 1.0
            self.assertFalse(
                buggy_detected,
                "Bug confirmed: comparing st_mtime with monotonic time fails to detect stale mtime!"
            )

            # Correct check: compares mtime against time.time()
            correct_detected = actual_mtime < now_wall - 1.0
            self.assertTrue(
                correct_detected,
                "Correct check: comparing st_mtime with wall-clock time properly detects stale mtime!"
            )

        # Also inspect run_suffix_resume_verification to ensure it does not use time.monotonic() for st_mtime
        import inspect
        source = inspect.getsource(pilot_prod.run_suffix_resume_verification)
        self.assertNotIn(
            "st_mtime < t_v_start",
            source,
            "Flaw reproduced: run_suffix_resume_verification compares st_mtime with monotonic start time!"
        )
        self.assertNotIn(
            "st_mtime < t_s_start",
            source,
            "Flaw reproduced: run_suffix_resume_verification compares st_mtime with monotonic start time!"
        )

    def test_07_pid_tracker_key_error_without_adapter_flaw(self):
        """Flaw 7: Restoring checkpoint leaves pid_tracker empty, causing KeyError on PROCESS CREATE.

        Without adapter: observe() throws KeyError on first PROCESS CREATE with PID.
        With adapter: pid_tracker.setdefault(host, {}) prevents KeyError and allows replay.
        """
        from ML.code.preprocess.process_context_tracker import HostProcessContextTracker, ProcessContextConfig, ProcessNode

        # Simulate a tracker restored from checkpoint where hosts has sysclient0201
        tracker_no_adapter = HostProcessContextTracker(ProcessContextConfig())
        tracker_no_adapter.hosts["sysclient0201"] = {
            "11111111-1111-1111-1111-111111111111": ProcessNode(
                uuid="11111111-1111-1111-1111-111111111111",
                host="sysclient0201",
                last_seen_t=1569100000000000,
            )
        }
        # Notice pid_tracker is empty {} as left by load_checkpoint
        self.assertEqual(tracker_no_adapter.pid_tracker, {})

        create_event = {
            "hostname": "sysclient0201.systemia.com",
            "actorID": "11111111-1111-1111-1111-111111111111",
            "objectID": "22222222-2222-2222-2222-222222222222",
            "object": "PROCESS",
            "action": "CREATE",
            "pid": 2048,
            "timestamp": "2019-09-22T10:00:00+00:00",
        }

        # Without adapter: raises KeyError('sysclient0201')
        with self.assertRaises(KeyError) as ctx:
            tracker_no_adapter.observe(create_event, event_t=1569160000000000)
        self.assertIn("sysclient0201", str(ctx.exception))

        # With adapter: initializing pid_tracker prevents KeyError
        tracker_with_adapter = HostProcessContextTracker(ProcessContextConfig())
        tracker_with_adapter.hosts["sysclient0201"] = {
            "11111111-1111-1111-1111-111111111111": ProcessNode(
                uuid="11111111-1111-1111-1111-111111111111",
                host="sysclient0201",
                last_seen_t=1569100000000000,
            )
        }
        for h in tracker_with_adapter.hosts:
            tracker_with_adapter.pid_tracker.setdefault(h, {})

        # Should execute cleanly without error
        tracker_with_adapter.observe(create_event, event_t=1569160000000000)
        self.assertIn("sysclient0201", tracker_with_adapter.pid_tracker)
        self.assertIn(2048, tracker_with_adapter.pid_tracker["sysclient0201"])

        # Verify production runner natively loads Schema v3 and does NOT call setdefault adapter
        import inspect
        source = inspect.getsource(pilot_prod.run_suffix_resume_verification)
        self.assertNotIn("tracker_vocab.pid_tracker.setdefault", source)
        self.assertNotIn("tracker_shard.pid_tracker.setdefault", source)


if __name__ == "__main__":
    unittest.main()
