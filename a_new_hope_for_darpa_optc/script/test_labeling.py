#!/usr/bin/env python3
"""
Unit and Integration Tests for OpTC Host Log Labeling Pipeline
=============================================================
Tests:
1. Ground truth loading from JSON.gz and directories
2. Label injection accuracy (1 for malicious IDs, 0 for benign IDs)
3. Output integrity verification and line count matching
4. Error handling & safety rollback (ensuring source files are never deleted on failure)
5. Multi-worker batch execution
"""

import os
import sys
import json
import gzip
import shutil
import tempfile
import unittest

# Add script directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from label_optc_host_logs import (
    load_ground_truth,
    _init_worker,
    _process_file_task,
    OpTCLabelingPipeline,
    setup_logger
)

class TestOpTCLabeling(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="optc_test_")
        self.hdd_dir = os.path.join(self.temp_dir, "hdd")
        self.ssd_dir = os.path.join(self.temp_dir, "ssd")
        self.gt_dir = os.path.join(self.temp_dir, "gt")

        os.makedirs(self.hdd_dir, exist_ok=True)
        os.makedirs(self.ssd_dir, exist_ok=True)
        os.makedirs(self.gt_dir, exist_ok=True)

        self.logger = setup_logger()

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_01_load_ground_truth_from_repo(self):
        """Test loading actual ground truth from the workspace."""
        repo_gt = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "labelling", "host", "ground_truths", "ground_truth_corrected_all_evts.json.gz"
        )
        if os.path.exists(repo_gt):
            gt_ids = load_ground_truth(repo_gt, self.logger)
            self.assertEqual(len(gt_ids), 360567)
            # Sample check known malicious ID
            self.assertIn("f3815ab9-206c-4072-8a50-46a1d62e10f6", gt_ids)

    def test_02_label_injection_accuracy(self):
        """Test that malicious IDs get label 1 and benign get label 0."""
        malicious_id_1 = "11111111-1111-1111-1111-111111111111"
        malicious_id_2 = "22222222-2222-2222-2222-222222222222"
        benign_id_1 = "33333333-3333-3333-3333-333333333333"
        benign_id_2 = "44444444-4444-4444-4444-444444444444"

        gt_ids = {malicious_id_1, malicious_id_2}
        _init_worker(gt_ids)

        test_records = [
            {"id": benign_id_1, "action": "START", "pid": 100, "timestamp": "2019-09-17T10:00:00"},
            {"id": malicious_id_1, "action": "CREATE", "pid": 200, "timestamp": "2019-09-17T10:00:01"},
            {"id": benign_id_2, "action": "TERMINATE", "pid": 300, "timestamp": "2019-09-17T10:00:02"},
            {"id": malicious_id_2, "action": "LOAD", "pid": 400, "timestamp": "2019-09-17T10:00:03"},
            {"id": "unknown-no-match", "action": "OPEN", "pid": 500, "timestamp": "2019-09-17T10:00:04"}
        ]

        in_file = os.path.join(self.hdd_dir, "test_input.json.gz")
        out_file = os.path.join(self.ssd_dir, "test_output.json.gz")

        with gzip.open(in_file, "wt", encoding="utf-8") as f:
            for r in test_records:
                f.write(json.dumps(r) + "\n")

        res = _process_file_task((in_file, out_file, 6))

        self.assertTrue(res["success"])
        self.assertEqual(res["total_lines"], 5)
        self.assertEqual(res["malicious_lines"], 2)

        # Read back and verify exact labels
        labeled_records = []
        with gzip.open(out_file, "rt", encoding="utf-8") as f:
            for line in f:
                labeled_records.append(json.loads(line))

        self.assertEqual(len(labeled_records), 5)
        self.assertEqual(labeled_records[0]["label"], 0)
        self.assertEqual(labeled_records[1]["label"], 1)
        self.assertEqual(labeled_records[2]["label"], 0)
        self.assertEqual(labeled_records[3]["label"], 1)
        self.assertEqual(labeled_records[4]["label"], 0)

        # Verify other fields remain untouched
        self.assertEqual(labeled_records[1]["action"], "CREATE")
        self.assertEqual(labeled_records[1]["pid"], 200)

    def test_03_directory_batch_and_safe_swap(self):
        """Test full pipeline on simulated date folder with atomic swap."""
        malicious_id = "malicious-uuid-9999"
        
        # Create synthetic ground truth
        gt_file = os.path.join(self.gt_dir, "ground_truth_corrected_all_evts.json.gz")
        with gzip.open(gt_file, "wt", encoding="utf-8") as f:
            f.write(json.dumps({"id": malicious_id, "action": "CREATE"}) + "\n")

        # Create synthetic HDD structure: 2019-09-17/AIA-101-125/file1.json.gz
        date_dir = os.path.join(self.hdd_dir, "2019-09-17")
        group_dir = os.path.join(date_dir, "AIA-101-125")
        os.makedirs(group_dir, exist_ok=True)

        file1 = os.path.join(group_dir, "AIA-101-125.ecar-2019-09-17-sysclient0101.json.gz")
        file2 = os.path.join(group_dir, "AIA-101-125.ecar-2019-09-17-sysclient0102.json.gz")

        records_1 = [{"id": f"rec1_{i}", "val": i} for i in range(50)]
        records_1[10]["id"] = malicious_id

        records_2 = [{"id": f"rec2_{i}", "val": i} for i in range(80)]

        with gzip.open(file1, "wt") as f:
            for r in records_1:
                f.write(json.dumps(r) + "\n")

        with gzip.open(file2, "wt") as f:
            for r in records_2:
                f.write(json.dumps(r) + "\n")

        pipeline = OpTCLabelingPipeline(
            hdd_root=self.hdd_dir,
            ssd_staging=self.ssd_dir,
            gt_path=gt_file,
            workers=2,
            compress_level=6,
            batch_level="date",
            dry_run=False,
            skip_swap=False,
            logger=self.logger
        )

        success = pipeline.run()
        self.assertTrue(success)

        # Verify HDD date directory still exists and is updated with labels
        self.assertTrue(os.path.exists(file1))
        self.assertTrue(os.path.exists(file2))

        # Check records in file1
        with gzip.open(file1, "rt") as f:
            lines = [json.loads(line) for line in f]
            self.assertEqual(len(lines), 50)
            self.assertEqual(lines[10]["label"], 1)
            self.assertEqual(lines[0]["label"], 0)

        # Check records in file2
        with gzip.open(file2, "rt") as f:
            lines = [json.loads(line) for line in f]
            self.assertEqual(len(lines), 80)
            self.assertTrue(all(l["label"] == 0 for l in lines))

    def test_04_safety_abort_on_corruption(self):
        """Test that if a file is corrupt/fails, HDD files are preserved untouched."""
        gt_file = os.path.join(self.gt_dir, "gt.json.gz")
        with gzip.open(gt_file, "wt") as f:
            f.write(json.dumps({"id": "some-id"}) + "\n")

        date_dir = os.path.join(self.hdd_dir, "2019-09-18")
        os.makedirs(date_dir, exist_ok=True)
        good_file = os.path.join(date_dir, "good.json.gz")
        bad_file = os.path.join(date_dir, "corrupt.json.gz")

        with gzip.open(good_file, "wt") as f:
            f.write(json.dumps({"id": "good-1"}) + "\n")

        # Write corrupted gzip content
        with open(bad_file, "wb") as f:
            f.write(b"not-a-valid-gzip-stream-corrupted-data")

        pipeline = OpTCLabelingPipeline(
            hdd_root=self.hdd_dir,
            ssd_staging=self.ssd_dir,
            gt_path=gt_file,
            workers=2,
            skip_swap=False,
            logger=self.logger
        )

        success = pipeline.run()
        self.assertFalse(success)

        # HDD files MUST still exist and remain untouched
        self.assertTrue(os.path.exists(good_file))
        self.assertTrue(os.path.exists(bad_file))


if __name__ == "__main__":
    unittest.main()
