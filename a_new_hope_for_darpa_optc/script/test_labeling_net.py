#!/usr/bin/env python3
"""
Unit tests for DARPA OpTC Zeek / Bro network log labeling pipeline.
"""

import gzip
import os
import shutil
import tempfile
import unittest

from label_optc_network_logs import (
    init_worker,
    load_network_ground_truth,
    process_network_file,
    setup_logger
)


class TestNetworkLabelingPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_net_labeling_")
        self.logger = setup_logger()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_load_ground_truth(self):
        """Test loading malicious connection UIDs from ground truth files."""
        gt_dir = os.path.join(self.test_dir, "gt")
        sc1_dir = os.path.join(gt_dir, "scenario-1")
        os.makedirs(sc1_dir, exist_ok=True)

        gt_file = os.path.join(sc1_dir, "conn-test.log")
        with open(gt_file, "wt") as f:
            f.write("#separator \\x09\n")
            f.write("#fields\tts\tuid\tid.orig_h\n")
            f.write("1569264342.246\tC_MALICIOUS_01\t142.20.56.105\n")
            f.write("1569264343.309\tC_MALICIOUS_02\t142.20.56.105\n")
            f.write("1569264344.250\t-\t142.20.56.105\n")  # Should be skipped

        uids = load_network_ground_truth(gt_dir, self.logger)
        self.assertEqual(len(uids), 2)
        self.assertIn("C_MALICIOUS_01", uids)
        self.assertIn("C_MALICIOUS_02", uids)
        self.assertNotIn("-", uids)

    def test_process_conn_log(self):
        """Test processing standard conn.log.gz with header injection and 0/1 labeling."""
        init_worker({"C_MALICIOUS_01"})

        src_file = os.path.join(self.test_dir, "conn.00_00_00.log.gz")
        dst_file = os.path.join(self.test_dir, "out", "conn.00_00_00.log.gz")

        sample_lines = [
            "#separator \\x09\n",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n",
            "1568591994.029\tC_BENIGN_01\t142.20.59.171\t65328\t101.57.111.5\t443\ttcp\n",
            "1568591994.173\tC_MALICIOUS_01\t142.20.56.124\t62147\t109.172.36.5\t443\ttcp\n",
            "1568591994.207\tC_BENIGN_02\t142.20.56.124\t62157\t109.172.36.5\t443\ttcp\n",
            "#close\t2019-09-16-01-00-00\n",
        ]

        with gzip.open(src_file, "wt") as f:
            f.writelines(sample_lines)

        res = process_network_file((src_file, dst_file, 6))
        self.assertTrue(res["success"])
        self.assertEqual(res["total_lines"], 3)
        self.assertEqual(res["malicious_lines"], 1)

        # Read back and verify
        with gzip.open(dst_file, "rt") as f:
            lines = f.readlines()

        # Check headers
        self.assertTrue(lines[1].startswith("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tlabel\n"))
        self.assertTrue(lines[2].startswith("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tint\n"))

        # Check data
        self.assertTrue(lines[3].endswith("\t0\n"))
        self.assertTrue(lines[4].endswith("\t1\n"))
        self.assertTrue(lines[5].endswith("\t0\n"))
        self.assertEqual(lines[6], "#close\t2019-09-16-01-00-00\n")

    def test_process_files_log_multi_uid(self):
        """Test processing files.log with multi-UID conn_uids column."""
        init_worker({"C_MALICIOUS_FILE_01"})

        src_file = os.path.join(self.test_dir, "files.log.gz")
        dst_file = os.path.join(self.test_dir, "out", "files.log.gz")

        sample_lines = [
            "#fields\tts\tfuid\ttx_hosts\trx_hosts\tconn_uids\tsource\n",
            "#types\ttime\tstring\tset[addr]\tset[addr]\tset[string]\tstring\n",
            "1568591994.029\tF123\t10.0.0.1\t10.0.0.2\tC_BENIGN_A,C_BENIGN_B\tHTTP\n",
            "1568591994.173\tF456\t10.0.0.1\t10.0.0.2\tC_BENIGN_C,C_MALICIOUS_FILE_01\tHTTP\n",
        ]

        with gzip.open(src_file, "wt") as f:
            f.writelines(sample_lines)

        res = process_network_file((src_file, dst_file, 6))
        self.assertTrue(res["success"])
        self.assertEqual(res["total_lines"], 2)
        self.assertEqual(res["malicious_lines"], 1)

        with gzip.open(dst_file, "rt") as f:
            lines = f.readlines()

        self.assertTrue(lines[2].endswith("\t0\n"))
        self.assertTrue(lines[3].endswith("\t1\n"))

    def test_process_meta_log_without_uid(self):
        """Test processing metadata logs without UID (e.g. communication.log)."""
        init_worker({"C_MALICIOUS_01"})

        src_file = os.path.join(self.test_dir, "comm.log.gz")
        dst_file = os.path.join(self.test_dir, "out", "comm.log.gz")

        sample_lines = [
            "#fields\tts\tpeer\tsrc_name\n",
            "#types\ttime\tstring\tstring\n",
            "1568591994.029\tpeer1\tbroker\n",
        ]

        with gzip.open(src_file, "wt") as f:
            f.writelines(sample_lines)

        res = process_network_file((src_file, dst_file, 6))
        self.assertTrue(res["success"])
        self.assertEqual(res["total_lines"], 1)
        self.assertEqual(res["malicious_lines"], 0)

        with gzip.open(dst_file, "rt") as f:
            lines = f.readlines()

        self.assertTrue(lines[0].startswith("#fields\tts\tpeer\tsrc_name\tlabel\n"))
        self.assertTrue(lines[1].startswith("#types\ttime\tstring\tstring\tint\n"))
        self.assertTrue(lines[2].endswith("\t0\n"))


if __name__ == "__main__":
    unittest.main()
