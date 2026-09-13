#!/usr/bin/env python3
"""
Parallel Host Log Labeling Script for DARPA OpTC Dataset
========================================================
This script processes DARPA OpTC host logs (.json.gz) on HDD, adds a binary "label"
field (1 for malicious events whose 'id' appears in the corrected ground truth, 0 otherwise),
and safely replaces the original logs on HDD via SSD staging.

Features:
- High performance multi-processing (parallelized across CPU cores)
- Shared ground-truth memory across worker processes (zero IPC overhead per file)
- Multi-tier integrity verification (gzip check, line count validation, JSON integrity)
- Safe HDD-SSD-HDD workflow: only deletes/swaps on HDD when 100% of files succeed
- Graceful termination handling (SIGINT / SIGTERM)
"""

import os
import sys
import glob
import time
import json
import gzip
import shutil
import signal
import logging
import argparse
from datetime import datetime
from multiprocessing import Pool, cpu_count
from typing import Set, List, Dict, Tuple, Optional

# Global variable initialized once per worker process to avoid IPC serialization overhead
_WORKER_MALICIOUS_IDS: Set[str] = set()


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    """Configure structured console and file logging."""
    logger = logging.getLogger("OpTCLabeler")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Optional file handler
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


def load_ground_truth(gt_path: str, logger: logging.Logger) -> Set[str]:
    """
    Load unique malicious event IDs from ground truth files.
    
    Supports:
    - Path to ground_truth_corrected_all_evts.json.gz
    - Directory containing ground_truth_corrected* files
    - Individual ground_truth_corrected_*.json.gz or .json files
    """
    malicious_ids: Set[str] = set()
    t0 = time.time()

    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"Ground truth path not found: {gt_path}")

    files_to_load = []
    if os.path.isfile(gt_path):
        files_to_load.append(gt_path)
    elif os.path.isdir(gt_path):
        # Look for consolidated ground truth first
        all_evts = os.path.join(gt_path, "ground_truth_corrected_all_evts.json.gz")
        if os.path.isfile(all_evts):
            files_to_load.append(all_evts)
        else:
            # Look for all corrected event json.gz files
            pattern = os.path.join(gt_path, "ground_truth_corrected*.json.gz")
            matched = glob.glob(pattern)
            if matched:
                files_to_load.extend(sorted(matched))
            else:
                # Fallback to any json.gz or csv in directory
                files_to_load.extend(sorted(glob.glob(os.path.join(gt_path, "*corrected*"))))

    if not files_to_load:
        raise ValueError(f"No valid ground truth files found in: {gt_path}")

    logger.info(f"Loading ground truth from {len(files_to_load)} file(s)...")

    for fpath in files_to_load:
        file_ids_count = 0
        if fpath.endswith(".gz"):
            open_fn = lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace")
        else:
            open_fn = lambda p: open(p, "r", encoding="utf-8", errors="replace")

        try:
            with open_fn(fpath) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("{"):
                        try:
                            record = json.loads(line)
                            if "id" in record and record["id"]:
                                malicious_ids.add(record["id"])
                                file_ids_count += 1
                        except json.JSONDecodeError:
                            continue
                    else:
                        # If CSV or plain list of IDs
                        parts = [p.strip() for p in line.split(",")]
                        for p in parts:
                            # UUID format check (length 36 with dashes)
                            if len(p) == 36 and p.count("-") == 4:
                                malicious_ids.add(p)
                                file_ids_count += 1
            logger.info(f"  -> Loaded {file_ids_count:,} events from {os.path.basename(fpath)}")
        except Exception as e:
            logger.error(f"Failed to read ground truth file {fpath}: {e}")
            raise

    elapsed = time.time() - t0
    logger.info(f"Ground truth loaded: {len(malicious_ids):,} unique malicious IDs in {elapsed:.2f}s")
    return malicious_ids


def _init_worker(malicious_ids: Set[str]):
    """Initializer function for multiprocessing Pool workers to share ground truth set."""
    global _WORKER_MALICIOUS_IDS
    _WORKER_MALICIOUS_IDS = malicious_ids
    # Ignore SIGINT in child processes so parent can handle graceful shutdown
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _process_file_task(args: Tuple[str, str, int]) -> Dict:
    """
    Worker task: read a single .json.gz file, inject label, write to temp output, and verify.
    
    args: (input_path, output_path, compress_level)
    """
    in_path, out_path, compress_level = args
    temp_out_path = out_path + ".tmp"
    
    res = {
        "input_path": in_path,
        "output_path": out_path,
        "total_lines": 0,
        "malicious_lines": 0,
        "in_bytes": 0,
        "out_bytes": 0,
        "elapsed_sec": 0.0,
        "success": False,
        "error": None
    }

    t0 = time.time()
    try:
        if not os.path.exists(in_path):
            raise FileNotFoundError(f"Input file does not exist: {in_path}")

        res["in_bytes"] = os.path.getsize(in_path)
        os.makedirs(os.path.dirname(temp_out_path), exist_ok=True)

        total_lines = 0
        malicious_lines = 0

        # Read and write streams
        with gzip.open(in_path, "rt", encoding="utf-8", errors="replace") as fin, \
             gzip.open(temp_out_path, "wt", compresslevel=compress_level, encoding="utf-8") as fout:
            
            for line in fin:
                if not line.strip():
                    continue
                record = json.loads(line)
                
                # Check ID against ground truth set
                event_id = record.get("id")
                if event_id and event_id in _WORKER_MALICIOUS_IDS:
                    record["label"] = 1
                    malicious_lines += 1
                else:
                    record["label"] = 0
                
                fout.write(json.dumps(record, ensure_ascii=False) + "\n")
                total_lines += 1

        # Atomically move temp output to final output
        if os.path.exists(out_path):
            os.remove(out_path)
        os.rename(temp_out_path, out_path)

        # Integrity Check on Output File
        if not os.path.exists(out_path):
            raise RuntimeError(f"Output file missing after processing: {out_path}")
        
        out_bytes = os.path.getsize(out_path)
        if out_bytes == 0 and res["in_bytes"] > 0:
            raise RuntimeError(f"Output file is empty (0 bytes): {out_path}")

        # Quick validation: check that output file opens and has identical line count
        verify_lines = 0
        with gzip.open(out_path, "rt", encoding="utf-8", errors="replace") as f_ver:
            for line in f_ver:
                if line.strip():
                    verify_lines += 1

        if verify_lines != total_lines:
            raise ValueError(f"Line count mismatch in {out_path}: expected {total_lines}, got {verify_lines}")

        res["total_lines"] = total_lines
        res["malicious_lines"] = malicious_lines
        res["out_bytes"] = out_bytes
        res["elapsed_sec"] = time.time() - t0
        res["success"] = True

    except Exception as e:
        res["error"] = str(e)
        res["success"] = False
        # Clean up temp file on error
        if os.path.exists(temp_out_path):
            try:
                os.remove(temp_out_path)
            except OSError:
                pass
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass

    return res


class OpTCLabelingPipeline:
    def __init__(
        self,
        hdd_root: str,
        ssd_staging: str,
        gt_path: str,
        workers: int = 12,
        compress_level: int = 6,
        batch_level: str = "date",
        dry_run: bool = False,
        skip_swap: bool = False,
        logger: Optional[logging.Logger] = None
    ):
        self.hdd_root = os.path.abspath(hdd_root)
        self.ssd_staging = os.path.abspath(ssd_staging)
        self.gt_path = os.path.abspath(gt_path)
        self.workers = min(workers, cpu_count())
        self.compress_level = compress_level
        self.batch_level = batch_level
        self.dry_run = dry_run
        self.skip_swap = skip_swap
        self.logger = logger or setup_logger()
        self.malicious_ids: Set[str] = set()

    def discover_batch_directories(self, date_filter: Optional[List[str]] = None) -> List[str]:
        """Discover date or sub-group directories on HDD."""
        if not os.path.exists(self.hdd_root):
            raise FileNotFoundError(f"HDD root directory does not exist: {self.hdd_root}")

        candidate_dirs = []
        entries = sorted(os.listdir(self.hdd_root))

        for entry in entries:
            full_path = os.path.join(self.hdd_root, entry)
            if not os.path.isdir(full_path):
                continue
            # Look for 2019-09-* directories
            if entry.startswith("2019-09"):
                if date_filter:
                    if entry in date_filter or any(f in entry for f in date_filter):
                        candidate_dirs.append(full_path)
                else:
                    candidate_dirs.append(full_path)

        if self.batch_level == "group":
            # Return subgroup directories (e.g. 2019-09-17/AIA-101-125)
            group_dirs = []
            for d in candidate_dirs:
                for sub in sorted(os.listdir(d)):
                    sub_full = os.path.join(d, sub)
                    if os.path.isdir(sub_full) and sub.startswith("AIA-"):
                        group_dirs.append(sub_full)
            return group_dirs

        return candidate_dirs

    def process_directory(self, target_dir: str, pool: Pool) -> bool:
        """
        Process all .json.gz files in a target directory.
        1. Find all .json.gz in target_dir
        2. Copy & label files to SSD staging directory
        3. Verify 100% integrity
        4. Swap directory on HDD (delete old -> move new)
        """
        rel_dir = os.path.relpath(target_dir, self.hdd_root)
        ssd_target_dir = os.path.join(self.ssd_staging, rel_dir)

        self.logger.info("=" * 70)
        self.logger.info(f"Starting batch: {rel_dir}")
        self.logger.info(f"  Source (HDD):  {target_dir}")
        self.logger.info(f"  Staging (SSD): {ssd_target_dir}")

        # Find all .json.gz files in directory
        input_files = []
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith(".json.gz") and not file.endswith(".tmp"):
                    input_files.append(os.path.join(root, file))

        input_files.sort()
        if not input_files:
            self.logger.warning(f"No .json.gz files found in {target_dir}. Skipping.")
            return True

        self.logger.info(f"Found {len(input_files)} .json.gz files to process.")

        if self.dry_run:
            self.logger.info("[DRY RUN] Would process files and swap directory. Skipping actual execution.")
            return True

        # Clean staging directory if existing
        if os.path.exists(ssd_target_dir):
            shutil.rmtree(ssd_target_dir)
        os.makedirs(ssd_target_dir, exist_ok=True)

        # Build task arguments
        tasks = []
        for in_file in input_files:
            rel_file = os.path.relpath(in_file, target_dir)
            out_file = os.path.join(ssd_target_dir, rel_file)
            tasks.append((in_file, out_file, self.compress_level))

        # Run parallel tasks
        t_start = time.time()
        results = []
        completed_count = 0
        total_lines_batch = 0
        total_malicious_batch = 0
        total_in_bytes = 0
        total_out_bytes = 0

        self.logger.info(f"Processing with {self.workers} parallel workers...")

        # Process async to track progress
        async_results = [pool.apply_async(_process_file_task, (t,)) for t in tasks]

        for i, async_res in enumerate(async_results, 1):
            res = async_res.get()
            results.append(res)
            
            if not res["success"]:
                self.logger.error(f"Error processing file {res['input_path']}: {res['error']}")
            else:
                completed_count += 1
                total_lines_batch += res["total_lines"]
                total_malicious_batch += res["malicious_lines"]
                total_in_bytes += res["in_bytes"]
                total_out_bytes += res["out_bytes"]

            if i % 25 == 0 or i == len(tasks):
                elapsed = time.time() - t_start
                rate = (total_in_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                pct = (i / len(tasks)) * 100
                self.logger.info(
                    f"  [{i}/{len(tasks)} - {pct:.1f}%] "
                    f"Lines: {total_lines_batch:,} | "
                    f"Malicious: {total_malicious_batch:,} | "
                    f"Speed: {rate:.1f} MB/s | "
                    f"Elapsed: {elapsed:.1f}s"
                )

        batch_elapsed = time.time() - t_start

        # Step 3: Strict 100% Verification
        self.logger.info("Performing 100% integrity validation...")
        failed_files = [r for r in results if not r["success"]]

        if failed_files:
            self.logger.critical(
                f"VALIDATION FAILED: {len(failed_files)}/{len(tasks)} files encountered errors in batch {rel_dir}!"
            )
            for f in failed_files[:10]:
                self.logger.critical(f"  Failed: {f['input_path']} -> {f['error']}")
            self.logger.critical("SAFETY HALT: HDD files will NOT be modified or deleted. Stopping execution.")
            return False

        if completed_count != len(input_files):
            self.logger.critical(
                f"VALIDATION FAILED: Expected {len(input_files)} processed files, got {completed_count}."
            )
            return False

        self.logger.info(
            f"Integrity Check PASSED (100% Valid): {completed_count} files, "
            f"{total_lines_batch:,} records ({total_malicious_batch:,} malicious) "
            f"in {batch_elapsed:.2f}s."
        )

        # Step 4: Atomic Swap (Delete old from HDD -> Move new from SSD to HDD)
        if self.skip_swap:
            self.logger.info(f"[SKIP SWAP] Labeled files preserved on SSD: {ssd_target_dir}")
            return True

        self.logger.info(f"Replacing original HDD directory with labeled copy...")
        try:
            # 1. Remove original HDD directory
            self.logger.info(f"  1. Removing old directory from HDD: {target_dir}")
            shutil.rmtree(target_dir)

            # 2. Move SSD directory to HDD
            self.logger.info(f"  2. Moving new directory from SSD to HDD: {ssd_target_dir} -> {target_dir}")
            shutil.move(ssd_target_dir, target_dir)

            # 3. Sync filesystem buffers to disk
            if hasattr(os, "sync"):
                os.sync()

            self.logger.info(f"  [SUCCESS] Batch {rel_dir} successfully updated on HDD!")
            return True

        except Exception as e:
            self.logger.critical(f"FATAL ERROR during directory swap for {rel_dir}: {e}")
            self.logger.critical(f"Labeled data remains safely stored at: {ssd_target_dir}")
            raise

    def run(self, date_filter: Optional[List[str]] = None) -> bool:
        """Run the end-to-end labeling pipeline."""
        start_time = time.time()
        self.logger.info("=" * 70)
        self.logger.info("OpTC HOST LOG PARALLEL LABELING PIPELINE")
        self.logger.info("=" * 70)
        self.logger.info(f"HDD Root:        {self.hdd_root}")
        self.logger.info(f"SSD Staging:     {self.ssd_staging}")
        self.logger.info(f"Ground Truth:    {self.gt_path}")
        self.logger.info(f"Parallel Workers:{self.workers}")
        self.logger.info(f"Compress Level:  {self.compress_level}")
        self.logger.info(f"Batch Level:     {self.batch_level}")
        self.logger.info(f"Dry Run:         {self.dry_run}")
        self.logger.info(f"Skip Swap:       {self.skip_swap}")
        self.logger.info("=" * 70)

        # 1. Load Ground Truth IDs
        self.malicious_ids = load_ground_truth(self.gt_path, self.logger)

        # 2. Discover batches
        batch_dirs = self.discover_batch_directories(date_filter)
        if not batch_dirs:
            self.logger.warning(f"No matching batch directories found in {self.hdd_root}")
            return True

        self.logger.info(f"Found {len(batch_dirs)} directory batch(es) to process:")
        for b in batch_dirs:
            self.logger.info(f"  - {os.path.relpath(b, self.hdd_root)}")

        # 3. Start Multiprocessing Pool with Shared Ground Truth
        self.logger.info(f"Initializing process pool ({self.workers} workers)...")
        pool = Pool(processes=self.workers, initializer=_init_worker, initargs=(self.malicious_ids,))

        overall_success = True
        try:
            for idx, b_dir in enumerate(batch_dirs, 1):
                self.logger.info(f"\nProcessing Batch [{idx}/{len(batch_dirs)}]")
                success = self.process_directory(b_dir, pool)
                if not success:
                    overall_success = False
                    self.logger.critical("Pipeline aborted due to batch failure.")
                    break
        except KeyboardInterrupt:
            self.logger.critical("\nPipeline interrupted by user (Ctrl+C). Terminating workers...")
            pool.terminate()
            pool.join()
            return False
        finally:
            pool.close()
            pool.join()

        total_elapsed = time.time() - start_time
        self.logger.info("=" * 70)
        if overall_success:
            self.logger.info(f"LABELING PIPELINE COMPLETED SUCCESSFULLY in {total_elapsed / 60:.2f} minutes.")
        else:
            self.logger.error("LABELING PIPELINE TERMINATED WITH ERRORS.")
        self.logger.info("=" * 70)

        return overall_success


def parse_args():
    parser = argparse.ArgumentParser(
        description="Parallel Host Log Labeling for DARPA OpTC (Corrected Dataset)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--hdd-root",
        type=str,
        default="/mnt/HDD_Data",
        help="Root directory containing raw DARPA OpTC date folders (e.g. 2019-09-17/)"
    )
    parser.add_argument(
        "--ssd-staging",
        type=str,
        default="/mnt/SSD_Data/temp_label_staging",
        help="Temporary staging directory on SSD"
    )
    parser.add_argument(
        "--gt-path",
        type=str,
        default="labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz",
        help="Path to ground truth file or directory containing corrected ground truths"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=cpu_count(),
        help="Number of parallel worker processes"
    )
    parser.add_argument(
        "-c", "--compress-level",
        type=int,
        default=6,
        choices=range(1, 10),
        help="Gzip compression level (1=fastest, 6=default/balanced, 9=maximum compression)"
    )
    parser.add_argument(
        "-b", "--batch-level",
        type=str,
        default="date",
        choices=["date", "group"],
        help="Batch granularity for swap ('date' for full day folders, 'group' for AIA subfolders)"
    )
    parser.add_argument(
        "-d", "--dates",
        nargs="+",
        default=None,
        help="Specific date folders to process (e.g., --dates 2019-09-17 2019-09-18)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan directories and print summary without writing or modifying files"
    )
    parser.add_argument(
        "--skip-swap",
        action="store_true",
        help="Process and write labeled files to SSD staging only; do NOT delete or replace HDD files"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="script/labeling.log",
        help="Path to log file"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logger(args.log_file)

    # Normalize relative gt-path from workspace root if needed
    gt_path = args.gt_path
    if not os.path.isabs(gt_path) and not os.path.exists(gt_path):
        workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        candidate = os.path.join(workspace_root, gt_path)
        if os.path.exists(candidate):
            gt_path = candidate

    pipeline = OpTCLabelingPipeline(
        hdd_root=args.hdd_root,
        ssd_staging=args.ssd_staging,
        gt_path=gt_path,
        workers=args.workers,
        compress_level=args.compress_level,
        batch_level=args.batch_level,
        dry_run=args.dry_run,
        skip_swap=args.skip_swap,
        logger=logger
    )

    success = pipeline.run(date_filter=args.dates)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
