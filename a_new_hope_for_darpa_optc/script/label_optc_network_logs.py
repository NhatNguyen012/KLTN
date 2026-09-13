#!/usr/bin/env python3
"""
=============================================================================
Parallel Labeling Pipeline for DARPA OpTC Zeek / Bro Network Logs
=============================================================================
Description:
  Reads Zeek/Bro TSV logs (.log.gz) from /mnt/SSD_Data/bro/, matches
  connection UIDs against ground truth files in labelling/network/
  (scenario-1, scenario-2, scenario-3), injects a 'label' field (1 for
  malicious, 0 for benign), and writes labeled .log.gz files to
  /mnt/SSD_Data/temp_label_staging_net/ in parallel.

Features:
  - Multi-process parallel streaming with zero-copy shared ground truth set.
  - Handles all Zeek TSV log formats (conn, http, dns, ssl, files, weird, etc.).
  - Automatically updates Zeek #fields and #types header metadata.
  - Supports multi-UID fields (e.g. conn_uids in files.log).
  - 100% integrity validation (decompression verification & line count parity).
  - Atomic file writes (.tmp.gz -> .log.gz) preventing partial corruption.
=============================================================================
"""

import argparse
import glob
import gzip
import logging
import multiprocessing
import os
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

# Global shared set for multiprocessing workers
g_malicious_uids: Set[str] = set()


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    """Configure structured console and file logging."""
    logger = logging.getLogger("optc_net_labeler")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def load_network_ground_truth(gt_dir: str, logger: logging.Logger) -> Set[str]:
    """
    Extracts all malicious connection UIDs from all ground truth .log files
    in labelling/network/ (scenario-1, scenario-2, scenario-3).
    """
    logger.info(f"Loading network ground truth from directory: {gt_dir}")
    gt_pattern = os.path.join(gt_dir, "scenario-*", "*.log")
    gt_files = sorted(glob.glob(gt_pattern))

    if not gt_files:
        # Fallback to direct .log search in gt_dir
        gt_files = sorted(glob.glob(os.path.join(gt_dir, "**", "*.log"), recursive=True))

    if not gt_files:
        logger.error(f"No ground truth .log files found in {gt_dir}!")
        sys.exit(1)

    malicious_uids: Set[str] = set()
    per_scenario_counts: Dict[str, int] = {}

    for fpath in gt_files:
        scenario = os.path.basename(os.path.dirname(fpath))
        file_uids = 0
        try:
            with open(fpath, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        uid = parts[1]  # 2nd column is UID in conn.log
                        if uid and uid != "-" and uid != "(empty)":
                            malicious_uids.add(uid)
                            file_uids += 1
            per_scenario_counts[scenario] = per_scenario_counts.get(scenario, 0) + file_uids
        except Exception as e:
            logger.error(f"Error reading ground truth file {fpath}: {e}")

    logger.info(f"Loaded ground truth from {len(gt_files)} files across {len(per_scenario_counts)} scenarios:")
    for sc, count in sorted(per_scenario_counts.items()):
        logger.info(f"  - {sc}: {count:,} records")
    logger.info(f"Total unique malicious connection UIDs: {len(malicious_uids):,}")

    return malicious_uids


def init_worker(shared_uids: Set[str]):
    """Initializer for multiprocessing pool workers."""
    global g_malicious_uids
    g_malicious_uids = shared_uids


def process_network_file(args_tuple: Tuple[str, str, int]) -> Dict:
    """
    Worker task: Reads a Zeek .log.gz file, injects 'label' field, and compresses to output path.
    """
    src_file, dst_file, compress_level = args_tuple
    start_t = time.time()

    total_lines = 0
    malicious_lines = 0
    file_size_bytes = os.path.getsize(src_file) if os.path.exists(src_file) else 0

    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
    tmp_dst_file = dst_file + ".tmp.gz"

    try:
        uid_col_idx = -1
        is_multi_uid = False

        with gzip.open(src_file, "rt", encoding="utf-8", errors="replace") as f_in, \
             gzip.open(tmp_dst_file, "wt", encoding="utf-8", compresslevel=compress_level) as f_out:

            for line in f_in:
                # Handle Zeek header comments
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.rstrip("\r\n").split("\t")[1:]
                        if "uid" in fields:
                            uid_col_idx = fields.index("uid")
                            is_multi_uid = False
                        elif "conn_uids" in fields:
                            uid_col_idx = fields.index("conn_uids")
                            is_multi_uid = True
                        else:
                            uid_col_idx = -1
                            is_multi_uid = False
                        # Append 'label' to #fields header
                        f_out.write(line.rstrip("\r\n") + "\tlabel\n")
                    elif line.startswith("#types"):
                        # Append 'int' to #types header
                        f_out.write(line.rstrip("\r\n") + "\tint\n")
                    else:
                        # Write other header lines unchanged (#separator, #set_separator, #path, etc.)
                        f_out.write(line)
                    continue

                clean_line = line.rstrip("\r\n")
                if not clean_line:
                    continue

                total_lines += 1
                parts = clean_line.split("\t")

                is_mal = False
                if uid_col_idx >= 0 and uid_col_idx < len(parts):
                    val = parts[uid_col_idx]
                    if is_multi_uid:
                        # Comma-separated list of UIDs (e.g. conn_uids in files.log)
                        is_mal = any(u in g_malicious_uids for u in val.split(","))
                    else:
                        is_mal = val in g_malicious_uids

                if is_mal:
                    malicious_lines += 1
                    f_out.write(clean_line + "\t1\n")
                else:
                    f_out.write(clean_line + "\t0\n")

        # Atomic rename after successful processing
        os.replace(tmp_dst_file, dst_file)

        # Integrity check: verify the output file is readable and has identical data line count
        valid_lines = 0
        with gzip.open(dst_file, "rt", encoding="utf-8", errors="replace") as f_check:
            for line in f_check:
                if not line.startswith("#") and line.strip():
                    valid_lines += 1

        if valid_lines != total_lines:
            raise ValueError(f"Integrity mismatch: expected {total_lines} lines, got {valid_lines}")

        duration = time.time() - start_t
        return {
            "src_file": src_file,
            "dst_file": dst_file,
            "total_lines": total_lines,
            "malicious_lines": malicious_lines,
            "file_size_bytes": file_size_bytes,
            "duration": duration,
            "success": True,
            "error": None
        }

    except Exception as e:
        if os.path.exists(tmp_dst_file):
            try:
                os.remove(tmp_dst_file)
            except OSError:
                pass
        return {
            "src_file": src_file,
            "dst_file": dst_file,
            "total_lines": total_lines,
            "malicious_lines": malicious_lines,
            "file_size_bytes": file_size_bytes,
            "duration": time.time() - start_t,
            "success": False,
            "error": str(e)
        }


def collect_network_files(
    bro_root: str,
    dates: Optional[List[str]] = None,
    log_types: Optional[List[str]] = None,
    logger: Optional[logging.Logger] = None
) -> List[str]:
    """Scans bro_root for all matching .log.gz files."""
    if logger:
        logger.info(f"Scanning for Zeek/Bro log files in {bro_root}...")

    all_files: List[str] = []

    # Get available date directories
    if not os.path.exists(bro_root):
        if logger:
            logger.error(f"Bro root directory {bro_root} does not exist!")
        return []

    subdirs = [d for d in os.listdir(bro_root) if os.path.isdir(os.path.join(bro_root, d))]

    target_dates = []
    if dates:
        for d in dates:
            if d in subdirs:
                target_dates.append(d)
            else:
                if logger:
                    logger.warning(f"Date folder '{d}' not found in {bro_root}")
    else:
        target_dates = sorted(subdirs)

    for d in sorted(target_dates):
        date_dir = os.path.join(bro_root, d)
        found = glob.glob(os.path.join(date_dir, "*.log.gz"))
        if log_types and "all" not in [lt.lower() for lt in log_types]:
            selected = []
            for f in found:
                prefix = os.path.basename(f).split(".")[0]
                if prefix in log_types:
                    selected.append(f)
            all_files.extend(sorted(selected))
        else:
            all_files.extend(sorted(found))

    return all_files


def run_pipeline(args: argparse.Namespace):
    """Main execution orchestrator for network labeling."""
    logger = setup_logger(args.log_file)
    logger.info("=" * 70)
    logger.info("DARPA OpTC Zeek / Bro Network Log Parallel Labeling Pipeline")
    logger.info("=" * 70)

    # 1. Load ground truth
    malicious_uids = load_network_ground_truth(args.gt_dir, logger)

    # 2. Collect files to process
    files_to_process = collect_network_files(
        bro_root=args.bro_root,
        dates=args.dates,
        log_types=args.log_types,
        logger=logger
    )

    if not files_to_process:
        logger.warning("No files found matching criteria. Exiting.")
        return

    logger.info(f"Total files to process: {len(files_to_process):,}")

    # Build task tuples: (src_file, dst_file, compress_level)
    tasks = []
    for src in files_to_process:
        rel_path = os.path.relpath(src, args.bro_root)
        dst = os.path.join(args.out_root, rel_path)
        tasks.append((src, dst, args.compress_level))

    if args.dry_run:
        logger.info(f"[DRY-RUN] Would process {len(tasks)} files to {args.out_root}")
        for t in tasks[:10]:
            logger.info(f"  [DRY-RUN] {t[0]} -> {t[1]}")
        if len(tasks) > 10:
            logger.info(f"  ... and {len(tasks) - 10} more files.")
        return

    # 3. Parallel Execution
    workers = min(args.workers or os.cpu_count() or 4, len(tasks))
    logger.info(f"Starting parallel processing with {workers} worker processes...")
    pipeline_start_t = time.time()

    total_records = 0
    total_malicious = 0
    total_bytes_processed = 0
    completed_files = 0
    failed_files = 0

    with multiprocessing.Pool(processes=workers, initializer=init_worker, initargs=(malicious_uids,)) as pool:
        for res in pool.imap_unordered(process_network_file, tasks, chunksize=2):
            completed_files += 1

            if res["success"]:
                total_records += res["total_lines"]
                total_malicious += res["malicious_lines"]
                total_bytes_processed += res["file_size_bytes"]
            else:
                failed_files += 1
                logger.error(f"Failed processing {res['src_file']}: {res['error']}")

            # Progress logging every 25 files or at 100%
            if completed_files % 25 == 0 or completed_files == len(tasks):
                elapsed = time.time() - pipeline_start_t
                speed_mb = (total_bytes_processed / (1024 * 1024)) / max(elapsed, 0.001)
                pct = (completed_files / len(tasks)) * 100
                logger.info(
                    f"[{completed_files}/{len(tasks)} - {pct:5.1f}%] "
                    f"Lines: {total_records:,} | Malicious: {total_malicious:,} | "
                    f"Speed: {speed_mb:.1f} MB/s | Elapsed: {elapsed:.1f}s"
                )

    total_duration = time.time() - pipeline_start_t
    logger.info("=" * 70)
    logger.info("PIPELINE SUMMARY:")
    logger.info(f"  - Total files processed : {completed_files:,}")
    logger.info(f"  - Failed files           : {failed_files}")
    logger.info(f"  - Total records labeled  : {total_records:,}")
    logger.info(f"  - Total malicious events : {total_malicious:,}")
    logger.info(f"  - Total elapsed time     : {total_duration:.2f}s ({total_duration/60:.2f} min)")
    logger.info(f"  - Output staging path    : {args.out_root}")
    logger.info("=" * 70)

    if failed_files > 0:
        logger.error(f"Pipeline completed with {failed_files} errors!")
        sys.exit(1)
    else:
        logger.info("Network labeling completed successfully (100% Validated)!")


def parse_arguments() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Parallel Labeling Pipeline for DARPA OpTC Zeek / Bro Network Logs"
    )
    parser.add_argument(
        "--bro-root",
        type=str,
        default="/mnt/SSD_Data/bro",
        help="Root directory containing Zeek/Bro date directories (default: /mnt/SSD_Data/bro)"
    )
    parser.add_argument(
        "--out-root",
        type=str,
        default="/mnt/SSD_Data/temp_label_staging_net",
        help="Target output directory for labeled logs (default: /mnt/SSD_Data/temp_label_staging_net)"
    )
    parser.add_argument(
        "--gt-dir",
        type=str,
        default="labelling/network",
        help="Directory containing ground truth scenario-* subfolders (default: labelling/network)"
    )
    parser.add_argument(
        "--dates",
        nargs="+",
        help="Specific date directories to process (e.g. --dates 2019-09-25 2019-09-24)"
    )
    parser.add_argument(
        "--log-types",
        nargs="+",
        default=["all"],
        help="Filter specific log types (e.g. --log-types conn http dns ssl, or 'all')"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=os.cpu_count(),
        help="Number of parallel worker processes (default: all CPU cores)"
    )
    parser.add_argument(
        "--compress-level",
        type=int,
        default=6,
        help="Gzip compression level 1-9 (default: 6)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and print matched files without processing"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Optional path to write detailed execution log file"
    )

    return parser.parse_args()


if __name__ == "__main__":
    run_pipeline(parse_arguments())
