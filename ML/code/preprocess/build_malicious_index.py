#!/usr/bin/env python3
"""Scan host-malicious/ (read-only) and produce a structured file index.

Output: code/output/malicious_index.json
Quick inventory only; its prefix label counts cannot drive stratified splitting.
The supervised pipeline uses build_host_index.py to index ALL Host labels from
both roots before build_split.py, build_vocab.py --split and build_matrix.py --split.
Source data is never modified.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from ML.code.preprocess.pipeline_contract import validate_output_path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MALICIOUS_ROOT = PROJECT_ROOT / "host-malicious"
DEFAULT_OUTPUT = PROJECT_ROOT / "code" / "output" / "malicious_index.json"

FILE_PATTERN = re.compile(
    r"(?:^|\.)(?:AIA-\d+-\d+\.)?ecar-(?P<day>\d{4}-\d{2}-\d{2})-"
    r"(?P<host>sysclient\d+)(?:[._-].*)?\.(json\.gz)$",
    re.IGNORECASE,
)
AIA_PATTERN = re.compile(r"AIA-(\d+)-(\d+)", re.IGNORECASE)


def _parse_file(path: Path) -> dict[str, Any] | None:
    """Extract metadata from a malicious data file path."""
    match = FILE_PATTERN.search(path.name)
    if not match:
        return None

    day = match["day"]
    host = match["host"].lower()

    # Extract AIA group from path
    aia_group = None
    for part in path.parts:
        aia_match = AIA_PATTERN.search(part)
        if aia_match:
            aia_group = part
            break

    return {
        "path": str(path),
        "relative_path": str(path.relative_to(PROJECT_ROOT)),
        "day": day,
        "host": host,
        "aia_group": aia_group,
        "size_bytes": path.stat().st_size,
    }


def _quick_line_count(path: Path, max_lines: int = 100) -> dict[str, int]:
    """Read a small prefix to estimate if the file is valid."""
    try:
        with gzip.open(path, "rb") as f:
            lines = 0
            label_counts: dict[str, int] = {"0": 0, "1": 0, "missing": 0}
            for i in range(max_lines):
                line = f.readline()
                if not line:
                    break
                lines += 1
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                    label = record.get("label")
                    if label == 1:
                        label_counts["1"] += 1
                    elif label == 0:
                        label_counts["0"] += 1
                    else:
                        label_counts["missing"] += 1
                except (json.JSONDecodeError, UnicodeError):
                    pass
            return {"sample_lines": lines, "sample_labels": label_counts}
    except (OSError, EOFError):
        return {"sample_lines": 0, "sample_labels": {}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_MALICIOUS_ROOT,
                        help=f"malicious data root (default: {DEFAULT_MALICIOUS_ROOT})")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--sample-lines", type=int, default=50,
                        help="lines to sample per file for label distribution (default: 50)")
    parser.add_argument("--skip-sample", action="store_true",
                        help="skip per-file header sampling (faster)")
    args = parser.parse_args()
    args.output = validate_output_path(args.output, [args.root])

    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: malicious root not found: {root}", file=sys.stderr)
        return 1

    print(f"Scanning {root} …", file=sys.stderr, flush=True)
    started = time.monotonic()

    files: list[dict[str, Any]] = []
    skipped: list[str] = []

    for path in sorted(root.rglob("*.json.gz")):
        if not path.is_file():
            continue
        info = _parse_file(path)
        if info is None:
            skipped.append(str(path))
            continue
        if not args.skip_sample:
            info.update(_quick_line_count(path, args.sample_lines))
        files.append(info)

    if not files:
        print("ERROR: no malicious .json.gz files found", file=sys.stderr)
        return 1

    # Compute summary statistics
    days = sorted(set(f["day"] for f in files))
    hosts = sorted(set(f["host"] for f in files))
    aia_groups = sorted(set(f["aia_group"] for f in files if f.get("aia_group")))
    total_size = sum(f["size_bytes"] for f in files)

    index = {
        "scan_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(root),
        "source_sha256": {
            "build_malicious_index.py": hashlib.sha256(
                Path(__file__).read_bytes()).hexdigest()
        },
        "summary": {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "total_size_gb": round(total_size / (1024 ** 3), 2),
            "days": days,
            "hosts_count": len(hosts),
            "aia_groups": aia_groups,
            "files_per_day": {
                day: sum(1 for f in files if f["day"] == day) for day in days
            },
        },
        "skipped_files": skipped,
        "files": files,
    }

    # Write output
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = validate_output_path(output.with_name(f".{output.name}.tmp"), [root])
    try:
        with temp.open("w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)
            f.write("\n")
        temp.replace(output)
    finally:
        temp.unlink(missing_ok=True)

    elapsed = time.monotonic() - started
    print(f"Done in {elapsed:.1f}s", file=sys.stderr)
    print(f"  {len(files):,} files across {len(days)} days, {len(hosts)} hosts",
          file=sys.stderr)
    print(f"  Total: {index['summary']['total_size_gb']:.2f} GB",
          file=sys.stderr)
    print(f"  Wrote {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
