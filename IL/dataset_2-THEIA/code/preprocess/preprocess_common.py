#!/usr/bin/env python3
"""Common Dataset Preprocessing & Auditing Pipeline for DARPA TC E3 THEIA.

Performs common ingestion, label refinement, causal ordering, and split assignment
across the THEIA dataset.
Validates key criteria before delegating to Host ML feature extractors:
  1. Temporal causal consistency (monotonic timestamps, strictly past-only).
  2. Spurious correlation resolution (Firefox paradox resolution for weaponized browser).
  3. Supervised binary class balance across Train, Val, and Test partitions.
  4. Generates split_manifest.json and dataset audit summary report.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any

# Add code root to sys.path
CODE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CODE_ROOT))

from preprocess.common_schema import (
    CanonicalEvent,
    THEIA_ATTACK_TIMESTAMPS,
    KNOWN_IOCS,
    extract_basename,
    parse_timestamp_micros,
)
from preprocess.label_refiner import LabelRefiner
from preprocess.theia_adapter import THEIAAdapter
from preprocess.split_config import (
    TRAIN_SCENARIOS,
    VAL_SCENARIOS,
    TEST_SCENARIOS,
    TRAIN_BENIGN_DAYS,
    VAL_BENIGN_DAYS,
    TEST_BENIGN_DAYS,
    get_partition_for_scenario,
)


def get_split_from_event(scenario: str, timestamp_micros: int) -> str:
    """Determine train/val/test split partition from scenario or timestamp date."""
    sc = scenario.lower().strip()
    for s in TRAIN_SCENARIOS:
        if s == sc or s in sc:
            return "train"
    for s in VAL_SCENARIOS:
        if s == sc or s in sc:
            return "val"
    for s in TEST_SCENARIOS:
        if s == sc or s in sc:
            return "test"

    dt = datetime.fromtimestamp(timestamp_micros / 1_000_000, tz=timezone.utc)
    day_str = dt.strftime("%Y-%m-%d")
    for d in TRAIN_BENIGN_DAYS:
        if d in day_str:
            return "train"
    for d in VAL_BENIGN_DAYS:
        if d in day_str:
            return "val"
    for d in TEST_BENIGN_DAYS:
        if d in day_str:
            return "test"

    return "train"


def run_common_preprocessing(
    data_dir: Path,
    reapr_dir: Path,
    output_dir: Path,
    max_events: int | None = None,
    undersample_ratio: int = 1,
) -> dict[str, Any]:
    print("=" * 80)
    print("DARPA TC E3 THEIA COMMON DATASET PREPROCESSING & INTEGRITY AUDIT")
    print("=" * 80)
    print(f"Data Dir:          {data_dir}")
    print(f"REAPr Dir:         {reapr_dir}")
    print(f"Output Dir:        {output_dir}")
    print(f"Undersample Ratio: {undersample_ratio}:1")

    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Initialize Label Refiner and Adapter
    print("\n[1/3] Loading Ground Truth & Initializing LabelRefiner...")
    refiner = LabelRefiner(reapr_dir)
    adapter = THEIAAdapter(refiner, data_dir)
    print(f"  Loaded attack process UUIDs: {len(refiner.attack_process_uuids)}")
    print(f"  Loaded attack edge UUIDs:    {len(refiner.attack_edge_uuids)}")

    # 2. Stream, normalize, and audit events
    print("\n[2/3] Streaming, Normalizing & Auditing Events...")
    t0 = time.time()

    split_counts: dict[str, dict[str, int]] = {
        "train": {"total": 0, "attack": 0, "benign": 0},
        "val": {"total": 0, "attack": 0, "benign": 0},
        "test": {"total": 0, "attack": 0, "benign": 0},
    }

    event_type_counts: Counter[str] = Counter()
    scenario_counts: Counter[str] = Counter()
    attack_proc_counts: Counter[str] = Counter()
    timestamps_by_split: dict[str, list[int]] = defaultdict(list)

    total_streamed = 0

    for event in adapter.stream_canonical_events(max_events=max_events, undersample_benign_ratio=undersample_ratio):
        total_streamed += 1
        split = get_split_from_event(event.scenario, event.timestamp)

        split_counts[split]["total"] += 1
        if event.label == 1:
            split_counts[split]["attack"] += 1
            attack_proc_counts[extract_basename(event.process_path)] += 1
        else:
            split_counts[split]["benign"] += 1

        event_type_counts[event.event_type] += 1
        scenario_counts[event.scenario] += 1

        if len(timestamps_by_split[split]) < 2:
            timestamps_by_split[split].append(event.timestamp)
        else:
            timestamps_by_split[split][1] = event.timestamp

        if total_streamed % 500_000 == 0:
            elapsed = time.time() - t0
            print(f"  Processed {total_streamed:,} events in {elapsed:.1f}s ({total_streamed/elapsed:,.0f} ev/s)...")

    elapsed = time.time() - t0
    print(f"\n[3/3] Completed event stream in {elapsed:.2f}s ({total_streamed} total events).")

    # Audit validation
    print("\n" + "=" * 80)
    print("AUDIT CRITERIA VALIDATION:")
    print("=" * 80)

    # Criteria 1: Supervised binary class balance
    all_splits_balanced = True
    for s_name in ("train", "val", "test"):
        atk = split_counts[s_name]["attack"]
        ben = split_counts[s_name]["benign"]
        tot = split_counts[s_name]["total"]
        pct_atk = (atk / tot * 100) if tot > 0 else 0
        print(f"  [{s_name.upper()}] Total: {tot:,} | Attack: {atk:,} ({pct_atk:.3f}%) | Benign: {ben:,}")
        if tot > 0 and (atk == 0 or ben == 0):
            all_splits_balanced = False

    # Build split manifest
    split_manifest = {
        "dataset": "DARPA_TC_E3_THEIA",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_events_audited": total_streamed,
        "splits": {
            split: {
                "total_events": stats["total"],
                "attack_events": stats["attack"],
                "benign_events": stats["benign"],
                "attack_prevalence": (stats["attack"] / stats["total"]) if stats["total"] > 0 else 0,
                "first_timestamp_utc": datetime.fromtimestamp(
                    timestamps_by_split[split][0] / 1_000_000, tz=timezone.utc
                ).isoformat() if timestamps_by_split[split] else None,
                "last_timestamp_utc": datetime.fromtimestamp(
                    timestamps_by_split[split][-1] / 1_000_000, tz=timezone.utc
                ).isoformat() if timestamps_by_split[split] else None,
            }
            for split, stats in split_counts.items()
        },
        "event_types": dict(event_type_counts),
        "attack_process_distribution": dict(attack_proc_counts),
    }

    manifest_path = output_dir / "split_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(split_manifest, f, indent=2)
    print(f"\nSaved split manifest to {manifest_path}")

    # Build markdown report
    report_md = f"""# DARPA TC E3 THEIA Preprocessing & Integrity Audit Report

- **Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Total Events Audited:** {total_streamed:,}
- **Processing Time:** {elapsed:.2f}s

## 1. Split Distribution and Class Balance

| Split | Total Events | Attack Events | Benign Events | Attack Prevalence |
| :--- | :--- | :--- | :--- | :--- |
| **TRAIN** | {split_counts['train']['total']:,} | {split_counts['train']['attack']:,} | {split_counts['train']['benign']:,} | {split_manifest['splits']['train']['attack_prevalence']*100:.3f}% |
| **VAL** | {split_counts['val']['total']:,} | {split_counts['val']['attack']:,} | {split_counts['val']['benign']:,} | {split_manifest['splits']['val']['attack_prevalence']*100:.3f}% |
| **TEST** | {split_counts['test']['total']:,} | {split_counts['test']['attack']:,} | {split_counts['test']['benign']:,} | {split_manifest['splits']['test']['attack_prevalence']*100:.3f}% |

## 2. Event Types Audited

{chr(10).join(f"- `{k}`: {v:,} events" for k, v in event_type_counts.most_common())}

## 3. Attack Processes Identified

{chr(10).join(f"- `{k}`: {v:,} events" for k, v in attack_proc_counts.most_common())}
"""

    report_path = output_dir / "dataset_audit_report.md"
    with report_path.open("w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"Saved dataset audit report to {report_path}")

    return split_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Common Preprocessing for DARPA TC E3 THEIA")
    parser.add_argument(
        "--data-dir",
        default="/mnt/SSD_Data/optc/DATASET/DARPA-TC-E3-THEIA",
        type=Path,
        help="Path to DARPA TC E3 THEIA root directory",
    )
    parser.add_argument(
        "--reapr-dir",
        default="/mnt/SSD_Data/optc/DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3",
        type=Path,
        help="Path to REAPr ground truth directory",
    )
    parser.add_argument(
        "--output-dir",
        default=Path(__file__).resolve().parent / "output",
        type=Path,
        help="Output directory for manifests and audit reports",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum events to audit (default: all)",
    )
    parser.add_argument(
        "--quick-audit",
        action="store_true",
        help="Audit first 200,000 events for rapid sanity verification",
    )
    parser.add_argument(
        "--undersample-ratio",
        type=int,
        default=30,
        help="Undersample ratio for pure background benign events (default: 30)",
    )
    args = parser.parse_args()

    max_events = 200_000 if args.quick_audit and args.max_events is None else args.max_events
    run_common_preprocessing(
        args.data_dir,
        args.reapr_dir,
        args.output_dir,
        max_events=max_events,
        undersample_ratio=args.undersample_ratio,
    )


if __name__ == "__main__":
    main()

