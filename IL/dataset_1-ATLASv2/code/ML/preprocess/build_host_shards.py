#!/usr/bin/env python3
"""Build Host ML Shards for ATLASv2 Incremental Learning.

Generates compressed binary sparse shards (.npz) and manifests matching the
Host ML contract from OpTC (host_shards.py, lgbm.ipynb).
- Preserves OpTC's frozen vocab.json (10,317 features) strictly immutable.
- Discovers new tokens on TRAIN and appends monotonically to vocab_extended.json.
- Resolves the 'Firefox Paradox' via 2-tier LabelRefiner.
- Applies 60% Train / 20% Val / 20% Test scenario-based split with benign undersampling.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
import math
from pathlib import Path
import random
import shutil
import sys
import time
from typing import Any

import numpy as np

# Add project roots
CODE_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_ROOT = Path("/mnt/SSD_Data/optc")
sys.path.insert(0, str(CODE_ROOT))
sys.path.insert(0, str(WORKSPACE_ROOT))

from preprocess.common_schema import (
    CanonicalEvent,
    classify_image_dir,
    extract_basename,
)
from preprocess.label_refiner import LabelRefiner
from preprocess.cbc_adapter import CBCAdapter
from preprocess.split_config import (
    TRAIN_SCENARIOS,
    VAL_SCENARIOS,
    TEST_SCENARIOS,
    TARGET_BENIGN_RATIO,
)
from ML.code.preprocess.ecar_tokenizer import (
    GROUPS,
    flatten_tokens,
    tokenize_record,
)
from ML.code.preprocess.host_shards import FORMAT, SCHEMA, SPLITS, ShardBuffer, sha256
from collections import defaultdict
import ntpath

# Finite directory categories from OpTC spec (no heuristic malware lists)
DIR_CATEGORIES = (
    "SYSTEM32",
    "PROGRAM_FILES",
    "TEMP_OR_APPDATA",
    "WINDOWS_OTHER",
    "USERS_OTHER",
    "OTHER",
)

PREDEFINED_DOMAIN_TOKENS = [
    # 1. Browser self-cache structural indicator
    "temp_context::app_own_cache",
    # 2. File Extension Structural Categorization
    "file_ext::type=exe",
    "file_ext::type=zip",
    "file_ext::type=hta",
    "file_ext::type=vbs",
    "file_ext::type=ps1",
    "file_ext::type=bat",
    "file_ext::type=tmp",
    "file_ext::type=sqlite",
    "file_ext::type=none_or_dir",
    "file_ext::type=other",
    "file_ext::office_autosave_tmp",
    # 3. Causal Typed Incoming Interaction Context (Past-only [ts - 30s/300s, ts])
    "proc_context::has_netconn",
    # 4. Cross-Process Structural Directory Transitions (Actor_Dir and Actor_Dir -> Target_Dir)
    *[f"crossproc::actor_dir={d}" for d in DIR_CATEGORIES],
    *[f"crossproc::dir={d1}->{d2}" for d1 in DIR_CATEGORIES for d2 in DIR_CATEGORIES],
]


class FileSessionIndex:
    """Strictly causal (past-only, t' <= t) index for Parent Lineage and Typed Incoming Interactions."""

    def __init__(self) -> None:
        self.netconns: dict[str, list[int]] = defaultdict(list)
        # parent_map: guid -> (parent_guid, parent_basename, parent_dir_category)
        self.parent_map: dict[str, tuple[str, str, str]] = {}
        # incoming_crossproc: target_guid -> list of (ts, actor_dir_category)
        self.incoming_crossproc: dict[str, list[tuple[int, str]]] = defaultdict(list)

    def add_event(self, event: CanonicalEvent) -> None:
        """Update session state causally at current event timestamp ts."""
        et = event.event_type
        guid = event.process_guid
        ts = event.timestamp

        # Record 1-hop parent mapping from current event
        if guid and event.parent_path:
            p_base = extract_basename(event.parent_path).lower()
            p_dir = classify_image_dir(event.parent_path)
            if p_base:
                self.parent_map[guid] = (event.parent_guid, p_base, p_dir)

        if et == "PROCESS_START":
            if event.target_guid and event.target_path:
                self.parent_map[event.target_guid] = (
                    guid,
                    extract_basename(event.process_path).lower(),
                    classify_image_dir(event.process_path),
                )
        elif et == "FLOW_START":
            # Record network activity timestamp in monotonic order
            if guid:
                self.netconns[guid].append(ts)
            if event.parent_guid:
                self.netconns[event.parent_guid].append(ts)
        elif et == "CROSS_PROCESS":
            # Record typed incoming cross-process interaction onto target_guid
            if event.target_guid:
                actor_dir = classify_image_dir(event.process_path)
                self.incoming_crossproc[event.target_guid].append((ts, actor_dir))

    def get_ancestors(self, guid: str, max_depth: int = 2) -> list[tuple[str, str]]:
        """Return list of (basename, dir_category) for up to max_depth ancestors."""
        ancestors: list[tuple[str, str]] = []
        curr = guid
        depth = 0
        while curr in self.parent_map and depth < max_depth:
            p_guid, p_base, p_dir = self.parent_map[curr]
            if p_base:
                ancestors.append((p_base, p_dir))
            if not p_guid or p_guid == curr:
                break
            curr = p_guid
            depth += 1
        return ancestors

    def has_netconn(self, guid: str, ts: int, window_micros: int = 30_000_000) -> bool:
        """Strictly causal check [ts - window, ts] on current process_guid (no 2-hop sibling leak)."""
        if not guid or guid not in self.netconns:
            return False
        n_list = self.netconns[guid]
        left = bisect_left(n_list, ts - window_micros)
        right = bisect_right(n_list, ts)
        return right > left

    def get_incoming_crossproc_dirs(self, guid: str, ts: int, window_micros: int = 30_000_000) -> set[str]:
        """Return distinct actor directory categories that opened `guid` within [ts - 30s, ts]."""
        if not guid or guid not in self.incoming_crossproc:
            return set()
        low = ts - window_micros
        dirs: set[str] = set()
        # Iterate backward from most recent causal interaction (<= ts)
        for ev_ts, actor_dir in reversed(self.incoming_crossproc[guid]):
            if ev_ts < low:
                break
            if ev_ts <= ts:
                dirs.add(actor_dir)
        return dirs


def extract_domain_shift_tokens(event: CanonicalEvent, session: FileSessionIndex) -> list[str]:
    tokens: list[str] = []
    proc_base = extract_basename(event.process_path).lower()
    self_dir = classify_image_dir(event.process_path)
    target_raw = event.target_path or ""
    target_norm = target_raw.strip().strip('"\'').replace("/", "\\").lower()
    target_base = extract_basename(target_raw).lower()
    et = event.event_type

    # 1. Intrinsic Event Structure: Browser local cache
    if proc_base == "firefox.exe" and ("mozilla" in target_norm or "firefox" in target_norm):
        tokens.append("temp_context::app_own_cache")

    # 2. Intrinsic Event Structure: File extension classification
    if et in ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE"):
        ext = ("." + target_base.rsplit(".", 1)[-1]) if "." in target_base else ""
        if ext in (".exe", ".com", ".scr", ".pif"):
            tokens.append("file_ext::type=exe")
        elif ext in (".zip", ".7z", ".tar", ".gz", ".rar", ".cab"):
            tokens.append("file_ext::type=zip")
        elif ext in (".hta", ".sct"):
            tokens.append("file_ext::type=hta")
        elif ext in (".vbs", ".vbe"):
            tokens.append("file_ext::type=vbs")
        elif ext in (".ps1", ".psm1", ".psd1"):
            tokens.append("file_ext::type=ps1")
        elif ext in (".bat", ".cmd"):
            tokens.append("file_ext::type=bat")
        elif ext in (".tmp",):
            tokens.append("file_ext::type=tmp")
        elif ext in (".sqlite", ".db", ".dat"):
            tokens.append("file_ext::type=sqlite")
        elif not ext or ext == "." or target_norm.endswith("\\"):
            tokens.append("file_ext::type=none_or_dir")
        else:
            tokens.append("file_ext::type=other")

        if proc_base in ("winword.exe", "excel.exe", "powerpnt.exe"):
            if "~" in target_base or ext in (".tmp", ".asd", ".wbk"):
                tokens.append("file_ext::office_autosave_tmp")

    # 3. Intrinsic Event Structure: Cross-Process structural directory transition
    if et == "CROSS_PROCESS":
        tokens.append(f"crossproc::actor_dir={self_dir}")
        if target_raw:
            target_dir = classify_image_dir(target_raw)
            tokens.append(f"crossproc::dir={self_dir}->{target_dir}")

    # 4. Typed Incoming Interaction Context (Strictly causal: [ts - W, ts])
    net_win = 30_000_000 if proc_base == "firefox.exe" else 300_000_000
    if session.has_netconn(event.process_guid, event.timestamp, window_micros=net_win):
        tokens.append("proc_context::has_netconn")

    # 5. Immediate Parent Process Lineage (1-Hop)
    p_base = extract_basename(event.parent_path).lower()
    if p_base:
        tokens.append(f"parent_image::basename={p_base}")

    return tokens


def canonical_ecar_record(event: CanonicalEvent) -> dict[str, Any]:
    """Convert CanonicalEvent into standard eCAR dictionary for tokenize_record."""
    et = event.event_type
    props = {}
    obj = "process"
    act = "start"

    if et == "PROCESS_START":
        obj = "process"
        act = "start"
        props = {
            "image_path": event.target_path or event.process_path,
            "parent_image_path": event.process_path,
            "command_line": event.process_cmdline,
        }
    elif et == "PROCESS_END":
        obj = "process"
        act = "terminate"
        props = {"image_path": event.process_path}
    elif et == "FILE_WRITE":
        obj = "file"
        act = "write"
        props = {"image_path": event.process_path, "file_path": event.target_path}
    elif et == "FILE_CREATE":
        obj = "file"
        act = "create"
        props = {"image_path": event.process_path, "file_path": event.target_path}
    elif et == "FILE_DELETE":
        obj = "file"
        act = "delete"
        props = {"image_path": event.process_path, "file_path": event.target_path}
    elif et == "REGISTRY_WRITE":
        obj = "registry"
        act = "modify"
        props = {"image_path": event.process_path, "key": event.target_path}
    elif et == "MODULE_LOAD":
        obj = "module"
        act = "load"
        props = {"image_path": event.process_path, "module_path": event.target_path}
    elif et == "CROSS_PROCESS":
        obj = "process"
        act = "open"
        props = {"image_path": event.process_path}
    elif et == "FLOW_START":
        # Network flow events on host
        obj = "flow"
        act = "start"
        props = {"image_path": event.process_path}

    return {
        "object": obj,
        "action": act,
        "principal": event.username,
        "properties": props,
    }


def get_split_from_event(scenario: str, timestamp_micros: int) -> str:
    """Determine train/val/test split partition from scenario or timestamp date."""
    sc = scenario.lower().strip()
    for s in TRAIN_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "train"
    for s in VAL_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "val"
    for s in TEST_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "test"

    dt = datetime.fromtimestamp(timestamp_micros / 1_000_000, tz=timezone.utc)
    day_str = dt.strftime("%Y-%m-%d")
    if day_str <= "2022-07-16":
        return "train"
    elif day_str == "2022-07-17":
        return "val"
    elif day_str == "2022-07-18":
        return "test"
    else:
        return "train"


def process_file_worker(args_tuple: tuple[str, str, str, int]) -> tuple[str, list[dict[str, Any]], int, int]:
    """Worker process: sort chronologically, update session causally (t' <= t), and tokenize."""
    f_path, sc, reapr_dir, sample_stride = args_tuple
    f = Path(f_path)
    refiner = LabelRefiner(Path(reapr_dir))
    adapter = CBCAdapter(refiner)
    is_bg = "benign" in f.stem

    # Read all events and sort strictly by timestamp ascending to guarantee causal order
    all_raw_events = list(adapter.stream_file(f, sc))
    all_raw_events.sort(key=lambda e: e.timestamp)

    session = FileSessionIndex()
    results = []
    file_total = 0
    file_attack = 0
    line_idx = 0

    for event in all_raw_events:
        # Update session state causally at current timestamp t (ONLY past & present t' <= t exist in session)
        session.add_event(event)
        if event.event_type == "FLOW_START":
            continue
        line_idx += 1
        if is_bg and (line_idx % sample_stride != 0):
            continue

        file_total += 1
        if event.label == 1:
            file_attack += 1

        split = get_split_from_event(sc, event.timestamp)
        rec = canonical_ecar_record(event)
        grouped, audit = tokenize_record(rec)
        tokens = flatten_tokens(grouped)
        shift_tokens = extract_domain_shift_tokens(event, session)
        all_tokens = tokens + shift_tokens

        results.append({
            "tokens": all_tokens,
            "label": event.label,
            "scenario": sc,
            "split": split,
        })

    return f.name, results, file_total, file_attack


def main():
    parser = argparse.ArgumentParser(description="Build Host ML Shards for ATLASv2")
    parser.add_argument(
        "--data-dir",
        default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/output/raw_cbc/atlasv2/data",
        help="Directory containing raw or extracted cbc-edr jsonl files",
    )
    parser.add_argument(
        "--reapr-dir",
        default="/mnt/SSD_Data/optc/DATASET/ATLASv2/reapr-ground-truth/atlasv2",
        help="Directory containing REAPr .labels and .seeds",
    )
    parser.add_argument(
        "--optc-vocab",
        default="/mnt/SSD_Data/optc/ML/code/output/host_ml_parent_incoming_seed02/vocab.json",
        help="Path to OpTC frozen vocab.json",
    )
    parser.add_argument(
        "--output-dir",
        default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML/preprocess/output",
        help="Output directory for generated shards and manifests",
    )
    parser.add_argument("--seed", type=int, default=42, help="Sampling seed")
    parser.add_argument("--workers", type=int, default=6, help="Parallel worker processes")
    parser.add_argument("--target-benign-ratio", type=int, default=TARGET_BENIGN_RATIO, help="Benign to attack ratio for train")
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    data_dir = Path(args.data_dir)
    reapr_dir = Path(args.reapr_dir)
    optc_vocab_path = Path(args.optc_vocab)
    output_dir = Path(args.output_dir)

    print("=" * 80)
    print("ATLASv2 HOST ML PREPROCESSING (FROZEN OP-TC VOCAB + MONOTONIC EXTENSION)")
    print("=" * 80)
    print(f"Data Dir:     {data_dir}")
    print(f"REAPr Dir:    {reapr_dir}")
    print(f"OpTC Vocab:   {optc_vocab_path}")
    print(f"Output Dir:   {output_dir}")
    print(f"Workers:      {args.workers}")

    # 1. Load Frozen OpTC Vocab
    print("\n[1/6] Loading Frozen OpTC Vocabulary...")
    optc_vocab = json.loads(optc_vocab_path.read_text(encoding="utf-8"))
    base_width = len(optc_vocab)
    print(f"  OpTC Vocab Base Width: {base_width:,} features")
    optc_sha = sha256(optc_vocab_path)
    print(f"  OpTC Vocab SHA256:     {optc_sha}")

    extended_vocab = dict(optc_vocab)
    new_train_tokens = {}
    for tok in PREDEFINED_DOMAIN_TOKENS:
        if tok not in extended_vocab:
            new_idx = len(extended_vocab)
            extended_vocab[tok] = new_idx
            new_train_tokens[tok] = new_idx

    # 2. Initialize LabelRefiner & Ground Truth
    print("\n[2/6] Initializing LabelRefiner & Ground Truth...")
    refiner = LabelRefiner(reapr_dir)
    print(f"  Loaded attack scenarios: {len(refiner.scenario_attack_guids)}")

    # 3. Find CBC-EDR JSONL files
    jsonl_files = sorted(list(data_dir.rglob("*.jsonl")))
    edr_files = [f for f in jsonl_files if "cbc-edr" in str(f) and "alerts" not in str(f)]
    print(f"\n[3/6] Discovered {len(edr_files)} CBC-EDR JSONL files:")
    for f in edr_files:
        print(f"  - {f.relative_to(data_dir)}")

    # 4. Stream and collect events in parallel
    print("\n[4/6] Streaming Host Events and Tokenizing in Parallel...")
    split_events_raw: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    split_events: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    total_events = 0
    refined_attack_events = 0
    t0 = time.time()

    tasks = []
    for f in edr_files:
        stem = f.stem
        parts = stem.split("-")
        sc = parts[-1] if len(parts) >= 3 else stem
        is_bg = "benign" in stem
        sample_stride = 10 if is_bg else 1
        tasks.append((str(f), sc, str(reapr_dir), sample_stride))

    num_workers = min(args.workers, len(edr_files))
    print(f"  Spawning {num_workers} parallel workers across {len(edr_files)} files...")
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        ordered_futures = [executor.submit(process_file_worker, t) for t in tasks]
        for future in ordered_futures:
            fname, results, file_total, file_attack = future.result()
            total_events += file_total
            refined_attack_events += file_attack
            for item in results:
                sp = item["split"]
                if sp == "train":
                    for token in item["tokens"]:
                        if token not in extended_vocab:
                            new_idx = len(extended_vocab)
                            extended_vocab[token] = new_idx
                            new_train_tokens[token] = new_idx
                split_events_raw[sp].append(item)
            print(f"  Processed {fname:25s}: {file_total:7,d} events | {file_attack:5,d} attack")

    # Map tokens to column indices using finalized extended_vocab
    print("  Mapping tokens to integer column indices...")
    for sp in ["train", "val", "test"]:
        for item in split_events_raw[sp]:
            col_indices = [extended_vocab[t] for t in item["tokens"] if t in extended_vocab]
            col_indices = sorted(set(col_indices))
            split_events[sp].append({
                "columns": col_indices,
                "label": item["label"],
                "scenario": item["scenario"],
            })

    elapsed = time.time() - t0
    print(f"  Streaming complete in {elapsed:.1f}s.")
    print(f"  Total processed events:   {total_events:,}")
    print(f"  Refined attack events:    {refined_attack_events:,}")
    print(f"  New TRAIN tokens found:   {len(new_train_tokens):,}")
    print(f"  Extended Vocab Width:     {len(extended_vocab):,}")

    # 5. Balance Partitions with Undersampling
    print("\n[5/6] Balancing Partitions...")
    train_pos = [e for e in split_events["train"] if e["label"] == 1]
    train_neg = [e for e in split_events["train"] if e["label"] == 0]
    print(f"  Raw TRAIN: positive={len(train_pos):,}, negative={len(train_neg):,}")

    max_train_neg = max(len(train_pos) * args.target_benign_ratio, len(train_pos) * 10)
    if len(train_neg) > max_train_neg:
        print(f"  Undersampling TRAIN negatives to {max_train_neg:,} (ratio {args.target_benign_ratio}:1)")
        sc_neg = [e for e in train_neg if "benign" not in e["scenario"]]
        bg_neg = [e for e in train_neg if "benign" in e["scenario"]]
        needed_bg = max_train_neg - len(sc_neg)
        if needed_bg > 0 and len(bg_neg) > needed_bg:
            bg_sampled = random.sample(bg_neg, needed_bg)
            train_neg = sc_neg + bg_sampled
        else:
            train_neg = random.sample(train_neg, max_train_neg)

    split_events["train"] = train_pos + train_neg
    random.shuffle(split_events["train"])

    print("\n  Partition Summary (Balanced Supervised Splits):")
    for sp in ["train", "val", "test"]:
        pos = sum(1 for e in split_events[sp] if e["label"] == 1)
        neg = sum(1 for e in split_events[sp] if e["label"] == 0)
        tot = len(split_events[sp])
        print(f"    - {sp.upper():5s}: total={tot:7,d} | positive={pos:5,d} | negative={neg:7,d} | pos_ratio={pos/max(1,tot):.4%}")

    # 6. Build Shards and Package Manifest
    print("\n[6/6] Writing Binary Delta Shards (.npz) and Manifest...")
    output_dir.mkdir(parents=True, exist_ok=True)
    assets_dir = output_dir / "assets"
    shards_dir = output_dir / "shards"
    assets_dir.mkdir(parents=True, exist_ok=True)
    shards_dir.mkdir(parents=True, exist_ok=True)

    # Write assets
    out_vocab = assets_dir / "vocab.json"
    shutil.copy2(optc_vocab_path, out_vocab)  # Exact frozen copy
    out_vocab_ext = assets_dir / "vocab_extended.json"
    out_vocab_ext.write_text(json.dumps(extended_vocab, indent=2, sort_keys=False), encoding="utf-8")

    split_sha = hashlib.sha256(b"atlasv2_scenario_stratified_split").hexdigest()
    vocab_metadata = {
        "base_vocabulary_source": str(optc_vocab_path),
        "base_vocabulary_sha256": optc_sha,
        "vocabulary_sha256": optc_sha,
        "split_sha256": split_sha,
        "base_width": base_width,
        "extended_width": len(extended_vocab),
        "new_train_tokens_count": len(new_train_tokens),
        "split_policy": "60_train_20_val_20_test_scenario_stratified",
    }
    out_meta = assets_dir / "vocab_metadata.json"
    out_meta.write_text(json.dumps(vocab_metadata, indent=2), encoding="utf-8")

    manifest_shards = []
    splits_totals = {s: dict(rows=0, nnz=0, label_0=0, label_1=0, bytes=0) for s in SPLITS}
    sources = [{"source_id": "atlasv2_host_telemetry", "name": "ATLASv2 EDR Telemetry"}]

    vocab_width = len(extended_vocab)
    rows_per_shard = 20_000
    for sp in SPLITS:
        sp_events = split_events[sp]
        sp_dir = shards_dir / sp
        sp_dir.mkdir(parents=True, exist_ok=True)

        n_shards = math.ceil(len(sp_events) / rows_per_shard) if sp_events else 0
        for shard_idx in range(n_shards):
            chunk = sp_events[shard_idx * rows_per_shard : (shard_idx + 1) * rows_per_shard]
            # Encode with full vocabulary width (base OpTC features + monotonic extensions)
            buf = ShardBuffer(vocab_width)

            for line_no, item in enumerate(chunk, start=1):
                buf.append(item["columns"], item["label"], line_no)

            payload, meta = buf.encode()
            shard_rel = f"shards/{sp}/shard_{shard_idx:04d}.npz"
            shard_path = output_dir / shard_rel
            shard_path.write_bytes(payload)

            manifest_shards.append({
                "source_id": "atlasv2_host_telemetry",
                "split": sp,
                "volume": "local",
                "path": shard_rel,
                "rows": meta["rows"],
                "nnz": meta["nnz"],
                "label_0": meta["label_0"],
                "label_1": meta["label_1"],
                "bytes": meta["bytes"],
                "sha256": meta["sha256"],
                "source_line_first": int(meta["source_line_first"]),
                "source_line_last": int(meta["source_line_last"]),
            })

            splits_totals[sp]["rows"] += meta["rows"]
            splits_totals[sp]["nnz"] += meta["nnz"]
            splits_totals[sp]["label_0"] += meta["label_0"]
            splits_totals[sp]["label_1"] += meta["label_1"]
            splits_totals[sp]["bytes"] += meta["bytes"]

    # Copy host_shards.py and shard_metrics.py to output root for standalone notebook execution
    shutil.copy2(WORKSPACE_ROOT / "ML/code/preprocess/host_shards.py", output_dir / "host_shards.py")
    shutil.copy2(WORKSPACE_ROOT / "ML/code/preprocess/shard_metrics.py", output_dir / "shard_metrics.py")

    manifest = {
        "format": FORMAT,
        "schema": SCHEMA,
        "complete": True,
        "vocab_size": vocab_width,
        "base_vocab_size": base_width,
        "extended_vocab_size": vocab_width,
        "volumes": {"local": "."},
        "assets_sha256": {
            "vocab.json": sha256(out_vocab),
            "vocab_metadata.json": sha256(out_meta),
        },
        "split_sha256": split_sha,
        "vocabulary_sha256": optc_sha,
        "sources": sources,
        "shards": manifest_shards,
        "splits": splits_totals,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Ensure volumes/local symlink exists for standalone packaging
    vol_dir = output_dir / "volumes"
    vol_dir.mkdir(exist_ok=True)
    symlink = vol_dir / "local"
    if not symlink.exists() and not symlink.is_symlink():
        symlink.symlink_to("..")

    print("\n" + "=" * 80)
    print("HOST ML PREPROCESSING COMPLETED SUCCESSFULLY!")
    print(f"Artifacts saved to: {output_dir}")
    print("=" * 80)


if __name__ == "__main__":
    main()
