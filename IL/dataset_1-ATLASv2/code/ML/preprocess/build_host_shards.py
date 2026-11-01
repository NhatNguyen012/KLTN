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

from preprocess.common_schema import CanonicalEvent, extract_basename
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

PREDEFINED_DOMAIN_TOKENS = [
    # Firefox & App Cache
    "temp_context::app_own_cache",
    # File Extension Categorization
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
    # Office Temporary / AutoSave
    "file_ext::office_autosave_tmp",
    # Process Context (active network socket)
    "proc_context::has_netconn",
    # Parent Process Basenames (Atomic Lineage)
    "parent_image::basename=regsvr32.exe",
    "parent_image::basename=mshta.exe",
    "parent_image::basename=winword.exe",
    "parent_image::basename=excel.exe",
    "parent_image::basename=eqnedt32.exe",
    "parent_image::basename=cmd.exe",
    "parent_image::basename=powershell.exe",
    "parent_image::basename=svchost.exe",
    "parent_image::basename=explorer.exe",
    "parent_image::basename=firefox.exe",
    "parent_image::basename=services.exe",
    "parent_image::basename=payload.exe",
    # Network Flow Tokens (RFC 1340 / RFC 1918 Standard)
    "net::direction=outbound",
    "net::direction=inbound",
    "net::proto=tcp",
    "net::proto=udp",
    "port::range=well_known",
    "port::range=registered",
    "port::range=dynamic_ephemeral",
    "port::service=http",
    "port::service=https",
    "port::service=dns",
    "port::service=smb",
    "port::service=other_well_known",
    "net::ip_scope=rfc1918_private",
    "net::ip_scope=loopback",
    "net::ip_scope=public",
]


def get_ip_scope(ip_str: str) -> str:
    """Classify IP address according to RFC 1918 private / loopback / public scopes."""
    if not ip_str:
        return "unknown"
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_loopback:
            return "loopback"
        elif ip.is_private:
            return "rfc1918_private"
        else:
            return "public"
    except Exception:
        return "unknown"


class FileSessionIndex:
    """Indexes process session activities (child spawns, netconns, and parent lineage) for rolling-window context."""
    def __init__(self) -> None:
        self.child_spawns: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.netconns: dict[str, list[int]] = defaultdict(list)
        self.parent_map: dict[str, tuple[str, str]] = {}  # guid -> (parent_guid, parent_basename)

    def add_event(self, event: CanonicalEvent) -> None:
        et = event.event_type
        guid = event.process_guid
        ts = event.timestamp
        if guid and event.parent_path:
            p_base = extract_basename(event.parent_path).lower()
            if p_base:
                self.parent_map[guid] = (event.parent_guid, p_base)
        if et == "PROCESS_START":
            child = extract_basename(event.target_path).lower()
            self.child_spawns[guid].append((ts, child))
            if event.parent_guid:
                self.child_spawns[event.parent_guid].append((ts, child))
            if event.target_guid and child:
                self.parent_map[event.target_guid] = (guid, extract_basename(event.process_path).lower())
        elif et == "FLOW_START":
            self.netconns[guid].append(ts)
            if event.parent_guid:
                self.netconns[event.parent_guid].append(ts)

    def get_ancestors(self, guid: str, max_depth: int = 5) -> list[str]:
        ancestors = []
        curr = guid
        depth = 0
        while curr in self.parent_map and depth < max_depth:
            p_guid, p_base = self.parent_map[curr]
            if p_base:
                ancestors.append(p_base)
            if not p_guid or p_guid == curr:
                break
            curr = p_guid
            depth += 1
        return ancestors

    def has_child_exploit(self, guid: str, ts: int, window_micros: int = 30_000_000) -> bool:
        if not guid:
            return False
        for c_ts, c_name in self.child_spawns.get(guid, ()):
            if abs(c_ts - ts) <= window_micros and c_name in EXPLOIT_CHILD_PROCS:
                return True
        return False

    def has_netconn(self, guid: str, ts: int, window_micros: int = 30_000_000) -> bool:
        if not guid:
            return False
        for n_ts in self.netconns.get(guid, ()):
            if abs(n_ts - ts) <= window_micros:
                return True
        return False


def extract_domain_shift_tokens(event: CanonicalEvent, session: FileSessionIndex) -> list[str]:
    tokens: list[str] = []
    proc_base = extract_basename(event.process_path).lower()
    target_raw = event.target_path or ""
    target_norm = target_raw.strip().strip('"\'').replace("/", "\\").lower()
    target_base = extract_basename(target_raw).lower()
    et = event.event_type

    # 1. Firefox & App Cache (Browser writing to its own local cache)
    if proc_base == "firefox.exe" and ("mozilla" in target_norm or "firefox" in target_norm):
        tokens.append("temp_context::app_own_cache")

    # 2. File extension classification
    if et in ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE"):
        if "." in target_base:
            ext = "." + target_base.rsplit(".", 1)[-1]
        else:
            ext = ""

        if ext in (".exe", ".com", ".scr", ".pif"):
            tokens.append("file_ext::type=exe")
        elif ext in (".zip", ".7z", ".tar", ".gz", ".rar", ".cab"):
            tokens.append("file_ext::type=zip")
        elif ext in (".hta",):
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

        # Office autosave draft / temp files (~*.tmp, .asd, .wbk)
        if proc_base in ("winword.exe", "excel.exe", "powerpnt.exe"):
            if "~" in target_base or ext in (".tmp", ".asd", ".wbk"):
                tokens.append("file_ext::office_autosave_tmp")

    # 3. Module Load: emit atomic module basename
    if et == "MODULE_LOAD" and target_base:
        tokens.append(f"module_name::{target_base}")

    # 4. Atomic Parent Process Basename
    parent_base = extract_basename(event.parent_path).lower()
    if parent_base:
        tokens.append(f"parent_image::basename={parent_base}")

    # 5. Process Session Rolling Window Context (active network socket)
    if session.has_netconn(event.process_guid, event.timestamp, window_micros=30_000_000):
        tokens.append("proc_context::has_netconn")

    # 6. Network Flow Attributes (RFC 1340 / RFC 1918 Standard)
    if et == "FLOW_START":
        tokens.append("net::direction=inbound" if event.inbound else "net::direction=outbound")
        if event.proto:
            proto_clean = event.proto.lower().strip()
            if proto_clean in ("tcp", "udp"):
                tokens.append(f"net::proto={proto_clean}")

        port = event.remote_port
        if 0 <= port <= 65535:
            if port < 1024:
                tokens.append("port::range=well_known")
                if port == 80:
                    tokens.append("port::service=http")
                elif port == 443:
                    tokens.append("port::service=https")
                elif port == 53:
                    tokens.append("port::service=dns")
                elif port == 445:
                    tokens.append("port::service=smb")
                else:
                    tokens.append("port::service=other_well_known")
            elif port <= 49151:
                tokens.append("port::range=registered")
            else:
                tokens.append("port::range=dynamic_ephemeral")

        scope = get_ip_scope(event.remote_ip)
        if scope != "unknown":
            tokens.append(f"net::ip_scope={scope}")

    return tokens


def canonical_ecar_record(event: CanonicalEvent) -> dict[str, Any]:
    """Convert CanonicalEvent into standard eCAR dictionary for tokenize_record."""
    et = event.event_type
    props = {}
    obj = "process"
    act = "start"

    if event.parent_path:
        props["parent_image_path"] = event.parent_path

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

    # 2. Initialize LabelRefiner & CBCAdapter
    print("\n[2/6] Initializing LabelRefiner & Ground Truth...")
    refiner = LabelRefiner(reapr_dir)
    adapter = CBCAdapter(refiner)
    print(f"  Loaded attack scenarios: {len(refiner.scenario_attack_guids)}")

    # 3. Find CBC-EDR JSONL files
    jsonl_files = sorted(list(data_dir.rglob("*.jsonl")))
    edr_files = [f for f in jsonl_files if "cbc-edr" in str(f) and "alerts" not in str(f)]
    print(f"\n[3/6] Discovered {len(edr_files)} CBC-EDR JSONL files:")
    for f in edr_files:
        print(f"  - {f.relative_to(data_dir)}")

    # 4. Stream and collect events
    print("\n[4/6] Streaming Host Events and Tokenizing...")
    split_events: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    total_events = 0
    refined_attack_events = 0
    t0 = time.time()

    for f in edr_files:
        stem = f.stem
        parts = stem.split("-")
        sc = parts[-1] if len(parts) >= 3 else stem

        file_total = 0
        file_attack = 0

        # Subsample benign files during reading to keep balanced representation
        is_bg = "benign" in stem
        sample_stride = 10 if is_bg else 1  # sample benign background stream

        session = FileSessionIndex()
        file_events = []
        line_idx = 0
        for event in adapter.stream_file(f, sc):
            session.add_event(event)
            line_idx += 1
            if is_bg and (line_idx % sample_stride != 0):
                continue
            file_events.append(event)

        for event in file_events:
            total_events += 1
            file_total += 1
            if event.label == 1:
                refined_attack_events += 1
                file_attack += 1

            split = get_split_from_event(sc, event.timestamp)

            # Tokenize record with base tokenizer + refined domain shift features
            rec = canonical_ecar_record(event)
            grouped, audit = tokenize_record(rec)
            tokens = flatten_tokens(grouped)
            shift_tokens = extract_domain_shift_tokens(event, session)
            all_tokens = tokens + shift_tokens

            # Check new tokens on TRAIN partition
            if split == "train":
                for token in all_tokens:
                    if token not in extended_vocab:
                        new_idx = len(extended_vocab)
                        extended_vocab[token] = new_idx
                        new_train_tokens[token] = new_idx

            # Map tokens to column indices using extended_vocab
            col_indices = [extended_vocab[t] for t in all_tokens if t in extended_vocab]
            col_indices = sorted(set(col_indices))

            split_events[split].append({
                "columns": col_indices,
                "label": event.label,
                "scenario": sc,
            })

        print(f"  Processed {f.name:25s}: {file_total:7,d} events | {file_attack:5,d} attack")

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
