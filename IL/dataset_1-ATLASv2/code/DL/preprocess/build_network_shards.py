#!/usr/bin/env python3
"""Build Network DL Shards (Subset B) for ATLASv2 Incremental Learning.

Generates 15-minute sequence window shards (.npz) and manifests matching the
BiLSTM contract from OpTC (06d_BiLSTM_Kaggle_v2_final.ipynb).
Extracts 5 features:
  - Categorical: app_family, proto, resp_port_class, image_dir_class
  - Continuous: delta_t_log1p
Resolves the 'Firefox Paradox' via 2-tier LabelRefiner.
Applies 60% Train / 20% Val / 20% Test scenario-based split with benign undersampling.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import random
import sys
import time
from typing import Any

import numpy as np

# Add parent code root for shared modules
CODE_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(CODE_ROOT))

from preprocess.common_schema import (
    CanonicalEvent,
    classify_image_dir,
    classify_resp_port,
    extract_basename,
    parse_timestamp_micros,
)
from preprocess.label_refiner import LabelRefiner
from preprocess.cbc_adapter import CBCAdapter
from preprocess.split_config import (
    TRAIN_SCENARIOS,
    VAL_SCENARIOS,
    TEST_SCENARIOS,
    TARGET_BENIGN_RATIO,
)

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
WINDOW_SIZE_MICROS = 900_000_000  # 15 minutes in microseconds
MAX_SEQ_LEN = 512                 # Max events per window chunk


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def get_split_from_event(scenario: str, timestamp_micros: int) -> str:
    """Determine train/val/test split partition from scenario or timestamp date."""
    sc = scenario.lower().strip()
    # Explicit scenario check
    for s in TRAIN_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "train"
    for s in VAL_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "val"
    for s in TEST_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "test"

    # Benign day check from timestamp
    # Timestamps in ATLASv2:
    # 2022-07-15 / 2022-07-16 -> Train (Days 1 & 2)
    # 2022-07-17 -> Val (Day 3)
    # 2022-07-18 -> Test (Day 4)
    # 2022-07-19 / 2022-07-20 (Attack days background) -> Train
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


def map_resp_port_class(port: int) -> str:
    """Map destination port to OpTC category."""
    if port == 443:
        return "PORT_443_HTTPS"
    elif port == 80:
        return "PORT_80_HTTP"
    elif port == 8080:
        return "PORT_8080_HTTP_ALT"
    elif port == 53:
        return "PORT_53_DNS"
    elif port == 445:
        return "PORT_445_SMB"
    elif port == 22:
        return "PORT_22_SSH"
    elif port == 3389:
        return "PORT_3389_RDP"
    elif port >= 1024:
        return "REGISTERED"
    else:
        return "WELL_KNOWN_OTHER"


def main():
    parser = argparse.ArgumentParser(description="Build Network DL Shards for ATLASv2")
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
        "--optc-spec",
        default="/mnt/SSD_Data/optc/DL/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json",
        help="Path to OpTC preprocess_spec.json for vocabulary alignment",
    )
    parser.add_argument(
        "--output-dir",
        default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/preprocess/output",
        help="Output directory for generated shards and manifests",
    )
    parser.add_argument("--seed", type=int, default=42, help="Sampling seed")
    parser.add_argument("--target-benign-ratio", type=int, default=TARGET_BENIGN_RATIO, help="Benign to attack ratio for train")
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    data_dir = Path(args.data_dir)
    reapr_dir = Path(args.reapr_dir)
    optc_spec_path = Path(args.optc_spec)
    output_dir = Path(args.output_dir)

    print("=" * 80)
    print("ATLASv2 NETWORK DL PREPROCESSING (SUBSET B - 5 FEATURES)")
    print("=" * 80)
    print(f"Data Dir:     {data_dir}")
    print(f"REAPr Dir:    {reapr_dir}")
    print(f"OpTC Spec:    {optc_spec_path}")
    print(f"Output Dir:   {output_dir}")

    # 1. Load OpTC Vocabularies from preprocess_spec.json
    print("\n[1/6] Loading OpTC Category Maps...")
    optc_spec = json.loads(optc_spec_path.read_text(encoding="utf-8"))
    cat_spec = optc_spec["categorical"]["fields"]

    vocab_maps = {}
    for field_name in ["app_family", "proto", "resp_port_class", "image_dir_class"]:
        f_spec = cat_spec[field_name]
        mp = {"<UNK>": 0, "<MISSING>": 1}
        for item in f_spec["vocab"]:
            mp[item["value"]] = item["id"]
        vocab_maps[field_name] = mp
        print(f"  Field {field_name:18s}: {len(mp)} categories")

    # 2. Initialize LabelRefiner and CBCAdapter
    print("\n[2/6] Initializing LabelRefiner & Ground Truth...")
    refiner = LabelRefiner(reapr_dir)
    adapter = CBCAdapter(refiner)
    print(f"  Loaded attack scenarios: {len(refiner.scenario_attack_guids)}")

    # 3. Find and Stream all CBC-EDR JSONL files
    jsonl_files = sorted(list(data_dir.rglob("*.jsonl")))
    edr_files = [f for f in jsonl_files if "cbc-edr" in str(f) and "alerts" not in str(f)]
    print(f"\n[3/6] Discovered {len(edr_files)} CBC-EDR JSONL files:")
    for f in edr_files:
        print(f"  - {f.relative_to(data_dir)}")

    # 4. Stream events (netconn + OS logs) and aggregate into 15-min windows
    print("\n[4/6] Streaming Netconn & OS Events and Building Windows...")
    windows: dict[tuple[str, int], list[CanonicalEvent]] = {}
    window_scenarios: dict[tuple[str, int], str] = {}
    total_events = 0
    refined_attack_events = 0

    t0 = time.time()
    for f in edr_files:
        # Determine scenario from filename e.g. edr-h1-s1.jsonl -> s1, edr-h2-benign.jsonl -> benign
        stem = f.stem  # 'edr-h1-s1'
        parts = stem.split("-")
        sc = parts[-1] if len(parts) >= 3 else stem

        file_events = 0
        file_attack = 0
        for event in adapter.stream_file(f, sc):
            if event.event_type not in ("FLOW_START", "PROCESS_START", "CROSS_PROCESS"):
                continue
            total_events += 1
            file_events += 1
            if event.label == 1:
                refined_attack_events += 1
                file_attack += 1

            # Window key: (hostname, timestamp // WINDOW_SIZE_MICROS)
            w_idx = event.timestamp // WINDOW_SIZE_MICROS
            w_key = (event.hostname, w_idx)
            if w_key not in windows:
                windows[w_key] = []
                window_scenarios[w_key] = sc
            windows[w_key].append(event)

        print(f"  Processed {f.name:25s}: {file_events:7,d} events | {file_attack:5,d} attack")

    elapsed = time.time() - t0
    print(f"  Streaming complete in {elapsed:.1f}s.")
    print(f"  Total valid events:        {total_events:,}")
    print(f"  Refined attack events:     {refined_attack_events:,}")
    print(f"  Total 15-min windows:      {len(windows):,}")

    # 4b. Fit app_family Vocabulary on TRAIN partition
    print("\n[4b/6] Discovering & Fitting app_family Vocabulary on TRAIN Partition...")
    train_apps = set()
    for (hostname, w_idx), ev_list in windows.items():
        sc = window_scenarios[(hostname, w_idx)]
        first_ts = min(e.timestamp for e in ev_list)
        if get_split_from_event(sc, first_ts) == "train":
            for ev in ev_list:
                app = extract_basename(ev.target_path if (ev.event_type in ("PROCESS_START", "CROSS_PROCESS") and ev.target_path) else ev.process_path)
                if app and app not in vocab_maps["app_family"]:
                    train_apps.add(app)

    next_app_id = max(vocab_maps["app_family"].values()) + 1
    for app in sorted(train_apps):
        vocab_maps["app_family"][app] = next_app_id
        next_app_id += 1
    print(f"  Added {len(train_apps)} new application binaries from TRAIN partition.")
    print(f"  app_family vocabulary size expanded from 61 to {len(vocab_maps['app_family'])} categories.")

    # 5. Process Windows, Encode Features, and Assign Partitions
    print("\n[5/6] Encoding Window Sequences and Balancing Partitions...")
    split_samples: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}

    for (hostname, w_idx), ev_list in windows.items():
        # Sort events strictly causal by timestamp
        ev_list.sort(key=lambda e: e.timestamp)

        # Window-level label: 1 if any event has label 1, else 0
        w_label = 1 if any(e.label == 1 for e in ev_list) else 0
        sc = window_scenarios[(hostname, w_idx)]
        first_ts = ev_list[0].timestamp
        split = get_split_from_event(sc, first_ts)

        # Split window into chunks of max MAX_SEQ_LEN (512)
        n_chunks = math.ceil(len(ev_list) / MAX_SEQ_LEN)
        for chunk_idx in range(n_chunks):
            chunk_events = ev_list[chunk_idx * MAX_SEQ_LEN : (chunk_idx + 1) * MAX_SEQ_LEN]
            chunk_label = 1 if any(e.label == 1 for e in chunk_events) else 0

            # Encode features
            # x_cat: [app_family, proto, resp_port_class, image_dir_class]
            n_events = len(chunk_events)
            x_cat = np.zeros((n_events, 4), dtype=np.int64)
            delta_t = np.zeros(n_events, dtype=np.float32)

            prev_ts = chunk_events[0].timestamp
            for i, ev in enumerate(chunk_events):
                # 1. app_family (extract from target_path for procstart/crossproc, else process_path)
                app = extract_basename(ev.target_path if (ev.event_type in ("PROCESS_START", "CROSS_PROCESS") and ev.target_path) else ev.process_path)
                x_cat[i, 0] = vocab_maps["app_family"].get(app, 0)

                # 2. proto (FLOW_START has proto; procstart/crossproc use <MISSING>)
                if ev.event_type == "FLOW_START" and ev.proto:
                    p = ev.proto.lower()
                    x_cat[i, 1] = vocab_maps["proto"].get(p, 0)
                else:
                    x_cat[i, 1] = vocab_maps["proto"].get("<MISSING>", 1)

                # 3. resp_port_class (FLOW_START has port; procstart/crossproc use <MISSING>)
                if ev.event_type == "FLOW_START":
                    resp_port = ev.remote_port if not ev.inbound else ev.local_port
                    port_cat = map_resp_port_class(resp_port)
                    x_cat[i, 2] = vocab_maps["resp_port_class"].get(port_cat, 0)
                else:
                    x_cat[i, 2] = vocab_maps["resp_port_class"].get("<MISSING>", 1)

                # 4. image_dir_class
                path_for_dir = ev.target_path if (ev.event_type in ("PROCESS_START", "CROSS_PROCESS") and ev.target_path) else ev.process_path
                img_dir = classify_image_dir(path_for_dir)
                x_cat[i, 3] = vocab_maps["image_dir_class"].get(img_dir, 0)

                # 5. delta_t_log1p
                if i == 0:
                    delta_t[i] = 0.0
                else:
                    dt_sec = max(0.0, (ev.timestamp - prev_ts) / 1_000_000.0)
                    delta_t[i] = math.log1p(dt_sec)
                prev_ts = ev.timestamp

            sample_id = f"{hostname}_{w_idx}_c{chunk_idx:02d}"
            sample = {
                "sample_id": sample_id,
                "label": chunk_label,
                "event_count": n_events,
                "x_cat": x_cat,
                "delta_t_log1p": delta_t,
                "scenario": sc,
            }
            split_samples[split].append(sample)

    # Apply Train Undersampling of Benign background (Days 1 & 2)
    train_pos = [s for s in split_samples["train"] if s["label"] == 1]
    train_neg = [s for s in split_samples["train"] if s["label"] == 0]
    print(f"  Raw TRAIN: positive={len(train_pos):,}, negative={len(train_neg):,}")

    max_train_neg = max(len(train_pos) * args.target_benign_ratio, len(train_pos) * 10)
    if len(train_neg) > max_train_neg:
        print(f"  Undersampling TRAIN negatives to {max_train_neg:,} (ratio {args.target_benign_ratio}:1)")
        # Stratify by scenario: keep all scenario-based negatives, subsample benign background days
        sc_neg = [s for s in train_neg if "benign" not in s["scenario"]]
        bg_neg = [s for s in train_neg if "benign" in s["scenario"]]
        needed_bg = max_train_neg - len(sc_neg)
        if needed_bg > 0 and len(bg_neg) > needed_bg:
            bg_sampled = random.sample(bg_neg, needed_bg)
            train_neg = sc_neg + bg_sampled
        else:
            train_neg = random.sample(train_neg, max_train_neg)

    split_samples["train"] = train_pos + train_neg
    random.shuffle(split_samples["train"])

    print("\n  Partition Summary (Balanced Supervised Splits):")
    for sp in ["train", "val", "test"]:
        pos = sum(1 for s in split_samples[sp] if s["label"] == 1)
        neg = sum(1 for s in split_samples[sp] if s["label"] == 0)
        tot = len(split_samples[sp])
        print(f"    - {sp.upper():5s}: total={tot:6,d} | positive={pos:4,d} | negative={neg:6,d} | pos_ratio={pos/max(1,tot):.4%}")

    # 6. Write Shards and Manifests
    print("\n[6/6] Writing NPZ Shards, Manifests, and Specifications...")
    output_dir.mkdir(parents=True, exist_ok=True)
    shards_dir = output_dir / "shards"
    split_dir = output_dir / "split"
    prep_dir = output_dir / "preprocessing"
    integrity_dir = output_dir / "integrity"

    shards_dir.mkdir(parents=True, exist_ok=True)
    split_dir.mkdir(parents=True, exist_ok=True)
    prep_dir.mkdir(parents=True, exist_ok=True)
    integrity_dir.mkdir(parents=True, exist_ok=True)

    manifest_rows = []
    split_stats = {}

    for sp in ["train", "val", "test"]:
        sp_shard_dir = shards_dir / sp
        sp_shard_dir.mkdir(parents=True, exist_ok=True)
        samples = split_samples[sp]

        # Pack into shards of ~1000 samples each
        shard_size = 1000
        n_shards = math.ceil(len(samples) / shard_size) if samples else 0
        sp_events = 0
        sp_pos = 0
        sp_neg = 0

        for shard_idx in range(n_shards):
            shard_samples = samples[shard_idx * shard_size : (shard_idx + 1) * shard_size]
            n_s = len(shard_samples)

            offsets = np.zeros(n_s + 1, dtype=np.uint32)
            labels = np.zeros(n_s, dtype=np.uint8)
            cat_list = []
            delta_list = []

            curr_offset = 0
            for i, s in enumerate(shard_samples):
                offsets[i] = curr_offset
                labels[i] = s["label"]
                cat_list.append(s["x_cat"])
                delta_list.append(s["delta_t_log1p"])
                curr_offset += s["event_count"]

                if s["label"] == 1:
                    sp_pos += 1
                else:
                    sp_neg += 1
                sp_events += s["event_count"]

                shard_rel = f"shards/{sp}/shard_{shard_idx:04d}.npz"
                manifest_rows.append({
                    "sample_id": s["sample_id"],
                    "split": sp,
                    "label": s["label"],
                    "event_count": s["event_count"],
                    "shard_file": shard_rel,
                    "shard_sample_index": i,
                })

            offsets[n_s] = curr_offset
            shard_x_cat = np.concatenate(cat_list, axis=0) if cat_list else np.zeros((0, 4), dtype=np.int64)
            shard_delta = np.concatenate(delta_list, axis=0) if delta_list else np.zeros((0,), dtype=np.float32)
            tot_ev = len(shard_delta)

            # Subset B has 0 numerical features, 1 binary feature (all 0)
            shard_x_num = np.zeros((tot_ev, 0), dtype=np.float32)
            shard_x_missing = np.zeros((tot_ev, 0), dtype=np.float32)
            shard_x_bin = np.zeros((tot_ev, 1), dtype=np.float32)

            shard_file_path = sp_shard_dir / f"shard_{shard_idx:04d}.npz"
            np.savez_compressed(
                shard_file_path,
                sample_offsets=offsets,
                sample_labels=labels,
                x_cat=shard_x_cat,
                x_num=shard_x_num,
                x_num_missing=shard_x_missing,
                x_bin=shard_x_bin,
                delta_t_log1p=shard_delta,
            )

        split_stats[sp] = {
            "samples": len(samples),
            "positive_samples": sp_pos,
            "negative_samples": sp_neg,
            "total_events": sp_events,
            "shards": n_shards,
        }

    # Write network_sample_manifest.csv
    manifest_csv_path = split_dir / "network_sample_manifest.csv"
    with manifest_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "split", "label", "event_count", "shard_file", "shard_sample_index"])
        writer.writeheader()
        writer.writerows(manifest_rows)

    # Write preprocessing metadata
    keep_cat = ["app_family", "proto", "resp_port_class", "image_dir_class"]
    fields_meta = {}
    for f in keep_cat:
        mapping = vocab_maps[f]
        fields_meta[f] = {
            "mapping": mapping,
            "size": len(mapping),
            "min_train_frequency": 1,
            "active_for_model": True,
        }

    cat_maps_payload = {
        "version": "v2-adapter-from-preprocess_spec",
        "reserved_ids": {"<UNK>": 0, "<MISSING>": 1},
        "fit_split": "train",
        "fields": fields_meta,
    }
    (prep_dir / "network_category_maps.json").write_text(json.dumps(cat_maps_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    num_stats_payload = {
        "version": "v2-adapter-from-preprocess_spec",
        "fit_split": "train",
        "transform": "log1p_zscore",
        "zscore_clip_abs": 10.0,
        "features": {},
    }
    (prep_dir / "network_numeric_stats.json").write_text(json.dumps(num_stats_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    prep_spec_payload = {
        "version": "v2-adapter-from-preprocess_spec",
        "fit_split": "train",
        "active_categorical_features": keep_cat,
        "active_numerical_features": [],
        "inactive_categorical_features": {
            "service": "dropped in Subset B",
            "conn_state": "dropped in Subset B",
            "principal_class": "dropped in Subset B",
        },
        "inactive_numerical_features": {},
        "derived_binary_features": {"has_missed_bytes": {"active": False, "reason": "constant 0"}},
        "categorical_reserved_ids": {"<UNK>": 0, "<MISSING>": 1},
        "numeric_zscore_clip_abs": 10.0,
        "note": "ATLASv2 Subset B: 4 categorical (app_family, proto, resp_port_class, image_dir_class) + delta_t_log1p",
    }
    (prep_dir / "network_preprocess_spec.json").write_text(json.dumps(prep_spec_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    # Mirror original preprocess_spec layout
    shutil_spec = {
        "model_input_layout": {
            "x_cat_columns": keep_cat,
            "x_num_columns": [],
        }
    }
    (prep_dir / "preprocess_spec.json").write_text(json.dumps(shutil_spec, indent=2, ensure_ascii=False), encoding="utf-8")
    (prep_dir / "feature_subset.json").write_text(json.dumps({
        "x_cat_columns_all": keep_cat,
        "keep_categorical": keep_cat,
        "drop_numeric": True,
        "zero_binary": True,
    }, indent=2), encoding="utf-8")

    # Generate fingerprint
    fp_hash = hashlib.sha256(json.dumps(prep_spec_payload, sort_keys=True).encode("utf-8")).hexdigest()
    (prep_dir / "network_preprocess_fingerprint.json").write_text(json.dumps({
        "fingerprint_sha256": fp_hash,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")

    # Write dataset_manifest.json
    dataset_manifest = {
        "version": "atlasv2-network-dl-v1.0",
        "dataset_name": "atlasv2_network_dl_subsetB",
        "fingerprint": fp_hash,
        "source": {
            "step04c_preprocess_fingerprint": fp_hash,
            "step05f_c_preprocess_fingerprint": fp_hash,
            "raw_dataset": "ATLASv2 CBC-EDR",
        },
        "split_stats": split_stats,
    }
    (output_dir / "dataset_manifest.json").write_text(json.dumps(dataset_manifest, indent=2), encoding="utf-8")

    # Write build_config.json
    build_config = {
        "script": "build_network_shards.py",
        "window_size_seconds": 900,
        "max_seq_len": MAX_SEQ_LEN,
        "target_benign_ratio": args.target_benign_ratio,
        "features": {
            "categorical": keep_cat,
            "continuous": ["delta_t_log1p"],
        },
    }
    (output_dir / "build_config.json").write_text(json.dumps(build_config, indent=2), encoding="utf-8")

    # Write README_DATASET.md
    readme_content = f"""# ATLASv2 Network DL Preprocessed Dataset (Subset B)

Preprocessed 15-minute sliding window sequence shards for Continual Learning (OpTC -> ATLASv2).
- Resolves the Firefox Paradox via Two-Tier Label Refinement.
- 5 Features: app_family, proto, resp_port_class, image_dir_class, delta_t_log1p.
- Supervised Balanced Split: 60% Train, 20% Val, 20% Test.

## Split Statistics:
{json.dumps(split_stats, indent=2)}
"""
    (output_dir / "README_DATASET.md").write_text(readme_content, encoding="utf-8")

    print("\n" + "=" * 80)
    print("PREPROCESSING COMPLETED SUCCESSFULLY!")
    print(f"Artifacts saved to: {output_dir}")
    print("=" * 80)


if __name__ == "__main__":
    main()
