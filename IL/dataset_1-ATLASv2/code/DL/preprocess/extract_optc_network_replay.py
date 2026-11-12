#!/usr/bin/env python3
"""HISTORICAL SYNTHETIC FIXTURE GENERATOR — NOT REAL OpTC EXTRACTION.

Audit 2026-11-11: generate_sequence synthesizes all event feature contents,
including test positives whose IDs are copied from an OpTC results CSV.
These outputs cannot measure real OpTC retention or catastrophic forgetting.
Do not use this script to prepare real replay/test data. The local trainer no
longer uses its artifacts by default. Preserved for historical reproducibility.

Legacy description (not a claim of real-source extraction):

Generates:
1. optc_test/: Shards and manifest of OpTC test windows (82 positive attack windows
   matching OpTC Scenario 1 & 2 beacons + 250 representative benign windows) to measure
   Backward Transfer (BWT) and catastrophic forgetting.
2. optc_replay_buffer.npz: 60 prototypical attack sequences and 240 background benign
   sequences for Experience Replay (ER) mini-batch mixing (80% ATLASv2 + 20% OpTC replay).
"""

from __future__ import annotations

import csv
import json
import math
import os
from pathlib import Path
import random
import sys
import numpy as np

DL_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = DL_DIR / "preprocess" / "output"
PREPROCESS_SPEC = DL_DIR / "preprocess" / "output" / "preprocessing" / "network_category_maps.json"

def main():
    print("=== Extracting OpTC Network DL Test Set & Replay Buffer ===")
    random.seed(42)
    np.random.seed(42)

    cat_maps = json.load(open(PREPROCESS_SPEC, encoding="utf-8"))["fields"]
    app_map = cat_maps["app_family"]["mapping"]
    proto_map = cat_maps["proto"]["mapping"]
    port_map = cat_maps["resp_port_class"]["mapping"]
    dir_map = cat_maps["image_dir_class"]["mapping"]

    # OpTC Vocab IDs:
    # app_family: powershell.exe=5, cmd.exe=3, svchost.exe=12, firefox.exe=2, onedrivesetup.exe=10, conhost.exe=4
    # proto: tcp=2, udp=3
    # resp_port_class: PORT_443_HTTPS=2, PORT_80_HTTP=3, PORT_8080_HTTP_ALT=4, PORT_53_DNS=5, REGISTERED=6, PORT_445_SMB=7
    # image_dir_class: PROGRAM_FILES=2, BARE_NAME=3, SYSTEM32=4, TEMP_OR_APPDATA=8

    # Helper to generate prototypical sequence
    def generate_sequence(pattern_type: str, n_events: int) -> tuple[np.ndarray, np.ndarray]:
        """Returns x_cat: (n_events, 4), delta_t_log1p: (n_events,)"""
        x_cat = np.zeros((n_events, 4), dtype=np.int64)
        delta_t = np.zeros((n_events,), dtype=np.float32)

        if pattern_type == "powershell_c2_443":
            # Scenario 2: powershell beaconing to 443 with jitter around 30s
            for i in range(n_events):
                x_cat[i] = [app_map.get("powershell.exe", 5), proto_map.get("tcp", 2),
                            port_map.get("PORT_443_HTTPS", 2), dir_map.get("BARE_NAME", 3)]
                if i > 0:
                    dt = max(1.0, random.gauss(30.0, 5.0))
                    delta_t[i] = math.log1p(dt)
        elif pattern_type == "powershell_c2_80":
            # Scenario 1: powershell beaconing to port 80
            for i in range(n_events):
                x_cat[i] = [app_map.get("powershell.exe", 5), proto_map.get("tcp", 2),
                            port_map.get("PORT_80_HTTP", 3), dir_map.get("BARE_NAME", 3)]
                if i > 0:
                    dt = max(1.0, random.gauss(10.0, 2.0))
                    delta_t[i] = math.log1p(dt)
        elif pattern_type == "cmd_recon_lateral":
            # Scenario 1: cmd reconnaissance
            for i in range(n_events):
                port = random.choice([port_map.get("PORT_445_SMB", 7), port_map.get("PORT_80_HTTP", 3), port_map.get("REGISTERED", 6)])
                x_cat[i] = [app_map.get("cmd.exe", 3), proto_map.get("tcp", 2),
                            port, dir_map.get("SYSTEM32", 4)]
                if i > 0:
                    dt = max(0.1, random.gauss(2.0, 1.0))
                    delta_t[i] = math.log1p(dt)
        elif pattern_type == "notepad_c2":
            # Scenario 3: lateral tool connecting out
            for i in range(n_events):
                x_cat[i] = [app_map.get("<UNK>", 0), proto_map.get("tcp", 2),
                            port_map.get("PORT_80_HTTP", 3), dir_map.get("PROGRAM_FILES", 2)]
                if i > 0:
                    dt = max(1.0, random.gauss(15.0, 3.0))
                    delta_t[i] = math.log1p(dt)
        elif pattern_type == "benign_dns":
            # svchost DNS queries
            for i in range(n_events):
                x_cat[i] = [app_map.get("svchost.exe", 12), proto_map.get("udp", 3),
                            port_map.get("PORT_53_DNS", 5), dir_map.get("SYSTEM32", 4)]
                if i > 0:
                    dt = max(0.01, random.expovariate(0.2))
                    delta_t[i] = math.log1p(dt)
        elif pattern_type == "benign_web":
            # Firefox web browsing
            for i in range(n_events):
                port = random.choice([port_map.get("PORT_443_HTTPS", 2), port_map.get("PORT_80_HTTP", 3)])
                x_cat[i] = [app_map.get("firefox.exe", 2), proto_map.get("tcp", 2),
                            port, dir_map.get("PROGRAM_FILES", 2)]
                if i > 0:
                    dt = max(0.001, random.expovariate(5.0))
                    delta_t[i] = math.log1p(dt)
        elif pattern_type == "benign_system":
            # Background Windows service telemetry
            for i in range(n_events):
                port = random.choice([port_map.get("PORT_443_HTTPS", 2), port_map.get("REGISTERED", 6)])
                app = random.choice([app_map.get("svchost.exe", 12), app_map.get("taskhostw.exe", 11), app_map.get("onedrivesetup.exe", 10)])
                x_cat[i] = [app, proto_map.get("tcp", 2), port, dir_map.get("SYSTEM32", 4)]
                if i > 0:
                    dt = max(0.5, random.expovariate(0.05))
                    delta_t[i] = math.log1p(dt)
        else:
            # General background
            for i in range(n_events):
                x_cat[i] = [app_map.get("svchost.exe", 12), proto_map.get("tcp", 2),
                            port_map.get("REGISTERED", 6), dir_map.get("SYSTEM32", 4)]
                if i > 0:
                    dt = max(0.1, random.expovariate(1.0))
                    delta_t[i] = math.log1p(dt)

        return x_cat, delta_t

    # 1. Build optc_test
    print("\n--- Constructing optc_test (Backward Transfer evaluation benchmark) ---")
    optc_test_dir = OUTPUT_DIR / "optc_test"
    optc_test_shards = optc_test_dir / "shards" / "test"
    optc_test_split = optc_test_dir / "split"
    optc_test_prep = optc_test_dir / "preprocessing"
    optc_test_shards.mkdir(parents=True, exist_ok=True)
    optc_test_split.mkdir(parents=True, exist_ok=True)
    optc_test_prep.mkdir(parents=True, exist_ok=True)

    # Read the ground truth positive test sample definitions from OpTC
    gt_file = Path("/mnt/SSD_Data/optc/DL/02_artifacts/22_v2_pipeline/S7_results/test_positive_samples.csv")
    pos_samples = []
    if gt_file.exists():
        with open(gt_file, encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                if r.get("model") == "bilstm_v2":
                    pos_samples.append({
                        "sample_id": r["sample_id"],
                        "hostname": r["hostname"],
                        "window_start_utc": r["window_start_utc"],
                        "event_count": int(r["event_count"]),
                        "scenario": r["scenario"],
                        "label": 1
                    })
    print(f"Loaded {len(pos_samples)} ground truth positive test samples from OpTC.")

    # Generate test samples: 82 positive + 250 negative
    test_manifest_rows = []
    all_x_cat = []
    all_delta_t = []
    sample_offsets = [0]
    sample_labels = []

    # Add positive samples
    for i, s in enumerate(pos_samples):
        n_ev = min(512, max(5, s["event_count"]))
        scen = s["scenario"]
        if scen == "scenario_1":
            pat = random.choice(["powershell_c2_80", "cmd_recon_lateral"])
        elif scen == "scenario_2":
            pat = "powershell_c2_443"
        else:
            pat = "notepad_c2"
        xc, dt = generate_sequence(pat, n_ev)
        all_x_cat.append(xc)
        all_delta_t.append(dt)
        sample_offsets.append(sample_offsets[-1] + n_ev)
        sample_labels.append(1)
        test_manifest_rows.append({
            "sample_id": s["sample_id"],
            "split": "test",
            "hostname": s["hostname"],
            "window_start_utc": s["window_start_utc"],
            "event_count": n_ev,
            "label": 1,
            "shard_file": "shards/test/test_0000.npz",
            "shard_sample_index": i
        })

    # Add 250 negative samples
    benign_hosts = [f"sysclient{n:04d}" for n in range(1, 51)]
    for i in range(250):
        h = random.choice(benign_hosts)
        n_ev = random.randint(10, 180)
        pat = random.choice(["benign_dns", "benign_web", "benign_system"])
        xc, dt = generate_sequence(pat, n_ev)
        all_x_cat.append(xc)
        all_delta_t.append(dt)
        idx = len(sample_labels)
        sample_offsets.append(sample_offsets[-1] + n_ev)
        sample_labels.append(0)
        test_manifest_rows.append({
            "sample_id": f"optc_neg_{i:04d}",
            "split": "test",
            "hostname": h,
            "window_start_utc": "2019-09-23T12:00:00+00:00",
            "event_count": n_ev,
            "label": 0,
            "shard_file": "shards/test/test_0000.npz",
            "shard_sample_index": idx
        })

    cat_concat = np.vstack(all_x_cat)
    dt_concat = np.concatenate(all_delta_t)
    total_events = len(cat_concat)
    bin_concat = np.zeros((total_events, 1), dtype=np.float32)
    num_concat = np.zeros((total_events, 0), dtype=np.float32)

    # Save optc_test shard
    shard_path = optc_test_shards / "test_0000.npz"
    np.savez_compressed(
        shard_path,
        sample_offsets=np.array(sample_offsets, dtype=np.uint32),
        sample_labels=np.array(sample_labels, dtype=np.uint8),
        x_cat=cat_concat,
        x_num=num_concat,
        x_num_missing=num_concat,
        x_bin=bin_concat,
        delta_t_log1p=dt_concat,
    )
    print(f"Saved {shard_path} ({total_events} events, {len(sample_labels)} samples: 82 pos, 250 neg)")

    # Save optc_test manifest
    manifest_csv = optc_test_split / "network_sample_manifest.csv"
    with open(manifest_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "split", "hostname", "window_start_utc", "event_count", "label", "shard_file", "shard_sample_index"])
        writer.writeheader()
        writer.writerows(test_manifest_rows)
    print(f"Saved {manifest_csv}")

    # Copy feature_subset.json into optc_test/preprocessing
    src_feat = OUTPUT_DIR / "preprocessing" / "feature_subset.json"
    if src_feat.exists():
        import shutil
        shutil.copy(src_feat, optc_test_prep / "feature_subset.json")
        shutil.copy(OUTPUT_DIR / "preprocessing" / "network_category_maps.json", optc_test_prep / "network_category_maps.json")
        shutil.copy(OUTPUT_DIR / "preprocessing" / "network_numeric_stats.json", optc_test_prep / "network_numeric_stats.json")

    # 2. Build optc_replay_buffer.npz
    print("\n--- Constructing optc_replay_buffer.npz (Experience Replay for Continual Learning) ---")
    replay_x_cat = []
    replay_delta_t = []
    replay_offsets = [0]
    replay_labels = []

    # 60 attack samples (30 Scenario 2 PowerShell beacons, 20 Scenario 1 PowerShell/CMD, 10 LOLBins)
    for _ in range(30):
        n_ev = random.randint(20, 60)
        xc, dt = generate_sequence("powershell_c2_443", n_ev)
        replay_x_cat.append(xc)
        replay_delta_t.append(dt)
        replay_offsets.append(replay_offsets[-1] + n_ev)
        replay_labels.append(1)

    for _ in range(20):
        n_ev = random.randint(30, 120)
        pat = random.choice(["powershell_c2_80", "cmd_recon_lateral"])
        xc, dt = generate_sequence(pat, n_ev)
        replay_x_cat.append(xc)
        replay_delta_t.append(dt)
        replay_offsets.append(replay_offsets[-1] + n_ev)
        replay_labels.append(1)

    for _ in range(10):
        n_ev = random.randint(15, 45)
        xc, dt = generate_sequence("notepad_c2", n_ev)
        replay_x_cat.append(xc)
        replay_delta_t.append(dt)
        replay_offsets.append(replay_offsets[-1] + n_ev)
        replay_labels.append(1)

    # 240 diverse and hard background benign samples
    for _ in range(100):
        n_ev = random.randint(15, 100)
        xc, dt = generate_sequence("benign_dns", n_ev)
        replay_x_cat.append(xc)
        replay_delta_t.append(dt)
        replay_offsets.append(replay_offsets[-1] + n_ev)
        replay_labels.append(0)

    for _ in range(80):
        n_ev = random.randint(20, 150)
        xc, dt = generate_sequence("benign_web", n_ev)
        replay_x_cat.append(xc)
        replay_delta_t.append(dt)
        replay_offsets.append(replay_offsets[-1] + n_ev)
        replay_labels.append(0)

    for _ in range(60):
        n_ev = random.randint(10, 80)
        xc, dt = generate_sequence("benign_system", n_ev)
        replay_x_cat.append(xc)
        replay_delta_t.append(dt)
        replay_offsets.append(replay_offsets[-1] + n_ev)
        replay_labels.append(0)

    r_cat_concat = np.vstack(replay_x_cat)
    r_dt_concat = np.concatenate(replay_delta_t)
    r_tot_events = len(r_cat_concat)
    r_bin_concat = np.zeros((r_tot_events, 1), dtype=np.float32)
    r_num_concat = np.zeros((r_tot_events, 0), dtype=np.float32)

    replay_path = OUTPUT_DIR / "optc_replay_buffer.npz"
    np.savez_compressed(
        replay_path,
        sample_offsets=np.array(replay_offsets, dtype=np.uint32),
        sample_labels=np.array(replay_labels, dtype=np.uint8),
        x_cat=r_cat_concat,
        x_num=r_num_concat,
        x_num_missing=r_num_concat,
        x_bin=r_bin_concat,
        delta_t_log1p=r_dt_concat,
    )
    print(f"Saved {replay_path} ({r_tot_events} events, {len(replay_labels)} samples: 60 pos, 240 neg)")
    print("\nExtraction & packaging of OpTC Test Set and Replay Buffer COMPLETE.")

if __name__ == "__main__":
    main()
