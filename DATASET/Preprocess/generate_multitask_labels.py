#!/usr/bin/env python3
"""Decoupled Sidecar Multi-Task Label Generator for DARPA OpTC Dataset.

Implements Two-Tier Grounded Semantic Mapping:
  Tier 1: Corpus Anchor (Scenario Attribution based on date, host, and Provatek/Inria ground truth).
  Tier 2: Event-level Semantic Discriminator (MITRE ATT&CK Stages/Tactics based on intrinsic action,
          object, payload, command-line syntax, and cross-process interactions).

Outputs:
  - output/optc_multitask_labels.json.gz (~7.7 MB, O(1) in-memory catalog for 360,567 malicious events)
  - output/manifest.json (Provenance, statistics, class distributions, SHA256)
"""

from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from DATASET.Preprocess.label_catalog import SCENARIO_MAP, STAGE_MAP

DEFAULT_GT_PATH = (
    PROJECT_ROOT
    / "DATASET/DARPA-OPTC/a_new_hope_for_darpa_optc/labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz"
)
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "DATASET/Preprocess/output"

# Known C2 destination addresses from Provatek Red Team Ground Truth
KNOWN_C2_HOSTS = {
    "132.197.158.98",  # SC1 C2 (news.com:80)
    "202.6.172.98",    # SC2 C2 (sports.com:443)
    "53.192.68.50",    # SC3 C2 (notepadplus-sourceforge.net:8080)
}


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("MultiTaskLabelGen")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(ch)
    return logger


def classify_event_semantics(event: dict) -> tuple[int, int]:
    """Map a malicious ground-truth event to (scenario_id, stage_id)."""
    ts = event.get("timestamp", "")
    day = ts[:10]
    host = event.get("hostname", "").lower().split(".")[0]
    obj = event.get("object", "")
    act = event.get("action", "")
    oa = f"{obj}:{act}"
    
    props = event.get("properties", {})
    img = (props.get("image_path") or "").lower()
    cmd = (props.get("command_line") or "").lower()
    parent_img = (props.get("parent_image_path") or "").lower()
    payload = (props.get("payload") or "").lower()
    
    # -------------------------------------------------------------
    # 1. Tier 1: Scenario Attribution (SC1, SC2, SC3)
    # -------------------------------------------------------------
    if day == "2019-09-23":
        scenario_id = 1  # SC1_EmpireStaging
    elif day == "2019-09-24":
        scenario_id = 2  # SC2_CustomEmpireLateral
    elif day == "2019-09-25":
        if host in ("sysclient0051", "sysclient0351"):
            scenario_id = 3  # SC3_MaliciousUpdate (Targeted hosts)
        else:
            scenario_id = 2  # SC2_CustomEmpireLateral (Overnight continuation)
    else:
        scenario_id = 0  # Benign / Outside evaluation
        
    # -------------------------------------------------------------
    # 2. Tier 2: MITRE ATT&CK Stage / Tactic
    # -------------------------------------------------------------
    stage_id = 1  # Default: Execution
    
    # Process Injection / Defense Evasion (T1055)
    if oa == "THREAD:REMOTE_CREATE" or "notepad++" in img or "lsass.exe" in parent_img:
        stage_id = 2  # Defense_Evasion_Injection
        
    # AMSI Bypass / Defense Evasion (T1562)
    elif "amsi" in payload or "amsiinitfailed" in payload:
        stage_id = 3  # Defense_Evasion_AMSI
        
    # Discovery (T1018, T1057, T1082)
    elif (
        "ping.exe" in img
        or "ipconfig" in cmd
        or "whoami" in img
        or "whoami" in cmd
        or "get-process" in payload
        or "net view" in cmd
    ):
        stage_id = 4  # Discovery
        
    # Credential Access (T1003)
    elif (
        "lsass" in img
        or "mimikatz" in payload
        or "lsadump" in payload
        or "sekurlsa" in payload
    ):
        stage_id = 5  # Credential_Access
        
    # Lateral Movement (T1021, T1047)
    elif (
        "mstsc.exe" in img
        or "plink.exe" in img
        or "remote desktop" in cmd
        or "invoke-wmimethod" in payload
    ):
        stage_id = 6  # Lateral_Movement
        
    # Persistence / Privilege Escalation (T1078, T1547)
    elif (
        "net user" in cmd
        or "administrators" in cmd
        or obj == "REGISTRY"
    ):
        stage_id = 7  # Persistence
        
    # Command and Control (T1071)
    elif obj == "FLOW":
        stage_id = 8  # Command_and_Control
        
    # Collection / Exfiltration (T1560, T1048)
    elif (obj == "FILE" and act in ("WRITE", "CREATE")) or "export.zip" in cmd or "allgone.zip" in cmd:
        stage_id = 9  # Collection_Exfiltration
        
    return scenario_id, stage_id


def generate_multitask_labels(
    gt_path: str | Path,
    output_dir: str | Path,
    version: str = "v1"
) -> dict:
    logger = setup_logger()
    gt_path = Path(gt_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Starting Multi-Task Label Generation (Version {version})")
    logger.info(f"Source Ground Truth: {gt_path}")
    
    if not gt_path.exists():
        raise FileNotFoundError(f"Ground truth file missing: {gt_path}")
        
    catalog = {}
    scenario_counts = Counter()
    stage_counts = Counter()
    
    t0 = time.time()
    total_records = 0
    
    with gzip.open(gt_path, "rt", encoding="utf-8") as f:
        for line in f:
            total_records += 1
            record = json.loads(line)
            eid = record.get("id")
            if not eid:
                continue
                
            sc_id, st_id = classify_event_semantics(record)
            catalog[eid] = [sc_id, st_id]
            scenario_counts[sc_id] += 1
            stage_counts[st_id] += 1
            
            if total_records % 100000 == 0:
                logger.info(f"Processed {total_records:,} records...")
                
    elapsed = time.time() - t0
    logger.info(f"Finished processing {total_records:,} events in {elapsed:.2f}s")
    
    # Save Catalog to output_dir
    catalog_filename = f"optc_multitask_labels_{version}.json.gz"
    catalog_path = output_dir / catalog_filename
    
    with gzip.open(catalog_path, "wt", encoding="utf-8") as f:
        json.dump(catalog, f)
        
    # Compute SHA256 of generated catalog
    hasher = hashlib.sha256()
    with open(catalog_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    catalog_sha256 = hasher.hexdigest()
    file_size_mb = catalog_path.stat().st_size / (1024 * 1024)
    
    logger.info(f"Catalog saved to: {catalog_path} ({file_size_mb:.2f} MB)")
    logger.info(f"SHA256: {catalog_sha256}")
    
    # Create Manifest
    manifest = {
        "version": version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_ground_truth": str(gt_path),
        "total_malicious_events": len(catalog),
        "catalog_file": catalog_filename,
        "catalog_sha256": catalog_sha256,
        "catalog_size_mb": round(file_size_mb, 2),
        "scenario_distribution": {
            SCENARIO_MAP.get(k, str(k)): v for k, v in sorted(scenario_counts.items())
        },
        "stage_distribution": {
            STAGE_MAP.get(k, str(k)): v for k, v in sorted(stage_counts.items())
        },
    }
    
    manifest_path = output_dir / f"manifest_{version}.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Manifest saved to: {manifest_path}")
    
    # Print Distributions
    print("\n=== Scenario Distribution ===")
    for sc_name, count in manifest["scenario_distribution"].items():
        print(f"  {sc_name:<28}: {count:,}")
        
    print("\n=== MITRE ATT&CK Stage Distribution ===")
    for st_name, count in manifest["stage_distribution"].items():
        print(f"  {st_name:<32}: {count:,}")
        
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate decoupled sidecar multi-task labels for OpTC.")
    parser.add_argument("--gt-path", default=str(DEFAULT_GT_PATH), help="Path to ground_truth_corrected_all_evts.json.gz")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory for sidecar catalog")
    parser.add_argument("--version", default="v1", help="Version identifier (e.g. v1, v2)")
    args = parser.parse_args()
    
    generate_multitask_labels(args.gt_path, args.output_dir, args.version)


if __name__ == "__main__":
    main()
