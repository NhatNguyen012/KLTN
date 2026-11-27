#!/usr/bin/env python3
"""Extract genuine unseen TEST-split raw OpTC eCAR & DARPA THEIA log slices for Docker demo.

Read-only with respect to DATASET/: writes compact demo JSONL files ONLY to Docker/sample_logs/.
Models never see truth metadata (`_meta_truth` is stripped by the gateway before inference).
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
import random
import sys
from typing import Any, Dict, List

import numpy as np
import torch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from DL.code.preprocess.label_catalog import MultiTaskLabelCatalog, SCENARIO_MAP, STAGE_MAP
from ML.code.preprocess.stratified_pipeline import resolve_source_path

DOCKER_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_OUT = DOCKER_ROOT / "sample_logs"
SPLIT_MANIFEST = PROJECT_ROOT / "ML/code/output/host_ml_seed02/split/manifest.json"
OPTC_CATALOG_PATH = PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz"
THEIA_SHARDS_DIR = PROJECT_ROOT / "IL/dataset_4-THEIA/output/dl_shards"

THEIA_SCENARIO_MAP = {
    0: "Benign",
    1: "THEIA_NationState_Firefox_Drakon",
    2: "THEIA_BrowserExtension_MicroAPT",
}
THEIA_STAGE_MAP = {
    0: "Benign",
    1: "THEIA_Initial_Compromise",
    2: "THEIA_Execution_PrivilegeEscalation",
    3: "THEIA_Discovery_Reconnaissance",
    4: "THEIA_C2_Exfiltration",
}


def _extract_optc_host_window(
    entry: Dict[str, Any],
    split_dir: Path,
    catalog: MultiTaskLabelCatalog,
    out_path: Path,
    target_window_size: int = 900,
) -> Dict[str, Any]:
    src_path = resolve_source_path(entry["source"]["path"])
    mask_path = split_dir / entry["artifact"]

    # Stream masks first to locate dense attack + benign TEST events cleanly
    with gzip.open(mask_path, "rb") as mf:
        mask_arr = np.frombuffer(mf.read(), dtype=np.uint8)

    mal_test_positions: List[int] = []
    ben_test_positions: List[int] = []
    with gzip.open(src_path, "rt", encoding="utf-8") as sf:
        for idx, line in enumerate(sf):
            if idx >= len(mask_arr):
                break
            c = int(mask_arr[idx])
            if c != 3:
                continue
            if '"label": 1' in line:
                rec = json.loads(line)
                if rec.get("label") == 1:
                    mal_test_positions.append(idx)
            elif len(ben_test_positions) < 40000:
                ben_test_positions.append(idx)

    if not mal_test_positions:
        raise RuntimeError(f"No TEST malicious events found in {src_path}")

    # Two-pointer sliding window across entire file to pick densest TEST attack cluster (width <= 600 lines)
    best_cnt, best_l = 0, mal_test_positions[0]
    l_ptr = 0
    for r_ptr, r_val in enumerate(mal_test_positions):
        while r_val - mal_test_positions[l_ptr] > 600:
            l_ptr += 1
        cnt = r_ptr - l_ptr + 1
        if cnt > best_cnt:
            best_cnt = cnt
            best_l = mal_test_positions[l_ptr]

    win_start = max(0, best_l - 250)
    win_end = win_start + target_window_size
    extra_ben_target = set(ben_test_positions[:80])  # Early benign baseline TEST slice on same host (for FPR contrast)

    window_records: List[tuple[int, int, Dict[str, Any]]] = []
    early_ben_records: List[tuple[int, int, Dict[str, Any]]] = []
    relevant_uuids = set()

    with gzip.open(src_path, "rt", encoding="utf-8") as sf:
        for idx, line in enumerate(sf):
            if idx >= win_end:
                break
            if not line.strip():
                continue
            if idx in extra_ben_target and idx < win_start:
                rec = json.loads(line)
                early_ben_records.append((idx, int(mask_arr[idx]), rec))
                continue
            if idx < win_start:
                continue
            rec = json.loads(line)
            code = int(mask_arr[idx])
            window_records.append((idx, code, rec))
            for k in ("actorID", "objectID"):
                u = rec.get(k)
                if isinstance(u, str) and u:
                    relevant_uuids.add(u.lower())

    # Collect genuine earlier causal warmup events for those exact UUIDs without slow regex scans:
    # 1. Fast C substring pass collects PROCESS CREATE records before win_start, then walks backwards
    #    to retain complete ancestor chains (e.g., gup.exe -> cKfGW.exe) for every UUID in the window.
    # 2. Recent window tail [win_start - 10000, win_start) captures non-CREATE OPEN/actor context.
    all_creates: List[tuple[int, int, Dict[str, Any]]] = []
    other_warmup_by_uuid: Dict[str, List[tuple[int, int, Dict[str, Any]]]] = {}
    near_start = max(0, win_start - 10000)
    if relevant_uuids and win_start > 0:
        with gzip.open(src_path, "rt", encoding="utf-8") as sf:
            for idx, line in enumerate(sf):
                if idx >= win_start:
                    break
                is_near = idx >= near_start
                has_proc_create = '"PROCESS"' in line and '"CREATE"' in line
                if not is_near and not has_proc_create:
                    continue
                if not line.strip():
                    continue
                rec = json.loads(line)
                act = str(rec.get("action", "")).upper()
                obj = str(rec.get("object", "")).upper()
                if obj == "PROCESS" and act == "CREATE":
                    all_creates.append((idx, int(mask_arr[idx]), rec))
                elif is_near:
                    aid = str(rec.get("actorID", "")).lower()
                    oid = str(rec.get("objectID", "")).lower()
                    hit_uuid = aid if aid in relevant_uuids else (oid if oid in relevant_uuids else None)
                    if hit_uuid:
                        q = other_warmup_by_uuid.setdefault(hit_uuid, [])
                        q.append((idx, int(mask_arr[idx]), rec))
                        if len(q) > 6:
                            q.pop(0)

    lineage_uuids = set(relevant_uuids)
    create_records_rev: List[tuple[int, int, Dict[str, Any]]] = []
    for idx, code, rec in reversed(all_creates):
        oid = str(rec.get("objectID", "")).lower()
        aid = str(rec.get("actorID", "")).lower()
        if oid in lineage_uuids or aid in relevant_uuids:
            create_records_rev.append((idx, code, rec))
            if aid:
                lineage_uuids.add(aid)
    create_records = list(reversed(create_records_rev))

    other_flat: List[tuple[int, int, Dict[str, Any]]] = []
    for q in other_warmup_by_uuid.values():
        other_flat.extend(q)
    warmup_tail = sorted(create_records + sorted(other_flat, key=lambda x: x[0])[-200:], key=lambda x: x[0])
    seen_line_idx = set()
    combined_tagged: List[tuple[int, int, Dict[str, Any], bool]] = []
    # Keep early benign baseline records + warmup ancestry + target attack window in chronological order
    early_ben_set = {i for i, _, _ in early_ben_records}
    merged = sorted(early_ben_records + warmup_tail, key=lambda x: x[0])
    for idx, code, rec in merged:
        if idx not in seen_line_idx:
            seen_line_idx.add(idx)
            is_warm = idx not in early_ben_set
            combined_tagged.append((idx, code, rec, is_warm))
    for idx, code, rec in window_records:
        if idx not in seen_line_idx:
            seen_line_idx.add(idx)
            combined_tagged.append((idx, code, rec, code != 3))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    test_ben = 0
    test_mal = 0
    warmup_cnt = 0
    scenarios = set()
    stages = set()
    with out_path.open("w", encoding="utf-8") as out_f:
        for _, code, rec, is_warmup in combined_tagged:
            clean = {k: v for k, v in rec.items() if k != "label"}
            if is_warmup:
                warmup_cnt += 1
            raw_lbl = rec.get("label")
            if raw_lbl in (0, 1):
                is_m, sc_id, st_id = catalog.lookup(rec.get("id"))
                tb = int(raw_lbl)
                sc_name = SCENARIO_MAP.get(sc_id, "OpTC_Unknown") if tb == 1 else "Benign"
                st_name = STAGE_MAP.get(st_id, "OpTC_Unknown") if tb == 1 else "Benign"
                if not is_warmup:
                    if tb == 1:
                        test_mal += 1
                        scenarios.add(sc_name)
                        stages.add(st_name)
                    else:
                        test_ben += 1
                clean["_meta_truth"] = {
                    "true_binary": tb,
                    "true_scenario": sc_name,
                    "true_stage": st_name,
                    "eval_split": "warmup" if is_warmup else "test",
                }
            out_f.write(json.dumps(clean) + "\n")

    return {
        "file": out_path.name,
        "host": entry["host"],
        "day": entry["day"],
        "total_lines": len(combined_tagged),
        "warmup_lines": warmup_cnt,
        "test_malicious": test_mal,
        "test_benign": test_ben,
        "scenarios": sorted(scenarios),
        "stages": sorted(stages),
    }


def _export_theia_sample(out_path: Path) -> Dict[str, Any]:
    with (THEIA_SHARDS_DIR / "extended_dl_vocab.json").open("r", encoding="utf-8") as f:
        vocab = json.load(f)
    id2tok = {int(v): str(k) for k, v in vocab.items()}

    def decode(ids: List[int]) -> List[str]:
        return [id2tok[int(i)] for i in ids if int(i) in id2tok and id2tok[int(i)] not in ("<pad>", "<empty>")]

    by_bucket: Dict[tuple[int, int], List[Dict[str, Any]]] = {}
    for sf in sorted((THEIA_SHARDS_DIR / "test").glob("shard_*.pt")):
        for item in torch.load(sf, map_location="cpu", weights_only=False):
            key = (int(item["scenario_id"]), int(item["stage_id"]))
            by_bucket.setdefault(key, []).append(item)

    rng = random.Random(42)
    selected: List[Dict[str, Any]] = []
    # Include all THEIA attack scenarios & stages present in TEST + 120 Benign
    quotas = {
        (0, 0): 120,
        (1, 1): 25,
        (1, 2): 9,
        (1, 3): 2,
        (1, 4): 25,
        (2, 1): 25,
        (2, 2): 12,
        (2, 3): 40,
        (2, 4): 19,
    }
    for k, q in quotas.items():
        pool = by_bucket.get(k, [])
        if pool:
            selected.extend(rng.sample(pool, min(q, len(pool))))

    selected.sort(key=lambda x: int(x.get("timestamp_rec", 0)))
    mal_cnt = sum(1 for x in selected if int(x["is_malicious"]) == 1)
    ben_cnt = len(selected) - mal_cnt

    with out_path.open("w", encoding="utf-8") as out_f:
        for item in selected:
            tb = int(item["is_malicious"])
            sc = int(item["scenario_id"])
            st = int(item["stage_id"])
            row = {
                "domain": "theia_linux",
                "hostname": "ta1-theia-e3-host",
                "event_uuid": str(item.get("event_uuid", "")),
                "timestamp": str(item.get("timestamp_rec", "")),
                "action": "THEIA_EVENT",
                "object": "PROVENANCE",
                "E_incoming": decode(item.get("incoming_ids", [])),
                "E_parent": decode(item.get("parent_ids", [])),
                "E_current": decode(item.get("current_ids", [])),
                "_meta_truth": {
                    "true_binary": tb,
                    "true_scenario": THEIA_SCENARIO_MAP.get(sc, str(sc)),
                    "true_stage": THEIA_STAGE_MAP.get(st, str(st)),
                    "eval_split": "test",
                },
            }
            out_f.write(json.dumps(row) + "\n")

    return {
        "file": out_path.name,
        "host": "ta1-theia-e3-host",
        "day": "2018-04-10..12 (T3)",
        "total_lines": len(selected),
        "warmup_lines": 0,
        "test_malicious": mal_cnt,
        "test_benign": ben_cnt,
        "scenarios": ["THEIA_NationState_Firefox_Drakon", "THEIA_BrowserExtension_MicroAPT"],
        "stages": list(THEIA_STAGE_MAP.values())[1:],
    }


def main() -> None:
    SAMPLE_OUT.mkdir(parents=True, exist_ok=True)
    split_manifest = json.loads(SPLIT_MANIFEST.read_text(encoding="utf-8"))
    catalog = MultiTaskLabelCatalog(OPTC_CATALOG_PATH)

    specs = [
        ("optc_sc1_test", "OpTC SC1 · Empire Staging (TEST Raw eCAR)", "2019-09-23", "sysclient0201", "optc_sc1_empire_staging_test.jsonl"),
        ("optc_sc2_test", "OpTC SC2 · Custom Empire Lateral (TEST Raw eCAR)", "2019-09-24", "sysclient0203", "optc_sc2_custom_empire_lateral_test.jsonl"),
        ("optc_sc3_test", "OpTC SC3 · Malicious Update (TEST Raw eCAR)", "2019-09-25", "sysclient0051", "optc_sc3_malicious_update_test.jsonl"),
    ]

    entries_idx = {(e["day"], e["host"]): e for e in split_manifest["entries"]}
    manifest_samples: List[Dict[str, Any]] = []

    for sid, title, day, host, fname in specs:
        entry = entries_idx[(day, host)]
        print(f"Extracting {sid} ({day} {host})...")
        info = _extract_optc_host_window(entry, SPLIT_MANIFEST.parent, catalog, SAMPLE_OUT / fname)
        info.update(
            {
                "id": sid,
                "title": title,
                "subtitle": f"OpTC Windows eCAR · {host} ({info['test_malicious']} ATK / {info['test_benign']} BEN TEST + {info['warmup_lines']} warmup)",
            }
        )
        manifest_samples.append(info)
        print(" ", info)

    print("Extracting DARPA TC E3 THEIA TEST slice...")
    theia_info = _export_theia_sample(SAMPLE_OUT / "theia_linux_apt_test.jsonl")
    theia_info.update(
        {
            "id": "theia_e3_test",
            "title": "DARPA THEIA T3 · Linux APT Multi-Stage (TEST)",
            "subtitle": f"Linux Provenance L=3 · {theia_info['test_malicious']} ATK / {theia_info['test_benign']} BEN (Drakon + MicroAPT + memtrace.so)",
        }
    )
    manifest_samples.append(theia_info)
    print(" ", theia_info)

    man_path = SAMPLE_OUT / "manifest.json"
    man_path.write_text(json.dumps({"samples": manifest_samples}, indent=2), encoding="utf-8")
    print(f"\nExported all demo samples cleanly -> {man_path}")


if __name__ == "__main__":
    main()
