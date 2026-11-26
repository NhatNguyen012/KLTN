#!/usr/bin/env python3
"""Build a stratified OpTC Experience Replay Buffer and Validation set from read-only OpTC DL shards.

Outputs under `IL/dataset_4-THEIA/output/optc_il_eval/`:
- `optc_replay_train.pt`: Stratified training replay pool (~100,000 samples: up to 40,000 stratified attack
  samples preserving 100% of ultra-rare stages like AMSI/Persistence/Credential + 60,000 benign samples)
  taken strictly from `DL/code/output/dl_shards/train/`.
- `optc_val_eval.pt`: Stratified validation cohort (~50,000 samples from `DL/code/output/dl_shards/val/`
  preserving OpTC positive ratio ~3.2% and covering all rare val stages) for joint IL checkpoint selection.
- `optc_bundle_manifest.json`: Exact counts, class breakdown, and source manifest provenance.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import random
from typing import Any, Dict, List

import torch

IL_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[4]


def collect_stratified_optc(
    shards_dir: Path,
    target_pos: int,
    target_neg: int,
    seed: int,
) -> tuple[List[Dict[str, Any]], Counter]:
    rng = random.Random(seed)
    shard_files = sorted(shards_dir.glob("shard_*.pt"))
    if not shard_files:
        raise FileNotFoundError(f"No shard_*.pt found in {shards_dir}")

    # Pass 1: bucket indices by (scenario_id, stage_id) so rare classes retain 100% representation
    pos_by_stratum: Dict[tuple[int, int], List[Dict[str, Any]]] = defaultdict(list)
    neg_pool: List[Dict[str, Any]] = []
    # Reservoir cap for negatives to bound memory while maintaining uniform coverage across all shards
    neg_reservoir_cap = max(target_neg * 2, 120000)
    neg_seen = 0

    for sf in shard_files:
        data = torch.load(sf, map_location="cpu", weights_only=False)
        for s in data:
            clean_s = {
                "incoming_ids": s["incoming_ids"] or [2],
                "parent_ids": s["parent_ids"] or [2],
                "current_ids": s["current_ids"] or [2],
                "is_malicious": int(s["is_malicious"]),
                "scenario_id": int(s["scenario_id"]),
                "stage_id": int(s["stage_id"]),
            }
            if clean_s["is_malicious"] == 1:
                pos_by_stratum[(clean_s["scenario_id"], clean_s["stage_id"])].append(clean_s)
            else:
                neg_seen += 1
                if len(neg_pool) < neg_reservoir_cap:
                    neg_pool.append(clean_s)
                else:
                    j = rng.randrange(neg_seen)
                    if j < neg_reservoir_cap:
                        neg_pool[j] = clean_s

    total_pos_avail = sum(len(v) for v in pos_by_stratum.values())
    chosen_pos: List[Dict[str, Any]] = []
    # Preserve rare strata while guaranteeing at least 55% budget for large strata
    if total_pos_avail <= target_pos:
        for _, items in sorted(pos_by_stratum.items()):
            chosen_pos.extend(items)
    else:
        rare_threshold = max(1, min(400, int(0.10 * target_pos)))
        rare_strata: List[tuple[tuple[int, int], List[Dict[str, Any]]]] = []
        large_strata: List[tuple[tuple[int, int], List[Dict[str, Any]]]] = []
        for k, items in sorted(pos_by_stratum.items()):
            if len(items) <= rare_threshold:
                rare_strata.append((k, items))
            else:
                large_strata.append((k, items))

        max_rare_budget = max(len(rare_strata), int(0.45 * target_pos)) if large_strata else target_pos
        rare_total = sum(len(v) for _, v in rare_strata)
        rare_cap = rare_threshold
        if rare_strata and rare_total > max_rare_budget:
            # Water-fill rare strata cap so smallest strata keep 100% while large strata retain >= 55% budget
            lo, hi = 1, rare_threshold
            best_cap = 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if sum(min(len(v), mid) for _, v in rare_strata) <= max_rare_budget:
                    best_cap = mid
                    lo = mid + 1
                else:
                    hi = mid - 1
            rare_cap = best_cap

        used_rare = 0
        for _, items in rare_strata:
            take = min(len(items), rare_cap)
            chosen_pos.extend(items if take == len(items) else rng.sample(items, take))
            used_rare += take

        remaining_budget = max(0, target_pos - used_rare)
        if large_strata and remaining_budget > 0:
            large_total = sum(len(v) for _, v in large_strata)
            for _, items in large_strata:
                take = max(1, round(remaining_budget * (len(items) / float(large_total))))
                take = min(take, len(items))
                chosen_pos.extend(rng.sample(items, take))

    rng.shuffle(neg_pool)
    chosen_neg = neg_pool[: min(target_neg, len(neg_pool))]
    combined = chosen_pos + chosen_neg
    rng.shuffle(combined)

    stats = Counter()
    for s in combined:
        stats[("bin", s["is_malicious"])] += 1
        stats[("sc", s["scenario_id"])] += 1
        stats[("st", s["stage_id"])] += 1
    return combined, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Build OpTC Experience Replay & Val bundles for IL.")
    parser.add_argument("--optc-shards-dir", type=Path, default=PROJECT_ROOT / "DL/code/output/dl_shards")
    parser.add_argument("--output-dir", type=Path, default=IL_ROOT / "output/optc_il_eval")
    parser.add_argument("--replay-pos", type=int, default=40000)
    parser.add_argument("--replay-neg", type=int, default=60000)
    parser.add_argument("--val-pos", type=int, default=4000)
    parser.add_argument("--val-neg", type=int, default=46000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Building OpTC Replay Pool from {args.optc_shards_dir / 'train'}...")
    replay_samples, rep_stats = collect_stratified_optc(
        args.optc_shards_dir / "train", args.replay_pos, args.replay_neg, args.seed
    )
    replay_out = args.output_dir / "optc_replay_train.pt"
    torch.save(replay_samples, replay_out)

    print(f"Building OpTC Val Eval bundle from {args.optc_shards_dir / 'val'}...")
    val_samples, val_stats = collect_stratified_optc(
        args.optc_shards_dir / "val", args.val_pos, args.val_neg, args.seed + 1
    )
    val_out = args.output_dir / "optc_val_eval.pt"
    torch.save(val_samples, val_out)

    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_optc_shards": str(args.optc_shards_dir),
        "replay_train": {
            "path": str(replay_out),
            "count": len(replay_samples),
            "size_mb": round(replay_out.stat().st_size / (1024 * 1024), 2),
            "binary": {str(k[1]): v for k, v in rep_stats.items() if k[0] == "bin"},
            "scenarios": {str(k[1]): v for k, v in sorted(rep_stats.items()) if k[0] == "sc"},
            "stages": {str(k[1]): v for k, v in sorted(rep_stats.items()) if k[0] == "st"},
        },
        "val_eval": {
            "path": str(val_out),
            "count": len(val_samples),
            "size_mb": round(val_out.stat().st_size / (1024 * 1024), 2),
            "binary": {str(k[1]): v for k, v in val_stats.items() if k[0] == "bin"},
            "scenarios": {str(k[1]): v for k, v in sorted(val_stats.items()) if k[0] == "sc"},
            "stages": {str(k[1]): v for k, v in sorted(val_stats.items()) if k[0] == "st"},
        },
    }
    man_out = args.output_dir / "optc_bundle_manifest.json"
    with man_out.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
