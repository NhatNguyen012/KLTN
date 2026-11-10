#!/usr/bin/env python3
"""Extract OpTC Hard-Example Experience Replay Buffer for THEIA Incremental Learning.

Applies Boundary-Aware Sampling (FROMP / Herding principle) from OpTC training shards:
- 25,000 attack events (label=1)
- 35,000 hard negative events (label=0, z_optc >= -6.5, captures complex daemons)
- 15,000 diverse random negative events (general benign background)
Total: 75,000 balanced replay events to prevent catastrophic forgetting and feature interference.
"""

from __future__ import annotations

import argparse
import glob
from pathlib import Path
import random
import sys
import time

try:
    import lightgbm as lgb
except ImportError:
    lgb = None

import numpy as np
from scipy import sparse

CODE_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_ROOT = Path("/mnt/SSD_Data/optc")
sys.path.insert(0, str(CODE_ROOT))
sys.path.insert(0, str(WORKSPACE_ROOT))

from ML.code.preprocess.host_shards import decode_shard


def extract_replay(
    shards_pattern: str,
    model_path: Path,
    output_path: Path,
    target_hard_neg: int = 35_000,
    target_rand_neg: int = 15_000,
) -> None:
    if lgb is None:
        raise ImportError(
            "LightGBM is required to extract boundary hard negatives. "
            "Please run with an environment that has lightgbm installed."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    train_shard_paths = sorted(glob.glob(shards_pattern, recursive=True))
    print(f"Discovered {len(train_shard_paths)} OpTC train shards.")

    print(f"Loading Base OpTC Booster from {model_path}...")
    optc_booster = lgb.Booster(model_file=str(model_path))

    # Attack Prototype Re-anchoring Quotas (Total: 25,000 attack prototypes)
    target_cmd = 1_131          # 100% of available CMD attacks
    target_script = 502         # 100% of available LOLBin attacks (WScript, CScript, Rundll32)
    target_ps = 11_500          # Prototypical PowerShell attacks
    target_other = 11_867       # Diverse other attack actions
    target_pos = target_cmd + target_script + target_ps + target_other

    cmd_cols = {190, 188}
    script_cols = {1294, 2521, 1595}
    ps_cols = {263, 261, 951}

    pool_pos_cmd = []
    pool_pos_script = []
    pool_pos_ps = []
    pool_pos_other = []

    hard_neg_matrices = []
    rand_neg_matrices = []

    total_hard = 0
    total_rand = 0

    t0 = time.time()
    random.seed(42)
    np.random.seed(42)

    shuffled_paths = list(train_shard_paths)
    random.shuffle(shuffled_paths)

    print("\nScanning OpTC shards for Attack Prototypes & Boundary Hard Negatives...")
    for p in shuffled_paths:
        matrix, labels, _ = decode_shard(p, 10317)
        pos_idx = np.where(labels == 1)[0]
        neg_idx = np.where(labels == 0)[0]

        # 1. Collect Attack Prototypes by process family
        if len(pos_idx) > 0:
            sub_pos = matrix[pos_idx]
            for i in range(len(pos_idx)):
                cols = set(sub_pos.indices[sub_pos.indptr[i]:sub_pos.indptr[i+1]])
                if cols & cmd_cols:
                    if len(pool_pos_cmd) < target_cmd:
                        pool_pos_cmd.append(sub_pos[i])
                elif cols & script_cols:
                    if len(pool_pos_script) < target_script:
                        pool_pos_script.append(sub_pos[i])
                elif cols & ps_cols:
                    if len(pool_pos_ps) < target_ps:
                        pool_pos_ps.append(sub_pos[i])
                else:
                    if len(pool_pos_other) < target_other:
                        pool_pos_other.append(sub_pos[i])

        # 2. Score negatives with base OpTC model for boundary sampling
        if len(neg_idx) > 0 and (total_hard < target_hard_neg or total_rand < target_rand_neg):
            sample_size = min(len(neg_idx), 3500)
            sub_neg = np.random.choice(neg_idx, sample_size, replace=False)
            z = optc_booster.predict(matrix[sub_neg], raw_score=True, num_threads=4)

            # Hard negatives: z >= -6.5 (closest to decision boundary)
            hard_mask = z >= -6.5
            hard_indices = sub_neg[hard_mask]
            if len(hard_indices) > 0 and total_hard < target_hard_neg:
                take_h = min(len(hard_indices), target_hard_neg - total_hard)
                hard_neg_matrices.append(matrix[hard_indices[:take_h]])
                total_hard += take_h

            # Random negatives: z < -6.5
            rand_indices = sub_neg[~hard_mask]
            if len(rand_indices) > 0 and total_rand < target_rand_neg:
                take_r = min(len(rand_indices), target_rand_neg - total_rand)
                rand_neg_matrices.append(matrix[rand_indices[:take_r]])
                total_rand += take_r

        if total_hard >= target_hard_neg and total_rand >= target_rand_neg:
            if (len(pool_pos_cmd) >= target_cmd and len(pool_pos_script) >= target_script
                    and len(pool_pos_ps) >= target_ps and len(pool_pos_other) >= target_other):
                break

    print(f"\nCompleted scan in {time.time()-t0:.2f}s:")
    print(f"  Positives: CMD={len(pool_pos_cmd)}, Script={len(pool_pos_script)}, PS={len(pool_pos_ps)}, Other={len(pool_pos_other)}")
    print(f"  Hard Negatives: {total_hard:,} / {target_hard_neg:,}")
    print(f"  Random Negatives: {total_rand:,} / {target_rand_neg:,}")

    # Combine all matrices
    all_pos = sparse.vstack(pool_pos_cmd + pool_pos_script + pool_pos_ps + pool_pos_other)
    all_hard = sparse.vstack(hard_neg_matrices)
    all_rand = sparse.vstack(rand_neg_matrices)

    X_replay = sparse.vstack([all_pos, all_hard, all_rand]).tocsr()
    y_replay = np.concatenate([
        np.ones(all_pos.shape[0], dtype=np.int8),
        np.zeros(all_hard.shape[0] + all_rand.shape[0], dtype=np.int8),
    ])

    print(f"\nFinal Replay Buffer Shape: {X_replay.shape}, Labels: {Counter(y_replay)}")
    print(f"Saving to {output_path}...")
    np.savez_compressed(
        output_path,
        data=X_replay.data,
        indices=X_replay.indices,
        indptr=X_replay.indptr,
        shape=X_replay.shape,
        labels=y_replay,
    )
    print("Experience replay buffer successfully saved!")


def main():
    parser = argparse.ArgumentParser(description="Extract OpTC Experience Replay Buffer for THEIA")
    parser.add_argument(
        "--shards-pattern",
        default="/mnt/SSD_Data/optc/ML/code/output/host_ml_parent_incoming_seed02/model_input/volumes/ssd/**/train_*.npz",
        help="Glob pattern for OpTC train shards",
    )
    parser.add_argument(
        "--model-path",
        default=Path(__file__).resolve().parent.parent / "pretrained_optc_model" / "model-slot-0.txt",
        type=Path,
        help="Path to base OpTC LightGBM model",
    )
    parser.add_argument(
        "--output-path",
        default=Path(__file__).resolve().parent / "output" / "optc_replay_buffer.npz",
        type=Path,
        help="Output path for optc_replay_buffer.npz",
    )
    args = parser.parse_args()

    extract_replay(
        shards_pattern=args.shards_pattern,
        model_path=args.model_path,
        output_path=args.output_path,
    )


if __name__ == "__main__":
    main()

