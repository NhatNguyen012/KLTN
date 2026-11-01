#!/usr/bin/env python3
"""Extract OpTC Hard-Example Experience Replay Buffer for Domain-Incremental Learning.

Applies Boundary-Aware Sampling (FROMP / Herding principle) from OpTC training shards:
- 25,000 attack events (label=1)
- 35,000 hard negative events (label=0, z_optc >= -6.5, captures complex daemons like lwabeat.exe)
- 15,000 diverse random negative events (general benign background)
Total: 75,000 balanced replay events to prevent catastrophic forgetting and feature interference.
"""

from __future__ import annotations

import glob
from pathlib import Path
import random
import sys
import time

import lightgbm as lgb
import numpy as np
from scipy import sparse

CODE_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_ROOT = Path("/mnt/SSD_Data/optc")
sys.path.insert(0, str(CODE_ROOT))
sys.path.insert(0, str(WORKSPACE_ROOT))

from ML.code.preprocess.host_shards import decode_shard

def main():
    shards_pattern = "/mnt/SSD_Data/optc/ML/code/output/host_ml_parent_incoming_seed02/model_input/volumes/ssd/**/train_*.npz"
    train_shard_paths = sorted(glob.glob(shards_pattern, recursive=True))
    print(f"Discovered {len(train_shard_paths)} OpTC train shards.")

    model_path = "/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML/pretrained_optc_model/model-slot-0.txt"
    print(f"Loading Base OpTC Booster from {model_path}...")
    optc_booster = lgb.Booster(model_file=model_path)

    target_pos = 25_000
    target_hard_neg = 35_000
    target_rand_neg = 15_000

    pos_matrices = []
    hard_neg_matrices = []
    rand_neg_matrices = []

    total_pos = 0
    total_hard = 0
    total_rand = 0

    lwabeat_col = 127
    lwabeat_in_hard = 0

    t0 = time.time()
    random.seed(42)
    np.random.seed(42)

    shuffled_paths = list(train_shard_paths)
    random.shuffle(shuffled_paths)

    for p in shuffled_paths:
        matrix, labels, _ = decode_shard(p, 10317)
        pos_idx = np.where(labels == 1)[0]
        neg_idx = np.where(labels == 0)[0]

        # 1. Sample positive attack events
        if len(pos_idx) > 0 and total_pos < target_pos:
            take_pos = min(len(pos_idx), target_pos - total_pos)
            chosen_pos = pos_idx[:take_pos] if take_pos == len(pos_idx) else np.random.choice(pos_idx, take_pos, replace=False)
            pos_matrices.append(matrix[chosen_pos])
            total_pos += take_pos

        # 2. Score negatives with base OpTC model for boundary sampling
        if len(neg_idx) > 0:
            sample_size = min(len(neg_idx), 3500)
            sub_neg = np.random.choice(neg_idx, sample_size, replace=False)
            z = optc_booster.predict(matrix[sub_neg], raw_score=True, num_threads=4)

            # Hard negatives: z >= -6.5 (closest to decision boundary)
            hard_mask = z >= -6.5
            hard_chosen = sub_neg[hard_mask]
            if len(hard_chosen) > 0 and total_hard < target_hard_neg:
                take_h = min(len(hard_chosen), target_hard_neg - total_hard)
                sel_h = hard_chosen[:take_h]
                hard_neg_matrices.append(matrix[sel_h])
                total_hard += take_h
                for idx in sel_h:
                    cols = matrix.indices[matrix.indptr[idx]:matrix.indptr[idx+1]]
                    if lwabeat_col in cols:
                        lwabeat_in_hard += 1

            # Diverse random negatives: z < -6.5
            easy_mask = z < -6.5
            easy_chosen = sub_neg[easy_mask]
            if len(easy_chosen) > 0 and total_rand < target_rand_neg:
                take_r = min(len(easy_chosen), target_rand_neg - total_rand)
                sel_r = np.random.choice(easy_chosen, take_r, replace=False)
                rand_neg_matrices.append(matrix[sel_r])
                total_rand += take_r

        if total_pos >= target_pos and total_hard >= target_hard_neg and total_rand >= target_rand_neg:
            break

    total_neg = total_hard + total_rand
    print(f"Sampling complete in {time.time()-t0:.1f}s:")
    print(f"  Positives:  {total_pos:,}")
    print(f"  Hard Neg:   {total_hard:,} (naturally captures {lwabeat_in_hard:,} lwabeat events near boundary)")
    print(f"  Random Neg: {total_rand:,}")
    print(f"  Total Neg:  {total_neg:,}")

    X_pos = sparse.vstack(pos_matrices, format="csr")
    X_neg = sparse.vstack(hard_neg_matrices + rand_neg_matrices, format="csr")

    X_replay = sparse.vstack([X_pos, X_neg], format="csr")
    y_replay = np.concatenate([np.ones(total_pos, dtype=np.int8), np.zeros(total_neg, dtype=np.int8)])

    # Shuffle
    perm = np.random.permutation(len(y_replay))
    X_replay = X_replay[perm]
    y_replay = y_replay[perm]

    output_path = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML/preprocess/output/optc_replay_buffer.npz")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Saving Replay Buffer to {output_path} (shape: {X_replay.shape})...")

    np.savez_compressed(
        output_path,
        data=X_replay.data,
        indices=X_replay.indices,
        indptr=X_replay.indptr,
        shape=X_replay.shape,
        labels=y_replay,
    )

    print(f"Experience Replay Buffer saved successfully! Total size: {output_path.stat().st_size / (1024*1024):.2f} MB")

if __name__ == "__main__":
    main()

