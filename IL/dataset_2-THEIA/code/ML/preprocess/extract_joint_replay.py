#!/usr/bin/env python3
"""Build Joint Continual Experience Replay Buffer (OpTC Task 1 + ATLASv2 Task 2) for THEIA.

To prevent catastrophic forgetting across the 3-domain sequence (OpTC -> ATLASv2 -> THEIA),
the replay buffer combines attack prototypes and boundary hard negatives from both previous domains:
- 37,500 samples from OpTC (12,500 attack prototypes + 25,000 negatives)
- 37,500 samples from ATLASv2 (1,880 attack prototypes + 35,620 negatives prioritized by boundary hardness)
Total: 75,000 balanced samples at width 12,337 features.
"""

from __future__ import annotations
import json
from pathlib import Path
import sys
import numpy as np
from scipy import sparse

WORKSPACE_ROOT = Path("/mnt/SSD_Data/optc")
sys.path.insert(0, str(WORKSPACE_ROOT))


def build_joint_replay_buffer(
    optc_buffer_path: Path,
    atlas_manifest_path: Path,
    atlas_model_path: Path,
    output_path: Path,
    target_total: int = 75_000,
    seed: int = 42,
) -> None:
    rng = np.random.default_rng(seed)
    print("=" * 80)
    print("EXTRACT JOINT EXPERIENCE REPLAY BUFFER (OpTC + ATLASv2 -> THEIA)")
    print("=" * 80)

    # 1. Load and sample OpTC prototypes (37,500 samples)
    print("\n[1/3] Loading OpTC Replay Buffer...")
    optc_data = np.load(optc_buffer_path, allow_pickle=False)
    X_optc = sparse.csr_matrix(
        (optc_data["data"], optc_data["indices"], optc_data["indptr"]),
        shape=tuple(optc_data["shape"]),
    )
    y_optc = optc_data["labels"]
    print(f"  OpTC loaded: shape={X_optc.shape}, pos={int(y_optc.sum())}, neg={len(y_optc) - int(y_optc.sum())}")

    optc_pos_idx = np.flatnonzero(y_optc == 1)
    optc_neg_idx = np.flatnonzero(y_optc == 0)

    # Subsample 12,500 pos and 25,000 neg from OpTC
    n_optc_pos = 12_500
    n_optc_neg = 25_000
    sel_optc_pos = rng.choice(optc_pos_idx, size=n_optc_pos, replace=False)
    sel_optc_neg = rng.choice(optc_neg_idx, size=n_optc_neg, replace=False)
    sel_optc = np.concatenate([sel_optc_pos, sel_optc_neg])
    rng.shuffle(sel_optc)

    X_optc_sel = X_optc[sel_optc]
    y_optc_sel = y_optc[sel_optc]

    # Pad OpTC to 12,337 columns (matching ATLASv2 extended feature space)
    pad_cols = 12_337 - X_optc_sel.shape[1]
    if pad_cols > 0:
        X_optc_padded = sparse.hstack(
            [X_optc_sel, sparse.csr_matrix((X_optc_sel.shape[0], pad_cols), dtype=X_optc_sel.dtype)],
            format="csr",
        )
    else:
        X_optc_padded = X_optc_sel
    print(f"  OpTC selected & padded to 12,337: shape={X_optc_padded.shape}, pos={int(y_optc_sel.sum())}, neg={len(y_optc_sel) - int(y_optc_sel.sum())}")

    # 2. Load and sample ATLASv2 prototypes (37,500 samples)
    print("\n[2/3] Loading ATLASv2 Train Shards...")
    from ML.code.preprocess.host_shards import decode_shard
    atlas_manifest = json.loads(atlas_manifest_path.read_text())
    atlas_train_shards = [s for s in atlas_manifest["shards"] if s["split"] == "train"]

    atlas_Xs, atlas_ys = [], []
    for s in atlas_train_shards:
        p = atlas_manifest_path.parent / s["path"]
        X_s, y_s, _ = decode_shard(p, 12_337, s)
        atlas_Xs.append(X_s)
        atlas_ys.append(y_s)

    X_atlas = sparse.vstack(atlas_Xs, format="csr")
    y_atlas = np.concatenate(atlas_ys)
    print(f"  ATLASv2 loaded: shape={X_atlas.shape}, pos={int(y_atlas.sum())}, neg={len(y_atlas) - int(y_atlas.sum())}")

    atlas_pos_idx = np.flatnonzero(y_atlas == 1)
    atlas_neg_idx = np.flatnonzero(y_atlas == 0)

    # Keep 100% of ATLASv2 attack prototypes (1,880 samples)
    # Remaining to reach 37,500 is 35,620 negatives
    n_atlas_neg = 37_500 - len(atlas_pos_idx)

    # Prioritize hard negatives using FrozenAtlasModel scores if model available
    if atlas_model_path.exists():
        sys.path.insert(0, str(output_path.parent))
        from frozen_atlas import FrozenAtlasModel
        fam = FrozenAtlasModel(atlas_model_path)
        print("  Scoring ATLASv2 negatives for boundary hard-example mining...")
        chunk_size = 10_000
        neg_logits = []
        for i in range(0, len(atlas_neg_idx), chunk_size):
            chunk = atlas_neg_idx[i:i + chunk_size]
            neg_logits.append(fam.predict(X_atlas[chunk], raw_score=True))
        neg_logits = np.concatenate(neg_logits)

        # 50% hard negatives (highest logits) + 50% diverse random negatives
        n_hard = n_atlas_neg // 2
        n_rand = n_atlas_neg - n_hard
        hard_order = np.argsort(neg_logits)[::-1]
        sel_hard_idx = atlas_neg_idx[hard_order[:n_hard]]
        remaining_neg_pool = np.setdiff1d(atlas_neg_idx, sel_hard_idx)
        sel_rand_idx = rng.choice(remaining_neg_pool, size=n_rand, replace=False)
        sel_atlas_neg = np.concatenate([sel_hard_idx, sel_rand_idx])
    else:
        sel_atlas_neg = rng.choice(atlas_neg_idx, size=n_atlas_neg, replace=False)

    sel_atlas = np.concatenate([atlas_pos_idx, sel_atlas_neg])
    rng.shuffle(sel_atlas)

    X_atlas_sel = X_atlas[sel_atlas]
    y_atlas_sel = y_atlas[sel_atlas]
    print(f"  ATLASv2 selected: shape={X_atlas_sel.shape}, pos={int(y_atlas_sel.sum())}, neg={len(y_atlas_sel) - int(y_atlas_sel.sum())}")

    # 3. Stack and save joint buffer
    print("\n[3/3] Assembling Joint Replay Buffer...")
    X_joint = sparse.vstack([X_optc_padded, X_atlas_sel], format="csr")
    y_joint = np.concatenate([y_optc_sel, y_atlas_sel])

    # Final shuffle
    final_perm = rng.permutation(len(y_joint))
    X_joint = X_joint[final_perm]
    y_joint = y_joint[final_perm]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        output_path,
        data=X_joint.data,
        indices=X_joint.indices,
        indptr=X_joint.indptr,
        shape=X_joint.shape,
        labels=y_joint,
    )
    print(f"\nJoint Replay Buffer saved successfully to {output_path}!")
    print(f"  Shape: {X_joint.shape}")
    print(f"  Total Positives: {int(y_joint.sum()):,} (OpTC: {n_optc_pos:,}, ATLASv2: {len(atlas_pos_idx):,})")
    print(f"  Total Negatives: {len(y_joint) - int(y_joint.sum()):,} (OpTC: {n_optc_neg:,}, ATLASv2: {n_atlas_neg:,})")
    print(f"  File size: {output_path.stat().st_size / (1024*1024):.2f} MB")


def main():
    root = Path(__file__).resolve().parent
    optc_buffer_path = root / "output/optc_replay_buffer.npz"
    atlas_manifest_path = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML/preprocess/output/manifest.json")
    atlas_model_path = root / "output/pretrained_optc_model/model-slot-0.txt"
    output_path = root / "output/optc_replay_buffer.npz"

    build_joint_replay_buffer(
        optc_buffer_path=optc_buffer_path,
        atlas_manifest_path=atlas_manifest_path,
        atlas_model_path=atlas_model_path,
        output_path=output_path,
    )


if __name__ == "__main__":
    main()
