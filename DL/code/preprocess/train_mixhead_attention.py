#!/usr/bin/env python3
"""End-to-End CLI Training Script for Mix-Head Self-Attention Causal Model.

Supports two data modes:
  --shards-dir  (PREFERRED) Load pre-built shards from build_dl_shards.py.
                            Vocab is read from the shard manifest; no on-the-fly
                            tokenisation needed.  Use this for full-corpus training.
  --data        (LEGACY)    Stream and tokenise a raw JSON/JSON.GZ events file on
                            the fly.  Capped at --max-events.  Use only for quick
                            local smoke-tests.

Supports both single GPU and Kaggle Dual T4 (T4x2) DistributedDataParallel (DDP).
Inspired by Peter Bloem (https://peterbloem.nl/blog/transformers).
"""

from __future__ import annotations
import argparse
import gzip
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import torch
import torch.distributed as dist
import torch.optim as optim
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data import DataLoader, Dataset
from torch.utils.data.distributed import DistributedSampler

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = next((p for p in CURRENT_DIR.parents if (p / "AGENTS.md").is_file()), CURRENT_DIR)

for p in (
    CURRENT_DIR,
    CURRENT_DIR.parent,
    PROJECT_ROOT,
    PROJECT_ROOT / "DL/code/preprocess",
    PROJECT_ROOT / "DATASET/Preprocess",
    PROJECT_ROOT / "ML/code/preprocess",
):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from label_catalog import MultiTaskLabelCatalog, SCENARIO_MAP, STAGE_MAP
except ImportError:
    from DATASET.Preprocess.label_catalog import MultiTaskLabelCatalog, SCENARIO_MAP, STAGE_MAP

try:
    from causal_dataset import (
        CausalTripletDataset,
        TokenVocabulary,
        collate_causal_batch,
    )
except ImportError:
    from preprocess.causal_dataset import (
        CausalTripletDataset,
        TokenVocabulary,
        collate_causal_batch,
    )

try:
    from model_mixhead_attention import MixHeadSelfAttentionCausalHost
except ImportError:
    from preprocess.model_mixhead_attention import MixHeadSelfAttentionCausalHost

try:
    from trainer import MultiTaskTrainer, MultiTaskLoss
except ImportError:
    from preprocess.trainer import MultiTaskTrainer, MultiTaskLoss


# ---------------------------------------------------------------------------
# Distributed helpers
# ---------------------------------------------------------------------------

def is_distributed() -> bool:
    return "WORLD_SIZE" in os.environ and int(os.environ["WORLD_SIZE"]) > 1


def init_distributed() -> tuple[int, int, int]:
    if is_distributed():
        rank = int(os.environ["RANK"])
        world_size = int(os.environ["WORLD_SIZE"])
        local_rank = int(os.environ["LOCAL_RANK"])
        torch.cuda.set_device(local_rank)
        dist.init_process_group(backend="nccl", init_method="env://")
        return rank, local_rank, world_size
    return 0, 0, 1


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("TrainMixHeadAttention")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(ch)
    return logger


# ---------------------------------------------------------------------------
# Shard Dataset  (new: loads pre-built .pt shards)
# ---------------------------------------------------------------------------

class ShardDataset(Dataset):
    """Reads pre-built causal triplet shards produced by build_dl_shards.py."""

    def __init__(self, shard_paths: List[Path]) -> None:
        self._samples: List[Dict[str, Any]] = []
        for sp in shard_paths:
            chunk = torch.load(sp, map_location="cpu", weights_only=False)
            self._samples.extend(chunk)

    def __len__(self) -> int:
        return len(self._samples)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return self._samples[idx]


def _load_shard_datasets(
    shards_dir: Path,
    logger: logging.Logger,
    load_test: bool = False,
) -> tuple[ShardDataset, ShardDataset, Optional[ShardDataset], int]:
    """
    Load train / val / (optionally test) ShardDatasets from a shards directory.

    Returns (train_ds, val_ds, test_ds, vocab_size).
    Vocab size is read from split_manifest.json so the embedding table matches
    exactly the vocab used during pre-processing.
    """
    manifest_path = shards_dir / "split_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"split_manifest.json not found in {shards_dir}. "
            "Run build_dl_shards.py first."
        )

    with manifest_path.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    vocab_size: int = manifest["vocab"]["vocab_size"]
    seed = manifest.get("seed") or manifest.get("source_split", {}).get("seed", 2)
    logger.info(
        f"Manifest: {manifest['total_samples']:,} total samples  "
        f"| vocab_size={vocab_size:,}  | seed={seed}"
    )

    splits_dict = manifest.get("split") or manifest.get("split_summary")
    if not splits_dict:
        raise KeyError("Neither 'split' nor 'split_summary' found in manifest!")

    def _load_split(split_name: str) -> ShardDataset:
        split_info = splits_dict[split_name]
        shard_files = [shards_dir / rel for rel in split_info["shards"]]
        missing = [p for p in shard_files if not p.exists()]
        if missing:
            raise FileNotFoundError(
                f"Missing {len(missing)} shard(s) for {split_name}: {missing[:3]} …"
            )
        ds = ShardDataset(shard_files)
        logger.info(
            f"  [{split_name}] {len(ds):,} samples from {len(shard_files)} shards"
        )
        return ds

    train_ds = _load_split("train")
    val_ds   = _load_split("val")
    if load_test:
        test_ds = _load_split("test")
    else:
        test_info = splits_dict.get("test", {})
        n_test = test_info.get("n_samples", 0)
        n_shards = len(test_info.get("shards", []))
        logger.info(
            f"  [test] {n_test:,} samples from {n_shards} shards (deferred to evaluation to save RAM)"
        )
        test_ds = None

    return train_ds, val_ds, test_ds, vocab_size


# ---------------------------------------------------------------------------
# Legacy: stream raw JSON events (kept for smoke-tests)
# ---------------------------------------------------------------------------

def load_events(data_path: str, max_events: int = 50_000) -> list[dict]:
    records: list[dict] = []
    p = Path(data_path)
    if not p.exists():
        raise FileNotFoundError(f"Events data file not found: {data_path}")
    opener = gzip.open if str(data_path).endswith(".gz") else open
    with opener(data_path, "rt", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if max_events and i >= max_events:
                break
            if line.strip():
                records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Train Mix-Head Self-Attention Causal Model (Peter Bloem)"
    )

    # --- Data source (mutually exclusive) ---
    data_group = parser.add_mutually_exclusive_group()
    data_group.add_argument(
        "--shards-dir",
        default=None,
        help="(PREFERRED) Directory of pre-built DL shards from build_dl_shards.py",
    )
    data_group.add_argument(
        "--data",
        default=str(PROJECT_ROOT / "DL/code/others/sample_multitask_cohort_42k.json.gz"),
        help="(LEGACY) Path to raw eCAR events file (.json.gz)",
    )

    parser.add_argument(
        "--labels",
        default=str(PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json"),
        help="[Legacy mode only] Path to sidecar multi-task labels catalog",
    )
    parser.add_argument(
        "--vocab",
        default=str(PROJECT_ROOT / "DL/code/output/dl_vocab.json"),
        help="[Legacy mode only] Path to frozen dl_vocab.json",
    )

    # --- Model hyper-params ---
    parser.add_argument("--epochs",     type=int,   default=5)
    parser.add_argument("--batch-size", type=int,   default=128, help="Batch size per GPU")
    parser.add_argument("--lr",         type=float, default=1e-3)
    parser.add_argument("--embed-dim",  type=int,   default=128)
    parser.add_argument("--num-heads",  type=int,   default=4)
    parser.add_argument("--blocks",     type=int,   default=2)

    # --- Legacy mode only ---
    parser.add_argument(
        "--max-events",
        type=int,
        default=50_000,
        help="[Legacy mode only] Max raw events to load (0 = unlimited)",
    )

    parser.add_argument(
        "--output-model",
        default=str(PROJECT_ROOT / "DL/code/output/mixhead_attention_multitask.pt"),
    )
    args = parser.parse_args()

    rank, local_rank, world_size = init_distributed()
    is_main = rank == 0

    logger = setup_logger()
    if is_main:
        logger.info(
            f"Initializing Mix-Head Self-Attention Training "
            f"(World: {world_size}, Local Rank: {local_rank})"
        )

    # -------------------------------------------------------------------
    # 1. Load dataset
    # -------------------------------------------------------------------
    if args.shards_dir is not None:
        # ── SHARD MODE (full corpus, pre-tokenised) ──────────────────
        shards_dir = Path(args.shards_dir)
        if is_main:
            logger.info(f"[SHARD MODE] Loading from: {shards_dir}")
        train_dataset, val_dataset, test_dataset, vocab_size = _load_shard_datasets(
            shards_dir, logger
        )
        # +100 safety pad to match training convention
        model_vocab_size = vocab_size + 100

    else:
        # ── LEGACY MODE (on-the-fly tokenisation) ────────────────────
        if is_main:
            logger.info(
                f"[LEGACY MODE] Loading raw events from: {args.data} "
                f"(max {args.max_events:,})"
            )
        catalog = MultiTaskLabelCatalog(args.labels)

        # Load vocab: prefer explicit --vocab file; fall back to auto-build
        vocab_path = Path(args.vocab)
        if vocab_path.exists():
            vocab = TokenVocabulary.from_vocab_file(vocab_path)
            if is_main:
                logger.info(f"  Loaded vocab from {vocab_path} ({len(vocab):,} tokens)")
        else:
            vocab = TokenVocabulary(max_tokens=15_000)
            if is_main:
                logger.warning(
                    f"  Vocab file not found ({vocab_path}), will auto-build from training data"
                )

        records = load_events(args.data, args.max_events)
        if is_main:
            logger.info(f"  Loaded {len(records):,} records")

        full_dataset = CausalTripletDataset(records, catalog, vocab=vocab)
        vocab.frozen = True

        train_dataset, val_dataset = full_dataset.split(train_ratio=0.8, seed=42, stratify=True)
        test_dataset = None  # no held-out test in legacy mode
        vocab_size = len(vocab)
        model_vocab_size = vocab_size + 100

    if is_main:
        logger.info(f"  Train: {len(train_dataset):,}  Val: {len(val_dataset):,}")
        if test_dataset is not None:
            logger.info(f"  Test:  {len(test_dataset):,}")
        logger.info(f"  Model vocab size: {model_vocab_size:,}")

    # -------------------------------------------------------------------
    # 2. DataLoaders
    # -------------------------------------------------------------------
    if is_distributed():
        train_sampler = DistributedSampler(
            train_dataset, num_replicas=world_size, rank=rank, shuffle=True
        )
        val_sampler = DistributedSampler(
            val_dataset, num_replicas=world_size, rank=rank, shuffle=False
        )
    else:
        train_sampler = None
        val_sampler   = None

    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=(train_sampler is None),
        sampler=train_sampler,
        collate_fn=collate_causal_batch,
        num_workers=2,
        pin_memory=True,
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        sampler=val_sampler,
        collate_fn=collate_causal_batch,
        num_workers=2,
        pin_memory=True,
    )

    if is_main:
        logger.info(
            f"Train batches/GPU: {len(train_loader)}  "
            f"Val batches/GPU: {len(val_loader)}"
        )

    # -------------------------------------------------------------------
    # 3. Model
    # -------------------------------------------------------------------
    device = torch.device(f"cuda:{local_rank}" if torch.cuda.is_available() else "cpu")
    if is_main:
        logger.info(f"Primary training device: {device}")

    model = MixHeadSelfAttentionCausalHost(
        vocab_size=model_vocab_size,
        embed_dim=args.embed_dim,
        num_heads=args.num_heads,
        ff_dim=args.embed_dim * 2,
        num_transformer_blocks=args.blocks,
        num_scenarios=4,
        num_stages=10,
        enable_il_adapter=True,
    ).to(device)

    if is_distributed():
        model = DDP(model, device_ids=[local_rank], output_device=local_rank)

    optimizer = optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    criterion = MultiTaskLoss(weight_binary=1.0, weight_scenario=0.5, weight_stage=0.8)
    trainer   = MultiTaskTrainer(model, optimizer, criterion=criterion, device=device)

    best_val_f1 = 0.0

    # -------------------------------------------------------------------
    # 4. Training loop
    # -------------------------------------------------------------------
    for epoch in range(1, args.epochs + 1):
        if train_sampler is not None:
            train_sampler.set_epoch(epoch)

        t0 = time.time()
        train_metrics = trainer.train_epoch(train_loader)
        val_metrics   = trainer.evaluate(val_loader)
        elapsed = time.time() - t0

        if is_main:
            logger.info(
                f"Epoch {epoch:02d}/{args.epochs:02d} [{elapsed:.1f}s] - "
                f"Train Loss: {train_metrics['train_loss']:.4f} | "
                f"Val Loss: {val_metrics['val_loss']:.4f} | "
                f"Binary F1: {val_metrics['binary_f1']*100:.2f}% | "
                f"Scenario F1: {val_metrics['scenario_f1_macro']*100:.2f}% | "
                f"Stage F1: {val_metrics['stage_f1_macro']*100:.2f}%"
            )

            if val_metrics["binary_f1"] >= best_val_f1:
                best_val_f1 = val_metrics["binary_f1"]
                out_path = Path(args.output_model)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                raw_model = model.module if hasattr(model, "module") else model

                # ── Save checkpoint WITH vocab metadata so eval can reconstruct
                #    the exact embedding table without dl_vocab.json mismatch. ──
                ckpt: Dict[str, Any] = {
                    "epoch":            epoch,
                    "model_state_dict": raw_model.state_dict(),
                    "val_metrics":      val_metrics,
                    # Vocab metadata — eval MUST use these values, not dl_vocab.json
                    "vocab_size":       vocab_size,          # raw count (without +100 pad)
                    "model_vocab_size": model_vocab_size,    # actual embedding rows
                    # Architecture params (for checkpoint portability)
                    "arch": {
                        "embed_dim":              args.embed_dim,
                        "num_heads":              args.num_heads,
                        "num_transformer_blocks": args.blocks,
                        "ff_dim":                 args.embed_dim * 2,
                        "num_scenarios":          4,
                        "num_stages":             10,
                        "enable_il_adapter":      True,
                    },
                    # Provenance
                    "data_mode":        "shards" if args.shards_dir else "legacy",
                    "shards_dir":       str(args.shards_dir) if args.shards_dir else None,
                }
                if args.shards_dir:
                    # Store manifest path so eval can verify shard / vocab consistency
                    ckpt["shards_manifest"] = str(
                        Path(args.shards_dir) / "split_manifest.json"
                    )

                torch.save(ckpt, out_path)
                logger.info(f"Saved best model checkpoint → {out_path}")

    if is_main:
        logger.info(f"Training complete. Best Binary F1: {best_val_f1*100:.2f}%")

    if is_distributed():
        dist.destroy_process_group()


if __name__ == "__main__":
    main()
