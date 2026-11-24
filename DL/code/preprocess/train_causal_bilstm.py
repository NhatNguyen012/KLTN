#!/usr/bin/env python3
"""End-to-End CLI Training Script for BiLSTM Causal Host Multi-Task Model.

Usage:
  python3 DL/01_code/causal_bilstm/train_causal_bilstm.py \
      --data /path/to/events.json.gz \
      --labels DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz \
      --epochs 10 \
      --batch-size 64 \
      --embed-dim 128 \
      --hidden-dim 128
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

import torch
import torch.distributed as dist
import torch.optim as optim
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data import DataLoader
from torch.utils.data.distributed import DistributedSampler

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = next((p for p in CURRENT_DIR.parents if (p / "AGENTS.md").is_file()), CURRENT_DIR)

for p in (CURRENT_DIR, CURRENT_DIR.parent, PROJECT_ROOT, PROJECT_ROOT / "DL/code/preprocess", PROJECT_ROOT / "DATASET/Preprocess", PROJECT_ROOT / "ML/code/preprocess"):
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
    from model_causal_bilstm import BiLSTMCausalHostMultiTask
except ImportError:
    from preprocess.model_causal_bilstm import BiLSTMCausalHostMultiTask

try:
    from trainer import MultiTaskTrainer, MultiTaskLoss
except ImportError:
    from preprocess.trainer import MultiTaskTrainer, MultiTaskLoss


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
    logger = logging.getLogger("TrainCausalBiLSTM")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(ch)
    return logger


def load_events(data_path: str, max_events: int = 50000) -> list[dict]:
    records = []
    p = Path(data_path)
    if not p.exists():
        raise FileNotFoundError(f"Events data file not found: {data_path}")
    opener = gzip.open if str(data_path).endswith(".gz") else open
    with opener(data_path, "rt", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= max_events:
                break
            if line.strip():
                records.append(json.loads(line))
    return records


def main():
    parser = argparse.ArgumentParser(description="Train BiLSTM Causal Host Multi-Task Model (Single & Dual GPU DDP)")
    parser.add_argument(
        "--data",
        default=str(
            PROJECT_ROOT
            / "DL/code/others/sample_multitask_cohort_42k.json.gz"
        ),
        help="Path to eCAR events file (.json.gz)",
    )
    parser.add_argument(
        "--labels",
        default=str(PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz"),
        help="Path to sidecar multi-task labels catalog (.json.gz)",
    )
    parser.add_argument("--epochs", type=int, default=5, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=128, help="Batch size per GPU")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--embed-dim", type=int, default=128, help="Embedding dimension per step")
    parser.add_argument("--hidden-dim", type=int, default=128, help="BiLSTM hidden dimension")
    parser.add_argument("--max-events", type=int, default=50000, help="Max events to load for training run")
    parser.add_argument("--output-model", default=str(PROJECT_ROOT / "DL/code/output/causal_bilstm_multitask.pt"))
    args = parser.parse_args()

    rank, local_rank, world_size = init_distributed()
    is_main = (rank == 0)

    logger = setup_logger()
    if is_main:
        logger.info(f"Initializing Causal BiLSTM Training (World size: {world_size}, Local Rank: {local_rank})")

    # 1. Load Labels & Data
    catalog = MultiTaskLabelCatalog(args.labels)
    if is_main:
        logger.info(f"Loaded sidecar label catalog ({len(catalog):,} malicious IDs)")
        logger.info(f"Loading events from: {args.data} (max {args.max_events:,} events)")
    
    records = load_events(args.data, args.max_events)
    if is_main:
        logger.info(f"Loaded {len(records):,} records")

    # 2. Extract Causal Triplets & Stratified Split
    vocab = TokenVocabulary(max_tokens=15000)
    full_dataset = CausalTripletDataset(records, catalog, vocab=vocab)
    vocab.frozen = True

    train_dataset, val_dataset = full_dataset.split(train_ratio=0.8, seed=42, stratify=True)

    if is_distributed():
        train_sampler = DistributedSampler(train_dataset, num_replicas=world_size, rank=rank, shuffle=True)
        val_sampler = DistributedSampler(val_dataset, num_replicas=world_size, rank=rank, shuffle=False)
    else:
        train_sampler = None
        val_sampler = None

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
        logger.info(f"Vocabulary size: {len(vocab):,} tokens")
        logger.info(f"Train samples: {len(train_dataset):,}, Val samples: {len(val_dataset):,}")
        logger.info(f"Train batches per GPU: {len(train_loader)}, Val batches per GPU: {len(val_loader)}")

    # 3. Model & Trainer
    device = torch.device(f"cuda:{local_rank}" if torch.cuda.is_available() else "cpu")
    if is_main:
        logger.info(f"Primary training device: {device}")

    model = BiLSTMCausalHostMultiTask(
        vocab_size=len(vocab) + 100,
        embed_dim=args.embed_dim,
        hidden_dim=args.hidden_dim,
        num_scenarios=4,
        num_stages=10,
    ).to(device)

    if is_distributed():
        model = DDP(model, device_ids=[local_rank], output_device=local_rank)

    optimizer = optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    criterion = MultiTaskLoss(weight_binary=1.0, weight_scenario=0.5, weight_stage=0.8)
    trainer = MultiTaskTrainer(model, optimizer, criterion=criterion, device=device)

    best_val_f1 = 0.0

    # 4. Training Loop
    for epoch in range(1, args.epochs + 1):
        if train_sampler is not None:
            train_sampler.set_epoch(epoch)

        t0 = time.time()
        train_metrics = trainer.train_epoch(train_loader)
        val_metrics = trainer.evaluate(val_loader)
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
                torch.save(
                    {
                        "epoch": epoch,
                        "model_state_dict": raw_model.state_dict(),
                        "val_metrics": val_metrics,
                        "vocab_size": len(vocab),
                    },
                    out_path,
                )
                logger.info(f"Saved best model checkpoint to {out_path}")

    if is_main:
        logger.info(f"Training completed! Best Binary F1: {best_val_f1*100:.2f}%")

    if is_distributed():
        dist.destroy_process_group()


if __name__ == "__main__":
    main()
