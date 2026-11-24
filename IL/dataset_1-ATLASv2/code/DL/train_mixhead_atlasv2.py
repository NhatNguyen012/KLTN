#!/usr/bin/env python3
"""Train Mix-Head Self-Attention for ATLASv2 Domain-Incremental Learning (OpTC -> ATLASv2).

Architecture & Continual Learning Strategy:
  1. Base Backbone: Pretrained Mix-Head Self-Attention from OpTC (Dual T4 Full-Train).
  2. Freezing Policy: freeze_base_for_il() freezes token embeddings, line embeddings,
     and all TransformerCausalBlocks (Mix-Head self-attention).
  3. Incremental Adaption: Trains the 32-dim Residual Bottleneck IL Adapter Layer
     alongside task-specific heads.
  4. Vocabulary Extension: Appends new ATLASv2 tokens without altering OpTC base indices;
     new rows start as copies of <unk>.
  5. Stage Classification: Maps to ATLASv2's 5 Discrete Kill-Chain stages:
     0: Benign, 1: Initial_Compromise, 2: Execution_Discovery, 3: Lateral_Movement, 4: Exfiltration.
  6. Replay Buffer: Samples OpTC training shards to prevent Catastrophic Forgetting (BWT >= 0).
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset

# Path resolution
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parents[3]  # /mnt/SSD_Data/optc
for p in (
    PROJECT_ROOT / "DL" / "code" / "preprocess",
    PROJECT_ROOT / "IL" / "dataset_1-ATLASv2" / "code" / "preprocess",
):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from model_mixhead_attention import MixHeadSelfAttentionCausalHost
from causal_dataset import collate_causal_batch

STAGE_NAMES = [
    "Benign",
    "Initial_Compromise",
    "Execution_Discovery",
    "Lateral_Movement",
    "Exfiltration",
]

SCENARIO_NAMES = [
    "Benign",
    "SingleHost_S",
    "MultiHost_M",
]


# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("train_mixhead_atlasv2")


# ---------------------------------------------------------------------------
# Dataset & Shard Streaming
# ---------------------------------------------------------------------------

class ShardSequenceDataset(Dataset):
    """Loads and concatenates samples across a list of .pt shard files."""

    def __init__(self, shard_paths: List[Path], max_samples: Optional[int] = None):
        self.samples: List[Dict[str, Any]] = []
        for sp in shard_paths:
            if not sp.exists():
                continue
            data = torch.load(sp, map_location="cpu", weights_only=False)
            self.samples.extend(data)
            if max_samples and len(self.samples) >= max_samples:
                self.samples = self.samples[:max_samples]
                break

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return self.samples[idx]


# ---------------------------------------------------------------------------
# Model Factory with Backbone Transfer & Freezing
# ---------------------------------------------------------------------------

def build_transfer_model(
    checkpoint_path: Path,
    vocab_size: int,
    num_scenarios: int = 3,
    num_stages: int = 5,
    embed_dim: int = 128,
    num_heads: int = 4,
    ff_dim: int = 256,
    num_transformer_blocks: int = 2,
    dropout: float = 0.1,
    device: str = "cpu",
) -> MixHeadSelfAttentionCausalHost:
    """Builds MixHead model, loads OpTC pretrained base weights, and freezes backbone."""
    logger.info(f"Loading pretrained OpTC checkpoint from: {checkpoint_path}")
    if not checkpoint_path.is_file():
        raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")

    ckpt = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    state_dict = ckpt.get("model_state_dict", ckpt)

    # Initialize model with extended vocab and ATLASv2 stage classes
    model = MixHeadSelfAttentionCausalHost(
        vocab_size=vocab_size,
        embed_dim=embed_dim,
        num_heads=num_heads,
        ff_dim=ff_dim,
        num_transformer_blocks=num_transformer_blocks,
        num_scenarios=num_scenarios,
        num_stages=num_stages,
        dropout=dropout,
        enable_il_adapter=True,
    )

    # Transfer Token Embedding (old rows copied, new rows initialized to <unk>)
    old_emb_weight = state_dict.get("token_embedding.weight")
    if old_emb_weight is not None:
        old_rows, d_emb = old_emb_weight.shape
        logger.info(f"  Transferring token embeddings: {old_rows} base rows -> {vocab_size} extended rows")
        with torch.no_grad():
            copy_rows = min(old_rows, vocab_size)
            model.token_embedding.weight[:copy_rows].copy_(old_emb_weight[:copy_rows])
            if vocab_size > copy_rows:
                unk_row = old_emb_weight[1:2]  # <unk> embedding
                model.token_embedding.weight[copy_rows:].copy_(unk_row.expand(vocab_size - copy_rows, -1))

    # Transfer Line Embedding & Transformer Blocks
    with torch.no_grad():
        if "line_embedding.weight" in state_dict:
            model.line_embedding.weight.copy_(state_dict["line_embedding.weight"])
        for k, v in state_dict.items():
            if k.startswith("blocks.") or k.startswith("token_norm.") or k.startswith("line_pooling_attn."):
                if k in model.state_dict() and model.state_dict()[k].shape == v.shape:
                    model.state_dict()[k].copy_(v)

    # Transfer Binary Head
    with torch.no_grad():
        for k in ["binary_head.0.weight", "binary_head.0.bias", "binary_head.3.weight", "binary_head.3.bias"]:
            if k in state_dict and k in model.state_dict():
                model.state_dict()[k].copy_(state_dict[k])

    # Freeze base backbone for Domain-Incremental Learning
    model.freeze_base_for_il()

    # Move to target device
    model.to(device)
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    logger.info(f"Model Summary: {total_params:,} total params | {trainable_params:,} trainable IL params ({trainable_params/total_params*100:.2f}%)")

    return model


# ---------------------------------------------------------------------------
# Evaluation Routine
# ---------------------------------------------------------------------------

def evaluate_model(
    model: nn.Module,
    loader: DataLoader,
    device: str = "cpu",
    prefix: str = "VAL",
) -> Dict[str, Any]:
    model.eval()
    all_bin_preds, all_bin_targets, all_bin_probs = [], [], []
    all_scen_preds, all_scen_targets = [], []
    all_stage_preds, all_stage_targets = [], []
    attention_maps_sample = None

    with torch.no_grad():
        for batch in loader:
            token_ids = batch["token_ids"].to(device)
            offsets = batch["offsets"].to(device)
            b_size = batch["batch_size"]
            targets_bin = batch["target_binary"].to(device)
            targets_sc = batch["target_scenario"].to(device)
            targets_st = batch["target_stage"].to(device)

            outputs = model(token_ids, offsets, b_size)
            if attention_maps_sample is None and "attention_maps" in outputs:
                attention_maps_sample = [am[0].cpu().numpy() for am in outputs["attention_maps"]]

            bin_probs = torch.sigmoid(outputs["binary_logits"]).cpu().numpy()
            bin_preds = (bin_probs >= 0.5).astype(int)
            scen_preds = outputs["scenario_logits"].argmax(dim=-1).cpu().numpy()
            stage_preds = outputs["stage_logits"].argmax(dim=-1).cpu().numpy()

            all_bin_probs.extend(bin_probs.tolist())
            all_bin_preds.extend(bin_preds.tolist())
            all_bin_targets.extend(targets_bin.cpu().numpy().tolist())

            all_scen_preds.extend(scen_preds.tolist())
            all_scen_targets.extend(targets_sc.cpu().numpy().tolist())

            all_stage_preds.extend(stage_preds.tolist())
            all_stage_targets.extend(targets_st.cpu().numpy().tolist())

    y_bin_true = np.array(all_bin_targets)
    y_bin_pred = np.array(all_bin_preds)
    y_bin_prob = np.array(all_bin_probs)

    y_sc_true = np.array(all_scen_targets)
    y_sc_pred = np.array(all_scen_preds)

    y_st_true = np.array(all_stage_targets)
    y_st_pred = np.array(all_stage_preds)

    # Binary Metrics
    acc = accuracy_score(y_bin_true, y_bin_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_bin_true, y_bin_pred, average="binary", zero_division=0)
    try:
        roc_auc = roc_auc_score(y_bin_true, y_bin_prob)
    except Exception:
        roc_auc = 0.5
    try:
        pr_auc = average_precision_score(y_bin_true, y_bin_prob)
    except Exception:
        pr_auc = 0.0

    # Multi-task Metrics
    scen_acc = accuracy_score(y_sc_true, y_sc_pred)
    scen_f1 = f1_score(y_sc_true, y_sc_pred, average="macro", zero_division=0)

    stage_acc = accuracy_score(y_st_true, y_st_pred)
    stage_f1 = f1_score(y_st_true, y_st_pred, average="macro", zero_division=0)

    # Per-stage F1
    per_stage_f1 = f1_score(y_st_true, y_st_pred, average=None, labels=list(range(len(STAGE_NAMES))), zero_division=0)

    metrics = {
        f"{prefix}_bin_acc": acc,
        f"{prefix}_bin_prec": prec,
        f"{prefix}_bin_rec": rec,
        f"{prefix}_bin_f1": f1,
        f"{prefix}_roc_auc": roc_auc,
        f"{prefix}_pr_auc": pr_auc,
        f"{prefix}_scen_acc": scen_acc,
        f"{prefix}_scen_f1": scen_f1,
        f"{prefix}_stage_acc": stage_acc,
        f"{prefix}_stage_f1": stage_f1,
        "per_stage_f1": per_stage_f1.tolist(),
        "cm_stage": confusion_matrix(y_st_true, y_st_pred, labels=list(range(len(STAGE_NAMES)))).tolist(),
        "attention_maps": attention_maps_sample,
    }

    logger.info(
        f"[{prefix}] Binary F1: {f1*100:.2f}% (Prec: {prec*100:.2f}%, Rec: {rec*100:.2f}%) | "
        f"PR-AUC: {pr_auc:.4f} | Stage Macro F1: {stage_f1*100:.2f}% | Scen F1: {scen_f1*100:.2f}%"
    )
    for i, sname in enumerate(STAGE_NAMES):
        logger.info(f"  Stage {i} ({sname:20s}): F1 = {per_stage_f1[i]*100:.2f}%")

    return metrics


# ---------------------------------------------------------------------------
# Training Loop
# ---------------------------------------------------------------------------

def train_atlasv2_il(
    model: nn.Module,
    train_loader: DataLoader,
    val_loader: DataLoader,
    test_loader: DataLoader,
    optc_replay_loader: Optional[DataLoader] = None,
    epochs: int = 10,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    device: str = "cpu",
    output_dir: Path = Path("output"),
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    optimizer = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad],
        lr=lr,
        weight_decay=weight_decay,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)

    criterion_bin = nn.BCEWithLogitsLoss()
    criterion_scen = nn.CrossEntropyLoss()
    criterion_stage = nn.CrossEntropyLoss()

    best_val_f1 = 0.0
    best_checkpoint_path = output_dir / "mixhead_atlasv2_best.pt"
    history: List[Dict[str, Any]] = []

    logger.info(f"\nStarting Incremental Training on ATLASv2 for {epochs} epochs...")
    t_start = time.time()

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        n_batches = 0

        replay_iter = iter(optc_replay_loader) if optc_replay_loader else None

        for batch in train_loader:
            optimizer.zero_grad()
            token_ids = batch["token_ids"].to(device)
            offsets = batch["offsets"].to(device)
            b_size = batch["batch_size"]
            targets_bin = batch["target_binary"].to(device)
            targets_sc = batch["target_scenario"].to(device)
            targets_st = batch["target_stage"].to(device)

            outputs = model(token_ids, offsets, b_size)
            l_bin = criterion_bin(outputs["binary_logits"], targets_bin)
            l_sc = criterion_scen(outputs["scenario_logits"], targets_sc)
            l_st = criterion_stage(outputs["stage_logits"], targets_st)

            loss = l_bin + 0.5 * l_st + 0.2 * l_sc

            # Optional Experience Replay from OpTC
            if replay_iter is not None:
                try:
                    rep_batch = next(replay_iter)
                except StopIteration:
                    replay_iter = iter(optc_replay_loader)
                    rep_batch = next(replay_iter)

                rep_tokens = rep_batch["token_ids"].to(device)
                rep_offsets = rep_batch["offsets"].to(device)
                rep_bs = rep_batch["batch_size"]
                rep_bin = rep_batch["target_binary"].to(device)

                rep_out = model(rep_tokens, rep_offsets, rep_bs)
                l_rep = criterion_bin(rep_out["binary_logits"], rep_bin)
                loss = loss + 0.3 * l_rep

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            train_loss += loss.item()
            n_batches += 1

        scheduler.step()
        avg_loss = train_loss / max(1, n_batches)
        logger.info(f"Epoch [{epoch:02d}/{epochs:02d}] Train Loss: {avg_loss:.4f} | LR: {scheduler.get_last_lr()[0]:.6f}")

        # Validation
        val_metrics = evaluate_model(model, val_loader, device=device, prefix="VAL")
        val_f1 = val_metrics["VAL_bin_f1"]

        epoch_record = {"epoch": epoch, "loss": avg_loss, **val_metrics}
        history.append(epoch_record)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "val_f1": best_val_f1,
                    "metrics": val_metrics,
                },
                best_checkpoint_path,
            )
            logger.info(f"  --> Saved new best checkpoint with Val Binary F1: {best_val_f1*100:.2f}%")

    # Final Test Scoring
    logger.info("\nEvaluating Best Model on TEST Partition...")
    best_ckpt = torch.load(best_checkpoint_path, map_location=device, weights_only=False)
    model.load_state_dict(best_ckpt["model_state_dict"])
    test_metrics = evaluate_model(model, test_loader, device=device, prefix="TEST")

    # Plot Confusion Matrix
    cm = np.array(test_metrics["cm_stage"])
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(STAGE_NAMES)))
    ax.set_yticks(range(len(STAGE_NAMES)))
    ax.set_xticklabels(STAGE_NAMES, rotation=35, ha="right")
    ax.set_yticklabels(STAGE_NAMES)
    ax.set_xlabel("Predicted Stage")
    ax.set_ylabel("True Stage")
    ax.set_title("ATLASv2 Multi-Stage Attack Confusion Matrix (Mix-Head IL)")
    for i in range(len(STAGE_NAMES)):
        for j in range(len(STAGE_NAMES)):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", color="red" if i != j else "black")
    fig.tight_layout()
    cm_path = output_dir / "atlasv2_confusion_matrix.png"
    plt.savefig(cm_path, dpi=200)
    plt.close()
    logger.info(f"Saved confusion matrix plot to {cm_path}")

    return {
        "best_val_f1": best_val_f1,
        "test_metrics": test_metrics,
        "history": history,
        "best_checkpoint": str(best_checkpoint_path),
    }


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Train Mix-Head Self-Attention IL on ATLASv2")
    parser.add_argument(
        "--shards-dir",
        default=str(PROJECT_ROOT / "IL" / "dataset_1-ATLASv2" / "output" / "dl_shards"),
        help="Path to directory containing ATLASv2 train/val/test shards",
    )
    parser.add_argument(
        "--base-checkpoint",
        default=str(PROJECT_ROOT / "DL" / "code" / "output" / "results" / "mixhead_attention_t4x2_full.pt"),
        help="Path to pretrained OpTC base checkpoint",
    )
    parser.add_argument(
        "--optc-shards-dir",
        default=str(PROJECT_ROOT / "DL" / "code" / "output" / "dl_shards" / "train"),
        help="Path to OpTC training shards for replay buffer",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "IL" / "dataset_1-ATLASv2" / "output" / "mixhead_results"),
        help="Path to results directory",
    )
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--enable-replay", action="store_true", help="Enable OpTC Experience Replay")
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")

    args = parser.parse_args()

    shards_dir = Path(args.shards_dir)
    manifest_path = shards_dir / "split_manifest.json"
    vocab_path = shards_dir / "atlasv2_vocab.json"

    if not manifest_path.is_file():
        raise FileNotFoundError(f"split_manifest.json not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    vocab_size = manifest["total_vocab_size"]
    logger.info(f"Loaded manifest. Extended vocabulary size: {vocab_size:,}")

    # Build model
    model = build_transfer_model(
        checkpoint_path=Path(args.base_checkpoint),
        vocab_size=vocab_size,
        num_scenarios=3,
        num_stages=5,
        device=args.device,
    )

    # Load shard datasets
    train_shards = sorted((shards_dir / "train").glob("*.pt"))
    val_shards = sorted((shards_dir / "val").glob("*.pt"))
    test_shards = sorted((shards_dir / "test").glob("*.pt"))

    logger.info(f"Shards: {len(train_shards)} TRAIN, {len(val_shards)} VAL, {len(test_shards)} TEST")

    train_ds = ShardSequenceDataset(train_shards)
    val_ds = ShardSequenceDataset(val_shards)
    test_ds = ShardSequenceDataset(test_shards)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, collate_fn=collate_causal_batch)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False, collate_fn=collate_causal_batch)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False, collate_fn=collate_causal_batch)

    # Replay loader
    replay_loader = None
    if args.enable_replay:
        optc_shards = sorted(Path(args.optc_shards_dir).glob("*.pt"))[:20]  # First 20 shards pool
        if optc_shards:
            optc_ds = ShardSequenceDataset(optc_shards)
            replay_loader = DataLoader(optc_ds, batch_size=args.batch_size // 4, shuffle=True, collate_fn=collate_causal_batch)
            logger.info(f"Loaded {len(optc_ds):,} OpTC samples for Experience Replay.")

    # Train
    train_atlasv2_il(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        test_loader=test_loader,
        optc_replay_loader=replay_loader,
        epochs=args.epochs,
        lr=args.lr,
        device=args.device,
        output_dir=Path(args.output_dir),
    )


if __name__ == "__main__":
    main()
