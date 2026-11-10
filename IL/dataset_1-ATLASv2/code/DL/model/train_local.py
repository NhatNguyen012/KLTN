#!/usr/bin/env python3
"""Local Training Pipeline for Multi-Stage Kill-Chain Continual BiLSTM.

Runs locally on NVIDIA RTX 3050 Laptop GPU (4GB VRAM) with AMP FP16.
Features:
- Dual-Head BiLSTM:
    1. Binary Head: Anomaly detection (0: Benign, 1: Malicious).
    2. Multi-Stage Head: 5-class Kill-Chain stage detection:
       - 0: Benign
       - 1: Initial_Compromise
       - 2: Execution_Discovery
       - 3: Lateral_Movement
       - 4: Exfiltration
- Transfer Learning from OpTC pretrained model with vocabulary expansion.
- Experience Replay (80/20 mix) from OpTC replay buffer for Backward Transfer (BWT >= -0.05).
- Class-weighted multi-task loss for handling extreme class imbalance.
- Unified hierarchical evaluation ensuring binary and stage predictions are 100% consistent.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import random
import sys
import time
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Local imports
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from bilstm import BiLSTMBaseline
from dataset import (
    PackedNetworkDataset,
    ReplayBufferDataset,
    ShardAwareBatchSampler,
    collate_sequence_batch,
)

# ==============================================================================
# RUN CONFIGURATION (USER CONTROL)
# ==============================================================================
RUN = 5  # Modify this global variable (e.g. RUN = 5 -> local_output/local_run_v5)
CODE_ROOT = Path(__file__).resolve().parent.parent
LOCAL_OUTPUT_BASE = CODE_ROOT / "output" / "local_output"

STAGE_NAMES = {
    0: "Benign",
    1: "Initial_Compromise",
    2: "Execution_Discovery",
    3: "Lateral_Movement",
    4: "Exfiltration",
}


def save_confusion_matrix_plot(
    cm: list[list[int]],
    output_path: str | Path,
    *,
    title: str = "ATLASv2 5-Stage Kill-Chain Confusion Matrix",
    threshold: float | None = None,
) -> None:
    """Plot and save publication-quality 5x5 confusion matrix heatmap (matrix.png)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns

        labels = ["Benign", "InitComp", "ExecDisc", "LatMov", "Exfil"]
        cm_arr = np.array(cm, dtype=int)

        plt.figure(figsize=(8, 6.5), dpi=300)
        annot = np.empty_like(cm_arr, dtype=object)
        for i in range(cm_arr.shape[0]):
            for j in range(cm_arr.shape[1]):
                annot[i, j] = f"{cm_arr[i, j]:,d}"

        ax = sns.heatmap(
            cm_arr,
            annot=annot,
            fmt="",
            cmap="Blues",
            xticklabels=labels,
            yticklabels=labels,
            cbar=True,
            linewidths=0.8,
            linecolor="#dddddd",
        )
        full_title = title if threshold is None else f"{title}\n(Binary Threshold = {threshold:.4f})"
        ax.set_title(full_title, fontsize=13, fontweight="bold", pad=12)
        ax.set_xlabel("Predicted Stage", fontsize=11, fontweight="bold", labelpad=8)
        ax.set_ylabel("Ground Truth Stage", fontsize=11, fontweight="bold", labelpad=8)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300)
        plt.close()
        print(f"Confusion matrix plot saved to: {output_path}")
    except Exception as e:
        print(f"[Warning] Could not generate matrix.png: {e}")


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True


def load_pretrained_checkpoint(
    model: nn.Module,
    ckpt_path: str | Path,
    device: torch.device,
    *,
    recenter_logit_bias: bool = True,
    optc_base_thr: float = 0.9956,
) -> dict[int, int]:
    """Load pretrained model weights with vocabulary expansion and logit recentering."""
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    state_dict = ckpt.get("model_state_dict", ckpt)
    model_state = model.state_dict()
    old_vocab_sizes: dict[int, int] = {}

    for key, val in state_dict.items():
        if key not in model_state:
            continue
        if model_state[key].shape == val.shape:
            model_state[key] = val
        elif "embeddings" in key and model_state[key].dim() == 2 and val.dim() == 2:
            try:
                emb_idx = int(key.split(".")[1])
            except Exception:
                emb_idx = -1
            n_old = min(val.shape[0], model_state[key].shape[0])
            d = min(val.shape[1], model_state[key].shape[1])
            model_state[key][:n_old, :d] = val[:n_old, :d]
            if emb_idx >= 0:
                old_vocab_sizes[emb_idx] = n_old
            if model_state[key].shape[0] > n_old:
                n_new = model_state[key].shape[0] - n_old
                base_vec = val[1:n_old, :d].mean(dim=0, keepdim=True) if n_old > 1 else val[0:1, :d]
                rng_gen = torch.Generator(device=val.device).manual_seed(42 + max(0, emb_idx))
                noise = torch.randn((n_new, d), generator=rng_gen, device=val.device, dtype=val.dtype) * 0.05
                model_state[key][n_old:, :d] = base_vec + noise
                print(
                    f"  [Vocab Expansion] {key}: transferred {n_old} rows from OpTC, "
                    f"initialized {n_new} new rows with Mean-Embedding + N(0, 0.05)."
                )
        else:
            print(f"  [Skip] Key {key} shape mismatch: ckpt {val.shape} vs model {model_state[key].shape}")

    model.load_state_dict(model_state)

    if recenter_logit_bias:
        logit_offset = math.log(optc_base_thr / (1.0 - optc_base_thr))
        with torch.no_grad():
            last_linear = model.classifier[-1]
            if isinstance(last_linear, nn.Linear) and last_linear.bias is not None:
                shift_val = 0.60 * logit_offset
                last_linear.bias.data -= shift_val
                print(f"  [Logit Recentering] Shifted classifier[-1].bias by -{shift_val:.4f}.")

    print(f"  Pretrained weights loaded successfully from {ckpt_path}")
    return old_vocab_sizes


def apply_optc_gradient_shield(model: nn.Module, old_sizes: dict[int, int], old_scale: float = 0.35) -> None:
    """Shield shared OpTC vocabulary from rapid drift during incremental fine-tuning."""
    if not old_sizes:
        return
    for i, emb in enumerate(model.embeddings):
        n_old = old_sizes.get(i, 0)
        if n_old > 0 and emb.weight.shape[0] > n_old:
            def _make_hook(cutoff: int, scale: float):
                def _hook(grad: torch.Tensor) -> torch.Tensor:
                    g = grad.clone()
                    g[:cutoff] *= scale
                    return g
                return _hook
            emb.weight.register_hook(_make_hook(n_old, old_scale))
            print(f"  [Gradient Shield] Protected {n_old} OpTC rows in embeddings[{i}] (scale={old_scale}x).")


def make_loader(
    dataset: PackedNetworkDataset,
    batch_size: int = 32,
    shuffle: bool = True,
    seed: int = 42,
    num_workers: int = 0,
) -> tuple[DataLoader, ShardAwareBatchSampler | None]:
    if shuffle:
        sampler = ShardAwareBatchSampler(dataset, batch_size=batch_size, shuffle=True, seed=seed)
        loader = DataLoader(dataset, batch_sampler=sampler, collate_fn=collate_sequence_batch, num_workers=num_workers)
        return loader, sampler
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False, collate_fn=collate_sequence_batch, num_workers=num_workers)
    return loader, None


def evaluate(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
    *,
    binary_threshold: float = 0.50,
) -> dict[str, Any]:
    """Hierarchical evaluation of both Binary Anomaly and Multi-Stage Kill-Chain detection."""
    model.eval()
    all_bin_probs: list[float] = []
    all_bin_targets: list[int] = []
    all_stage_logits: list[np.ndarray] = []
    all_stage_targets: list[int] = []

    with torch.no_grad():
        for batch in loader:
            x_cat = batch["x_cat"].to(device)
            x_num = batch["x_num"].to(device)
            x_num_missing = batch["x_num_missing"].to(device)
            x_bin = batch["x_bin"].to(device)
            delta_t = batch["delta_t_log1p"].to(device)
            lengths = batch["lengths"].to(device)

            with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                bin_logits, stg_logits = model(
                    x_cat=x_cat,
                    x_num=x_num,
                    x_num_missing=x_num_missing,
                    x_bin=x_bin,
                    delta_t_log1p=delta_t,
                    lengths=lengths,
                    return_stage_logits=True,
                )

            bin_probs = torch.sigmoid(bin_logits).cpu().numpy().tolist()
            bin_targets = batch["labels"].numpy().astype(int).tolist()
            stg_targets = batch["stages"].numpy().astype(int).tolist()
            stg_logits_np = stg_logits.cpu().float().numpy()

            all_bin_probs.extend(bin_probs)
            all_bin_targets.extend(bin_targets)
            all_stage_logits.append(stg_logits_np)
            all_stage_targets.extend(stg_targets)

    y_bin_true = np.array(all_bin_targets, dtype=int)
    y_bin_prob = np.array(all_bin_probs, dtype=float)
    y_bin_pred = (y_bin_prob >= binary_threshold).astype(int)

    # Binary Metrics
    bin_f1 = float(f1_score(y_bin_true, y_bin_pred, zero_division=0))
    bin_prec = float(precision_score(y_bin_true, y_bin_pred, zero_division=0))
    bin_rec = float(recall_score(y_bin_true, y_bin_pred, zero_division=0))
    try:
        bin_pr_auc = float(average_precision_score(y_bin_true, y_bin_prob))
    except Exception:
        bin_pr_auc = 0.0
    try:
        bin_roc_auc = float(roc_auc_score(y_bin_true, y_bin_prob))
    except Exception:
        bin_roc_auc = 0.0

    # Stage Prediction: Hierarchical Consistent Prediction
    # Head 1: Binary Gate (Benign vs Attack)
    # Head 2: Attack Stage Classifier (1: InitComp, 2: ExecDisc, 3: LatMov, 4: Exfil)
    all_stg_logits = np.concatenate(all_stage_logits, axis=0) if all_stage_logits else np.zeros((0, 4))
    y_stg_true = np.array(all_stage_targets, dtype=int)
    y_stg_pred = np.zeros_like(y_stg_true)

    for i in range(len(y_bin_pred)):
        if y_bin_pred[i] == 0:
            y_stg_pred[i] = 0
        else:
            y_stg_pred[i] = int(np.argmax(all_stg_logits[i])) + 1

    # Multi-Stage Metrics
    # Macro F1 across all 5 classes
    stage_macro_f1 = float(f1_score(y_stg_true, y_stg_pred, average="macro", zero_division=0))
    stage_weighted_f1 = float(f1_score(y_stg_true, y_stg_pred, average="weighted", zero_division=0))

    # Attack-only Macro F1 (Stages 1..4)
    attack_mask = y_stg_true > 0
    if np.any(attack_mask):
        attack_macro_f1 = float(f1_score(y_stg_true[attack_mask], y_stg_pred[attack_mask], labels=[1, 2, 3, 4], average="macro", zero_division=0))
    else:
        attack_macro_f1 = 0.0

    # Per-stage precision, recall, F1
    per_stage: dict[str, dict[str, float]] = {}
    for sid, sname in STAGE_NAMES.items():
        s_true = (y_stg_true == sid).astype(int)
        s_pred = (y_stg_pred == sid).astype(int)
        per_stage[sname] = {
            "support": int(np.sum(s_true)),
            "precision": float(precision_score(s_true, s_pred, zero_division=0)),
            "recall": float(recall_score(s_true, s_pred, zero_division=0)),
            "f1": float(f1_score(s_true, s_pred, zero_division=0)),
        }

    # Confusion matrix (5x5)
    cm = confusion_matrix(y_stg_true, y_stg_pred, labels=[0, 1, 2, 3, 4]).tolist()

    return {
        "binary_threshold": binary_threshold,
        "binary_f1": bin_f1,
        "binary_precision": bin_prec,
        "binary_recall": bin_rec,
        "binary_pr_auc": bin_pr_auc,
        "binary_roc_auc": bin_roc_auc,
        "stage_macro_f1": stage_macro_f1,
        "stage_weighted_f1": stage_weighted_f1,
        "attack_macro_f1": attack_macro_f1,
        "per_stage": per_stage,
        "confusion_matrix": cm,
    }


def find_optimal_threshold(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
) -> tuple[float, dict[str, Any]]:
    """Grid search for threshold on validation set that maximizes combined score."""
    model.eval()
    all_bin_probs: list[float] = []
    all_bin_targets: list[int] = []
    all_stage_logits: list[np.ndarray] = []
    all_stage_targets: list[int] = []

    with torch.no_grad():
        for batch in loader:
            x_cat = batch["x_cat"].to(device)
            x_num = batch["x_num"].to(device)
            x_num_missing = batch["x_num_missing"].to(device)
            x_bin = batch["x_bin"].to(device)
            delta_t = batch["delta_t_log1p"].to(device)
            lengths = batch["lengths"].to(device)

            with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                bin_logits, stg_logits = model(
                    x_cat=x_cat,
                    x_num=x_num,
                    x_num_missing=x_num_missing,
                    x_bin=x_bin,
                    delta_t_log1p=delta_t,
                    lengths=lengths,
                    return_stage_logits=True,
                )

            all_bin_probs.extend(torch.sigmoid(bin_logits).cpu().numpy().tolist())
            all_bin_targets.extend(batch["labels"].numpy().astype(int).tolist())
            all_stage_logits.append(stg_logits.cpu().float().numpy())
            all_stage_targets.extend(batch["stages"].numpy().astype(int).tolist())

    y_bin_true = np.array(all_bin_targets, dtype=int)
    y_bin_prob = np.array(all_bin_probs, dtype=float)
    y_stg_true = np.array(all_stage_targets, dtype=int)
    all_stg_logits = np.concatenate(all_stage_logits, axis=0)

    best_score = -1.0
    best_thr = 0.15
    min_fpr_thr = 0.15
    min_fpr = 1.0
    best_metrics: dict[str, Any] = {}

    for thr in np.linspace(0.015, 0.40, 78):
        y_bin_pred = (y_bin_prob >= thr).astype(int)
        fp = np.sum((y_bin_pred == 1) & (y_bin_true == 0))
        tn = np.sum((y_bin_pred == 0) & (y_bin_true == 0))
        fpr = fp / max(1, fp + tn)

        if fpr < min_fpr:
            min_fpr = fpr
            min_fpr_thr = float(thr)

        if fpr > 0.020:  # Operational security constraint: max 2.0% FPR
            continue

        y_stg_pred = np.zeros_like(y_stg_true)
        for i in range(len(y_bin_pred)):
            if y_bin_pred[i] == 0:
                y_stg_pred[i] = 0
            else:
                y_stg_pred[i] = int(np.argmax(all_stg_logits[i])) + 1

        macro_f1 = f1_score(y_stg_true, y_stg_pred, average="macro", zero_division=0)
        bin_f1 = f1_score(y_bin_true, y_bin_pred, zero_division=0)

        # Multi-stage Attack Macro F1 (Stages 1..4)
        attack_mask = y_stg_true > 0
        if np.any(attack_mask):
            atk_macro_f1 = float(f1_score(y_stg_true[attack_mask], y_stg_pred[attack_mask], labels=[1, 2, 3, 4], average="macro", zero_division=0))
        else:
            atk_macro_f1 = 0.0

        # Prioritize Attack detection and multi-stage classification
        combined_score = 0.50 * atk_macro_f1 + 0.30 * macro_f1 + 0.20 * bin_f1

        if combined_score > best_score:
            best_score = combined_score
            best_thr = float(thr)

    if best_score < 0:
        best_thr = min_fpr_thr

    # Compute final metrics with best threshold
    best_metrics = evaluate(model, loader, device, binary_threshold=best_thr)
    return best_thr, best_metrics


def print_confusion_matrix_ascii(cm: list[list[int]]) -> None:
    headers = ["Benign", "InitComp", "ExecDisc", "LatMov", "Exfil"]
    print("\n  5x5 Stage Confusion Matrix (Rows: Ground Truth, Cols: Predicted):")
    print(f"  {'':15s} " + " ".join(f"{h:>10s}" for h in headers))
    for i, row in enumerate(cm):
        r_name = headers[i]
        vals = " ".join(f"{v:10,d}" for v in row)
        print(f"  {r_name:15s} {vals}")
    print()


def train(args: argparse.Namespace) -> None:
    set_seed(args.seed)
    device = torch.device(args.device if torch.cuda.is_available() and args.device == "cuda" else "cpu")

    if getattr(args, "output_dir", None):
        output_dir = Path(args.output_dir)
    else:
        run_num = getattr(args, "run", RUN)
        output_dir = LOCAL_OUTPUT_BASE / f"local_run_v{run_num}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("LOCAL MULTI-STAGE KILL-CHAIN CONTINUAL BiLSTM TRAINING")
    print("=" * 80)
    print(f"Device:           {device} ({torch.cuda.get_device_name(0) if device.type == 'cuda' else 'CPU'})")
    print(f"Data Dir:         {args.data_dir}")
    print(f"Pretrained Ckpt:  {args.pretrained_ckpt}")
    print(f"Replay Buffer:    {args.replay_buffer}")
    print(f"OpTC Test Root:   {args.optc_test_root}")
    print(f"Output Dir:       {output_dir}")
    print(f"Batch Size:       {args.batch_size}")
    print(f"Epochs:           {args.epochs}")
    print(f"Learning Rate:    {args.lr}")
    print(f"Weights:          Stage={args.stage_weight} | Replay={args.replay_weight} | Replay Ratio={args.replay_ratio}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Datasets
    print("\n[1/5] Loading Datasets...")
    train_ds = PackedNetworkDataset(args.data_dir, "train")
    val_ds = PackedNetworkDataset(args.data_dir, "val")
    test_ds = PackedNetworkDataset(args.data_dir, "test")
    print(f"  Train samples: {len(train_ds):,}")
    print(f"  Val samples:   {len(val_ds):,}")
    print(f"  Test samples:  {len(test_ds):,}")

    train_loader, train_sampler = make_loader(train_ds, batch_size=args.batch_size, shuffle=True, seed=args.seed)
    val_loader, _ = make_loader(val_ds, batch_size=args.batch_size, shuffle=False)
    test_loader, _ = make_loader(test_ds, batch_size=args.batch_size, shuffle=False)

    replay_ds = None
    if args.replay_buffer and Path(args.replay_buffer).exists():
        replay_ds = ReplayBufferDataset(args.replay_buffer)
        print(f"  Replay buffer: {len(replay_ds):,} OpTC samples (pos={len(replay_ds.pos_indices):,}, neg={len(replay_ds.neg_indices):,})")

    # 2. Build Model & Load Pretrained Weights
    print("\n[2/5] Initializing BiLSTM Architecture...")
    prep_dir = Path(args.data_dir) / "preprocessing"
    cat_maps = json.loads((prep_dir / "network_category_maps.json").read_text(encoding="utf-8"))
    cardinalities = [cat_maps["fields"][f]["size"] for f in ["app_family", "proto", "resp_port_class", "image_dir_class"]]
    print(f"  Categorical cardinalities: {cardinalities}")

    model = BiLSTMBaseline(
        categorical_cardinalities=cardinalities,
        numerical_dim=0,
        binary_dim=1,
        event_dim=64,
        hidden_dim=64,
        lstm_layers=1,
        dropout=0.20,
        num_stages=4,
    ).to(device)

    old_sizes = {}
    if args.pretrained_ckpt and Path(args.pretrained_ckpt).exists():
        old_sizes = load_pretrained_checkpoint(
            model,
            args.pretrained_ckpt,
            device,
            recenter_logit_bias=False,
            optc_base_thr=0.9956,
        )
        apply_optc_gradient_shield(model, old_sizes, old_scale=0.35)

    # 3. Setup Losses & Optimizer
    print("\n[3/5] Configuring Losses & Optimizer...")
    # Binary loss pos_weight (balanced to prevent over-conservative predictions)
    pos_weight_val = 5.0
    binary_loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pos_weight_val], device=device))
    atk_binary_loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([2.0], device=device))
    replay_loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([2.0], device=device))

    # Stage Loss on 4 Attack Stages: InitComp, ExecDisc, LatMov, Exfil
    stage_counts = [sum(1 for r in train_ds.rows if r["stage"] == sid) for sid in range(1, 5)]
    atk_stage_names = [STAGE_NAMES[sid] for sid in range(1, 5)]
    print(f"  Train attack stage counts: {dict(zip(atk_stage_names, stage_counts))}")

    # Index attack samples for balanced stage batching
    attack_indices_by_stage: dict[int, list[int]] = {1: [], 2: [], 3: [], 4: []}
    for idx, r in enumerate(train_ds.rows):
        stg = r["stage"]
        if stg in attack_indices_by_stage:
            attack_indices_by_stage[stg].append(idx)
    print(f"  Balanced Stage Sampler Pool: {[(STAGE_NAMES[k], len(v)) for k, v in attack_indices_by_stage.items()]}")

    stage_loss_fn = nn.CrossEntropyLoss()

    # Layer-wise learning rates: lower for pretrained backbone, higher for stage head
    backbone_params = []
    head_params = []
    for name, p in model.named_parameters():
        if "stage_classifier" in name:
            head_params.append(p)
        else:
            backbone_params.append(p)

    optimizer = torch.optim.AdamW([
        {"params": backbone_params, "lr": args.lr * 0.40, "weight_decay": 1e-4},
        {"params": head_params, "lr": args.lr * 1.50, "weight_decay": 1e-4},
    ])
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs, eta_min=args.lr * 0.05)
    scaler = torch.amp.GradScaler(device="cuda", enabled=(device.type == "cuda"))

    # Initial Zero-Shot / Pre-training Evaluation
    print("\n[3b/5] Pre-Training Zero-Shot Evaluation on VAL...")
    init_val_m = evaluate(model, val_loader, device, binary_threshold=0.50)
    print(f"  Pre-train Val: Binary F1={init_val_m['binary_f1']:.4f} | Stage Macro F1={init_val_m['stage_macro_f1']:.4f} | Attack F1={init_val_m['attack_macro_f1']:.4f}")

    optc_test_pre_f1 = None
    if args.optc_test_root and Path(args.optc_test_root).exists():
        print("  Evaluating Pre-Training OpTC Benchmark...")
        optc_test_ds = PackedNetworkDataset(args.optc_test_root, "test")
        optc_loader, _ = make_loader(optc_test_ds, batch_size=args.batch_size, shuffle=False)
        optc_pre_m = evaluate(model, optc_loader, device, binary_threshold=0.50)
        optc_test_pre_f1 = optc_pre_m["binary_f1"]
        print(f"  Pre-train OpTC Test: Binary F1={optc_test_pre_f1:.4f} | PR-AUC={optc_pre_m['binary_pr_auc']:.4f}")

    # 4. Training Loop
    print("\n[4/5] Starting Local Training Loop...")
    best_score = -1.0
    best_epoch = -1
    best_model_path = output_dir / "best_model.pt"
    train_history = []

    for epoch in range(1, args.epochs + 1):
        t_start = time.time()
        model.train()
        if train_sampler is not None:
            train_sampler.set_epoch(epoch)

        epoch_loss = 0.0
        epoch_bin_loss = 0.0
        epoch_stg_loss = 0.0
        epoch_rep_loss = 0.0
        num_batches = 0

        for batch in train_loader:
            optimizer.zero_grad()

            x_cat = batch["x_cat"].to(device)
            x_num = batch["x_num"].to(device)
            x_num_missing = batch["x_num_missing"].to(device)
            x_bin = batch["x_bin"].to(device)
            delta_t = batch["delta_t_log1p"].to(device)
            lengths = batch["lengths"].to(device)
            bin_targets = batch["labels"].to(device)

            # Sample balanced attack batch across all 4 stages (2 per stage = 8 samples)
            atk_samples = []
            for sid in (1, 2, 3, 4):
                pool = attack_indices_by_stage[sid]
                if pool:
                    for s_idx in random.choices(pool, k=2):
                        atk_samples.append(train_ds[s_idx])
            atk_batch = collate_sequence_batch(atk_samples)
            ax_cat = atk_batch["x_cat"].to(device)
            ax_num = atk_batch["x_num"].to(device)
            ax_num_missing = atk_batch["x_num_missing"].to(device)
            ax_bin = atk_batch["x_bin"].to(device)
            adelta = atk_batch["delta_t_log1p"].to(device)
            alengths = atk_batch["lengths"].to(device)
            atargets_bin = atk_batch["labels"].to(device)
            atargets_stg = (atk_batch["stages"].to(device) - 1).long()

            with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                # 1. Main stream batch (mostly benign background + natural anomalies)
                bin_logits = model(
                    x_cat=x_cat,
                    x_num=x_num,
                    x_num_missing=x_num_missing,
                    x_bin=x_bin,
                    delta_t_log1p=delta_t,
                    lengths=lengths,
                    return_stage_logits=False,
                )
                loss_bin = binary_loss_fn(bin_logits, bin_targets)

                # 2. Balanced Attack Stage Batch (discrimination across all 4 Kill-Chain stages)
                abin_logits, astg_logits = model(
                    x_cat=ax_cat,
                    x_num=ax_num,
                    x_num_missing=ax_num_missing,
                    x_bin=ax_bin,
                    delta_t_log1p=adelta,
                    lengths=alengths,
                    return_stage_logits=True,
                )
                loss_stg = stage_loss_fn(astg_logits, atargets_stg)
                loss_bin_atk = atk_binary_loss_fn(abin_logits, atargets_bin)

                loss = loss_bin + 1.00 * loss_bin_atk + args.stage_weight * loss_stg

                # 3. Experience Replay Batch from OpTC
                loss_rep = torch.tensor(0.0, device=device)
                if replay_ds is not None and args.replay_ratio > 0:
                    n_rep = max(2, int(len(bin_targets) * args.replay_ratio))
                    rep_samples = replay_ds.sample_batch(n_rep, pos_ratio=0.30, max_pos=3)
                    if rep_samples:
                        rep_batch = collate_sequence_batch(rep_samples)
                        rx_cat = rep_batch["x_cat"].to(device)
                        rx_num = rep_batch["x_num"].to(device)
                        rx_num_missing = rep_batch["x_num_missing"].to(device)
                        rx_bin = rep_batch["x_bin"].to(device)
                        rdelta = rep_batch["delta_t_log1p"].to(device)
                        rlengths = rep_batch["lengths"].to(device)
                        rtargets = rep_batch["labels"].to(device)

                        rbin_logits = model(
                            x_cat=rx_cat,
                            x_num=rx_num,
                            x_num_missing=rx_num_missing,
                            x_bin=rx_bin,
                            delta_t_log1p=rdelta,
                            lengths=rlengths,
                            return_stage_logits=False,
                        )
                        loss_rep = replay_loss_fn(rbin_logits, rtargets)
                        loss = loss + args.replay_weight * loss_rep

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            scaler.step(optimizer)
            scaler.update()

            epoch_loss += loss.item()
            epoch_bin_loss += loss_bin.item() + loss_bin_atk.item()
            epoch_stg_loss += loss_stg.item()
            epoch_rep_loss += loss_rep.item()
            num_batches += 1

        scheduler.step()
        elapsed = time.time() - t_start

        avg_loss = epoch_loss / max(1, num_batches)
        avg_bin = epoch_bin_loss / max(1, num_batches)
        avg_stg = epoch_stg_loss / max(1, num_batches)
        avg_rep = epoch_rep_loss / max(1, num_batches)

        # Validate on epoch
        val_m = evaluate(model, val_loader, device, binary_threshold=0.50)
        # Combined score gives priority to attack stage detection while ensuring high binary precision
        combined_val_score = 0.35 * val_m["binary_f1"] + 0.35 * val_m["stage_macro_f1"] + 0.30 * val_m["attack_macro_f1"]

        is_best = combined_val_score > best_score
        marker = " [*BEST*]" if is_best else ""
        if is_best:
            best_score = combined_val_score
            best_epoch = epoch
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_metrics": val_m,
                "combined_val_score": combined_val_score,
            }, best_model_path)

        print(
            f"  Epoch {epoch:02d}/{args.epochs:02d} ({elapsed:4.1f}s) | "
            f"Loss: {avg_loss:.4f} (bin={avg_bin:.3f}, stg={avg_stg:.3f}, rep={avg_rep:.3f}) | "
            f"Val Bin F1: {val_m['binary_f1']:.4f} (Rec={val_m['binary_recall']:.3f}) | "
            f"Val Stg Macro: {val_m['stage_macro_f1']:.4f} | Atk F1: {val_m['attack_macro_f1']:.4f}{marker}"
        )

        train_history.append({
            "epoch": epoch,
            "train_loss": avg_loss,
            "val_binary_f1": val_m["binary_f1"],
            "val_stage_macro_f1": val_m["stage_macro_f1"],
            "val_attack_macro_f1": val_m["attack_macro_f1"],
        })

    print(f"\nTraining completed! Best epoch: {best_epoch} (Combined score: {best_score:.4f})")

    # 5. Final Evaluation on TEST with Best Model
    print("\n[5/5] Final Test Benchmark Evaluation...")
    best_ckpt = torch.load(best_model_path, map_location=device, weights_only=False)
    model.load_state_dict(best_ckpt["model_state_dict"])

    # Threshold optimization on Validation
    print("  Optimizing threshold on Validation Set...")
    opt_thr, opt_val_m = find_optimal_threshold(model, val_loader, device)
    print(f"  Optimal Threshold: {opt_thr:.4f} | Val Bin F1: {opt_val_m['binary_f1']:.4f} | Val Stg Macro: {opt_val_m['stage_macro_f1']:.4f}")

    # Evaluate on TEST with optimal threshold
    print("\n" + "=" * 80)
    print("FINAL TEST EVALUATION RESULTS (ATLASv2 MULTI-STAGE KILL-CHAIN)")
    print("=" * 80)
    test_m = evaluate(model, test_loader, device, binary_threshold=opt_thr)

    print(f"\n--- Binary Detection Performance (Threshold={opt_thr:.4f}) ---")
    print(f"  Binary F1 Score:       {test_m['binary_f1']:.4f} ({test_m['binary_f1']*100:.2f}%)")
    print(f"  Binary Precision:      {test_m['binary_precision']:.4f} ({test_m['binary_precision']*100:.2f}%)")
    print(f"  Binary Recall:         {test_m['binary_recall']:.4f} ({test_m['binary_recall']*100:.2f}%)")
    print(f"  PR-AUC (Average Prec): {test_m['binary_pr_auc']:.4f}")
    print(f"  ROC-AUC:               {test_m['binary_roc_auc']:.4f}")

    print(f"\n--- Multi-Stage Kill-Chain Detection Performance ---")
    print(f"  Stage Macro F1 (all):  {test_m['stage_macro_f1']:.4f} ({test_m['stage_macro_f1']*100:.2f}%)")
    print(f"  Stage Weighted F1:     {test_m['stage_weighted_f1']:.4f} ({test_m['stage_weighted_f1']*100:.2f}%)")
    print(f"  Attack-only Macro F1:  {test_m['attack_macro_f1']:.4f} ({test_m['attack_macro_f1']*100:.2f}%)")

    print("\n--- Per-Stage Breakdown ---")
    print(f"  {'Stage':22s} | {'Support':7s} | {'Precision':10s} | {'Recall':10s} | {'F1-Score':10s}")
    print("  " + "-" * 70)
    for sname, s_met in test_m["per_stage"].items():
        print(
            f"  {sname:22s} | {s_met['support']:7d} | {s_met['precision']:10.4f} | "
            f"{s_met['recall']:10.4f} | {s_met['f1']:10.4f}"
        )

    print_confusion_matrix_ascii(test_m["confusion_matrix"])

    # OpTC Test Set Backward Transfer Evaluation
    bwt_metrics = {}
    if args.optc_test_root and Path(args.optc_test_root).exists() and optc_test_pre_f1 is not None:
        print("\n--- Backward Transfer (BWT) on OpTC Benchmark ---")
        optc_post_m = evaluate(model, optc_loader, device, binary_threshold=opt_thr)
        optc_post_f1 = optc_post_m["binary_f1"]
        bwt_f1 = optc_post_f1 - optc_test_pre_f1
        print(f"  OpTC Test F1 (Pre-train) : {optc_test_pre_f1:.4f}")
        print(f"  OpTC Test F1 (Post-train): {optc_post_f1:.4f}")
        print(f"  Backward Transfer (BWT)  : {bwt_f1:+.4f} ({bwt_f1*100:+.2f}%)")
        bwt_status = "PASS (No catastrophic forgetting)" if bwt_f1 >= -0.05 else "FAIL"
        print(f"  Continual Learning Gate  : {bwt_status}")

        bwt_metrics = {
            "optc_pre_f1": optc_test_pre_f1,
            "optc_post_f1": optc_post_f1,
            "bwt_f1": bwt_f1,
            "bwt_pass": bool(bwt_f1 >= -0.05),
        }

    # Save summary results
    results_payload = {
        "best_epoch": best_epoch,
        "optimal_threshold": opt_thr,
        "val_metrics": opt_val_m,
        "test_metrics": test_m,
        "bwt_metrics": bwt_metrics,
        "train_history": train_history,
    }
    results_path = output_dir / "training_summary.json"
    results_path.write_text(json.dumps(results_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSummary metrics saved to: {results_path}")

    # Save Confusion Matrix CSV
    cm_csv_path = output_dir / "stage_confusion_matrix.csv"
    with cm_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ground_truth", "pred_benign", "pred_init_comp", "pred_exec_disc", "pred_lat_mov", "pred_exfil"])
        for sid, row in enumerate(test_m["confusion_matrix"]):
            writer.writerow([STAGE_NAMES[sid]] + row)
    print(f"Confusion matrix CSV saved to: {cm_csv_path}")

    # Save Confusion Matrix Plot (matrix.png)
    matrix_png_path = output_dir / "matrix.png"
    save_confusion_matrix_plot(test_m["confusion_matrix"], matrix_png_path, threshold=opt_thr)


def main():
    parser = argparse.ArgumentParser(description="Local BiLSTM Training on Staged ATLASv2")
    parser.add_argument("--data-dir", default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/preprocess/output")
    parser.add_argument("--pretrained-ckpt", default="/mnt/SSD_Data/optc/DL/05_models/bilstm_v2_subsetB/best_model.pt")
    parser.add_argument("--replay-buffer", default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/preprocess/output/optc_replay_buffer.npz")
    parser.add_argument("--optc-test-root", default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/preprocess/output/optc_test")
    parser.add_argument(
        "--run",
        type=int,
        default=RUN,
        help=f"Run iteration number (default: {RUN}, maps to {LOCAL_OUTPUT_BASE}/local_run_v<run>)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=f"Optional custom output directory. If omitted, defaults to {LOCAL_OUTPUT_BASE}/local_run_v<run>",
    )
    parser.add_argument("--device", default="cuda", help="Target device (cuda or cpu)")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--lr", type=float, default=6e-4)
    parser.add_argument("--stage-weight", type=float, default=1.5, help="Loss weight multiplier for stage cross entropy")
    parser.add_argument("--replay-weight", type=float, default=0.5, help="Loss weight multiplier for OpTC experience replay")
    parser.add_argument("--replay-ratio", type=float, default=0.20, help="Fraction of batch size from replay buffer")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train(args)


if __name__ == "__main__":
    main()
