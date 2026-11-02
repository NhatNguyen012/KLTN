#!/usr/bin/env python3
"""Domain-Incremental Learning (Continual Learning) for BiLSTM on ATLASv2.

Implements:
1. Zero-shot Evaluation of OpTC pretrained model on ATLASv2.
2. ATLASv2 Scratch Baseline (random initialization).
3. Continual Learning (IL) from OpTC pretrained model with Experience Replay (80/20 mix).
4. Backward Transfer (BWT) Evaluation on OpTC test benchmark.
5. 3-Panel Confusion Matrix generation (comparison_confusion_matrix.png).
6. Traceback Deep-Dive Analysis for False Negatives & False Positives.
7. Publication of comparison_metrics.csv matching Host ML Run 6 standards.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from contextlib import nullcontext
from pathlib import Path
import random
import sys
import time
from typing import Any

import numpy as np
import torch
import torch.nn as nn


def get_autocast(device: torch.device, enabled: bool):
    if device.type == "cuda":
        return torch.cuda.amp.autocast(enabled=enabled)
    return nullcontext()


def get_scaler(device: torch.device, enabled: bool):
    if device.type == "cuda" and enabled:
        return torch.cuda.amp.GradScaler(enabled=True)

    class _DummyScaler:
        def scale(self, loss):
            return loss

        def step(self, optimizer):
            optimizer.step()

        def update(self):
            pass

        def unscale_(self, optimizer):
            pass

    return _DummyScaler()
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from torch.utils.data import DataLoader

try:
    from .bilstm import BiLSTMBaseline
    from .dataset import (
        PackedNetworkDataset,
        ReplayBufferDataset,
        ShardAwareBatchSampler,
        collate_sequence_batch,
    )
except ImportError:
    from bilstm import BiLSTMBaseline
    from dataset import (
        PackedNetworkDataset,
        ReplayBufferDataset,
        ShardAwareBatchSampler,
        collate_sequence_batch,
    )

SCRIPT_VERSION = "atlasv2-bilstm-incremental-v2.0"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def categorical_cardinalities(dataset_root: Path) -> tuple[list[str], list[int]]:
    spec = load_json(dataset_root / "preprocessing" / "network_preprocess_spec.json")
    maps = load_json(dataset_root / "preprocessing" / "network_category_maps.json")
    fields = list(spec["active_categorical_features"])
    cards = []
    for field in fields:
        mapping = maps["fields"][field]["mapping"]
        cards.append(max(int(v) for v in mapping.values()) + 1)
    return fields, cards


def numeric_fields(dataset_root: Path) -> list[str]:
    spec = load_json(dataset_root / "preprocessing" / "network_preprocess_spec.json")
    return list(spec.get("active_numerical_features", []))


def make_loader(dataset, *, batch_size: int, shuffle: bool, seed: int, num_workers: int = 0, pin_memory: bool = False):
    sampler = ShardAwareBatchSampler(
        dataset,
        batch_size,
        shuffle=shuffle,
        seed=seed,
        drop_last=False,
    )
    loader = DataLoader(
        dataset,
        batch_sampler=sampler,
        num_workers=num_workers,
        pin_memory=pin_memory,
        collate_fn=collate_sequence_batch,
    )
    return loader, sampler


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict[str, Any]:
    y_true = np.asarray(y_true, dtype=np.int32)
    y_prob = np.asarray(y_prob, dtype=np.float64)
    y_pred = (y_prob >= float(threshold)).astype(np.int32)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    denom_fpr = fp + tn
    fpr = float(fp / denom_fpr) if denom_fpr > 0 else 0.0

    try:
        pr_auc = float(average_precision_score(y_true, y_prob))
    except Exception:
        pr_auc = float("nan")

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        roc_auc = float("nan")

    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))

    return {
        "threshold": float(threshold),
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
    }


def find_best_f1_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> tuple[float, dict[str, Any]]:
    y_true = np.asarray(y_true, dtype=np.int32)
    y_prob = np.asarray(y_prob, dtype=np.float64)

    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    best_f1 = -1.0
    best_thr = 0.5
    best_metrics = binary_metrics(y_true, y_prob, best_thr)

    for p, r, t in zip(precisions, recalls, thresholds):
        denom = p + r
        f1 = (2.0 * p * r / denom) if denom > 0 else 0.0
        if f1 > best_f1:
            best_f1 = f1
            best_thr = float(t)
            best_metrics = binary_metrics(y_true, y_prob, best_thr)

    # Secondary grid search between 0.01 and 0.99
    grid = np.linspace(0.01, 0.99, 99)
    for t in grid:
        m = binary_metrics(y_true, y_prob, float(t))
        if m["f1"] > best_f1 or (abs(m["f1"] - best_f1) < 1e-6 and m["fpr"] < best_metrics["fpr"]):
            best_f1 = m["f1"]
            best_thr = float(t)
            best_metrics = m

    return best_thr, best_metrics


def load_pretrained_checkpoint(model: nn.Module, ckpt_path: str | Path, device: torch.device) -> None:
    """Load pretrained model weights, adapting embedding layers when vocabulary is expanded."""
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    state_dict = ckpt.get("model_state_dict", ckpt)
    model_state = model.state_dict()

    for key, val in state_dict.items():
        if key not in model_state:
            continue
        if model_state[key].shape == val.shape:
            model_state[key] = val
        elif "embeddings" in key and model_state[key].dim() == 2 and val.dim() == 2:
            # Vocabulary expansion handling: copy old embeddings, initialize new rows with <UNK> vector (row 0)
            n_old = min(val.shape[0], model_state[key].shape[0])
            d = min(val.shape[1], model_state[key].shape[1])
            model_state[key][:n_old, :d] = val[:n_old, :d]
            if model_state[key].shape[0] > n_old:
                unk_vec = val[0:1, :d]  # row 0 is <UNK>
                model_state[key][n_old:, :d] = unk_vec
                print(f"  [Vocab Expansion] {key}: transferred {n_old} rows from OpTC, initialized {model_state[key].shape[0] - n_old} new rows with <UNK> embedding.")
        else:
            print(f"  [Warning] Skipping key {key} due to shape mismatch: ckpt {val.shape} vs model {model_state[key].shape}")

    model.load_state_dict(model_state)
    print(f"Loaded pretrained weights from {ckpt_path}")


def predict(model: nn.Module, loader: DataLoader, device: torch.device, amp: bool = False) -> tuple[np.ndarray, np.ndarray, list[str]]:
    model.eval()
    all_prob = []
    all_true = []
    all_ids = []

    with torch.no_grad():
        for batch in loader:
            x_cat = batch["x_cat"].to(device)
            x_num = batch["x_num"].to(device)
            x_num_missing = batch["x_num_missing"].to(device)
            x_bin = batch["x_bin"].to(device)
            delta = batch["delta_t_log1p"].to(device)
            mask = batch["attention_mask"].to(device)
            lengths = batch["lengths"].to(device)

            with get_autocast(device, amp):
                logits = model(
                    x_cat=x_cat,
                    x_num=x_num,
                    x_num_missing=x_num_missing,
                    x_bin=x_bin,
                    delta_t_log1p=delta,
                    lengths=lengths,
                )
                probs = torch.sigmoid(logits)

            all_prob.extend(probs.detach().cpu().numpy().tolist())
            all_true.extend(batch["labels"].numpy().tolist())
            all_ids.extend(batch["sample_ids"])

    return np.asarray(all_true, dtype=np.int32), np.asarray(all_prob, dtype=np.float64), all_ids


def train_single_model(
    model: nn.Module,
    train_ds: PackedNetworkDataset,
    val_loader: DataLoader,
    test_loader: DataLoader,
    *,
    device: torch.device,
    output_dir: Path,
    epochs: int = 10,
    batch_size: int = 32,
    lr: float = 2e-4,
    weight_decay: float = 1e-4,
    grad_clip: float = 1.0,
    patience: int = 3,
    amp: bool = False,
    seed: int = 42,
    replay_ds: ReplayBufferDataset | None = None,
    replay_ratio: float = 0.20,
    model_tag: str = "model",
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    best_path = output_dir / f"{model_tag}_best.pt"

    # Compute loss weighting
    train_labels = [row["label"] for row in train_ds.rows]
    train_pos = sum(train_labels)
    train_neg = len(train_labels) - train_pos
    pos_weight = torch.tensor([float(train_neg / max(1, train_pos))], device=device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scaler = get_scaler(device, amp)

    best_val_pr_auc = -1.0
    best_epoch = 0
    stale_epochs = 0
    history = []

    print(f"\n--- Training {model_tag.upper()} ({epochs} epochs, lr={lr}, ER replay={replay_ds is not None}) ---")

    for epoch in range(1, epochs + 1):
        t_start = time.time()
        model.train()
        train_loader, sampler = make_loader(train_ds, batch_size=batch_size, shuffle=True, seed=seed + epoch)
        sampler.set_epoch(epoch)

        running_loss = 0.0
        seen_batches = 0

        for raw_batch_items in sampler:
            batch_items = [train_ds[i] for i in raw_batch_items]

            # Interleave Experience Replay buffer samples if available
            if replay_ds is not None and len(replay_ds) > 0 and replay_ratio > 0:
                n_replay = max(1, int(len(batch_items) * replay_ratio))
                if hasattr(replay_ds, "sample_batch"):
                    batch_items.extend(replay_ds.sample_batch(n_replay, pos_ratio=0.5))
                else:
                    replay_indices = np.random.choice(len(replay_ds), size=n_replay, replace=False)
                    for repl_idx in replay_indices:
                        batch_items.append(replay_ds[repl_idx])

            batch = collate_sequence_batch(batch_items)

            x_cat = batch["x_cat"].to(device)
            x_num = batch["x_num"].to(device)
            x_num_missing = batch["x_num_missing"].to(device)
            x_bin = batch["x_bin"].to(device)
            delta = batch["delta_t_log1p"].to(device)
            mask = batch["attention_mask"].to(device)
            lengths = batch["lengths"].to(device)
            targets = batch["labels"].to(device)

            optimizer.zero_grad(set_to_none=True)
            with get_autocast(device, amp):
                logits = model(
                    x_cat=x_cat,
                    x_num=x_num,
                    x_num_missing=x_num_missing,
                    x_bin=x_bin,
                    delta_t_log1p=delta,
                    lengths=lengths,
                )
                loss = criterion(logits, targets)

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip)
            scaler.step(optimizer)
            scaler.update()

            running_loss += float(loss.item())
            seen_batches += 1

        train_loss = running_loss / max(1, seen_batches)
        val_true, val_prob, _ = predict(model, val_loader, device=device, amp=amp)
        val_pr_auc = float(average_precision_score(val_true, val_prob))
        val_thr, val_metrics = find_best_f1_threshold(val_true, val_prob)
        elapsed = time.time() - t_start

        row = {
            "epoch": epoch,
            "train_loss": train_loss,
            "val_pr_auc": val_pr_auc,
            "val_f1": val_metrics["f1"],
            "val_recall": val_metrics["recall"],
            "val_precision": val_metrics["precision"],
            "val_fpr": val_metrics["fpr"],
            "val_threshold": val_thr,
            "elapsed_seconds": elapsed,
        }
        history.append(row)
        print(f"  [{model_tag} Ep {epoch:2d}/{epochs:2d}] Loss: {train_loss:.4f} | Val PR-AUC: {val_pr_auc:.4f} | Val F1: {val_metrics['f1']:.4f} | Thr: {val_thr:.4f} ({elapsed:.1f}s)")

        if val_pr_auc > best_val_pr_auc + 1e-6:
            best_val_pr_auc = val_pr_auc
            best_epoch = epoch
            stale_epochs = 0
            torch.save({
                "model_state_dict": model.state_dict(),
                "best_epoch": best_epoch,
                "best_val_pr_auc": best_val_pr_auc,
            }, best_path)
        else:
            stale_epochs += 1

        if stale_epochs >= patience:
            print(f"  [{model_tag} Early Stopping] No improvement in Val PR-AUC for {stale_epochs} epochs.")
            break

    # Load best checkpoint
    best_ckpt = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(best_ckpt["model_state_dict"])

    # Optimize threshold on VAL
    val_true, val_prob, val_ids = predict(model, val_loader, device=device, amp=amp)
    final_thr, final_val_m = find_best_f1_threshold(val_true, val_prob)

    # Evaluate on TEST (frozen threshold)
    test_true, test_prob, test_ids = predict(model, test_loader, device=device, amp=amp)
    final_test_m = binary_metrics(test_true, test_prob, final_thr)

    # Save predictions
    pred_csv = output_dir / f"{model_tag}_test_predictions.csv"
    with open(pred_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sample_id", "label", "probability", "prediction"])
        for sid, yt, yp in zip(test_ids, test_true, test_prob):
            writer.writerow([sid, yt, float(yp), int(yp >= final_thr)])

    return {
        "best_epoch": best_epoch,
        "best_val_pr_auc": best_val_pr_auc,
        "threshold": final_thr,
        "val": final_val_m,
        "test": final_test_m,
        "test_true": test_true,
        "test_prob": test_prob,
        "test_ids": test_ids,
        "model": model,
    }


def plot_3panel_confusion_matrix(
    zs_metrics: dict[str, Any],
    scratch_metrics: dict[str, Any],
    il_metrics: dict[str, Any],
    output_path: Path,
) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        panels = [
            ("OpTC Base Model (Zero-Shot)", zs_metrics),
            ("ATLASv2 Scratch (Baseline)", scratch_metrics),
            ("OpTC -> ATLASv2 Continual (IL + ER)", il_metrics),
        ]

        for ax, (title, m) in zip(axes, panels):
            cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
            cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.7)
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=14, fontweight="bold")
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(["Pred Neg (0)", "Pred Pos (1)"], fontsize=11)
            ax.set_yticklabels(["True Neg (0)", "True Pos (1)"], fontsize=11)
            ax.set_title(f"{title}\nF1: {m['f1']:.4f} | Prec: {m['precision']:.4f} | Rec: {m['recall']:.4f}", fontsize=12, pad=15)

        fig.tight_layout()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
        plt.close(fig)
        print(f"Saved 3-panel confusion matrix: {output_path}")
    except Exception as e:
        print(f"Warning: could not generate confusion matrix plot ({e})")


def run_traceback_analysis(
    test_ds: PackedNetworkDataset,
    test_ids: list[str],
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
    output_path: Path,
) -> list[dict[str, Any]]:
    manifest_map = {row["sample_id"]: row for row in test_ds.rows}
    trace_rows = []

    for sid, yt, yp in zip(test_ids, y_true, y_prob):
        pred = int(yp >= threshold)
        if pred != yt:
            m_row = manifest_map.get(sid, {})
            err_type = "FN" if yt == 1 else "FP"
            trace_rows.append({
                "sample_id": sid,
                "error_type": err_type,
                "label": int(yt),
                "probability": float(yp),
                "threshold": float(threshold),
                "event_count": int(m_row.get("event_count", 0)),
                "shard_file": m_row.get("shard_file", ""),
                "hostname": m_row.get("hostname", "unknown"),
                "window_start_utc": m_row.get("window_start_utc", "unknown"),
            })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["sample_id", "error_type", "label", "probability", "threshold", "event_count", "shard_file", "hostname", "window_start_utc"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(trace_rows)

    print(f"Saved Traceback Analysis: {output_path} ({len(trace_rows)} error samples found: {sum(1 for r in trace_rows if r['error_type'] == 'FN')} FN, {sum(1 for r in trace_rows if r['error_type'] == 'FP')} FP)")
    return trace_rows


def main():
    p = argparse.ArgumentParser(description="BiLSTM Incremental Learning & Benchmark on ATLASv2")
    p.add_argument("--dataset-root", required=True, help="Path to preprocessed dataset root")
    p.add_argument("--output-dir", required=True, help="Directory to save model checkpoints and logs")
    p.add_argument("--init-model", default=None, help="Path to OpTC pretrained checkpoint (best_model.pt)")
    p.add_argument("--replay-buffer", default=None, help="Path to OpTC Experience Replay buffer (optc_replay_buffer.npz)")
    p.add_argument("--replay-ratio", type=float, default=0.20, help="Fraction of replay samples per mini-batch (default 0.20)")
    p.add_argument("--optc-test-root", default=None, help="Path to optc_test/ directory for Backward Transfer evaluation")
    p.add_argument("--run-benchmark", action="store_true", help="Run full 4-experiment benchmark suite (Scratch, Zero-shot, IL, BWT)")
    p.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    p.add_argument("--batch-size", type=int, default=32, help="Mini-batch size")
    p.add_argument("--lr", type=float, default=2e-4, help="Learning rate for incremental fine-tuning")
    p.add_argument("--weight-decay", type=float, default=1e-4)
    p.add_argument("--grad-clip", type=float, default=1.0)
    p.add_argument("--patience", type=int, default=3, help="Early stopping patience")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-amp", action="store_true")
    args = p.parse_args()

    dataset_root = Path(args.dataset_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results_dir = output_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    seed_everything(args.seed)

    cat_fields, cat_cards = categorical_cardinalities(dataset_root)
    num_fields = numeric_fields(dataset_root)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    amp = (not args.no_amp) and device.type == "cuda"

    print("=" * 80)
    print("BILSTM CONTINUAL LEARNING BENCHMARK ON ATLASv2")
    print("=" * 80)
    print(f"Dataset Root:      {dataset_root}")
    print(f"Output Dir:        {output_dir}")
    print(f"Device:            {device} (AMP: {amp})")
    print(f"Replay Buffer:     {args.replay_buffer} (ratio: {args.replay_ratio})")
    print(f"OpTC Test Set:     {args.optc_test_root}")

    train_ds = PackedNetworkDataset(dataset_root, "train")
    val_ds = PackedNetworkDataset(dataset_root, "val")
    test_ds = PackedNetworkDataset(dataset_root, "test")

    val_loader, _ = make_loader(val_ds, batch_size=args.batch_size, shuffle=False, seed=args.seed)
    test_loader, _ = make_loader(test_ds, batch_size=args.batch_size, shuffle=False, seed=args.seed)

    replay_ds = None
    if args.replay_buffer and Path(args.replay_buffer).exists():
        replay_ds = ReplayBufferDataset(args.replay_buffer)
        print(f"Loaded Experience Replay Buffer: {len(replay_ds)} samples")

    # Helper function to create fresh BiLSTM model instance
    def create_model():
        return BiLSTMBaseline(
            categorical_cardinalities=cat_cards,
            numerical_dim=len(num_fields),
            event_dim=64,
            hidden_dim=64,
            lstm_layers=1,
            dropout=0.2,
        ).to(device)

    # -------------------------------------------------------------
    # 1. Zero-shot Evaluation of OpTC Pretrained Model on ATLASv2
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print("EXPERIMENT 1: OpTC Pretrained Model (Zero-Shot on ATLASv2)")
    print("=" * 60)
    zs_model = create_model()
    if args.init_model and Path(args.init_model).exists():
        load_pretrained_checkpoint(zs_model, args.init_model, device)

    zs_val_true, zs_val_prob, _ = predict(zs_model, val_loader, device=device, amp=amp)
    zs_test_true, zs_test_prob, zs_test_ids = predict(zs_model, test_loader, device=device, amp=amp)
    optc_frozen_thr = 0.9956
    zs_val_m = binary_metrics(zs_val_true, zs_val_prob, optc_frozen_thr)
    zs_test_m = binary_metrics(zs_test_true, zs_test_prob, optc_frozen_thr)
    print(f"  Zero-Shot Test: F1={zs_test_m['f1']:.4f} | Prec={zs_test_m['precision']:.4f} | Rec={zs_test_m['recall']:.4f} | TP={zs_test_m['tp']}, FP={zs_test_m['fp']}, FN={zs_test_m['fn']}")

    # -------------------------------------------------------------
    # 2. ATLASv2 Scratch Baseline (Random Initialization)
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print("EXPERIMENT 2: ATLASv2 Scratch Baseline (From Scratch)")
    print("=" * 60)
    scratch_model = create_model()
    scratch_res = train_single_model(
        scratch_model,
        train_ds,
        val_loader,
        test_loader,
        device=device,
        output_dir=results_dir / "scratch",
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr * 2,  # scratch typically trains with higher lr
        patience=args.patience,
        amp=amp,
        seed=args.seed,
        replay_ds=None,  # No replay for scratch baseline
        model_tag="scratch",
    )
    scratch_test_m = scratch_res["test"]
    scratch_val_m = scratch_res["val"]
    print(f"  Scratch Baseline Test: F1={scratch_test_m['f1']:.4f} | Prec={scratch_test_m['precision']:.4f} | Rec={scratch_test_m['recall']:.4f} | TP={scratch_test_m['tp']}, FP={scratch_test_m['fp']}, FN={scratch_test_m['fn']}")

    # -------------------------------------------------------------
    # 3. OpTC -> ATLASv2 Continual Learning (IL with Replay Buffer)
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print("EXPERIMENT 3: OpTC -> ATLASv2 Continual Learning (Domain-IL with ER)")
    print("=" * 60)
    il_model = create_model()
    if args.init_model and Path(args.init_model).exists():
        load_pretrained_checkpoint(il_model, args.init_model, device)

    il_res = train_single_model(
        il_model,
        train_ds,
        val_loader,
        test_loader,
        device=device,
        output_dir=results_dir / "incremental",
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        patience=args.patience,
        amp=amp,
        seed=args.seed,
        replay_ds=replay_ds,
        replay_ratio=args.replay_ratio,
        model_tag="incremental",
    )
    il_test_m = il_res["test"]
    il_val_m = il_res["val"]
    print(f"  Continual IL Test: F1={il_test_m['f1']:.4f} | Prec={il_test_m['precision']:.4f} | Rec={il_test_m['recall']:.4f} | TP={il_test_m['tp']}, FP={il_test_m['fp']}, FN={il_test_m['fn']}")

    # -------------------------------------------------------------
    # 4. Backward Transfer (BWT) Evaluation on OpTC Test Set
    # -------------------------------------------------------------
    bwt_metrics = {}
    if args.optc_test_root and Path(args.optc_test_root).exists():
        print("\n" + "=" * 60)
        print("EXPERIMENT 4: Backward Transfer (BWT) Evaluation on OpTC Test")
        print("=" * 60)
        optc_test_ds = PackedNetworkDataset(args.optc_test_root, "test")
        optc_loader, _ = make_loader(optc_test_ds, batch_size=args.batch_size, shuffle=False, seed=args.seed)

        # Before IL (Base OpTC model)
        b_true, b_prob, _ = predict(zs_model, optc_loader, device=device, amp=amp)
        before_m = binary_metrics(b_true, b_prob, optc_frozen_thr)

        # After IL (Continual Learning model)
        a_true, a_prob, _ = predict(il_model, optc_loader, device=device, amp=amp)
        after_m = binary_metrics(a_true, a_prob, optc_frozen_thr)

        bwt_f1 = after_m["f1"] - before_m["f1"]
        bwt_ap = after_m["pr_auc"] - before_m["pr_auc"]

        bwt_metrics = {
            "optc_before_il": before_m,
            "optc_after_il": after_m,
            "bwt_f1": bwt_f1,
            "bwt_ap": bwt_ap,
        }
        dump_json(results_dir / "bwt_metrics.json", bwt_metrics)

        print(f"  OpTC Test Before IL : F1={before_m['f1']:.4f} | Prec={before_m['precision']:.4f} | Rec={before_m['recall']:.4f} | TP={before_m['tp']}, FP={before_m['fp']}")
        print(f"  OpTC Test After IL  : F1={after_m['f1']:.4f} | Prec={after_m['precision']:.4f} | Rec={after_m['recall']:.4f} | TP={after_m['tp']}, FP={after_m['fp']}")
        print(f"  Backward Transfer (BWT F1): {bwt_f1:+.4f} ({bwt_f1*100:+.2f}%)")

    # -------------------------------------------------------------
    # 5. Build comparison_metrics.csv (Matching Host ML Run 6 Standards)
    # -------------------------------------------------------------
    comp_rows = [
        {
            "Model Experiment": "ATLASv2 Scratch (Baseline)",
            "Val AP": round(scratch_val_m["pr_auc"], 4),
            "Val F1": round(scratch_val_m["f1"], 4),
            "Threshold": round(scratch_res["threshold"], 4),
            "Test AP": round(scratch_test_m["pr_auc"], 4),
            "Test ROC-AUC": round(scratch_test_m["roc_auc"], 4),
            "Test F1": round(scratch_test_m["f1"], 4),
            "Test Precision": round(scratch_test_m["precision"], 4),
            "Test Recall": round(scratch_test_m["recall"], 4),
            "Test FPR": f"{scratch_test_m['fpr']*100:.4f}%",
            "TP": scratch_test_m["tp"],
            "FP": scratch_test_m["fp"],
            "FN": scratch_test_m["fn"],
            "TN": scratch_test_m["tn"],
        },
        {
            "Model Experiment": "OpTC -> ATLASv2 Continual Learning (IL)",
            "Val AP": round(il_val_m["pr_auc"], 4),
            "Val F1": round(il_val_m["f1"], 4),
            "Threshold": round(il_res["threshold"], 4),
            "Test AP": round(il_test_m["pr_auc"], 4),
            "Test ROC-AUC": round(il_test_m["roc_auc"], 4),
            "Test F1": round(il_test_m["f1"], 4),
            "Test Precision": round(il_test_m["precision"], 4),
            "Test Recall": round(il_test_m["recall"], 4),
            "Test FPR": f"{il_test_m['fpr']*100:.4f}%",
            "TP": il_test_m["tp"],
            "FP": il_test_m["fp"],
            "FN": il_test_m["fn"],
            "TN": il_test_m["tn"],
        },
        {
            "Model Experiment": "OpTC Base Model (Zero-shot / Trước IL)",
            "Val AP": round(zs_val_m["pr_auc"], 4),
            "Val F1": round(zs_val_m["f1"], 4),
            "Threshold": round(optc_frozen_thr, 4),
            "Test AP": round(zs_test_m["pr_auc"], 4),
            "Test ROC-AUC": round(zs_test_m["roc_auc"], 4),
            "Test F1": round(zs_test_m["f1"], 4),
            "Test Precision": round(zs_test_m["precision"], 4),
            "Test Recall": round(zs_test_m["recall"], 4),
            "Test FPR": f"{zs_test_m['fpr']*100:.4f}%",
            "TP": zs_test_m["tp"],
            "FP": zs_test_m["fp"],
            "FN": zs_test_m["fn"],
            "TN": zs_test_m["tn"],
        },
    ]

    comp_csv = results_dir / "comparison_metrics.csv"
    with open(comp_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["Model Experiment", "Val AP", "Val F1", "Threshold", "Test AP", "Test ROC-AUC", "Test F1", "Test Precision", "Test Recall", "Test FPR", "TP", "FP", "FN", "TN"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(comp_rows)
    print(f"\nSaved comparison metrics: {comp_csv}")

    # -------------------------------------------------------------
    # 6. Generate 3-Panel Confusion Matrix
    # -------------------------------------------------------------
    plot_3panel_confusion_matrix(
        zs_test_m,
        scratch_test_m,
        il_test_m,
        results_dir / "comparison_confusion_matrix.png",
    )

    # -------------------------------------------------------------
    # 7. Traceback Analysis for False Negatives & False Positives
    # -------------------------------------------------------------
    run_traceback_analysis(
        test_ds,
        il_res["test_ids"],
        il_res["test_true"],
        il_res["test_prob"],
        il_res["threshold"],
        results_dir / "traceback_fn_fp.csv",
    )

    print("\n" + "=" * 80)
    print("ALL BENCHMARK RUNS, TRACEBACK, AND VISUALIZATIONS COMPLETE!")
    print("=" * 80)


if __name__ == "__main__":
    main()
