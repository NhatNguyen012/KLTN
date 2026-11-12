from __future__ import annotations

import argparse
import csv
import json
import math
import random
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from torch.nn.utils.rnn import pack_padded_sequence
from torch.utils.data import DataLoader

from network_dl_dataset_v1_1 import (
    PackedNetworkDataset,
    ShardAwareBatchSampler,
    collate_sequence_batch,
)

SCRIPT_VERSION = "step05b-bilstm-baseline-v1.0"


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
    return list(spec["active_numerical_features"])


def embedding_dim(cardinality: int) -> int:
    return int(min(16, max(4, round(math.sqrt(cardinality) * 2))))


class BiLSTMBaseline(nn.Module):
    def __init__(
        self,
        *,
        categorical_cardinalities: list[int],
        numerical_dim: int,
        binary_dim: int = 1,
        event_dim: int = 64,
        hidden_dim: int = 64,
        lstm_layers: int = 1,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.embeddings = nn.ModuleList([
            nn.Embedding(cardinality, embedding_dim(cardinality))
            for cardinality in categorical_cardinalities
        ])
        cat_dim = sum(emb.embedding_dim for emb in self.embeddings)
        raw_event_dim = cat_dim + numerical_dim + numerical_dim + binary_dim + 1

        self.event_encoder = nn.Sequential(
            nn.Linear(raw_event_dim, event_dim),
            nn.LayerNorm(event_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.lstm = nn.LSTM(
            input_size=event_dim,
            hidden_size=hidden_dim,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0,
        )
        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_dim * 2),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
        )

    def forward(
        self,
        *,
        x_cat: torch.Tensor,
        x_num: torch.Tensor,
        x_num_missing: torch.Tensor,
        x_bin: torch.Tensor,
        delta_t_log1p: torch.Tensor,
        lengths: torch.Tensor,
    ) -> torch.Tensor:
        cat_parts = [embedding(x_cat[:, :, i]) for i, embedding in enumerate(self.embeddings)]
        event = torch.cat([*cat_parts, x_num, x_num_missing, x_bin, delta_t_log1p], dim=-1)
        event = self.event_encoder(event)
        packed = pack_padded_sequence(event, lengths.cpu(), batch_first=True, enforce_sorted=False)
        _, (h_n, _) = self.lstm(packed)
        pooled = torch.cat([h_n[-2], h_n[-1]], dim=-1)
        return self.classifier(pooled).squeeze(-1)


def make_loader(dataset, *, batch_size: int, shuffle: bool, seed: int, num_workers: int, pin_memory: bool):
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
        persistent_workers=num_workers > 0,
        collate_fn=collate_sequence_batch,
    )
    return loader, sampler


def move_batch(batch: dict[str, Any], device: torch.device) -> dict[str, Any]:
    result = dict(batch)
    for key in ("x_cat", "x_num", "x_num_missing", "x_bin", "delta_t_log1p", "labels", "lengths"):
        result[key] = batch[key].to(device, non_blocking=True)
    return result


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(np.uint8)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    result = {
        "threshold": float(threshold),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn) if (fp + tn) else 0.0),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else None,
    }
    return result


def best_f1_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> tuple[float, dict[str, Any]]:
    precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
    if len(thresholds) == 0:
        return 0.5, binary_metrics(y_true, y_prob, 0.5)
    p, r = precision[:-1], recall[:-1]
    denom = p + r
    f1 = np.divide(2 * p * r, denom, out=np.zeros_like(denom), where=denom > 0)
    index = int(np.nanargmax(f1))
    threshold = float(thresholds[index])
    return threshold, binary_metrics(y_true, y_prob, threshold)


@torch.no_grad()
def predict(model, loader, *, device, amp: bool, max_batches: int | None = None):
    model.eval()
    probs, labels, sample_ids = [], [], []
    for step, raw_batch in enumerate(loader):
        if max_batches is not None and step >= max_batches:
            break
        batch = move_batch(raw_batch, device)
        with torch.autocast(
            device_type=device.type,
            dtype=torch.float16,
            enabled=amp and device.type == "cuda",
        ):
            logits = model(
                x_cat=batch["x_cat"],
                x_num=batch["x_num"],
                x_num_missing=batch["x_num_missing"],
                x_bin=batch["x_bin"],
                delta_t_log1p=batch["delta_t_log1p"],
                lengths=batch["lengths"],
            )
        probs.append(torch.sigmoid(logits).cpu().numpy())
        labels.append(batch["labels"].cpu().numpy())
        sample_ids.extend(raw_batch["sample_ids"])
    return np.concatenate(labels), np.concatenate(probs), sample_ids


def save_predictions(path: Path, *, sample_ids, y_true, y_prob, threshold: float) -> None:
    y_pred = (y_prob >= threshold).astype(np.uint8)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", "label", "probability", "prediction"])
        for sid, y, p, pred in zip(sample_ids, y_true, y_prob, y_pred):
            w.writerow([sid, int(y), float(p), int(pred)])


def save_curves(output_dir: Path, *, y_true, y_prob, prefix: str) -> None:
    import matplotlib.pyplot as plt
    from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay

    fig, ax = plt.subplots()
    PrecisionRecallDisplay.from_predictions(y_true, y_prob, ax=ax)
    ax.set_title(f"{prefix.upper()} Precision-Recall")
    fig.tight_layout()
    fig.savefig(output_dir / f"{prefix}_pr_curve.png", dpi=150)
    plt.close(fig)

    if len(np.unique(y_true)) > 1:
        fig, ax = plt.subplots()
        RocCurveDisplay.from_predictions(y_true, y_prob, ax=ax)
        ax.set_title(f"{prefix.upper()} ROC")
        fig.tight_layout()
        fig.savefig(output_dir / f"{prefix}_roc_curve.png", dpi=150)
        plt.close(fig)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--epochs", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--event-dim", type=int, default=64)
    p.add_argument("--hidden-dim", type=int, default=64)
    p.add_argument("--lstm-layers", type=int, default=1)
    p.add_argument("--dropout", type=float, default=0.2)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--weight-decay", type=float, default=1e-4)
    p.add_argument("--grad-clip", type=float, default=1.0)
    p.add_argument("--patience", type=int, default=3)
    p.add_argument("--num-workers", type=int, default=2)
    p.add_argument("--cache-shards", type=int, default=1)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-amp", action="store_true")
    p.add_argument("--max-train-batches", type=int, default=None, help="Debug only")
    p.add_argument("--max-eval-batches", type=int, default=None, help="Debug only")
    args = p.parse_args()

    dataset_root = Path(args.dataset_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    seed_everything(args.seed)

    manifest = load_json(dataset_root / "dataset_manifest.json")
    train_stats = manifest["split_stats"]["train"]
    train_positive = int(train_stats["positive_samples"])
    train_negative = int(train_stats["negative_samples"])
    if train_positive <= 0:
        raise RuntimeError("TRAIN has no positive samples")
    pos_weight_value = train_negative / train_positive

    cat_fields, cat_cards = categorical_cardinalities(dataset_root)
    num_fields = numeric_fields(dataset_root)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    amp = (not args.no_amp) and device.type == "cuda"

    print("=" * 100)
    print("STEP 05B — BiLSTM baseline")
    print("=" * 100)
    print(f"[DATASET] {dataset_root}")
    print(f"[TRAIN] negative={train_negative:,} | positive={train_positive:,} | pos_weight={pos_weight_value:.6f}")
    print(f"[CAT] {list(zip(cat_fields, cat_cards))}")
    print(f"[NUM] {num_fields}")
    print(f"[DEVICE] {device} | amp={amp}")

    train_ds = PackedNetworkDataset(dataset_root, "train", cache_shards=args.cache_shards)
    val_ds = PackedNetworkDataset(dataset_root, "val", cache_shards=args.cache_shards)
    test_ds = PackedNetworkDataset(dataset_root, "test", cache_shards=args.cache_shards)
    pin = device.type == "cuda"

    train_loader, train_sampler = make_loader(train_ds, batch_size=args.batch_size, shuffle=True, seed=args.seed, num_workers=args.num_workers, pin_memory=pin)
    val_loader, _ = make_loader(val_ds, batch_size=args.batch_size, shuffle=False, seed=args.seed, num_workers=args.num_workers, pin_memory=pin)
    test_loader, _ = make_loader(test_ds, batch_size=args.batch_size, shuffle=False, seed=args.seed, num_workers=args.num_workers, pin_memory=pin)

    model = BiLSTMBaseline(
        categorical_cardinalities=cat_cards,
        numerical_dim=len(num_fields),
        event_dim=args.event_dim,
        hidden_dim=args.hidden_dim,
        lstm_layers=args.lstm_layers,
        dropout=args.dropout,
    ).to(device)
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"[PARAMS] {trainable:,}")

    criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(pos_weight_value, dtype=torch.float32, device=device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scaler = torch.amp.GradScaler("cuda", enabled=amp)

    config = {
        "script_version": SCRIPT_VERSION,
        "dataset_root": str(dataset_root),
        "dataset_preprocess_fingerprint": (manifest["source"].get("step04c_preprocess_fingerprint") or manifest["source"]["step05f_c_preprocess_fingerprint"]),
        "seed": args.seed,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "event_dim": args.event_dim,
        "hidden_dim": args.hidden_dim,
        "lstm_layers": args.lstm_layers,
        "dropout": args.dropout,
        "lr": args.lr,
        "weight_decay": args.weight_decay,
        "grad_clip": args.grad_clip,
        "patience": args.patience,
        "num_workers": args.num_workers,
        "amp": amp,
        "loss": "BCEWithLogitsLoss",
        "train_pos_weight": pos_weight_value,
        "threshold_policy": "maximize F1 on VAL only",
        "early_stopping_metric": "VAL PR-AUC",
        "test_policy": "evaluate once after best epoch + VAL threshold are frozen",
        "categorical_fields": cat_fields,
        "categorical_cardinalities": cat_cards,
        "numerical_fields": num_fields,
        "trainable_parameters": trainable,
    }
    dump_json(output_dir / "config.json", config)

    best_pr_auc = -1.0
    best_epoch = -1
    stale_epochs = 0
    history = []
    best_path = output_dir / "best_model.pt"

    for epoch in range(1, args.epochs + 1):
        train_sampler.set_epoch(epoch)
        model.train()
        running_loss = 0.0
        seen_batches = 0
        started = time.time()

        for step, raw_batch in enumerate(train_loader, start=1):
            if args.max_train_batches is not None and step > args.max_train_batches:
                break
            batch = move_batch(raw_batch, device)
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=amp):
                logits = model(
                    x_cat=batch["x_cat"],
                    x_num=batch["x_num"],
                    x_num_missing=batch["x_num_missing"],
                    x_bin=batch["x_bin"],
                    delta_t_log1p=batch["delta_t_log1p"],
                    lengths=batch["lengths"],
                )
                loss = criterion(logits, batch["labels"])

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.grad_clip)
            scaler.step(optimizer)
            scaler.update()

            running_loss += float(loss.item())
            seen_batches += 1
            if step % 200 == 0:
                print(f"[EPOCH {epoch}] batch={step}/{len(train_loader)} loss={running_loss/seen_batches:.6f}")

        train_loss = running_loss / max(1, seen_batches)
        val_true, val_prob, _ = predict(model, val_loader, device=device, amp=amp, max_batches=args.max_eval_batches)
        val_pr_auc = float(average_precision_score(val_true, val_prob))
        val_threshold, val_metrics = best_f1_threshold(val_true, val_prob)
        elapsed = time.time() - started

        row = {
            "epoch": epoch,
            "train_loss": train_loss,
            "val_pr_auc": val_pr_auc,
            "val_best_f1_threshold": val_threshold,
            "val_precision": val_metrics["precision"],
            "val_recall": val_metrics["recall"],
            "val_f1": val_metrics["f1"],
            "val_fpr": val_metrics["fpr"],
            "elapsed_seconds": elapsed,
        }
        history.append(row)
        print(f"[EPOCH {epoch}] loss={train_loss:.6f} | val_PR_AUC={val_pr_auc:.6f} | val_F1={val_metrics['f1']:.6f} | thr={val_threshold:.6f} | {elapsed/60:.1f} min")

        if val_pr_auc > best_pr_auc + 1e-8:
            best_pr_auc = val_pr_auc
            best_epoch = epoch
            stale_epochs = 0
            torch.save({
                "model_state_dict": model.state_dict(),
                "config": config,
                "best_epoch": best_epoch,
                "best_val_pr_auc": best_pr_auc,
            }, best_path)
            print(f"[CHECKPOINT] epoch={epoch}")
        else:
            stale_epochs += 1

        if stale_epochs >= args.patience:
            print(f"[EARLY STOP] no VAL PR-AUC improvement for {stale_epochs} epochs")
            break

    if not history or not best_path.exists():
        raise RuntimeError("Training did not produce a best checkpoint")

    with (output_dir / "history.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(history[0].keys()))
        w.writeheader()
        w.writerows(history)

    checkpoint = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])

    val_true, val_prob, val_ids = predict(model, val_loader, device=device, amp=amp, max_batches=args.max_eval_batches)
    threshold, val_metrics = best_f1_threshold(val_true, val_prob)
    threshold_payload = {
        "selected_on": "val",
        "policy": "maximize F1",
        "threshold": threshold,
        "best_epoch": best_epoch,
        "best_val_pr_auc": best_pr_auc,
        "val_metrics_at_threshold": val_metrics,
    }
    dump_json(output_dir / "threshold.json", threshold_payload)
    save_predictions(output_dir / "val_predictions.csv", sample_ids=val_ids, y_true=val_true, y_prob=val_prob, threshold=threshold)
    save_curves(output_dir, y_true=val_true, y_prob=val_prob, prefix="val")

    # TEST is touched only after checkpoint and threshold are frozen on VAL.
    test_true, test_prob, test_ids = predict(model, test_loader, device=device, amp=amp, max_batches=args.max_eval_batches)
    test_metrics = binary_metrics(test_true, test_prob, threshold)
    save_predictions(output_dir / "test_predictions.csv", sample_ids=test_ids, y_true=test_true, y_prob=test_prob, threshold=threshold)
    save_curves(output_dir, y_true=test_true, y_prob=test_prob, prefix="test")

    final_metrics = {
        "script_version": SCRIPT_VERSION,
        "best_epoch": best_epoch,
        "best_val_pr_auc": best_pr_auc,
        "threshold_selected_on_val": threshold,
        "val": val_metrics,
        "test": test_metrics,
    }
    dump_json(output_dir / "metrics.json", final_metrics)

    print("\n" + "=" * 100)
    print("[SUCCESS] BiLSTM baseline complete")
    print(f"[BEST EPOCH] {best_epoch}")
    print(f"[VAL]  PR-AUC={val_metrics['pr_auc']:.6f} | F1={val_metrics['f1']:.6f} | Recall={val_metrics['recall']:.6f} | FPR={val_metrics['fpr']:.6f}")
    print(f"[TEST] PR-AUC={test_metrics['pr_auc']:.6f} | F1={test_metrics['f1']:.6f} | Recall={test_metrics['recall']:.6f} | FPR={test_metrics['fpr']:.6f}")
    print(f"[OUTPUT] {output_dir}")
    print("=" * 100)


if __name__ == "__main__":
    main()
