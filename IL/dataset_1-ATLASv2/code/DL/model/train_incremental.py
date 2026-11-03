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
import torch.nn.functional as F


def get_autocast(device: torch.device, enabled: bool):
    if device.type == "cuda":
        if hasattr(torch, "amp") and hasattr(torch.amp, "autocast"):
            return torch.amp.autocast(device_type="cuda", enabled=enabled)
        return torch.cuda.amp.autocast(enabled=enabled)
    return nullcontext()


def get_scaler(device: torch.device, enabled: bool):
    if device.type == "cuda" and enabled:
        if hasattr(torch, "amp") and hasattr(torch.amp, "GradScaler"):
            return torch.amp.GradScaler(device="cuda", enabled=True)
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

SCRIPT_VERSION = "atlasv2-bilstm-incremental-v9.0"


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


def make_smoothed_class_weights(y: np.ndarray, device: torch.device, pos_multiplier: float = 2.0) -> torch.Tensor:
    """Calculate square-root smoothed class weights (Task 3.md Section 1).

    Prevents over-magnification of positive loss when combined with controlled sampling
    (sample_batch) and Experience Replay.
    For 1470 neg / 49 pos: sqrt(30) * 2.0 ≈ 10.95 -> clamped into [2.5, 6.0].
    """
    n_neg = float(np.sum(y == 0))
    n_pos = max(float(np.sum(y == 1)), 1.0)
    raw_ratio = np.sqrt(n_neg / n_pos)
    w0 = 1.0
    w1 = min(max(raw_ratio * pos_multiplier, 2.5), 6.0)
    return torch.tensor([w0, w1], dtype=torch.float32, device=device)


class BinaryFocalLossWithWeights(nn.Module):
    """Focal Loss with exterior class weights for binary classification (Task 3.md Section 1).

    Computes unweighted BCE to preserve exact pt probability, modulates by (1 - pt)^gamma,
    and applies smoothed alpha_t externally to avoid MORPH-IDS double-weighting and pt distortion.
    """

    def __init__(self, alpha: torch.Tensor | None = None, gamma: float = 2.0):
        super().__init__()
        self.alpha = alpha  # Tensor [w0, w1] from make_smoothed_class_weights
        self.gamma = float(gamma)

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        targets = targets.float().view_as(logits)
        # 1. Compute unweighted BCE to preserve exact probability pt
        bce_raw = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")
        pt = torch.exp(-bce_raw)  # pt = p when y=1, and (1 - p) when y=0

        # 2. Modulate with focal factor (1 - pt)^gamma
        focal_term = (1.0 - pt) ** self.gamma

        # 3. Apply class weights alpha_t externally
        if self.alpha is not None:
            alpha_t = targets * self.alpha[1] + (1.0 - targets) * self.alpha[0]
            loss = alpha_t * focal_term * bce_raw
        else:
            loss = focal_term * bce_raw

        return loss.mean()


class AsymmetricFocalLoss(nn.Module):
    """Asymmetric Focal Loss (ASL) for hard-negative suppression and extreme class imbalance."""

    def __init__(self, gamma_neg: float = 4.0, gamma_pos: float = 1.0, clip: float = 0.05, eps: float = 1e-8):
        super().__init__()
        self.gamma_neg = float(gamma_neg)
        self.gamma_pos = float(gamma_pos)
        self.clip = float(clip)
        self.eps = float(eps)

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        probs = torch.sigmoid(logits)
        probs_neg = probs
        if self.clip > 0:
            probs_neg = (probs_neg - self.clip).clamp(min=0.0)
        loss_neg = (1.0 - targets) * torch.pow(probs_neg, self.gamma_neg) * torch.log((1.0 - probs).clamp(min=self.eps))
        loss_pos = targets * torch.pow(1.0 - probs, self.gamma_pos) * torch.log(probs.clamp(min=self.eps))
        return -(loss_pos + loss_neg).mean()


class SupConWithHardNegativeRepulsion(nn.Module):
    """Contrastive Loss with Positive Cohesion & Hard-Negative Cosine Repulsion (Run 12)."""

    def __init__(
        self,
        feature_dim: int = 128,
        temperature: float = 0.1,
        margin: float = 0.15,
        scale: float = 0.15,
    ):
        super().__init__()
        self.temperature = float(temperature)
        self.margin = float(margin)
        self.scale = float(scale)

    def forward(self, features: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        device = features.device
        batch_size = features.shape[0]
        if batch_size <= 1:
            return torch.tensor(0.0, device=device)

        features_norm = F.normalize(features, p=2, dim=1)
        cos_sim = torch.matmul(features_norm, features_norm.T)
        targets_flat = targets.view(-1)
        is_pos = (targets_flat == 1).view(-1, 1)
        is_neg = (targets_flat == 0).view(1, -1)

        # 1. Positive cohesion (loss_pos): kéo các mẫu dương lại gần nhau
        pos_pos_mask = (is_pos & (targets_flat == 1).view(1, -1)).clone()
        pos_pos_mask.fill_diagonal_(False)
        if pos_pos_mask.any():
            loss_pos = (1.0 - cos_sim[pos_pos_mask]).clamp(min=0.0).mean()
        else:
            loss_pos = torch.tensor(0.0, device=device)

        # 2. Hard negative repulsion (loss_neg): đẩy các mẫu âm khó ra xa mẫu dương
        pos_neg_mask = (is_pos & is_neg)
        if pos_neg_mask.any():
            pos_neg_sim = cos_sim[pos_neg_mask]
            loss_neg = F.relu(pos_neg_sim - self.margin).pow(2).mean()
        else:
            loss_neg = torch.tensor(0.0, device=device)

        return self.scale * (loss_pos + loss_neg)


SupervisedContrastiveLoss = SupConWithHardNegativeRepulsion  # Alias for backward compatibility


def find_optimal_threshold(
    y_val_true: np.ndarray,
    y_val_probs: np.ndarray,
    *,
    t_min: float = 0.20,
    t_max: float = 0.50,
    beta: float = 1.0,
    soft_max_fpr: float = 0.08,
    num_points: int = 71,
) -> tuple[float, dict[str, Any]]:
    """Controlled threshold sweep in [t_min, t_max] with balanced F_beta (default beta=1.0) and soft FPR penalty.

    - Clamps lower bound at t_min = 0.20 to eliminate background noise causing false alarms.
    - Default beta = 1.0 seeks the true harmonic mean between Precision and Recall.
    - Soft exponential penalty if validation FPR exceeds soft_max_fpr (8%).
    - Moving average smoothing (kernel=3) for plateau threshold stability.
    """
    y_val_true = np.asarray(y_val_true, dtype=np.int32)
    y_val_probs = np.asarray(y_val_probs, dtype=np.float64)

    thresholds = np.linspace(t_min, t_max, num_points)
    scores = []
    n_neg = max(int(np.sum(y_val_true == 0)), 1)

    for t in thresholds:
        preds = (y_val_probs >= t).astype(np.int32)
        tp = int(np.sum((preds == 1) & (y_val_true == 1)))
        fp = int(np.sum((preds == 1) & (y_val_true == 0)))
        fn = int(np.sum((preds == 0) & (y_val_true == 1)))

        if tp == 0:
            scores.append(0.0)
            continue

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        denom = (beta**2 * prec) + rec + 1e-8
        f_beta = ((1.0 + beta**2) * (prec * rec)) / denom

        fpr = fp / n_neg
        if fpr > soft_max_fpr:
            f_beta *= float(np.exp(-5.0 * (fpr - soft_max_fpr)))

        scores.append(float(f_beta))

    scores = np.array(scores, dtype=np.float64)

    if np.max(scores) <= 0.0:
        best_t = float((t_min + t_max) / 2.0)
        return best_t, binary_metrics(y_val_true, y_val_probs, best_t)

    smoothed_scores = np.convolve(scores, np.ones(3) / 3.0, mode="same")
    best_idx = int(np.argmax(smoothed_scores))
    best_t = float(thresholds[best_idx])
    return best_t, binary_metrics(y_val_true, y_val_probs, best_t)


def find_optimal_threshold_run6(y_val_true, y_val_probs, **kwargs):
    """Alias pointing to find_optimal_threshold."""
    return find_optimal_threshold(y_val_true, y_val_probs, **kwargs)


def find_best_f1_threshold(y_true, y_prob, **kwargs):
    """Legacy alias routing to controlled threshold search for backward compatibility."""
    return find_optimal_threshold(y_true, y_prob, t_min=0.20, t_max=0.50)


def augment_dormant_positives(batch_items: list[dict[str, Any]], p_aug: float = 0.5) -> list[dict[str, Any]]:
    """DEEPDIST Entity Perturbation (Run 9 / Task 6.md Giải pháp 3):
    Tạo các mẫu tấn công pha loãng / đuôi kịch bản (dormant tail) bằng cách trích xuất phân đoạn thưa
    từ mẫu Positive kết hợp với giao tiếp nền Benign.
    """
    pos_items = [x for x in batch_items if x["label"] == 1 and str(x.get("sample_id", "")).startswith("win-")]
    neg_items = [x for x in batch_items if x["label"] == 0 and str(x.get("sample_id", "")).startswith("win-")]
    if not pos_items or not neg_items:
        return batch_items

    augmented = list(batch_items)
    for pos in pos_items:
        if random.random() > p_aug or pos["event_count"] < 6:
            continue
        neg = random.choice(neg_items)
        # Lấy 40% sự kiện cuối của mẫu Positive (mô phỏng đuôi kịch bản m6)
        cut_p = max(2, int(pos["event_count"] * 0.4))
        # Ghép với tối đa 30% sự kiện nền của mẫu Benign (DEEPDIST benign interaction injection)
        cut_n = min(40, max(2, int(neg["event_count"] * 0.3)))

        aug_item = {
            "sample_id": f"{pos['sample_id']}_pert",
            "label": 1,
            "event_count": cut_n + cut_p,
            "x_cat": np.concatenate([neg["x_cat"][:cut_n], pos["x_cat"][-cut_p:]], axis=0),
            "x_num": np.concatenate([neg["x_num"][:cut_n], pos["x_num"][-cut_p:]], axis=0),
            "x_num_missing": np.concatenate([neg["x_num_missing"][:cut_n], pos["x_num_missing"][-cut_p:]], axis=0),
            "x_bin": np.concatenate([neg["x_bin"][:cut_n], pos["x_bin"][-cut_p:]], axis=0),
            "delta_t_log1p": np.concatenate([neg["delta_t_log1p"][:cut_n], pos["delta_t_log1p"][-cut_p:]], axis=0),
        }
        augmented.append(aug_item)
    return augmented


def find_harmonic_domain_threshold(
    y_atlas_true: np.ndarray,
    y_atlas_probs: np.ndarray,
    y_optc_true: np.ndarray | None = None,
    y_optc_probs: np.ndarray | None = None,
    *,
    t_min: float = 0.20,
    t_max: float = 0.65,
    soft_max_fpr: float = 0.010,  # Phạt mạnh nếu FPR trên ATLASv2 Val vượt quá 1.0% (~7 FP)
    num_points: int = 91,
) -> tuple[float, dict[str, Any]]:
    """Harmonic Domain-Balanced Threshold Search with Peak Smoothing (Run 12)."""
    thresholds = np.linspace(t_min, t_max, num_points)
    scores = []

    for t in thresholds:
        m_atlas = binary_metrics(y_atlas_true, y_atlas_probs, t)
        f1_atlas = m_atlas["f1"]
        fpr_atlas = m_atlas["fpr"]

        fpr_penalty = 1.0
        if fpr_atlas > soft_max_fpr:
            fpr_penalty = float(np.exp(-15.0 * (fpr_atlas - soft_max_fpr)))

        if y_optc_true is not None and y_optc_probs is not None:
            m_optc = binary_metrics(y_optc_true, y_optc_probs, t)
            f1_optc = m_optc["f1"]
            if f1_atlas <= 0.0 or f1_optc <= 0.0:
                scores.append(0.0)
                continue
            w_atlas, w_optc = 0.75, 0.25
            weighted_h_f1 = 1.0 / ((w_atlas / (f1_atlas + 1e-8)) + (w_optc / (f1_optc + 1e-8)))
            scores.append(float(weighted_h_f1 * fpr_penalty))
        else:
            scores.append(float(f1_atlas * fpr_penalty))

    scores = np.array(scores, dtype=np.float64)
    if np.max(scores) <= 0.0:
        best_t = float((t_min + t_max) / 2.0)
    else:
        smoothed = np.convolve(scores, np.ones(3) / 3.0, mode="same")
        chosen_idx = int(np.argmax(smoothed))
        best_t = float(thresholds[chosen_idx])

    m_atlas = binary_metrics(y_atlas_true, y_atlas_probs, best_t)
    if y_optc_true is not None and y_optc_probs is not None:
        m_optc = binary_metrics(y_optc_true, y_optc_probs, best_t)
        m_atlas["f1_atlas"] = m_atlas["f1"]
        m_atlas["f1_optc"] = m_optc["f1"]
        denom = m_atlas["f1"] + m_optc["f1"] + 1e-8
        m_atlas["harmonic_f1"] = (2.0 * m_atlas["f1"] * m_optc["f1"]) / denom
    return best_t, m_atlas


def evaluate_domain_validation(
    model: nn.Module,
    val_loader: DataLoader,
    replay_ds: ReplayBufferDataset | None,
    device: torch.device,
    amp: bool,
    max_replay_val: int = 150,
) -> tuple[np.ndarray, np.ndarray, list[str], np.ndarray | None, np.ndarray | None, list[str] | None]:
    """Action 1 & Task 5.md Thay đổi 4: Evaluates ATLASv2 validation and OpTC replay buffer separately."""
    atlas_true, atlas_prob, atlas_ids = predict(model, val_loader, device=device, amp=amp)
    rep_labels, rep_probs, rep_ids = None, None, None
    if replay_ds is not None and len(replay_ds) > 0:
        n_rep = min(max_replay_val, len(replay_ds))
        rep_indices = np.linspace(0, len(replay_ds) - 1, n_rep, dtype=int)
        rep_items = [replay_ds[i] for i in rep_indices]
        rep_batch = collate_sequence_batch(rep_items)
        model.eval()
        with torch.no_grad():
            with get_autocast(device, amp):
                rep_logits = model(
                    x_cat=rep_batch["x_cat"].to(device),
                    x_num=rep_batch["x_num"].to(device),
                    x_num_missing=rep_batch["x_num_missing"].to(device),
                    x_bin=rep_batch["x_bin"].to(device),
                    delta_t_log1p=rep_batch["delta_t_log1p"].to(device),
                    lengths=rep_batch["lengths"].to(device),
                )
                rep_probs = torch.sigmoid(rep_logits).cpu().numpy()
        rep_labels = rep_batch["labels"].numpy()
        rep_ids = rep_batch["sample_ids"]
    return atlas_true, atlas_prob, atlas_ids, rep_labels, rep_probs, rep_ids


def evaluate_combined_validation(
    model: nn.Module,
    val_loader: DataLoader,
    replay_ds: ReplayBufferDataset | None,
    device: torch.device,
    amp: bool,
    max_replay_val: int = 150,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Legacy helper combining both domains into a single flat array."""
    atlas_true, atlas_prob, atlas_ids, rep_labels, rep_probs, rep_ids = evaluate_domain_validation(
        model, val_loader, replay_ds, device, amp, max_replay_val
    )
    if rep_labels is not None and rep_probs is not None:
        val_true = np.concatenate([atlas_true, rep_labels])
        val_prob = np.concatenate([atlas_prob, rep_probs])
        val_ids = atlas_ids + (rep_ids or [])
        return val_true, val_prob, val_ids
    return atlas_true, atlas_prob, atlas_ids



def load_pretrained_checkpoint(
    model: nn.Module,
    ckpt_path: str | Path,
    device: torch.device,
    *,
    recenter_logit_bias: bool = False,
    optc_base_thr: float = 0.9956,
) -> dict[int, int]:
    """Load pretrained model weights, with optional Zero-Step Logit Recentering for Continual Learning."""
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
                    f"initialized {n_new} new rows with Mean-Embedding + N(0, 0.05) symmetry breaking."
                )
        else:
            print(f"  [Warning] Skipping key {key} due to shape mismatch: ckpt {val.shape} vs model {model_state[key].shape}")

    model.load_state_dict(model_state)

    if recenter_logit_bias:
        # Dịch chuyển 60% độ lệch logit từ ngưỡng OpTC (0.9956 -> logit +5.4216 * 0.60 = +3.2530)
        # Vừa đủ xóa sạch các cụm FP lành tính, vừa không làm tụt xác suất của các chuỗi exfiltration
        logit_offset = math.log(optc_base_thr / (1.0 - optc_base_thr))
        with torch.no_grad():
            last_linear = model.classifier[-1]
            if isinstance(last_linear, nn.Linear) and last_linear.bias is not None:
                shift_val = 0.60 * logit_offset
                last_linear.bias.data -= shift_val
                print(f"  [Logit Recentering] Shifted classifier[-1].bias by -{shift_val:.4f} (60% of OpTC thr offset {logit_offset:.4f} -> ~ -3.25).")

    print(f"Loaded pretrained weights from {ckpt_path}")
    return old_vocab_sizes


def apply_optc_gradient_shield(model: nn.Module, old_sizes: dict[int, int], old_scale: float = 0.35) -> None:
    """Shield shared OpTC vocabulary from rapid drift during incremental training (default: 0.35x)."""
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
            print(f"  [Gradient Shield] Protected {n_old} OpTC rows in embeddings[{i}] (grad_scale={old_scale}x); {emb.weight.shape[0] - n_old} new ATLASv2 rows train at full speed (1.0x).")



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
    min_epochs: int = 3,
    batch_size: int = 32,
    lr: float = 2e-4,
    weight_decay: float = 1e-4,
    grad_clip: float = 1.0,
    patience: int = 4,
    amp: bool = False,
    seed: int = 42,
    replay_ds: ReplayBufferDataset | None = None,
    replay_ratio: float = 0.05,
    model_tag: str = "model",
    freeze_epochs: int = 0,
    loss_type: str = "focal",
    t_min: float = 0.35,
    t_max: float = 0.75,
    soft_max_fpr: float = 0.015,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    best_path = output_dir / f"{model_tag}_best.pt"

    train_labels = np.array([row["label"] for row in train_ds.rows], dtype=np.int32)
    train_pos = int(np.sum(train_labels == 1))
    train_neg = int(np.sum(train_labels == 0))

    # Loss Criterion Setup (Task 3.md Section 1: BinaryFocalLossWithWeights with smoothed weights)
    if loss_type == "focal":
        alpha = make_smoothed_class_weights(train_labels, device=device, pos_multiplier=2.0)
        criterion = BinaryFocalLossWithWeights(alpha=alpha, gamma=2.0)
        print(f"  [Loss] Configured BinaryFocalLossWithWeights (gamma=2.0, alpha=[{alpha[0]:.2f}, {alpha[1]:.2f}])")
    elif loss_type == "asl":
        criterion = AsymmetricFocalLoss(gamma_neg=4.0, gamma_pos=1.0, clip=0.05)
        print("  [Loss] Configured Asymmetric Focal Loss (ASL: gamma_neg=4.0, gamma_pos=1.0, clip=0.05)")
    else:
        raw_ratio = float(train_neg / max(1, train_pos))
        clamped_pos_weight = min(10.0, max(2.0, raw_ratio * 0.25))
        pos_weight = torch.tensor([clamped_pos_weight], device=device)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        print(f"  [Loss] Configured BCEWithLogitsLoss (pos_weight={clamped_pos_weight:.2f})")

    # Configured SupConWithHardNegativeRepulsion with loss_pos + loss_neg scaled by 0.15
    if model_tag == "incremental":
        contrastive_criterion = SupConWithHardNegativeRepulsion(margin=0.15, scale=0.15)
        print("  [Loss] Configured SupConWithHardNegativeRepulsion (margin=0.15, scale=0.15 with loss_pos + loss_neg)")
    else:
        contrastive_criterion = None

    # Mở khóa toàn bộ tham số mô hình (Task 3.md Section 2)
    for param in model.parameters():
        param.requires_grad = True

    # 3-Tier Decoupled Learning Rate Setup (Task 7.md Giải pháp 3)
    if model_tag == "incremental":
        lr_emb = lr * 3.0       # 6e-4: học nhanh 80 token mới như Scratch
        lr_backbone = lr * 1.5  # 3e-4: đủ nhanh để thích nghi với Multi-Scale Pooling mới
        lr_head = lr * 3.0      # 6e-4: cân bằng lại thang đo logit

        backbone_params = list(model.event_encoder.parameters()) + list(model.lstm.parameters())
        optimizer = torch.optim.AdamW([
            {"params": model.embeddings.parameters(), "lr": lr_emb, "weight_decay": weight_decay},
            {"params": backbone_params, "lr": lr_backbone, "weight_decay": weight_decay},
            {"params": model.classifier.parameters(), "lr": lr_head, "weight_decay": weight_decay},
        ])
        print(f"  [3-Tier Decoupled LR] Embeddings: {lr_emb:.2e} | Backbone (Encoder+LSTM): {lr_backbone:.2e} | Classifier Head: {lr_head:.2e}")
    else:
        optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)

    # Task 7.md: Giữ LR hằng số trong 10 epoch để không bị đóng băng khi đang tăng tốc hội tụ
    scheduler = None
    scaler = get_scaler(device, amp)

    best_val_score = -1.0
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

            # Interleave Experience Replay buffer samples if available (Adaptive Replay Scheduling - MalFSCIL 2024)
            if replay_ds is not None and len(replay_ds) > 0 and replay_ratio > 0:
                n_replay = max(1, min(2, int(round(len(batch_items) * replay_ratio))))
                if hasattr(replay_ds, "sample_batch"):
                    batch_items.extend(replay_ds.sample_batch(n_replay, pos_ratio=0.30, max_pos=3))
                else:
                    replay_indices = np.random.choice(len(replay_ds), size=n_replay, replace=False)
                    for repl_idx in replay_indices:
                        batch_items.append(replay_ds[repl_idx])

            # DEEPDIST Entity Perturbation disabled in Run 10 (Task 7.md: eliminates label noise)
            # if model_tag == "incremental":
            #     batch_items = augment_dormant_positives(batch_items, p_aug=0.5)

            batch = collate_sequence_batch(batch_items)

            x_cat = batch["x_cat"].to(device)
            x_num = batch["x_num"].to(device)
            x_num_missing = batch["x_num_missing"].to(device)
            x_bin = batch["x_bin"].to(device)
            delta = batch["delta_t_log1p"].to(device)
            lengths = batch["lengths"].to(device)
            targets = batch["labels"].to(device)

            optimizer.zero_grad(set_to_none=True)
            with get_autocast(device, amp):
                if contrastive_criterion is not None:
                    logits, pooled = model(
                        x_cat=x_cat,
                        x_num=x_num,
                        x_num_missing=x_num_missing,
                        x_bin=x_bin,
                        delta_t_log1p=delta,
                        lengths=lengths,
                        return_features=True,
                    )
                    loss_focal = criterion(logits, targets)
                    loss_con = contrastive_criterion(pooled, targets)
                    loss = loss_focal + loss_con
                else:
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

        # Harmonic Domain-Balanced Validation (Run 10 / Task 7.md Giải pháp 4)
        if model_tag == "incremental" and replay_ds is not None:
            atlas_true, atlas_prob, _, rep_true, rep_prob, _ = evaluate_domain_validation(
                model, val_loader, replay_ds, device=device, amp=amp
            )
            val_thr, val_metrics = find_harmonic_domain_threshold(
                atlas_true, atlas_prob, rep_true, rep_prob, t_min=t_min, t_max=t_max, soft_max_fpr=soft_max_fpr
            )
            # Tính PR-AUC trực tiếp trên tập Validation của ATLASv2 để chọn đúng epoch hội tụ tốt nhất trên miền đích (Task 7.md)
            val_pr_auc = float(average_precision_score(atlas_true, atlas_prob))
            val_score = val_pr_auc + 0.2 * val_metrics.get("harmonic_f1", val_metrics["f1"])
        else:
            val_true, val_prob, _ = predict(model, val_loader, device=device, amp=amp)
            val_pr_auc = float(average_precision_score(val_true, val_prob))
            val_thr, val_metrics = find_optimal_threshold(val_true, val_prob, t_min=t_min, t_max=t_max, beta=1.0)
            val_score = val_pr_auc + 0.1 * val_metrics["f1"]

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

        # Warm-up Checkpoint & Early Stopping Policy (Task 3.md Section 3)
        if val_score > best_val_score + 1e-6:
            best_val_score = val_score
            best_epoch = epoch
            stale_epochs = 0
            torch.save({
                "model_state_dict": model.state_dict(),
                "best_epoch": best_epoch,
                "best_val_pr_auc": val_pr_auc,
                "best_val_score": best_val_score,
            }, best_path)
        else:
            if epoch >= min_epochs:
                stale_epochs += 1

        if scheduler is not None:
            scheduler.step()

        if stale_epochs >= patience:
            print(f"  [{model_tag} Early Stopping] No improvement in Val score for {stale_epochs} epochs (after epoch {min_epochs}).")
            break

    # Load best checkpoint
    best_ckpt = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(best_ckpt["model_state_dict"])

    # Optimize threshold on VAL (Harmonic Domain-Balanced Validation for Run 9)
    if model_tag == "incremental" and replay_ds is not None:
        atlas_true, atlas_prob, atlas_ids, rep_true, rep_prob, rep_ids = evaluate_domain_validation(
            model, val_loader, replay_ds, device=device, amp=amp
        )
        final_thr, final_val_m = find_harmonic_domain_threshold(
            atlas_true, atlas_prob, rep_true, rep_prob, t_min=t_min, t_max=t_max, soft_max_fpr=soft_max_fpr
        )
    else:
        val_true, val_prob, val_ids = predict(model, val_loader, device=device, amp=amp)
        final_thr, final_val_m = find_optimal_threshold(val_true, val_prob, t_min=t_min, t_max=t_max, beta=1.0)

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
        "best_val_pr_auc": best_ckpt.get("best_val_pr_auc", final_val_m["pr_auc"]),
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
    p.add_argument("--replay-ratio", type=float, default=0.05, help="Fraction of replay samples per mini-batch (default 0.05 - MalFSCIL 2024)")
    p.add_argument("--optc-test-root", default=None, help="Path to optc_test/ directory for Backward Transfer evaluation")
    p.add_argument("--run-benchmark", action="store_true", help="Run full 4-experiment benchmark suite (Scratch, Zero-shot, IL, BWT)")
    p.add_argument("--epochs", type=int, default=15, help="Number of training epochs (default: 15 - Run 11)")
    p.add_argument("--min-epochs", type=int, default=3, help="Minimum warmup epochs before allowing early stopping (default: 3)")
    p.add_argument("--freeze-epochs", type=int, default=0, help="Legacy parameter, kept for compatibility (default: 0)")
    p.add_argument("--loss", default="focal", choices=["focal", "asl", "bce"], help="Loss function for training (default: focal - MORPH-IDS BinaryFocalLossWithWeights)")
    p.add_argument("--t-min", type=float, default=0.20, help="Minimum threshold for controlled search (default: 0.20)")
    p.add_argument("--t-max", type=float, default=0.65, help="Maximum threshold for controlled search (default: 0.65)")
    p.add_argument("--soft-max-fpr", type=float, default=0.010, help="Soft maximum validation FPR constraint (default: 0.010 - Run 11)")
    p.add_argument("--max-fpr", type=float, default=0.03, help="Maximum validation FPR constraint (legacy)")
    p.add_argument("--batch-size", type=int, default=32, help="Mini-batch size")
    p.add_argument("--lr", type=float, default=2e-4, help="Learning rate for incremental fine-tuning")
    p.add_argument("--weight-decay", type=float, default=1e-4)
    p.add_argument("--grad-clip", type=float, default=1.0)
    p.add_argument("--patience", type=int, default=5, help="Early stopping patience (default: 5 - Run 11)")
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
        load_pretrained_checkpoint(zs_model, args.init_model, device, recenter_logit_bias=False)

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
        min_epochs=args.min_epochs,
        batch_size=args.batch_size,
        lr=args.lr * 2,  # scratch typically trains with higher lr
        patience=args.patience,
        amp=amp,
        seed=args.seed,
        replay_ds=None,  # No replay for scratch baseline
        model_tag="scratch",
        freeze_epochs=0,
        loss_type="focal",
        t_min=args.t_min,
        t_max=args.t_max,
        soft_max_fpr=args.soft_max_fpr,
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
    old_vocab_sizes: dict[int, int] = {}
    if args.init_model and Path(args.init_model).exists():
        old_vocab_sizes = load_pretrained_checkpoint(il_model, args.init_model, device, recenter_logit_bias=True)
        apply_optc_gradient_shield(il_model, old_vocab_sizes, old_scale=0.35)

    il_res = train_single_model(
        il_model,
        train_ds,
        val_loader,
        test_loader,
        device=device,
        output_dir=results_dir / "incremental",
        epochs=args.epochs,
        min_epochs=args.min_epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        patience=args.patience,
        amp=amp,
        seed=args.seed,
        replay_ds=replay_ds,
        replay_ratio=args.replay_ratio,
        model_tag="incremental",
        freeze_epochs=args.freeze_epochs,
        loss_type=args.loss,
        t_min=args.t_min,
        t_max=args.t_max,
        soft_max_fpr=args.soft_max_fpr,
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

        # Before IL (Base OpTC model) at frozen base threshold (0.9956)
        b_true, b_prob, _ = predict(zs_model, optc_loader, device=device, amp=amp)
        before_m = binary_metrics(b_true, b_prob, optc_frozen_thr)

        # After IL (Continual Learning model) evaluated at Unified Threshold (Task 4.md Action 1)
        # Note: In Domain-IL, the single calibrated threshold from combined validation is used without test leakage!
        unified_thr = il_res["threshold"]
        a_true, a_prob, _ = predict(il_model, optc_loader, device=device, amp=amp)
        after_m_unified = binary_metrics(a_true, a_prob, unified_thr)
        after_m_legacy = binary_metrics(a_true, a_prob, optc_frozen_thr)

        bwt_f1 = after_m_unified["f1"] - before_m["f1"]
        bwt_ap = after_m_unified["pr_auc"] - before_m["pr_auc"]
        bwt_roc_auc = after_m_unified["roc_auc"] - before_m["roc_auc"]

        bwt_metrics = {
            "optc_before_il": before_m,
            "optc_after_il": after_m_unified,
            "optc_after_il_unified": after_m_unified,
            "optc_after_il_legacy_thr": after_m_legacy,
            "unified_threshold": float(unified_thr),
            "bwt_f1": float(bwt_f1),
            "bwt_f1_unified": float(bwt_f1),
            "bwt_ap": float(bwt_ap),
            "bwt_roc_auc": float(bwt_roc_auc),
        }
        dump_json(results_dir / "bwt_metrics.json", bwt_metrics)

        print(f"  OpTC Test Before IL (Base Thr={optc_frozen_thr:.4f})  : F1={before_m['f1']:.4f} | Prec={before_m['precision']:.4f} | Rec={before_m['recall']:.4f} | TP={before_m['tp']}, FP={before_m['fp']}")
        print(f"  OpTC Test After IL  (Unified Thr={unified_thr:.4f}): F1={after_m_unified['f1']:.4f} | Prec={after_m_unified['precision']:.4f} | Rec={after_m_unified['recall']:.4f} | TP={after_m_unified['tp']}, FP={after_m_unified['fp']}")
        print(f"  OpTC Test After IL  (Legacy Thr={optc_frozen_thr:.4f}) : F1={after_m_legacy['f1']:.4f} | Prec={after_m_legacy['precision']:.4f} | Rec={after_m_legacy['recall']:.4f} | TP={after_m_legacy['tp']}, FP={after_m_legacy['fp']}")
        print(f"  Backward Transfer (BWT F1 Unified): {bwt_f1:+.4f} ({bwt_f1*100:+.2f}%)")
        print(f"  Backward Transfer (BWT AP): {bwt_ap:+.4f} | BWT ROC-AUC: {bwt_roc_auc:+.4f}")

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
