"""Validation-only decision rules; constraints apply to the final emitted alerts."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import f1_score


def attack_macro_f1(y_true, y_pred) -> float:
    """Average stages 1..4, retaining benign rows as possible false positives."""
    return float(f1_score(y_true, y_pred, labels=[1, 2, 3, 4], average="macro", zero_division=0))


def select_binary_threshold(y_true, scores, max_fpr=0.02) -> float:
    """Exact observed-score search, including the feasible no-alert operating point."""
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    if not len(y) or y.shape != s.shape or not np.isfinite(s).all():
        raise ValueError("Expected nonempty finite aligned labels and scores")
    if not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be in [0, 1]")
    # Sort once; evaluate after each tied score block. Larger threshold wins ties.
    order = np.argsort(-s, kind="stable")
    sorted_s, sorted_y = s[order], y[order]
    ends = np.r_[np.flatnonzero(sorted_s[:-1] != sorted_s[1:]), len(y) - 1]
    tp = np.cumsum(sorted_y)[ends]
    fp = ends + 1 - tp
    positives, negatives = int(y.sum()), int((y == 0).sum())
    f1 = 2 * tp / np.maximum(1, positives + tp + fp)
    valid = fp <= max_fpr * max(1, negatives) + 1e-12
    best = float(np.nextafter(s.max(), np.inf))
    best_f1 = 0.0
    for j in range(len(ends)):
        if valid[j] and f1[j] > best_f1:
            best_f1 = float(f1[j])
            best = float(sorted_s[ends[j]])
    return best


def global_predictions(binary_scores, stage_logits, threshold):
    active = np.asarray(binary_scores) >= threshold
    return np.where(active, np.asarray(stage_logits).argmax(axis=1) + 1, 0)
