"""Validation-only threshold selection and fixed-threshold binary metrics."""
import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_curve, precision_score, recall_score,
                             roc_auc_score, roc_curve)


def validate_binary_target(y):
    if set(np.unique(y)) != {0, 1}:
        raise ValueError("supervised evaluation requires both benign and malicious labels")


def select_validation_threshold(y, probabilities):
    validate_binary_target(y)
    precision, recall, thresholds = precision_recall_curve(y, probabilities)
    scores = 2 * precision[:-1] * recall[:-1] / (precision[:-1] + recall[:-1] + 1e-12)
    return float(thresholds[int(np.argmax(scores))])


def fixed_threshold_metrics(y, probabilities, threshold):
    validate_binary_target(y)
    predicted = np.asarray(probabilities) >= threshold
    fpr, tpr, _ = roc_curve(y, probabilities)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "pr_auc": float(average_precision_score(y, probabilities)),
        "roc_auc": float(roc_auc_score(y, probabilities)),
        "threshold": float(threshold), "threshold_source": "validation",
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "observed_fpr": float(fp / (fp + tn)),
        "recall_at_1pct_fpr": float(np.max(tpr[fpr <= 0.01])),
        "recall_at_1pct_fpr_note": "descriptive ROC sweep, maximum observed TPR at FPR <= 0.01; not a test-tuned operating threshold",
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "total_samples": len(y), "total_positive": int(np.sum(y)), "total_negative": int(len(y) - np.sum(y)),
    }
