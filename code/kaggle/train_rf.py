#!/usr/bin/env python3
"""Train a Random Forest classifier on pre-built sparse matrices.

Input:  X_train.npz, y_train.npy, X_val.npz, y_val.npy, vocab.json
Output: rf_model.pkl, rf_feature_importances.csv, rf_training_log.json

Designed to run on Kaggle (CPU). Accepts --input-dir and --output-dir.
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline_contract import validate_output_path, load_training_bundle
from evaluation_metrics import validate_binary_target

import numpy as np
from scipy import sparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)


def _detect_input_dir() -> Path:
    """Auto-detect input directory on Kaggle or local."""
    candidates = [
        Path("/kaggle/input"),
        Path(__file__).resolve().parent,
    ]
    for base in candidates:
        # Look for vocab.json in base or any subdirectory
        if (base / "vocab.json").exists():
            return base
        for sub in base.iterdir() if base.exists() else []:
            if sub.is_dir() and (sub / "vocab.json").exists():
                return sub
    return Path(".")


def load_data(input_dir: Path) -> tuple:
    """Load sparse matrices and labels."""
    matrix_dir = input_dir / "matrix"
    if not matrix_dir.exists():
        matrix_dir = input_dir  # flat layout fallback

    X_train = sparse.load_npz(matrix_dir / "X_train.npz")
    y_train = np.load(matrix_dir / "y_train.npy")
    X_val = sparse.load_npz(matrix_dir / "X_val.npz")
    y_val = np.load(matrix_dir / "y_val.npy")

    print(f"Train: {X_train.shape}, pos={y_train.sum():,}/{len(y_train):,}", flush=True)
    print(f"Val:   {X_val.shape}, pos={y_val.sum():,}/{len(y_val):,}", flush=True)
    return X_train, y_train, X_val, y_val


def train_rf(X_train, y_train, X_val, y_val, vocab: dict[str, int],
             output_dir: Path) -> dict:
    """Train RF with depth grid search, select best on val PR-AUC."""
    output_dir = validate_output_path(output_dir)
    validate_binary_target(y_train)
    validate_binary_target(y_val)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}

    # Grid search over max_depth
    depth_candidates = [10, 15, 20, None]
    best_prauc = -1.0
    best_depth = None
    best_model = None

    for depth in depth_candidates:
        depth_str = str(depth) if depth is not None else "None"
        print(f"\n--- RF max_depth={depth_str} ---", flush=True)
        started = time.monotonic()

        model = RandomForestClassifier(
            n_estimators=500,
            max_depth=depth,
            min_samples_leaf=5,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=-1,
            random_state=1,
            verbose=0,
        )

        model.fit(X_train, y_train)
        train_time = time.monotonic() - started

        # Evaluate on val
        y_proba = model.predict_proba(X_val)[:, 1]
        prauc = average_precision_score(y_val, y_proba)
        roc = roc_auc_score(y_val, y_proba)

        # Best F1 threshold
        precision, recall, thresholds = precision_recall_curve(y_val, y_proba)
        f1_scores = 2 * precision[:-1] * recall[:-1] / (precision[:-1] + recall[:-1] + 1e-12)
        best_f1_idx = f1_scores.argmax()
        best_f1 = float(f1_scores[best_f1_idx])
        best_threshold = float(thresholds[min(best_f1_idx, len(thresholds) - 1)])

        print(f"  PR-AUC={prauc:.6f}, ROC-AUC={roc:.6f}, "
              f"F1={best_f1:.4f}@{best_threshold:.4f}, "
              f"time={train_time:.1f}s", flush=True)

        results[depth_str] = {
            "max_depth": depth,
            "pr_auc": prauc,
            "roc_auc": roc,
            "best_f1": best_f1,
            "best_threshold": best_threshold,
            "train_time_s": round(train_time, 2),
            "n_estimators": 500,
        }

        if prauc > best_prauc:
            best_prauc = prauc
            best_depth = depth
            best_model = model

    # Save best model
    print(f"\nBest RF: max_depth={best_depth}, PR-AUC={best_prauc:.6f}", flush=True)

    model_path = output_dir / "rf_model.pkl"
    with model_path.open("wb") as f:
        pickle.dump(best_model, f, protocol=5)
    print(f"Saved model to {model_path} ({model_path.stat().st_size / 1e6:.1f} MB)",
          flush=True)

    # Feature importances
    importances = best_model.feature_importances_
    idx_to_token = {v: k for k, v in vocab.items()}
    importance_rows = sorted(
        [(idx_to_token.get(i, f"col_{i}"), float(importances[i]))
         for i in range(len(importances)) if importances[i] > 0],
        key=lambda x: -x[1],
    )

    imp_path = output_dir / "rf_feature_importances.csv"
    with imp_path.open("w") as f:
        f.write("token,importance\n")
        for token, imp in importance_rows:
            f.write(f"{token},{imp:.8f}\n")
    print(f"Saved {len(importance_rows)} non-zero importances to {imp_path}", flush=True)

    # Save training log
    log = {
        "model": "RandomForest",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "best_max_depth": best_depth,
        "best_pr_auc": best_prauc,
        "grid_results": results,
        "train_shape": list(X_train.shape),
        "val_shape": list(X_val.shape),
        "top_20_features": [{"token": t, "importance": v} for t, v in importance_rows[:20]],
    }
    log_path = output_dir / "rf_training_log.json"
    with log_path.open("w") as f:
        json.dump(log, f, indent=2)

    # Save val predictions for evaluate_models.py
    y_proba_best = best_model.predict_proba(X_val)[:, 1]
    np.save(output_dir / "rf_val_proba.npy", y_proba_best)

    return log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=None,
                        help="directory with vocab.json + matrix/ (auto-detect if omitted)")
    parser.add_argument("--output-dir", type=Path, default=Path("results"),
                        help="output directory (default: results/)")
    args = parser.parse_args()

    input_dir = args.input_dir or _detect_input_dir()
    print(f"Input: {input_dir}", flush=True)
    print(f"Output: {args.output_dir}", flush=True)

    # Load vocab
    vocab, provenance = load_training_bundle(input_dir)
    print(f"Vocab: {len(vocab):,} tokens", flush=True)

    X_train, y_train, X_val, y_val = load_data(input_dir)
    log = train_rf(X_train, y_train, X_val, y_val, vocab, args.output_dir)
    log.update(provenance, model_seed=1)
    validate_output_path(args.output_dir / "rf_training_log.json").write_text(json.dumps(log, indent=2))

    print(f"\n{'='*60}")
    print(f"RF DONE — best PR-AUC: {log['best_pr_auc']:.6f} "
          f"(max_depth={log['best_max_depth']})")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
