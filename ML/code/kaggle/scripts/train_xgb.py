#!/usr/bin/env python3
"""Train an XGBoost classifier on pre-built sparse matrices.

Input:  X_train.npz, y_train.npy, X_val.npz, y_val.npy, vocab.json
Output: xgb_model.ubj, xgb_feature_importances.csv, xgb_training_log.json

Designed to run on Kaggle (T4/P100 GPU). Accepts --input-dir and --output-dir.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline_contract import validate_output_path, load_training_bundle
from evaluation_metrics import validate_binary_target

import numpy as np
from scipy import sparse
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)

try:
    import xgboost as xgb
except ImportError:
    print("ERROR: xgboost not installed. pip install xgboost", file=sys.stderr)
    sys.exit(1)


def _detect_input_dir() -> Path:
    """Auto-detect input directory on Kaggle or local."""
    candidates = [
        Path("/kaggle/input"),
        Path(__file__).resolve().parent,
    ]
    for base in candidates:
        if (base / "vocab.json").exists():
            return base
        for sub in base.iterdir() if base.exists() else []:
            if sub.is_dir() and (sub / "vocab.json").exists():
                return sub
    return Path(".")


def _detect_device() -> str:
    """Detect if GPU is available for XGBoost."""
    try:
        import subprocess
        result = subprocess.run(["nvidia-smi"], capture_output=True, timeout=5)
        if result.returncode == 0:
            return "cuda"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "cpu"


def load_data(input_dir: Path) -> tuple:
    """Load sparse matrices and labels."""
    matrix_dir = input_dir / "matrix"
    if not matrix_dir.exists():
        matrix_dir = input_dir

    X_train = sparse.load_npz(matrix_dir / "X_train.npz")
    y_train = np.load(matrix_dir / "y_train.npy")
    X_val = sparse.load_npz(matrix_dir / "X_val.npz")
    y_val = np.load(matrix_dir / "y_val.npy")

    print(f"Train: {X_train.shape}, pos={y_train.sum():,}/{len(y_train):,}", flush=True)
    print(f"Val:   {X_val.shape}, pos={y_val.sum():,}/{len(y_val):,}", flush=True)
    return X_train, y_train, X_val, y_val


def train_xgboost(X_train, y_train, X_val, y_val, vocab: dict[str, int],
                  output_dir: Path) -> dict:
    """Train XGBoost with early stopping on val PR-AUC."""
    output_dir = validate_output_path(output_dir)
    validate_binary_target(y_train)
    validate_binary_target(y_val)
    output_dir.mkdir(parents=True, exist_ok=True)

    device = _detect_device()
    print(f"Device: {device}", flush=True)

    # Compute scale_pos_weight
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    scale_pos_weight = n_neg / max(n_pos, 1)
    print(f"scale_pos_weight: {scale_pos_weight:.2f} "
          f"({n_neg:,} neg / {n_pos:,} pos)", flush=True)

    started = time.monotonic()

    params = {
        "n_estimators": 1000,
        "max_depth": 8,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.3,
        "tree_method": "hist",
        "device": device,
        "scale_pos_weight": scale_pos_weight,
        "eval_metric": "aucpr",
        "random_state": 1,
        "verbosity": 1,
    }

    model = xgb.XGBClassifier(**params)

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    train_time = time.monotonic() - started
    best_iteration = model.best_iteration if hasattr(model, "best_iteration") else params["n_estimators"]
    best_score = model.best_score if hasattr(model, "best_score") else None

    print(f"\nBest iteration: {best_iteration}, "
          f"best val score: {best_score}", flush=True)

    # Evaluate on val
    y_proba = model.predict_proba(X_val)[:, 1]
    prauc = average_precision_score(y_val, y_proba)
    roc = roc_auc_score(y_val, y_proba)

    precision, recall, thresholds = precision_recall_curve(y_val, y_proba)
    f1_scores = 2 * precision[:-1] * recall[:-1] / (precision[:-1] + recall[:-1] + 1e-12)
    best_f1_idx = f1_scores.argmax()
    best_f1 = float(f1_scores[best_f1_idx])
    best_threshold = float(thresholds[min(best_f1_idx, len(thresholds) - 1)])

    print(f"Val PR-AUC={prauc:.6f}, ROC-AUC={roc:.6f}, "
          f"F1={best_f1:.4f}@{best_threshold:.4f}", flush=True)

    # Save model
    model_path = output_dir / "xgb_model.ubj"
    model.save_model(str(model_path))
    print(f"Saved model to {model_path} ({model_path.stat().st_size / 1e6:.1f} MB)",
          flush=True)

    # Feature importances (gain)
    importances = model.feature_importances_
    idx_to_token = {v: k for k, v in vocab.items()}
    importance_rows = sorted(
        [(idx_to_token.get(i, f"col_{i}"), float(importances[i]))
         for i in range(len(importances)) if importances[i] > 0],
        key=lambda x: -x[1],
    )

    imp_path = output_dir / "xgb_feature_importances.csv"
    with imp_path.open("w") as f:
        f.write("token,importance\n")
        for token, imp in importance_rows:
            f.write(f"{token},{imp:.8f}\n")
    print(f"Saved {len(importance_rows)} non-zero importances to {imp_path}", flush=True)

    # Save val predictions
    np.save(output_dir / "xgb_val_proba.npy", y_proba)

    # Training log
    log = {
        "model": "XGBoost",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "device": device,
        "params": {k: v for k, v in params.items() if k != "device"},
        "best_iteration": best_iteration,
        "best_val_aucpr": float(best_score) if best_score is not None else None,
        "val_pr_auc": prauc,
        "val_roc_auc": roc,
        "val_best_f1": best_f1,
        "val_best_threshold": best_threshold,
        "train_time_s": round(train_time, 2),
        "train_shape": list(X_train.shape),
        "val_shape": list(X_val.shape),
        "scale_pos_weight": scale_pos_weight,
        "top_20_features": [{"token": t, "importance": v} for t, v in importance_rows[:20]],
    }
    log_path = output_dir / "xgb_training_log.json"
    with log_path.open("w") as f:
        json.dump(log, f, indent=2)

    return log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()

    input_dir = args.input_dir or _detect_input_dir()
    print(f"Input: {input_dir}", flush=True)
    print(f"Output: {args.output_dir}", flush=True)

    vocab, provenance = load_training_bundle(input_dir)
    print(f"Vocab: {len(vocab):,} tokens", flush=True)

    X_train, y_train, X_val, y_val = load_data(input_dir)
    log = train_xgboost(X_train, y_train, X_val, y_val, vocab, args.output_dir)
    log.update(provenance, model_seed=1)
    validate_output_path(args.output_dir / "xgb_training_log.json").write_text(json.dumps(log, indent=2))

    print(f"\n{'='*60}")
    print(f"XGBoost DONE — val PR-AUC: {log['val_pr_auc']:.6f}")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
