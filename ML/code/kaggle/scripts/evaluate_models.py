#!/usr/bin/env python3
"""Unified evaluation for RF, XGBoost, and LightGBM models.

Loads all three trained models and evaluates on val and test sets.
Produces: metrics_summary.json, PR/ROC curves, confusion matrices,
SHAP top-30 features, and a feature importance comparison.

Input:  model files + X_val/X_test/y_val/y_test from training outputs
Output: results/ directory with all evaluation artifacts

Designed to run on Kaggle after all three training scripts.
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation_metrics import fixed_threshold_metrics, select_validation_threshold
from pipeline_contract import validate_output_path, load_training_bundle

import numpy as np
from scipy import sparse
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("WARNING: matplotlib not available; plots will be skipped", file=sys.stderr)

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    print("WARNING: shap not available; SHAP analysis will be skipped", file=sys.stderr)

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False


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


def load_data(input_dir: Path, split: str = "val") -> tuple:
    """Load sparse matrix and labels for a given split."""
    matrix_dir = input_dir / "matrix"
    if not matrix_dir.exists():
        matrix_dir = input_dir

    X = sparse.load_npz(matrix_dir / f"X_{split}.npz")
    y = np.load(matrix_dir / f"y_{split}.npy")
    return X, y


def load_models(model_dir: Path) -> dict[str, Any]:
    """Load all available trained models."""
    models = {}

    # RF
    rf_path = model_dir / "rf_model.pkl"
    if rf_path.exists():
        with rf_path.open("rb") as f:
            models["RF"] = pickle.load(f)
        print(f"  Loaded RF from {rf_path}", flush=True)

    # XGBoost
    xgb_path = model_dir / "xgb_model.ubj"
    if xgb_path.exists() and HAS_XGB:
        model = xgb.XGBClassifier()
        model.load_model(str(xgb_path))
        models["XGBoost"] = model
        print(f"  Loaded XGBoost from {xgb_path}", flush=True)

    # LightGBM
    lgbm_path = model_dir / "lgbm_model.txt"
    if lgbm_path.exists() and HAS_LGB:
        booster = lgb.Booster(model_file=str(lgbm_path))
        models["LightGBM"] = booster
        print(f"  Loaded LightGBM from {lgbm_path}", flush=True)

    return models


def evaluate_model(model, model_name: str, X, y, vocab: dict[str, int],
                   split: str, threshold: float | None = None) -> tuple:
    """Choose a validation threshold once; require that frozen value for test."""
    if model_name == "LightGBM" and HAS_LGB and isinstance(model, lgb.Booster):
        y_proba = model.predict(X)
    else:
        y_proba = model.predict_proba(X)[:, 1]
    if threshold is None:
        if split != "val":
            raise ValueError("test evaluation requires a frozen validation threshold")
        threshold = select_validation_threshold(y, y_proba)
    metrics = fixed_threshold_metrics(y, y_proba, threshold)
    metrics.update(model=model_name, split=split)
    precision, recall, _ = precision_recall_curve(y, y_proba)
    fpr, tpr, _ = roc_curve(y, y_proba)
    return metrics, y_proba, precision, recall, fpr, tpr


def plot_pr_curves(all_results: dict, output_dir: Path, split: str) -> None:
    """Plot PR curves for all models on one figure."""
    if not HAS_MATPLOTLIB:
        return

    fig, ax = plt.subplots(figsize=(10, 7))
    colors = {"RF": "#2196F3", "XGBoost": "#FF9800", "LightGBM": "#4CAF50"}

    for name, data in all_results.items():
        precision = data["precision_arr"]
        recall = data["recall_arr"]
        prauc = data["metrics"]["pr_auc"]
        ax.plot(recall, precision, label=f"{name} (AP={prauc:.4f})",
                color=colors.get(name, "gray"), linewidth=2)

    ax.set_xlabel("Recall", fontsize=13)
    ax.set_ylabel("Precision", fontsize=13)
    ax.set_title(f"Precision-Recall Curve — {split}", fontsize=15)
    ax.legend(fontsize=12, loc="best")
    ax.grid(True, alpha=0.3)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.05])
    fig.tight_layout()
    fig.savefig(output_dir / f"pr_curve_{split}.png", dpi=150)
    plt.close(fig)
    print(f"  Saved pr_curve_{split}.png", flush=True)


def plot_roc_curves(all_results: dict, output_dir: Path, split: str) -> None:
    """Plot ROC curves for all models on one figure."""
    if not HAS_MATPLOTLIB:
        return

    fig, ax = plt.subplots(figsize=(10, 7))
    colors = {"RF": "#2196F3", "XGBoost": "#FF9800", "LightGBM": "#4CAF50"}

    for name, data in all_results.items():
        fpr = data["fpr_arr"]
        tpr = data["tpr_arr"]
        roc_auc = data["metrics"]["roc_auc"]
        ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc:.4f})",
                color=colors.get(name, "gray"), linewidth=2)

    ax.plot([0, 1], [0, 1], "k--", alpha=0.3, linewidth=1)
    ax.set_xlabel("False Positive Rate", fontsize=13)
    ax.set_ylabel("True Positive Rate", fontsize=13)
    ax.set_title(f"ROC Curve — {split}", fontsize=15)
    ax.legend(fontsize=12, loc="lower right")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_dir / f"roc_curve_{split}.png", dpi=150)
    plt.close(fig)
    print(f"  Saved roc_curve_{split}.png", flush=True)


def plot_confusion_matrix(cm_dict: dict, model_name: str, output_dir: Path,
                          split: str) -> None:
    """Plot a single confusion matrix."""
    if not HAS_MATPLOTLIB:
        return

    cm = np.array([[cm_dict["tn"], cm_dict["fp"]],
                    [cm_dict["fn"], cm_dict["tp"]]])

    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Benign", "Malicious"], fontsize=12)
    ax.set_yticklabels(["Benign", "Malicious"], fontsize=12)
    ax.set_xlabel("Predicted", fontsize=13)
    ax.set_ylabel("Actual", fontsize=13)
    ax.set_title(f"Confusion Matrix — {model_name} ({split})", fontsize=14)

    # Add text annotations
    for i in range(2):
        for j in range(2):
            text_color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    fontsize=16, fontweight="bold", color=text_color)

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(output_dir / f"confusion_{model_name.lower()}_{split}.png", dpi=150)
    plt.close(fig)


def run_shap_analysis(model, model_name: str, X, vocab: dict[str, int],
                      output_dir: Path, n_samples: int = 5000) -> None:
    """Run SHAP TreeExplainer on a sample and save top features."""
    if not HAS_SHAP:
        print(f"  Skipping SHAP for {model_name} (shap not installed)", flush=True)
        return

    print(f"  Running SHAP for {model_name} ({n_samples} samples)…", flush=True)
    started = time.monotonic()

    # Sample rows
    n_total = X.shape[0]
    if n_total > n_samples:
        rng = np.random.RandomState(42)
        indices = rng.choice(n_total, n_samples, replace=False)
        X_sample = X[indices]
    else:
        X_sample = X

    try:
        if model_name == "LightGBM" and isinstance(model, lgb.Booster):
            explainer = shap.TreeExplainer(model)
        else:
            explainer = shap.TreeExplainer(model)

        shap_values = explainer.shap_values(X_sample)

        # For binary classification, take class 1 shap values
        if isinstance(shap_values, list) and len(shap_values) == 2:
            shap_values = shap_values[1]

        # Mean absolute SHAP values per feature
        mean_abs_shap = np.abs(shap_values).mean(axis=0)

        idx_to_token = {v: k for k, v in vocab.items()}
        shap_rows = sorted(
            [(idx_to_token.get(i, f"col_{i}"), float(mean_abs_shap[i]))
             for i in range(len(mean_abs_shap)) if mean_abs_shap[i] > 0],
            key=lambda x: -x[1],
        )

        # Save top 30
        shap_path = output_dir / f"shap_{model_name.lower()}_top30.csv"
        with shap_path.open("w") as f:
            f.write("rank,token,mean_abs_shap\n")
            for rank, (token, value) in enumerate(shap_rows[:30], 1):
                f.write(f"{rank},{token},{value:.8f}\n")

        elapsed = time.monotonic() - started
        print(f"  SHAP {model_name}: {len(shap_rows)} features, "
              f"top={shap_rows[0][0] if shap_rows else 'N/A'}, "
              f"{elapsed:.1f}s", flush=True)

    except Exception as exc:
        print(f"  WARNING: SHAP failed for {model_name}: {exc}", file=sys.stderr)


def build_importance_comparison(output_dir: Path) -> None:
    """Merge feature importance CSVs into one comparison table."""
    models = {"rf": "RF_MDI", "xgb": "XGB_Gain", "lgbm": "LGBM_Gain"}
    all_features: dict[str, dict[str, float]] = {}

    for prefix, col_name in models.items():
        path = output_dir / f"{prefix}_feature_importances.csv"
        if not path.exists():
            continue
        with path.open() as f:
            next(f)  # skip header
            for line in f:
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    token, imp = parts[0], float(parts[1])
                    all_features.setdefault(token, {})[col_name] = imp

    if not all_features:
        return

    # Sort by max importance across models
    sorted_features = sorted(
        all_features.items(),
        key=lambda x: max(x[1].values()),
        reverse=True,
    )

    comp_path = output_dir / "feature_importance_comparison.csv"
    col_names = list(models.values())
    with comp_path.open("w") as f:
        f.write("token," + ",".join(col_names) + "\n")
        for token, vals in sorted_features:
            row = [str(vals.get(col, 0.0)) for col in col_names]
            f.write(f"{token},{','.join(row)}\n")

    print(f"  Saved feature_importance_comparison.csv "
          f"({len(sorted_features)} features)", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=None,
                        help="directory with vocab.json + matrix/")
    parser.add_argument("--model-dir", type=Path, default=Path("results"),
                        help="directory with trained model files")
    parser.add_argument("--output-dir", type=Path, default=Path("results"),
                        help="output directory for evaluation results")
    parser.add_argument("--shap-samples", type=int, default=5000,
                        help="number of samples for SHAP analysis (default: 5000)")
    parser.add_argument("--skip-shap", action="store_true",
                        help="skip SHAP analysis")
    args = parser.parse_args()

    input_dir = args.input_dir or _detect_input_dir()
    output_dir = validate_output_path(args.output_dir, [input_dir])
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Input: {input_dir}", flush=True)
    print(f"Models: {args.model_dir}", flush=True)
    print(f"Output: {output_dir}", flush=True)

    # Load vocab
    vocab, provenance = load_training_bundle(input_dir, splits=('val', 'test'))
    print(f"Vocab: {len(vocab):,} tokens\n", flush=True)

    # Load models
    print("Loading models…", flush=True)
    models = load_models(args.model_dir)
    if not models:
        print("ERROR: no trained models found", file=sys.stderr)
        return 1
    for name in models:
        prefix = {'RF': 'rf', 'XGBoost': 'xgb', 'LightGBM': 'lgbm'}[name]
        log = json.loads((args.model_dir / f'{prefix}_training_log.json').read_text())
        if any(log.get(key) != value for key, value in provenance.items()):
            raise ValueError(f'{name} was trained with a different vocabulary or split')
    print(f"Loaded {len(models)} models: {', '.join(models.keys())}\n", flush=True)

    # Evaluate on val and test
    all_metrics: list[dict] = []
    validation_thresholds: dict[str, float] = {}

    for split in ("val", "test"):
        print(f"{'='*60}", flush=True)
        print(f"Evaluating on {split} set", flush=True)
        print(f"{'='*60}", flush=True)

        try:
            X, y = load_data(input_dir, split)
        except FileNotFoundError:
            print(f"  WARNING: {split} data not found, skipping", file=sys.stderr)
            continue

        print(f"  {split}: {X.shape}, pos={y.sum():,}/{len(y):,}\n", flush=True)

        split_results: dict[str, dict] = {}

        for name, model in models.items():
            print(f"  --- {name} ---", flush=True)
            metrics, y_proba, prec, rec, fpr, tpr = evaluate_model(
                model, name, X, y, vocab, split, validation_thresholds.get(name),
            )
            validation_thresholds[name] = metrics["threshold"]
            all_metrics.append(metrics)
            split_results[name] = {
                "metrics": metrics,
                "precision_arr": prec,
                "recall_arr": rec,
                "fpr_arr": fpr,
                "tpr_arr": tpr,
            }

            print(f"  PR-AUC={metrics['pr_auc']:.6f}  "
                  f"ROC-AUC={metrics['roc_auc']:.6f}  "
                  f"F1={metrics['f1']:.4f}  "
                  f"Recall@1%FPR={metrics['recall_at_1pct_fpr']:.4f}", flush=True)
            print(f"  CM: TP={metrics['confusion_matrix']['tp']:,} "
                  f"FP={metrics['confusion_matrix']['fp']:,} "
                  f"FN={metrics['confusion_matrix']['fn']:,} "
                  f"TN={metrics['confusion_matrix']['tn']:,}\n", flush=True)

            # Plot confusion matrix
            plot_confusion_matrix(metrics["confusion_matrix"], name, output_dir, split)

        # Plot combined curves
        plot_pr_curves(split_results, output_dir, split)
        plot_roc_curves(split_results, output_dir, split)

    # SHAP analysis on val set
    if not args.skip_shap:
        print(f"\n{'='*60}", flush=True)
        print("SHAP Analysis", flush=True)
        print(f"{'='*60}", flush=True)
        try:
            X_val, y_val = load_data(input_dir, "val")
            for name, model in models.items():
                run_shap_analysis(model, name, X_val, vocab, output_dir,
                                  args.shap_samples)
        except FileNotFoundError:
            print("  WARNING: val data not found, skipping SHAP", file=sys.stderr)

    # Feature importance comparison
    build_importance_comparison(output_dir)

    # Save metrics summary
    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "vocab_size": len(vocab),
        "models_evaluated": list(models.keys()),
        "metrics": all_metrics,
    }

    summary_path = output_dir / "metrics_summary.json"
    with summary_path.open("w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved metrics_summary.json", flush=True)

    # Print final comparison table
    print(f"\n{'='*80}", flush=True)
    print("FINAL RESULTS COMPARISON", flush=True)
    print(f"{'='*80}", flush=True)
    print(f"{'Model':<12} {'Split':<6} {'PR-AUC':>8} {'ROC-AUC':>8} "
          f"{'F1':>8} {'R@1%FPR':>8} {'TP':>8} {'FP':>8} {'FN':>8}", flush=True)
    print("-" * 80, flush=True)

    for m in all_metrics:
        cm = m["confusion_matrix"]
        print(f"{m['model']:<12} {m['split']:<6} {m['pr_auc']:>8.4f} "
              f"{m['roc_auc']:>8.4f} {m['f1']:>8.4f} "
              f"{m['recall_at_1pct_fpr']:>8.4f} "
              f"{cm['tp']:>8,} {cm['fp']:>8,} {cm['fn']:>8,}", flush=True)

    print(f"\nAll outputs saved to {output_dir}/", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
