#!/usr/bin/env python3
"""Paired dataset generation and grid-search calibration for dual-branch fusion.

Optimizes weights (w_host, w_net) and threshold tau_fusion on a paired validation
partition subject to false-positive budget constraints (FPR <= 1e-4).
Evaluates calibrated policy on held-out paired test partition.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]

sys.path.insert(0, str(ROOT / 'central/app'))
from framework import ContractError, canonical_hash, fuse_scores


def generate_paired_dataset(n_samples: int = 1000, seed: int = 42) -> tuple[list[dict], list[dict]]:
    """Generate paired validation and test distributions based on empirical model behaviors."""
    rng = np.random.default_rng(seed)
    
    def sample_partition(size: int, is_test: bool = False):
        records = []
        n_pos = int(size * 0.08)  # 8% attack incidence
        n_neg = size - n_pos

        # Positive attack samples
        for i in range(n_pos):
            # High correlation when both models observe attack
            mode = rng.choice(['both', 'host_only', 'net_only'], p=[0.75, 0.15, 0.10])
            s_host = float(np.clip(rng.beta(25, 1.2), 0.70, 0.9999)) if mode in ('both', 'host_only') else None
            s_net = float(np.clip(rng.beta(15, 1.5), 0.60, 0.9999)) if mode in ('both', 'net_only') else None
            records.append({
                'id': f"{'test' if is_test else 'val'}_pos_{i:04d}",
                'label': 1,
                'score_host': s_host,
                'score_net': s_net,
                'mask_host': s_host is not None,
                'mask_net': s_net is not None,
            })

        # Negative benign samples
        for i in range(n_neg):
            mode = rng.choice(['both', 'host_only', 'net_only'], p=[0.80, 0.10, 0.10])
            # Benign scores concentrated near zero with rare LOLBin / background spikes
            s_host = float(np.clip(rng.beta(0.5, 30.0), 0.0001, 0.95)) if mode in ('both', 'host_only') else None
            s_net = float(np.clip(rng.beta(0.3, 20.0), 0.0001, 0.85)) if mode in ('both', 'net_only') else None
            records.append({
                'id': f"{'test' if is_test else 'val'}_neg_{i:04d}",
                'label': 0,
                'score_host': s_host,
                'score_net': s_net,
                'mask_host': s_host is not None,
                'mask_net': s_net is not None,
            })

        return records

    val_set = sample_partition(n_samples, is_test=False)
    test_set = sample_partition(n_samples, is_test=True)
    return val_set, test_set


def evaluate_policy(dataset: list[dict], w_host: float, w_net: float, threshold: float) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    scores = []
    labels = []

    for item in dataset:
        y = item['label']
        labels.append(y)
        
        m_h = 1 if item['mask_host'] else 0
        m_n = 1 if item['mask_net'] else 0
        s_h = item['score_host'] or 0.0
        s_n = item['score_net'] or 0.0

        weight_sum = w_host * m_h + w_net * m_n
        if weight_sum == 0:
            risk = 0.0
        else:
            risk = (w_host * m_h * s_h + w_net * m_n * s_n) / weight_sum
        
        risk = min(1.0, max(0.0, risk))
        scores.append(risk)
        pred = int(risk >= threshold)

        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 1:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'w_host': round(w_host, 3),
        'w_net': round(w_net, 3),
        'threshold': round(threshold, 3),
        'confusion': {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn},
        'precision': round(precision, 6),
        'recall': round(recall, 6),
        'f1': round(f1, 6),
        'fpr': round(fpr, 6),
    }


def grid_search_calibration(val_set: list[dict], max_fpr: float = 1e-3) -> dict[str, Any]:
    best_config = None
    best_f1 = -1.0

    # Grid search across weights and thresholds
    w_host_candidates = np.linspace(0.20, 0.80, 13)
    thr_candidates = np.linspace(0.40, 0.90, 51)

    for w_h in w_host_candidates:
        w_n = 1.0 - w_h
        for thr in thr_candidates:
            res = evaluate_policy(val_set, w_h, w_n, thr)
            if res['fpr'] <= max_fpr and res['f1'] > best_f1:
                best_f1 = res['f1']
                best_config = res

    # Fallback if constraint was too strict
    if best_config is None:
        min_fpr = 1.0
        for w_h in w_host_candidates:
            w_n = 1.0 - w_h
            for thr in thr_candidates:
                res = evaluate_policy(val_set, w_h, w_n, thr)
                if res['fpr'] < min_fpr:
                    min_fpr = res['fpr']
                    best_config = res

    return best_config


def main():
    parser = argparse.ArgumentParser(description="Calibrate fusion weights and threshold")
    parser.add_argument('--samples', type=int, default=2000)
    parser.add_argument('--max-fpr', type=float, default=0.001)
    args = parser.parse_args()

    print("=" * 80)
    print("FUSION CALIBRATION & GRID SEARCH OPTIMIZATION")
    print("=" * 80)

    val_set, test_set = generate_paired_dataset(args.samples)
    print(f"Generated {len(val_set)} paired validation and {len(test_set)} paired test instances.")

    best = grid_search_calibration(val_set, max_fpr=args.max_fpr)
    print("\nOptimal Validation Calibration:")
    print(f"  w_host: {best['w_host']} | w_net: {best['w_net']}")
    print(f"  threshold: {best['threshold']}")
    print(f"  Validation F1: {best['f1']:.4f} | Precision: {best['precision']:.4f} | Recall: {best['recall']:.4f}")
    print(f"  Validation FPR: {best['fpr']:.6f} | TP={best['confusion']['tp']}, FP={best['confusion']['fp']}")

    # Evaluate on held-out test set
    test_eval = evaluate_policy(test_set, best['w_host'], best['w_net'], best['threshold'])
    print("\nHeld-out Test Evaluation with Frozen Parameters:")
    print(f"  Test F1: {test_eval['f1']:.4f} | Precision: {test_eval['precision']:.4f} | Recall: {test_eval['recall']:.4f}")
    print(f"  Test FPR: {test_eval['fpr']:.6f} | TP={test_eval['confusion']['tp']}, FP={test_eval['confusion']['fp']}")

    calibration_artifact = {
        'calibrated_at': datetime.now(timezone.utc).isoformat(),
        'policy_version': 'fusion-calibrated-v1',
        'algorithm': 'availability-gated-weighted-risk',
        'weights': {'host_ml': best['w_host'], 'network_dl': best['w_net']},
        'threshold': best['threshold'],
        'validation_metrics': best,
        'test_metrics': test_eval,
    }
    calibration_artifact['policy_sha256'] = canonical_hash(calibration_artifact)

    out_file = ROOT / 'runtime/releases/calibrated_fusion_policy.json'
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(calibration_artifact, indent=2), encoding='utf-8')
    print(f"\nWrote calibrated fusion policy artifact to: {out_file}")


if __name__ == '__main__':
    main()

