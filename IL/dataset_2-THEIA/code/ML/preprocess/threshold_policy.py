"""Validation-negative-only and F1-constrained operating points; ties are never split to meet a budget."""
from __future__ import annotations
import numpy as np


def select_fpr_threshold(negative_histogram, target_fpr=0.005):
    negative = np.asarray(negative_histogram)
    if negative.ndim != 1 or len(negative) < 2 or np.any(negative < 0):
        raise ValueError('Invalid negative histogram')
    if not 0 <= target_fpr < 1 or not negative.sum():
        raise ValueError('Need validation negatives and FPR in [0,1)')
    fp = negative[::-1].cumsum()[::-1]
    allowed = int(np.floor(target_fpr * int(negative.sum())))
    candidates = np.flatnonzero(fp <= allowed)
    if not len(candidates):
        return float(np.nextafter(1.0, np.inf)), len(negative)
    index = int(candidates[0])
    return index / (len(negative) - 1), index


def select_validation_operating_point(
    positive_histogram,
    negative_histogram,
    max_fpr: float = 0.01,
    plateau_rel_tol: float = 0.03,
):
    """Validation F1-optimal operating point under an empirical FPR ceiling with Left-Edge Plateau selection."""
    pos = np.asarray(positive_histogram)
    neg = np.asarray(negative_histogram)
    if pos.ndim != 1 or neg.ndim != 1 or len(pos) != len(neg) or len(pos) < 2:
        raise ValueError('Invalid histograms')
    total_p, total_n = int(pos.sum()), int(neg.sum())
    if not total_p or not total_n:
        raise ValueError('Need both positive and negative validation samples')
    tps, fps = pos[::-1].cumsum()[::-1], neg[::-1].cumsum()[::-1]
    f1s = 2 * tps / np.maximum(2 * tps + fps + (total_p - tps), 1)
    if max_fpr is not None and 0 < max_fpr < 1:
        allowed = int(np.floor(max_fpr * total_n))
        candidates = np.flatnonzero(fps <= allowed)
        if len(candidates):
            peak_f1 = np.max(f1s[candidates])
            if plateau_rel_tol is not None and plateau_rel_tol > 0 and peak_f1 > 0:
                plateau_candidates = candidates[f1s[candidates] >= (1.0 - plateau_rel_tol) * peak_f1]
                best = int(plateau_candidates[0])
            else:
                best = int(candidates[np.argmax(f1s[candidates])])
        else:
            best = int(np.argmax(f1s))
    else:
        if plateau_rel_tol is not None and plateau_rel_tol > 0:
            peak_f1 = np.max(f1s)
            plateau_candidates = np.flatnonzero(f1s >= (1.0 - plateau_rel_tol) * peak_f1)
            best = int(plateau_candidates[0]) if len(plateau_candidates) else int(np.argmax(f1s))
        else:
            best = int(np.argmax(f1s))
    return float(best / (len(pos) - 1)), best


def select_validation_threshold(
    y_val: np.ndarray,
    scores_val: np.ndarray,
    fpr_ceiling: float = 0.005,
    fpr_safety_margin: float = 0.0008,
    plateau_rel_tol: float = 0.03,
) -> dict:
    """Chọn ngưỡng trên tập Validation theo nguyên lý Left-Edge F1-Plateau dưới trần FPR.

    - Tuân thủ 100% Validation-Only Calibration (không chạm tới tập Test).
    - Đảm bảo FPR_val <= (fpr_ceiling - fpr_safety_margin) để chống trượt FPR sang Test.
    - Chọn cận trái (ngưỡng thấp nhất) trên vùng đỉnh phẳng F1 để bảo vệ Recall trước Domain Shift.
    """
    y_val = np.asarray(y_val, dtype=np.int32)
    scores_val = np.asarray(scores_val, dtype=np.float64)

    n_pos = int(np.sum(y_val == 1))
    n_neg = int(np.sum(y_val == 0))
    effective_fpr_cap = max(1e-5, fpr_ceiling - fpr_safety_margin)

    # Tạo lưới ngưỡng từ phân vị điểm số thực tế trên Validation
    quantiles = np.linspace(0.0, 1.0, 2000)
    candidates = np.unique(np.quantile(scores_val, quantiles))

    valid_records = []
    for thresh in candidates:
        preds = scores_val >= thresh
        tp = int(np.sum(preds & (y_val == 1)))
        fp = int(np.sum(preds & (y_val == 0)))
        fn = n_pos - tp
        fpr = fp / max(1, n_neg)

        if fpr <= effective_fpr_cap:
            precision = tp / max(1, tp + fp)
            recall = tp / max(1, n_pos)
            f1 = (2 * precision * recall) / max(1e-12, precision + recall)
            valid_records.append({
                "threshold": float(thresh),
                "f1": float(f1),
                "precision": float(precision),
                "recall": float(recall),
                "fpr": float(fpr),
                "tp": tp,
                "fp": fp,
                "fn": fn,
            })

    if not valid_records:
        # Fallback: lấy phân vị (1 - effective_fpr_cap) của tập âm tính Validation
        neg_scores = scores_val[y_val == 0]
        fallback_thresh = float(np.quantile(neg_scores, 1.0 - effective_fpr_cap))
        return {"threshold": fallback_thresh, "policy": "negative_quantile_fallback"}

    # Tìm đỉnh F1 trên Validation trong vùng thỏa mãn ngân sách FPR
    peak_f1 = max(r["f1"] for r in valid_records)
    if peak_f1 <= 0.0:
        neg_scores = scores_val[y_val == 0]
        fallback_thresh = float(np.quantile(neg_scores, 1.0 - effective_fpr_cap))
        return {"threshold": fallback_thresh, "policy": "zero_f1_fallback"}

    # Lọc các điểm nằm trên vùng đỉnh phẳng F1 (F1 >= (1 - plateau_rel_tol) * peak_f1)
    f1_floor = (1.0 - plateau_rel_tol) * peak_f1
    plateau_candidates = [r for r in valid_records if r["f1"] >= f1_floor]

    # Chọn cận trái (threshold nhỏ nhất) của vùng plateau để tối đa hóa biên độ Recall cho Test
    best_record = min(plateau_candidates, key=lambda r: r["threshold"])
    best_record["peak_val_f1"] = float(peak_f1)
    best_record["policy"] = "left_edge_f1_plateau_fpr_bounded"
    return best_record
