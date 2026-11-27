#!/usr/bin/env python3
"""Host ML (LightGBM OpTC Seed-02) inference microservice."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
import lightgbm as lgb
import numpy as np
from pydantic import BaseModel, Field
from scipy import sparse

from shared.causal_runtime import extract_stream_features

MODEL_PATH = Path(os.environ.get("ML_MODEL_PATH", "/models/ml/model-slot-1.txt"))
VOCAB_PATH = Path(os.environ.get("ML_VOCAB_PATH", "/models/ml/vocab.json"))
DEFAULT_THRESHOLD = float(os.environ.get("ML_THRESHOLD", "0.87427"))

app = FastAPI(title="Host ML Inference Service (LightGBM OpTC)", version="1.0.0")

_STATE: Dict[str, Any] = {}


def _load_artifacts() -> None:
    if _STATE.get("loaded"):
        return
    with VOCAB_PATH.open("r", encoding="utf-8") as f:
        vocab: Dict[str, int] = json.load(f)
    booster = lgb.Booster(model_file=str(MODEL_PATH))
    width = max(int(booster.num_feature()), len(vocab))
    _STATE.update(
        {
            "loaded": True,
            "vocab": vocab,
            "width": width,
            "booster": booster,
            "num_trees": int(booster.num_trees()),
        }
    )


@app.on_event("startup")
def startup_event() -> None:
    _load_artifacts()


class PredictRequest(BaseModel):
    records: List[Dict[str, Any]] = Field(..., min_length=1)
    threshold: Optional[float] = None
    adapt_external: bool = True


def _prioritize_matched_tokens(tokens: List[str], limit: int = 12) -> List[str]:
    priority_prefixes = ("ctx::incoming::", "ctx::parent::", "shell::", "command_line::", "structure::", "action::", "object::")
    ordered = sorted(
        tokens,
        key=lambda t: (next((i for i, p in enumerate(priority_prefixes) if t.startswith(p)), 99), t),
    )
    return ordered[:limit]


@app.get("/health")
def health() -> Dict[str, Any]:
    _load_artifacts()
    return {
        "status": "ok",
        "service": "ml-service",
        "model_name": "LightGBM Host ML (OpTC Seed-02 Parent+Incoming)",
        "domain_scope": "optc_ecar",
        "num_trees": _STATE["num_trees"],
        "vocab_size": len(_STATE["vocab"]),
        "default_threshold": DEFAULT_THRESHOLD,
    }


@app.post("/predict")
def predict(req: PredictRequest) -> Dict[str, Any]:
    _load_artifacts()
    t0 = time.perf_counter()
    thr = DEFAULT_THRESHOLD if req.threshold is None else float(req.threshold)
    vocab: Dict[str, int] = _STATE["vocab"]
    width: int = _STATE["width"]
    booster: lgb.Booster = _STATE["booster"]

    features = extract_stream_features(req.records, adapt_external=req.adapt_external)
    eligible_idx: List[int] = []
    rows: List[int] = []
    cols: List[int] = []
    matched_per_item: Dict[int, List[str]] = {}
    oov_rates: Dict[int, float] = {}

    for feat in features:
        matched = [t for t in feat.ml_tokens if t in vocab]
        matched_per_item[feat.index] = _prioritize_matched_tokens(matched)
        oov_rates[feat.index] = round(
            1.0 - (len(matched) / float(len(feat.ml_tokens))) if feat.ml_tokens else 1.0,
            4,
        )
        if feat.ml_eligible:
            row_i = len(eligible_idx)
            eligible_idx.append(feat.index)
            unique_cols = sorted({vocab[t] for t in matched if 0 <= vocab[t] < width})
            rows.extend([row_i] * len(unique_cols))
            cols.extend(unique_cols)

    probs_by_idx: Dict[int, float] = {}
    if eligible_idx:
        data = np.ones(len(cols), dtype=np.float32)
        mat = sparse.csr_matrix((data, (rows, cols)), shape=(len(eligible_idx), width), dtype=np.float32)
        preds = booster.predict(mat)
        for row_i, orig_idx in enumerate(eligible_idx):
            probs_by_idx[orig_idx] = float(preds[row_i])

    outputs: List[Dict[str, Any]] = []
    mal_count = 0
    for feat in features:
        if feat.index in probs_by_idx:
            p = probs_by_idx[feat.index]
            is_mal = int(p >= thr)
            mal_count += is_mal
            note = None
        else:
            p = None
            is_mal = None
            note = (
                "out_of_domain_theia_linux"
                if feat.domain_hint == "theia_linux"
                else "non_host_event_context_only"
            )
        outputs.append(
            {
                "index": feat.index,
                "domain_hint": feat.domain_hint,
                "eligible": feat.ml_eligible,
                "prob": round(p, 6) if p is not None else None,
                "pred_binary": is_mal,
                "matched_token_count": len(matched_per_item[feat.index]),
                "matched_tokens": matched_per_item[feat.index],
                "oov_rate": oov_rates[feat.index],
                "note": note,
            }
        )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "model_name": "LightGBM Host ML (OpTC Seed-02 Parent+Incoming)",
        "threshold": thr,
        "total_events": len(features),
        "scored_events": len(eligible_idx),
        "malicious_detected": mal_count,
        "latency_ms": elapsed_ms,
        "predictions": outputs,
    }
