#!/usr/bin/env python3
"""Host DL (ExpandableMixHeadCausalIL: OpTC + THEIA Unified) inference microservice."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field
import torch
import torch.nn as nn
import torch.nn.functional as F

from shared.causal_runtime import extract_stream_features

CKPT_PATH = Path(os.environ.get("DL_CKPT_PATH", "/models/dl/theia_mixhead_il_best.pt"))
VOCAB_PATH = Path(os.environ.get("DL_VOCAB_PATH", "/models/dl/extended_dl_vocab.json"))
DEFAULT_THRESHOLD = float(os.environ.get("DL_THRESHOLD", "0.50"))

app = FastAPI(title="Host DL Inference Service (ExpandableMixHeadCausalIL)", version="1.0.0")
_STATE: Dict[str, Any] = {}


class PeterBloemMultiHeadSelfAttention(nn.Module):
    def __init__(self, embed_dim: int = 128, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads
        self.to_keys = nn.Linear(embed_dim, embed_dim, bias=False)
        self.to_queries = nn.Linear(embed_dim, embed_dim, bias=False)
        self.to_values = nn.Linear(embed_dim, embed_dim, bias=False)
        self.unify_heads = nn.Linear(embed_dim, embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor):
        b, t, d = x.size()
        h, s = self.num_heads, self.head_dim
        queries = self.to_queries(x).view(b, t, h, s).transpose(1, 2)
        keys = self.to_keys(x).view(b, t, h, s).transpose(1, 2)
        values = self.to_values(x).view(b, t, h, s).transpose(1, 2)
        scores = torch.matmul(queries, keys.transpose(-2, -1)) / math.sqrt(s)
        attn_weights = F.softmax(scores, dim=-1)
        out = torch.matmul(self.dropout(attn_weights), values).transpose(1, 2).contiguous().view(b, t, d)
        return self.unify_heads(out), attn_weights


class TransformerCausalBlock(nn.Module):
    def __init__(self, embed_dim: int = 128, num_heads: int = 4, ff_dim: int = 256, dropout: float = 0.1):
        super().__init__()
        self.attention = PeterBloemMultiHeadSelfAttention(embed_dim, num_heads=num_heads, dropout=dropout)
        self.norm1 = nn.LayerNorm(embed_dim)
        self.norm2 = nn.LayerNorm(embed_dim)
        self.ffn = nn.Sequential(
            nn.Linear(embed_dim, ff_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ff_dim, embed_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor):
        attn_out, weights = self.attention(x)
        x = self.norm1(x + attn_out)
        x = self.norm2(x + self.ffn(x))
        return x, weights


class IncrementalLearningAdapter(nn.Module):
    def __init__(self, embed_dim: int = 128, bottleneck_dim: int = 32, dropout: float = 0.1):
        super().__init__()
        self.down_proj = nn.Linear(embed_dim, bottleneck_dim)
        self.act = nn.GELU()
        self.up_proj = nn.Linear(bottleneck_dim, embed_dim)
        self.norm = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor):
        out = self.up_proj(self.dropout(self.act(self.down_proj(x))))
        return self.norm(x + out)


class MixHeadOpTCBase(nn.Module):
    def __init__(self, vocab_size: int = 10599, embed_dim: int = 128, num_heads: int = 4, ff_dim: int = 256, num_blocks: int = 2, dropout: float = 0.1):
        super().__init__()
        self.embed_dim = embed_dim
        self.token_embedding = nn.EmbeddingBag(vocab_size, embed_dim, mode="mean", padding_idx=0)
        self.token_norm = nn.LayerNorm(embed_dim)
        self.line_embedding = nn.Embedding(3, embed_dim)
        self.blocks = nn.ModuleList([TransformerCausalBlock(embed_dim, num_heads, ff_dim, dropout) for _ in range(num_blocks)])
        self.il_adapter = IncrementalLearningAdapter(embed_dim, 32, dropout)
        self.line_pooling_attn = nn.Linear(embed_dim, 1)
        pooled_dim = embed_dim * 2
        self.binary_head = nn.Sequential(nn.Linear(pooled_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, 1))
        self.scenario_head = nn.Sequential(nn.Linear(pooled_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, 4))
        self.stage_head = nn.Sequential(nn.Linear(pooled_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, 10))

    def forward_base_features(self, token_ids: torch.Tensor):
        b, n_lines, l_max = token_ids.shape
        x = self.token_norm(self.token_embedding(token_ids.reshape(b * n_lines, l_max))).view(b, n_lines, self.embed_dim)
        line_ids = torch.tensor([0, 1, 2], device=x.device).unsqueeze(0).expand(b, -1)
        x = x + self.line_embedding(line_ids)
        attn_maps = []
        for block in self.blocks:
            x, w = block(x)
            attn_maps.append(w)
        x = self.il_adapter(x)
        w_base = F.softmax(self.line_pooling_attn(x), dim=1)
        h_base = torch.cat([(x * w_base).sum(dim=1), x[:, 2, :]], dim=-1)
        return x, h_base, attn_maps, w_base.squeeze(-1)


class ExpandableMixHeadCausalIL(MixHeadOpTCBase):
    def __init__(self, vocab_size: int, embed_dim: int = 128, num_heads: int = 4, ff_dim: int = 256, num_blocks: int = 2, num_scenarios: int = 6, num_stages: int = 14, dropout: float = 0.1):
        super().__init__(vocab_size=vocab_size, embed_dim=embed_dim, num_heads=num_heads, ff_dim=ff_dim, num_blocks=num_blocks, dropout=dropout)
        self.num_scenarios = num_scenarios
        self.num_stages = num_stages
        self.domain_blocks = nn.ModuleList([TransformerCausalBlock(embed_dim, num_heads, ff_dim, dropout)])
        self.domain_norm = nn.LayerNorm(embed_dim)
        self.domain_pooling_attn = nn.Linear(embed_dim, 1)
        dom_dim = embed_dim * 4
        self.delta_binary_head = nn.Sequential(nn.Linear(dom_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, 1))
        self.delta_scenario_head = nn.Sequential(nn.Linear(dom_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, num_scenarios))
        self.delta_stage_head = nn.Sequential(nn.Linear(dom_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, num_stages))
        self.gate_bin = nn.Parameter(torch.zeros(()))
        self.gate_sc = nn.Parameter(torch.zeros(()))
        self.gate_st = nn.Parameter(torch.zeros(()))

    def forward(self, token_ids: torch.Tensor):
        x_base, h_base, attn_maps, lw_base = self.forward_base_features(token_ids)
        z_bin_base = self.binary_head(h_base).squeeze(-1)
        z_sc_base = self.scenario_head(h_base)
        z_st_base = self.stage_head(h_base)

        x_dom = x_base
        for blk in self.domain_blocks:
            x_dom, w_dom = blk(x_dom)
            attn_maps.append(w_dom)
        x_dom = self.domain_norm(x_dom)
        w_dom_pool = F.softmax(self.domain_pooling_attn(x_dom), dim=1)
        pooled_dom = (x_dom * w_dom_pool).sum(dim=1)
        h_dom = torch.cat([pooled_dom, x_dom[:, 0, :], x_dom[:, 1, :], x_dom[:, 2, :]], dim=-1)

        binary_logits = z_bin_base + self.gate_bin * self.delta_binary_head(h_dom).squeeze(-1)
        sc_pad_fill = z_sc_base.min(dim=-1, keepdim=True).values - 5.0
        sc_ext_base = torch.cat([z_sc_base, sc_pad_fill.expand(-1, self.num_scenarios - 4)], dim=-1)
        scenario_logits = sc_ext_base + self.gate_sc * self.delta_scenario_head(h_dom)

        st_pad_fill = z_st_base.min(dim=-1, keepdim=True).values - 5.0
        st_ext_base = torch.cat([z_st_base, st_pad_fill.expand(-1, self.num_stages - 10)], dim=-1)
        stage_logits = st_ext_base + self.gate_st * self.delta_stage_head(h_dom)

        return {
            "binary_logits": binary_logits,
            "scenario_logits": scenario_logits,
            "stage_logits": stage_logits,
            "base_line_weights": lw_base,
            "domain_line_weights": w_dom_pool.squeeze(-1),
        }


def _load_artifacts() -> None:
    if _STATE.get("loaded"):
        return
    with VOCAB_PATH.open("r", encoding="utf-8") as f:
        vocab: Dict[str, int] = {str(k): int(v) for k, v in json.load(f).items()}
    ckpt = torch.load(CKPT_PATH, map_location="cpu", weights_only=False)
    sd = ckpt["model_state_dict"]
    vocab_rows = int(sd["token_embedding.weight"].shape[0])
    embed_dim = int(sd["token_embedding.weight"].shape[1])
    num_blocks = sum(1 for k in sd if k.startswith("blocks.") and k.endswith(".norm1.weight"))
    ff_dim = int(sd["blocks.0.ffn.0.weight"].shape[0])
    sc_names = {int(k): str(v) for k, v in ckpt.get("unified_scenario_names", {}).items()}
    st_names = {int(k): str(v) for k, v in ckpt.get("unified_stage_names", {}).items()}

    model = ExpandableMixHeadCausalIL(
        vocab_size=vocab_rows,
        embed_dim=embed_dim,
        num_heads=4,
        ff_dim=ff_dim,
        num_blocks=num_blocks,
        num_scenarios=len(sc_names) or 6,
        num_stages=len(st_names) or 14,
        dropout=0.1,
    )
    model.load_state_dict(sd, strict=True)
    model.eval()
    unk_id = int(vocab.get("<unk>", 1))

    _STATE.update(
        {
            "loaded": True,
            "vocab": vocab,
            "unk_id": unk_id,
            "model": model,
            "vocab_rows": vocab_rows,
            "base_vocab_size": int(ckpt.get("base_vocab_size", 10499)),
            "scenario_names": sc_names,
            "stage_names": st_names,
            "epoch": int(ckpt.get("epoch", 0)),
            "phase": str(ckpt.get("phase", "")),
            "gates": [
                round(float(model.gate_bin.detach()), 4),
                round(float(model.gate_sc.detach()), 4),
                round(float(model.gate_st.detach()), 4),
            ],
            "param_count": sum(p.numel() for p in model.parameters()),
        }
    )


@app.on_event("startup")
def startup_event() -> None:
    _load_artifacts()


class PredictRequest(BaseModel):
    records: List[Dict[str, Any]] = Field(..., min_length=1)
    threshold: Optional[float] = None
    adapt_external: bool = True


def _tokens_to_ids(toks: List[str], vocab: Dict[str, int], unk_id: int) -> tuple[List[int], int]:
    if not toks:
        return [2], 0
    ids: List[int] = []
    oov = 0
    for t in toks:
        if t in vocab:
            ids.append(vocab[t])
        else:
            ids.append(unk_id)
            oov += 1
    return ids or [2], oov


@app.get("/health")
def health() -> Dict[str, Any]:
    _load_artifacts()
    return {
        "status": "ok",
        "service": "dl-service",
        "model_name": "ExpandableMixHeadCausalIL (OpTC Domain-0 + THEIA Domain-2)",
        "domain_scope": "unified_optc_and_theia",
        "vocab_size": len(_STATE["vocab"]),
        "base_vocab_size": _STATE["base_vocab_size"],
        "param_count": _STATE["param_count"],
        "best_epoch": _STATE["epoch"],
        "best_phase": _STATE["phase"],
        "gates": _STATE["gates"],
        "default_threshold": DEFAULT_THRESHOLD,
        "unified_scenarios": _STATE["scenario_names"],
        "unified_stages": _STATE["stage_names"],
    }


@app.post("/predict")
def predict(req: PredictRequest) -> Dict[str, Any]:
    _load_artifacts()
    t0 = time.perf_counter()
    thr = DEFAULT_THRESHOLD if req.threshold is None else float(req.threshold)
    vocab: Dict[str, int] = _STATE["vocab"]
    unk_id: int = _STATE["unk_id"]
    model: ExpandableMixHeadCausalIL = _STATE["model"]
    sc_names: Dict[int, str] = _STATE["scenario_names"]
    st_names: Dict[int, str] = _STATE["stage_names"]

    features = extract_stream_features(req.records, adapt_external=req.adapt_external)
    triplets: List[List[List[int]]] = []
    oov_rates: List[float] = []
    max_len = 1

    for feat in features:
        if feat.incoming_ids_raw and feat.parent_ids_raw and feat.current_ids_raw:
            l0, o0 = feat.incoming_ids_raw, 0
            l1, o1 = feat.parent_ids_raw, 0
            l2, o2 = feat.current_ids_raw, 0
            total_toks = len(l0) + len(l1) + len(l2)
        else:
            l0, o0 = _tokens_to_ids(feat.incoming_tokens, vocab, unk_id)
            l1, o1 = _tokens_to_ids(feat.parent_tokens, vocab, unk_id)
            l2, o2 = _tokens_to_ids(feat.current_tokens, vocab, unk_id)
            total_toks = len(feat.incoming_tokens) + len(feat.parent_tokens) + len(feat.current_tokens)
        oov_rates.append(round((o0 + o1 + o2) / float(max(1, total_toks)), 4))
        max_len = max(max_len, len(l0), len(l1), len(l2))
        triplets.append([l0, l1, l2])

    b = len(triplets)
    token_ids = torch.zeros((b, 3, max_len), dtype=torch.long)
    for i, row in enumerate(triplets):
        for li, ids in enumerate(row):
            token_ids[i, li, : len(ids)] = torch.tensor(ids, dtype=torch.long)

    with torch.no_grad():
        out = model(token_ids)
        bin_probs = torch.sigmoid(out["binary_logits"]).cpu().numpy()
        sc_probs = F.softmax(out["scenario_logits"], dim=-1).cpu().numpy()
        st_probs = F.softmax(out["stage_logits"], dim=-1).cpu().numpy()
        lw_dom = out["domain_line_weights"].cpu().numpy()

    outputs: List[Dict[str, Any]] = []
    mal_count = 0
    for i, feat in enumerate(features):
        bp = float(bin_probs[i])
        is_mal = int(bp >= thr)
        mal_count += is_mal
        sc_id = int(sc_probs[i].argmax())
        st_id = int(st_probs[i].argmax())
        outputs.append(
            {
                "index": feat.index,
                "domain_hint": feat.domain_hint,
                "hostname": feat.hostname,
                "timestamp": feat.timestamp,
                "action": feat.action,
                "object": feat.object_type,
                "summary": feat.command_preview,
                "eligible": feat.dl_eligible,
                "prob": round(bp, 6),
                "pred_binary": is_mal,
                "scenario_id": sc_id,
                "scenario_name": sc_names.get(sc_id, str(sc_id)),
                "scenario_prob": round(float(sc_probs[i][sc_id]), 4),
                "stage_id": st_id,
                "stage_name": st_names.get(st_id, str(st_id)),
                "stage_prob": round(float(st_probs[i][st_id]), 4),
                "line_attention": {
                    "incoming": round(float(lw_dom[i][0]), 4),
                    "parent": round(float(lw_dom[i][1]), 4),
                    "current": round(float(lw_dom[i][2]), 4),
                },
                "lines": {
                    "incoming": feat.incoming_tokens[:10],
                    "parent": feat.parent_tokens[:10],
                    "current": feat.current_tokens[:12],
                },
                "oov_rate": oov_rates[i],
            }
        )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "model_name": "ExpandableMixHeadCausalIL (OpTC Domain-0 + THEIA Domain-2)",
        "threshold": thr,
        "total_events": len(features),
        "scored_events": len(features),
        "malicious_detected": mal_count,
        "latency_ms": elapsed_ms,
        "predictions": outputs,
    }
