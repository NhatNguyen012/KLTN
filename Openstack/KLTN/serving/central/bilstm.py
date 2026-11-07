"""Inference-only BiLSTM architecture used by the approved OpTC→ATLASv2 run."""
from __future__ import annotations

import math
from typing import Any
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence


def embedding_dim(cardinality: int) -> int:
    return int(min(16, max(4, round(math.sqrt(cardinality) * 2))))


class BiLSTMBaseline(nn.Module):
    def __init__(self, *, categorical_cardinalities: list[int], numerical_dim: int = 0,
                 binary_dim: int = 1, event_dim: int = 64, hidden_dim: int = 64,
                 lstm_layers: int = 1, dropout: float = 0.2) -> None:
        super().__init__()
        self.embeddings = nn.ModuleList([
            nn.Embedding(cardinality, embedding_dim(cardinality))
            for cardinality in categorical_cardinalities
        ])
        cat_dim = sum(layer.embedding_dim for layer in self.embeddings)
        raw_event_dim = cat_dim + numerical_dim + numerical_dim + binary_dim + 1
        self.event_encoder = nn.Sequential(
            nn.Linear(raw_event_dim, event_dim), nn.LayerNorm(event_dim),
            nn.GELU(), nn.Dropout(dropout),
        )
        self.lstm = nn.LSTM(event_dim, hidden_dim, num_layers=lstm_layers,
                            batch_first=True, bidirectional=True,
                            dropout=dropout if lstm_layers > 1 else 0.0)
        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_dim * 2), nn.Linear(hidden_dim * 2, hidden_dim),
            nn.GELU(), nn.Dropout(dropout), nn.Linear(hidden_dim, 1),
        )

    def forward(self, *, x_cat: torch.Tensor, x_num: torch.Tensor,
                x_num_missing: torch.Tensor, x_bin: torch.Tensor,
                delta_t_log1p: torch.Tensor, lengths: torch.Tensor,
                attention_mask: torch.Tensor | None = None,
                return_features: bool = False, **kwargs: Any):
        cat = torch.cat([embedding(x_cat[:, :, index])
                         for index, embedding in enumerate(self.embeddings)], dim=-1)
        cat = F.dropout(cat, p=0.15, training=self.training)
        event = self.event_encoder(torch.cat(
            [cat, x_num, x_num_missing, x_bin, delta_t_log1p], dim=-1))
        packed = pack_padded_sequence(event, lengths.cpu(), batch_first=True,
                                      enforce_sorted=False)
        packed_output, (hidden, _) = self.lstm(packed)
        output, _ = pad_packed_sequence(packed_output, batch_first=True)
        final = torch.cat([hidden[-2], hidden[-1]], dim=-1)
        mask = torch.arange(output.size(1), device=lengths.device)[None, :] < lengths[:, None]
        fill = -1e4 if output.dtype in (torch.float16, torch.bfloat16) else -1e9
        masked = output.masked_fill(~mask.unsqueeze(-1), fill)

        def topk_mean(tensor: torch.Tensor, size: int) -> torch.Tensor:
            effective = max(1, min(size, int(tensor.size(1))))
            values, _ = torch.topk(tensor, k=effective, dim=1)
            valid = torch.clamp(lengths, max=effective).unsqueeze(1).unsqueeze(2)
            indices = torch.arange(effective, device=lengths.device).unsqueeze(0).unsqueeze(2)
            values = values.masked_fill(~(indices < valid), 0.0)
            return values.sum(dim=1) / valid.squeeze(1).float().clamp(min=1.0)

        pooled = 0.40 * final + 0.35 * topk_mean(masked, 3) + 0.25 * topk_mean(masked, 12)
        logits = self.classifier(pooled).squeeze(-1)
        return (logits, pooled) if return_features else logits
