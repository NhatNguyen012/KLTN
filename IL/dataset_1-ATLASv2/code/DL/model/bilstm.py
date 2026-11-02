#!/usr/bin/env python3
"""BiLSTM Network DL Baseline Architecture.

Matches exactly the model architecture and layer weights from DARPA OpTC
(06d_BiLSTM_Kaggle_v2_final.ipynb) for seamless transfer and domain-incremental learning.
"""

from __future__ import annotations

import math
from typing import Any
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence


def embedding_dim(cardinality: int) -> int:
    """Calculate embedding dimension proportional to square root of cardinality."""
    return int(min(16, max(4, round(math.sqrt(cardinality) * 2))))


class BiLSTMBaseline(nn.Module):
    """Bidirectional LSTM model over sliding window sequences of network flow events."""

    def __init__(
        self,
        *,
        categorical_cardinalities: list[int],
        numerical_dim: int = 0,
        binary_dim: int = 1,
        event_dim: int = 64,
        hidden_dim: int = 64,
        lstm_layers: int = 1,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.categorical_cardinalities = categorical_cardinalities
        self.numerical_dim = numerical_dim
        self.binary_dim = binary_dim
        self.event_dim = event_dim
        self.hidden_dim = hidden_dim
        self.lstm_layers = lstm_layers

        # Categorical embeddings
        self.embeddings = nn.ModuleList([
            nn.Embedding(cardinality, embedding_dim(cardinality))
            for cardinality in categorical_cardinalities
        ])
        cat_dim = sum(emb.embedding_dim for emb in self.embeddings)

        # Raw event dimension: embeddings + numeric + missing indicators + binary + delta_t
        raw_event_dim = cat_dim + numerical_dim + numerical_dim + binary_dim + 1

        # Event encoder
        self.event_encoder = nn.Sequential(
            nn.Linear(raw_event_dim, event_dim),
            nn.LayerNorm(event_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # Bidirectional LSTM
        self.lstm = nn.LSTM(
            input_size=event_dim,
            hidden_size=hidden_dim,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0,
        )

        # Classification head with pooled bidirectional states
        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_dim * 2),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
        )

    def forward(
        self,
        *,
        x_cat: torch.Tensor,
        x_num: torch.Tensor,
        x_num_missing: torch.Tensor,
        x_bin: torch.Tensor,
        delta_t_log1p: torch.Tensor,
        lengths: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
        return_features: bool = False,
        **kwargs: Any,
    ) -> torch.Tensor | tuple[torch.Tensor, torch.Tensor]:
        """Forward pass over a batch of variable-length event sequences.

        Incorporates Anti-Dilution Pooling (Temp/task/4.md Action 3): combines final hidden
        states with time-dimension max-pooling to retain peak attack activations (e.g., C2 beacons,
        payload execution) even across long dormant windows without adding new parameters.

        Args:
            x_cat: (batch_size, seq_len, num_cats) categorical integer IDs
            x_num: (batch_size, seq_len, num_numerics) continuous features
            x_num_missing: (batch_size, seq_len, num_numerics) missing flags
            x_bin: (batch_size, seq_len, num_binaries) binary features
            delta_t_log1p: (batch_size, seq_len, 1) log1p(delta_t)
            lengths: (batch_size,) integer length of each sequence
            return_features: if True, returns tuple (logits, pooled_representation)

        Returns:
            logits: (batch_size,) raw scalar prediction before sigmoid, or (logits, pooled)
        """
        cat_parts = [embedding(x_cat[:, :, i]) for i, embedding in enumerate(self.embeddings)]
        cat_concat = torch.cat(cat_parts, dim=-1)
        # Embedding Dropout (Run 8 / Task 5.md Thay đổi 3): prevents memorizing individual process tokens (e.g. firefox.exe)
        cat_concat = F.dropout(cat_concat, p=0.15, training=self.training)
        event = torch.cat([cat_concat, x_num, x_num_missing, x_bin, delta_t_log1p], dim=-1)
        event = self.event_encoder(event)

        # Pack sequence for LSTM computation ignoring padding
        packed = pack_padded_sequence(
            event,
            lengths.cpu(),
            batch_first=True,
            enforce_sorted=False,
        )
        lstm_out_packed, (h_n, _) = self.lstm(packed)
        lstm_out, _ = pad_packed_sequence(lstm_out_packed, batch_first=True)

        # 1. Final hidden state of forward and backward LSTM: (batch_size, hidden_dim * 2)
        h_last = torch.cat([h_n[-2], h_n[-1]], dim=-1)

        # 2. Top-K Mean Pooling (k=15) over valid time dimension (Run 8 / Task 5.md Thay đổi 1)
        # Smooths out single-event outlier spikes while capturing sustained anomaly amplitude
        seq_mask = torch.arange(lstm_out.size(1), device=lengths.device)[None, :] < lengths[:, None]
        fill_val = -1e4 if lstm_out.dtype in (torch.float16, torch.bfloat16) else -1e9
        lstm_out_masked = lstm_out.masked_fill(~seq_mask.unsqueeze(-1), fill_val)

        k_steps = min(15, int(lstm_out.size(1)))
        topk_vals, _ = torch.topk(lstm_out_masked, k=k_steps, dim=1)  # (batch_size, k_steps, hidden_dim * 2)

        # Valid step mask for sequences shorter than k_steps (avoids averaging padding fill_val)
        valid_k = torch.clamp(lengths, max=k_steps).unsqueeze(1).unsqueeze(2)  # (batch_size, 1, 1)
        k_idx = torch.arange(k_steps, device=lengths.device).unsqueeze(0).unsqueeze(2)  # (1, k_steps, 1)
        valid_mask = k_idx < valid_k  # (batch_size, k_steps, 1)

        topk_vals_clean = topk_vals.masked_fill(~valid_mask, 0.0)
        h_topk_mean = topk_vals_clean.sum(dim=1) / valid_k.squeeze(1).float().clamp(min=1.0)

        # Run 8 Hybrid Pooling: context preservation + smoothed sustained anomaly activation
        pooled = 0.5 * h_last + 0.5 * h_topk_mean

        # Output logit
        logits = self.classifier(pooled).squeeze(-1)
        if return_features:
            return logits, pooled
        return logits

