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
from torch.nn.utils.rnn import pack_padded_sequence


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
        **kwargs: Any,
    ) -> torch.Tensor:
        """Forward pass over a batch of variable-length event sequences.

        Args:
            x_cat: (batch_size, seq_len, num_cats) categorical integer IDs
            x_num: (batch_size, seq_len, num_numerics) continuous features
            x_num_missing: (batch_size, seq_len, num_numerics) missing flags
            x_bin: (batch_size, seq_len, num_binaries) binary features
            delta_t_log1p: (batch_size, seq_len, 1) log1p(delta_t)
            lengths: (batch_size,) integer length of each sequence

        Returns:
            logits: (batch_size,) raw scalar prediction before sigmoid
        """
        cat_parts = [embedding(x_cat[:, :, i]) for i, embedding in enumerate(self.embeddings)]
        event = torch.cat([*cat_parts, x_num, x_num_missing, x_bin, delta_t_log1p], dim=-1)
        event = self.event_encoder(event)

        # Pack sequence for LSTM computation ignoring padding
        packed = pack_padded_sequence(
            event,
            lengths.cpu(),
            batch_first=True,
            enforce_sorted=False,
        )
        _, (h_n, _) = self.lstm(packed)

        # Concatenate forward and backward final hidden states: (batch_size, hidden_dim * 2)
        pooled = torch.cat([h_n[-2], h_n[-1]], dim=-1)

        # Output logit
        logits = self.classifier(pooled).squeeze(-1)
        return logits
