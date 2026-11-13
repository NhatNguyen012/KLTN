# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_1-ATLASv2/code/DL/optc_il/vendor/05b_train_bilstm.py
# source sha256 39f53e3d96d8056cd5f76d8187dc4949d8b82fafe684248314c84058bee1057b; do not edit (re-run the vendoring script instead).
from __future__ import annotations

import math

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence


def embedding_dim(cardinality: int) -> int:
    return int(min(16, max(4, round(math.sqrt(cardinality) * 2))))


class BiLSTMBaseline(nn.Module):
    def __init__(
        self,
        *,
        categorical_cardinalities: list[int],
        numerical_dim: int,
        binary_dim: int = 1,
        event_dim: int = 64,
        hidden_dim: int = 64,
        lstm_layers: int = 1,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.embeddings = nn.ModuleList([
            nn.Embedding(cardinality, embedding_dim(cardinality))
            for cardinality in categorical_cardinalities
        ])
        cat_dim = sum(emb.embedding_dim for emb in self.embeddings)
        raw_event_dim = cat_dim + numerical_dim + numerical_dim + binary_dim + 1

        self.event_encoder = nn.Sequential(
            nn.Linear(raw_event_dim, event_dim),
            nn.LayerNorm(event_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.lstm = nn.LSTM(
            input_size=event_dim,
            hidden_size=hidden_dim,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0,
        )
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
    ) -> torch.Tensor:
        cat_parts = [embedding(x_cat[:, :, i]) for i, embedding in enumerate(self.embeddings)]
        event = torch.cat([*cat_parts, x_num, x_num_missing, x_bin, delta_t_log1p], dim=-1)
        event = self.event_encoder(event)
        packed = pack_padded_sequence(event, lengths.cpu(), batch_first=True, enforce_sorted=False)
        _, (h_n, _) = self.lstm(packed)
        pooled = torch.cat([h_n[-2], h_n[-1]], dim=-1)
        return self.classifier(pooled).squeeze(-1)
