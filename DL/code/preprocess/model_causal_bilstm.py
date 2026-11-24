#!/usr/bin/env python3
"""PyTorch BiLSTM Multi-Task Architecture over Causal Triplet with Rich Host ML Features.

Input Sequence Length: L = 3
  Step 1: E_incoming (Cross-process injection, thread remote create, open process)
  Step 2: E_parent   (Process creation context, parent image role, AST lineage)
  Step 3: E_current  (Candidate action, AST command syntax, flags, switches, operands)

Multi-Task Output Heads:
  1. Head 1 (Binary): Malicious (1) vs Benign (0)
  2. Head 2 (Scenario Attribution): Benign (0), SC1 (1), SC2 (2), SC3 (3)
  3. Head 3 (MITRE ATT&CK Stage): 10 Classes (Benign + 9 ATT&CK Tactics)
"""

from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Any


class CausalStepEmbedding(nn.Module):
    """Embeds a bag of sparse token IDs into a dense representation x_t in R^D."""

    def __init__(self, vocab_size: int = 15000, embed_dim: int = 128, dropout: float = 0.1):
        super().__init__()
        self.embedding_bag = nn.EmbeddingBag(
            vocab_size,
            embed_dim,
            mode="mean",
            padding_idx=0
        )
        self.proj = nn.Sequential(
            nn.Linear(embed_dim, embed_dim),
            nn.LayerNorm(embed_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

    def forward(self, token_ids: torch.Tensor, offsets: torch.Tensor) -> torch.Tensor:
        """Embeds a 1D sequence of token IDs using offsets for each sample/step."""
        emb = self.embedding_bag(token_ids, offsets)
        return self.proj(emb)


class BiLSTMCausalHostMultiTask(nn.Module):
    """Bidirectional LSTM over L=3 Causal Sequence with Multi-Task Prediction Heads."""

    def __init__(
        self,
        vocab_size: int = 15000,
        embed_dim: int = 128,
        hidden_dim: int = 128,
        num_layers: int = 1,
        num_scenarios: int = 4,  # Benign, SC1, SC2, SC3
        num_stages: int = 10,    # Benign + 9 MITRE ATT&CK Tactics
        dropout: float = 0.2
    ):
        super().__init__()
        self.embed_dim = embed_dim
        self.hidden_dim = hidden_dim
        self.num_scenarios = num_scenarios
        self.num_stages = num_stages

        # Step Embedder
        self.step_embedder = CausalStepEmbedding(vocab_size, embed_dim, dropout=dropout * 0.5)

        # BiLSTM Backbone: Processes sequence of length 3: [E_incoming, E_parent, E_current]
        self.bilstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True
        )

        bilstm_out_dim = hidden_dim * 2

        # Attention Pooling over the 3 steps
        self.attn = nn.Sequential(
            nn.Linear(bilstm_out_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )

        # Head 1: Binary Malicious Detection Logit
        self.binary_head = nn.Sequential(
            nn.Linear(bilstm_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1)
        )

        # Head 2: Scenario / Campaign Attribution Logits (SC1, SC2, SC3)
        self.scenario_head = nn.Sequential(
            nn.Linear(bilstm_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_scenarios)
        )

        # Head 3: MITRE ATT&CK Stage Logits
        self.stage_head = nn.Sequential(
            nn.Linear(bilstm_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_stages)
        )

    def forward_dense_steps(self, step_vectors: torch.Tensor) -> Dict[str, torch.Tensor]:
        """Forward pass when input is already dense step vectors (Batch, 3, Embed_Dim)."""
        # bilstm_out: (Batch, 3, hidden_dim * 2)
        bilstm_out, _ = self.bilstm(step_vectors)

        # Attention Weights: (Batch, 3, 1)
        attn_scores = self.attn(bilstm_out)
        attn_weights = F.softmax(attn_scores, dim=1)

        # Context Vector: (Batch, hidden_dim * 2)
        context = torch.sum(bilstm_out * attn_weights, dim=1)

        # Multi-Head Outputs
        binary_logits = self.binary_head(context).squeeze(-1)
        scenario_logits = self.scenario_head(context)
        stage_logits = self.stage_head(context)

        return {
            "binary_logits": binary_logits,
            "scenario_logits": scenario_logits,
            "stage_logits": stage_logits,
            "attn_weights": attn_weights.squeeze(-1),
            "context_vector": context
        }

    def forward(
        self,
        step_tokens_1d: torch.Tensor,
        step_offsets: torch.Tensor,
        batch_size: int
    ) -> Dict[str, torch.Tensor]:
        """End-to-end forward pass taking token bags with offsets.

        step_tokens_1d: 1D tensor containing concatenated tokens for (Batch * 3) steps
        step_offsets: starting index of each step in the 1D tensor
        batch_size: number of events in batch
        """
        # step_embeddings: (Batch * 3, Embed_Dim)
        step_embs = self.step_embedder(step_tokens_1d, step_offsets)

        # Reshape to (Batch, 3, Embed_Dim)
        step_vectors = step_embs.view(batch_size, 3, self.embed_dim)

        return self.forward_dense_steps(step_vectors)
