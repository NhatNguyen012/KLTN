#!/usr/bin/env python3
"""Mix-Head Self-Attention Architecture for Causal Host Provenance Sequences.

Inspired by Peter Bloem's 'Transformers from Scratch' (https://peterbloem.nl/blog/transformers)
and Modular Continual Learning (Adapter-based Incremental Learning).

Architecture Overview:
  1. Input: 3 Causal Lines [E_incoming, E_parent, E_current]
  2. Line Identity & Semantic Token Bag Embeddings (nn.EmbeddingBag + LineEmbedding)
  3. Multi-Head Self-Attention Block (Peter Bloem formulation: Q, K, V projections across h heads)
  4. Residual & LayerNorm Connections (Post-LN or Pre-LN Transformer Block)
  5. Expandable Incremental Learning (IL) Adapter Layer (for Domain-Incremental transfer)
  6. Multi-Task Heads:
     - Head 1: Binary Detection
     - Head 2: Scenario Attribution
     - Head 3: MITRE ATT&CK Stages
"""

from __future__ import annotations
import math
from typing import Dict, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


class PeterBloemMultiHeadSelfAttention(nn.Module):
    """Multi-Head Self-Attention implemented directly from first principles.
    
    Reference: Peter Bloem (https://peterbloem.nl/blog/transformers)
    Section: 'Multi-head self-attention'
    """

    def __init__(self, embed_dim: int = 128, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        assert embed_dim % num_heads == 0, f"embed_dim ({embed_dim}) must be divisible by num_heads ({num_heads})"
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads

        # Key, Query, Value linear projections for all heads
        self.to_keys = nn.Linear(embed_dim, embed_dim, bias=False)
        self.to_queries = nn.Linear(embed_dim, embed_dim, bias=False)
        self.to_values = nn.Linear(embed_dim, embed_dim, bias=False)

        # Unify heads back to embed_dim
        self.unify_heads = nn.Linear(embed_dim, embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Compute multi-head self-attention.
        
        Args:
            x: Tensor of shape (batch_size, seq_len=3, embed_dim)
            
        Returns:
            (out, attention_weights)
            out: (batch_size, seq_len=3, embed_dim)
            attention_weights: (batch_size, num_heads, seq_len, seq_len)
        """
        b, t, d = x.size()
        h = self.num_heads
        s = self.head_dim

        # Project and reshape into heads: (b, t, h, s) -> transpose to (b, h, t, s)
        queries = self.to_queries(x).view(b, t, h, s).transpose(1, 2)
        keys = self.to_keys(x).view(b, t, h, s).transpose(1, 2)
        values = self.to_values(x).view(b, t, h, s).transpose(1, 2)

        # Scaled dot-product: (queries @ keys.T) / sqrt(head_dim)
        # Shape: (b, h, t, t)
        scores = torch.matmul(queries, keys.transpose(-2, -1)) / math.sqrt(s)
        attn_weights = F.softmax(scores, dim=-1)
        attn_weights_drop = self.dropout(attn_weights)

        # Weighted sum: (b, h, t, t) @ (b, h, t, s) -> (b, h, t, s)
        out = torch.matmul(attn_weights_drop, values)

        # Transpose and fold heads back: (b, t, h, s) -> (b, t, d)
        out = out.transpose(1, 2).contiguous().view(b, t, d)
        out = self.unify_heads(out)
        return out, attn_weights


class TransformerCausalBlock(nn.Module):
    """Full Transformer Block: Self-Attention + Residual/Norm + FeedForward + Residual/Norm."""

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

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        # Self-Attention + Residual + LayerNorm
        attn_out, weights = self.attention(x)
        x = self.norm1(x + attn_out)

        # FeedForward + Residual + LayerNorm
        ffn_out = self.ffn(x)
        x = self.norm2(x + ffn_out)
        return x, weights


class IncrementalLearningAdapter(nn.Module):
    """Modular Adapter Layer for Domain-Incremental Learning (IL).
    
    Allows freezing base transformer parameters while learning new domain/scenario
    variations (SC1 -> SC2 -> SC3) through a lightweight bottleneck without
    Catastrophic Forgetting.
    """

    def __init__(self, embed_dim: int = 128, bottleneck_dim: int = 32, dropout: float = 0.1):
        super().__init__()
        self.down_proj = nn.Linear(embed_dim, bottleneck_dim)
        self.act = nn.GELU()
        self.up_proj = nn.Linear(bottleneck_dim, embed_dim)
        self.norm = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Residual Bottleneck Adapter
        residual = x
        out = self.down_proj(x)
        out = self.act(out)
        out = self.dropout(out)
        out = self.up_proj(out)
        return self.norm(residual + out)


class MixHeadSelfAttentionCausalHost(nn.Module):
    """Mix-Head Self-Attention Model over 3 Causal Lines with IL Adapter Layer."""

    def __init__(
        self,
        vocab_size: int = 15000,
        embed_dim: int = 128,
        num_heads: int = 4,
        ff_dim: int = 256,
        num_transformer_blocks: int = 2,
        num_scenarios: int = 4,
        num_stages: int = 10,
        dropout: float = 0.1,
        enable_il_adapter: bool = True,
    ):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads

        # 1. Token Bag Embedder for semantic structural features
        self.token_embedding = nn.EmbeddingBag(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            mode="mean",
            padding_idx=0,
        )
        self.token_norm = nn.LayerNorm(embed_dim)

        # 2. Line Role/Position Embedding: 3 Lines (0: Incoming, 1: Parent, 2: Current)
        self.line_embedding = nn.Embedding(3, embed_dim)

        # 3. Transformer Encoder Blocks (Mix-Head Self-Attention)
        self.blocks = nn.ModuleList([
            TransformerCausalBlock(embed_dim=embed_dim, num_heads=num_heads, ff_dim=ff_dim, dropout=dropout)
            for _ in range(num_transformer_blocks)
        ])

        # 4. Incremental Learning (IL) Adapter Layer (Can be activated during domain shifts)
        self.enable_il_adapter = enable_il_adapter
        if enable_il_adapter:
            self.il_adapter = IncrementalLearningAdapter(embed_dim=embed_dim, bottleneck_dim=32, dropout=dropout)
        else:
            self.il_adapter = None

        # 5. Causal Line Pooling Attention: Aggregates [E_incoming, E_parent, E_current]
        self.line_pooling_attn = nn.Linear(embed_dim, 1)

        # 6. Multi-Task Output Heads
        pooled_dim = embed_dim * 2  # Concat pooled representation + Current Line representation

        # Head 1: Binary Detection
        self.binary_head = nn.Sequential(
            nn.Linear(pooled_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
        )

        # Head 2: Scenario Attribution (4 classes)
        self.scenario_head = nn.Sequential(
            nn.Linear(pooled_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_scenarios),
        )

        # Head 3: MITRE ATT&CK Stages (10 classes)
        self.stage_head = nn.Sequential(
            nn.Linear(pooled_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_stages),
        )

    def freeze_base_for_il(self):
        """Freeze base transformer and embedders; leave only IL adapter and heads trainable."""
        for param in self.token_embedding.parameters():
            param.requires_grad = False
        for param in self.line_embedding.parameters():
            param.requires_grad = False
        for param in self.blocks.parameters():
            param.requires_grad = False
        print("Base Transformer backbone FROZEN for Incremental Learning.")

    def forward(
        self,
        token_ids: torch.Tensor,
        offsets: torch.Tensor,
        batch_size: int,
    ) -> Dict[str, torch.Tensor]:
        """Forward pass over L=3 Causal Lines with Mix-Head Self-Attention.
        
        Args:
            token_ids: 1D Tensor of all token IDs across the batch (batch_size * 3 steps)
            offsets: 1D Tensor of offset starts in token_ids
            batch_size: Number of events in batch
        """
        # Step A: Embed all token bags
        all_step_vectors = self.token_embedding(token_ids, offsets)  # (batch_size * 3, embed_dim)
        all_step_vectors = self.token_norm(all_step_vectors)

        # Step B: Reshape to (batch_size, 3, embed_dim)
        x = all_step_vectors.view(batch_size, 3, self.embed_dim)

        # Step C: Add Causal Line Identity Embeddings [0, 1, 2]
        line_ids = torch.tensor([0, 1, 2], device=x.device).unsqueeze(0).expand(batch_size, -1)
        x = x + self.line_embedding(line_ids)

        # Step D: Pass through Mix-Head Self-Attention Transformer Blocks
        attn_maps = []
        for block in self.blocks:
            x, weights = block(x)
            attn_maps.append(weights)

        # Step E: Apply IL Adapter Layer (if enabled)
        if self.il_adapter is not None:
            x = self.il_adapter(x)

        # Step F: Extract Current Line and Pool across all 3 Lines
        # x is (batch_size, 3, embed_dim)
        current_line_repr = x[:, 2, :]  # Step 3 = Current Line

        # Attention pooling across the 3 lines
        line_weights = F.softmax(self.line_pooling_attn(x), dim=1)  # (batch_size, 3, 1)
        pooled_causal = (x * line_weights).sum(dim=1)  # (batch_size, embed_dim)

        # Combined representation
        combined = torch.cat([pooled_causal, current_line_repr], dim=-1)  # (batch_size, embed_dim * 2)

        # Step G: Multi-Task Predictions
        binary_logits = self.binary_head(combined).squeeze(-1)
        scenario_logits = self.scenario_head(combined)
        stage_logits = self.stage_head(combined)

        return {
            "binary_logits": binary_logits,
            "scenario_logits": scenario_logits,
            "stage_logits": stage_logits,
            "attention_maps": attn_maps,
            "line_weights": line_weights.squeeze(-1),
        }
