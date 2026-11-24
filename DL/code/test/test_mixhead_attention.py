#!/usr/bin/env python3
"""Unit and Integration Test for MixHeadSelfAttentionCausalHost."""

import sys
import unittest
from pathlib import Path

import torch

PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
DL_CODE_ROOT = PROJECT_ROOT / "DL/code"
DL_PREPROCESS_ROOT = DL_CODE_ROOT / "preprocess"

for p in (str(PROJECT_ROOT), str(DL_CODE_ROOT), str(DL_PREPROCESS_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from preprocess.model_mixhead_attention import (
    MixHeadSelfAttentionCausalHost,
    PeterBloemMultiHeadSelfAttention,
    TransformerCausalBlock,
)


class TestMixHeadSelfAttention(unittest.TestCase):
    def setUp(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = 8
        self.seq_len = 3
        self.embed_dim = 128
        self.num_heads = 4

    def test_peter_bloem_multihead_attention(self):
        mha = PeterBloemMultiHeadSelfAttention(
            embed_dim=self.embed_dim, num_heads=self.num_heads
        ).to(self.device)
        x = torch.randn(self.batch_size, self.seq_len, self.embed_dim, device=self.device)
        out, weights = mha(x)

        self.assertEqual(out.shape, (self.batch_size, self.seq_len, self.embed_dim))
        self.assertEqual(
            weights.shape, (self.batch_size, self.num_heads, self.seq_len, self.seq_len)
        )
        # Weights along last dimension must sum to 1.0 (softmax)
        sums = weights.sum(dim=-1)
        self.assertTrue(torch.allclose(sums, torch.ones_like(sums), atol=1e-5))

    def test_full_model_forward_and_backward(self):
        model = MixHeadSelfAttentionCausalHost(
            vocab_size=1000,
            embed_dim=self.embed_dim,
            num_heads=self.num_heads,
            num_transformer_blocks=2,
            num_scenarios=4,
            num_stages=10,
        ).to(self.device)

        # Create dummy batch of token_ids and offsets for 8 events (8 * 3 = 24 steps)
        num_steps = self.batch_size * 3
        tokens_per_step = 5
        token_ids = torch.randint(1, 1000, (num_steps * tokens_per_step,), device=self.device)
        offsets = torch.arange(0, num_steps * tokens_per_step, tokens_per_step, device=self.device)

        outputs = model(token_ids, offsets, self.batch_size)

        self.assertEqual(outputs["binary_logits"].shape, (self.batch_size,))
        self.assertEqual(outputs["scenario_logits"].shape, (self.batch_size, 4))
        self.assertEqual(outputs["stage_logits"].shape, (self.batch_size, 10))
        self.assertEqual(len(outputs["attention_maps"]), 2)
        self.assertEqual(outputs["line_weights"].shape, (self.batch_size, 3))

        # Backward test
        loss = (
            outputs["binary_logits"].sum()
            + outputs["scenario_logits"].sum()
            + outputs["stage_logits"].sum()
        )
        loss.backward()

        self.assertIsNotNone(model.token_embedding.weight.grad)
        self.assertIsNotNone(model.binary_head[0].weight.grad)

    def test_il_freezing(self):
        model = MixHeadSelfAttentionCausalHost(
            vocab_size=1000,
            embed_dim=self.embed_dim,
            num_heads=self.num_heads,
            enable_il_adapter=True,
        )
        model.freeze_base_for_il()

        # Token embedding and blocks must be frozen
        self.assertFalse(model.token_embedding.weight.requires_grad)
        for p in model.blocks.parameters():
            self.assertFalse(p.requires_grad)

        # IL Adapter and Heads must remain trainable
        self.assertTrue(model.il_adapter.down_proj.weight.requires_grad)
        self.assertTrue(model.binary_head[0].weight.requires_grad)


if __name__ == "__main__":
    unittest.main()
