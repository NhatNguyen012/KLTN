#!/usr/bin/env python3
"""End-to-End Integration Test for Causal Triplet BiLSTM Multi-Task Pipeline."""

import gzip
import json
import sys
import unittest
from pathlib import Path

import torch
import torch.optim as optim
from torch.utils.data import DataLoader

PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
DL_CODE_ROOT = PROJECT_ROOT / "DL/code"
DL_PREPROCESS_ROOT = DL_CODE_ROOT / "preprocess"

for p in (str(PROJECT_ROOT), str(DL_CODE_ROOT), str(DL_PREPROCESS_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from DATASET.Preprocess.label_catalog import MultiTaskLabelCatalog
from preprocess.causal_dataset import (
    CausalTripletDataset,
    TokenVocabulary,
    collate_causal_batch,
)
from preprocess.model_causal_bilstm import BiLSTMCausalHostMultiTask
from preprocess.trainer import MultiTaskTrainer, MultiTaskLoss


class TestCausalBiLSTMPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog_path = PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz"
        cls.catalog = MultiTaskLabelCatalog(catalog_path)

        # Load 100 sample records from SC3 sysclient0051
        sc3_file = (
            PROJECT_ROOT
            / "DATASET/DARPA-OPTC/a_new_hope_for_darpa_optc/labelling/host/ground_truths/ground_truth_corrected_sc3_evts_sysclient0051.json.gz"
        )
        cls.records = []
        with gzip.open(sc3_file, "rt") as f:
            for i, line in enumerate(f):
                if i >= 100:
                    break
                cls.records.append(json.loads(line))

    def test_causal_dataset_and_collation(self):
        vocab = TokenVocabulary(max_tokens=5000)
        dataset = CausalTripletDataset(self.records, self.catalog, vocab=vocab)
        self.assertEqual(len(dataset), 100)

        loader = DataLoader(dataset, batch_size=16, shuffle=False, collate_fn=collate_causal_batch)
        batch = next(iter(loader))

        self.assertEqual(batch["batch_size"], 16)
        # There should be 16 * 3 = 48 steps in offsets
        self.assertEqual(len(batch["offsets"]), 16 * 3)
        self.assertEqual(len(batch["target_binary"]), 16)
        self.assertEqual(len(batch["target_scenario"]), 16)
        self.assertEqual(len(batch["target_stage"]), 16)

    def test_model_forward_and_backward(self):
        vocab = TokenVocabulary(max_tokens=5000)
        dataset = CausalTripletDataset(self.records, self.catalog, vocab=vocab)
        loader = DataLoader(dataset, batch_size=16, shuffle=False, collate_fn=collate_causal_batch)
        batch = next(iter(loader))

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = BiLSTMCausalHostMultiTask(
            vocab_size=len(vocab) + 10,
            embed_dim=64,
            hidden_dim=64,
            num_scenarios=4,
            num_stages=10
        ).to(device)

        token_ids = batch["token_ids"].to(device)
        offsets = batch["offsets"].to(device)
        out = model(token_ids, offsets, batch["batch_size"])

        self.assertEqual(out["binary_logits"].shape, torch.Size([16]))
        self.assertEqual(out["scenario_logits"].shape, torch.Size([16, 4]))
        self.assertEqual(out["stage_logits"].shape, torch.Size([16, 10]))
        self.assertEqual(out["attn_weights"].shape, torch.Size([16, 3]))

        # Test trainer
        optimizer = optim.Adam(model.parameters(), lr=1e-3)
        trainer = MultiTaskTrainer(model, optimizer, device=device)
        metrics = trainer.train_epoch(loader)
        self.assertIn("train_loss", metrics)
        self.assertGreater(metrics["train_loss"], 0.0)

        val_metrics = trainer.evaluate(loader)
        self.assertIn("binary_f1", val_metrics)
        self.assertIn("scenario_f1_macro", val_metrics)
        self.assertIn("stage_f1_macro", val_metrics)


if __name__ == "__main__":
    unittest.main()
