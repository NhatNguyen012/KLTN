#!/usr/bin/env python3
"""Regression tests for THEIA Multi-Domain Expandable IL notebook, OpTC replay bundle, and Phase A/B/C mechanics."""

from __future__ import annotations

import json
from pathlib import Path
import unittest
import zipfile

import torch

PROJECT_ROOT = Path(__file__).resolve().parents[4]
THEIA_ROOT = PROJECT_ROOT / "IL/dataset_4-THEIA"
NB_PATH = THEIA_ROOT / "code/kaggle/THEIA-MixHead-IL.ipynb"
OPT_BUNDLE_MANIFEST = THEIA_ROOT / "output/optc_il_eval/optc_bundle_manifest.json"
OPT_CKPT = PROJECT_ROOT / "DL/code/output/results/mixhead_attention_t4x2_full.pt"


def _load_nb_model_defs():
    nb = json.loads(NB_PATH.read_text(encoding="utf-8"))
    cells = ["".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"]
    # Build clean namespace with Data/Model definitions without running heavy loads
    ns: dict = {}
    env_src = cells[0].split("def locate_inputs():")[0]
    exec(env_src, ns)
    ns["UNIFIED_SCENARIO_NAMES"] = {0: "Benign", 1: "S1", 2: "S2", 3: "S3", 4: "T1", 5: "T2"}
    ns["UNIFIED_STAGE_NAMES"] = {i: f"St{i}" for i in range(14)}
    ns["THEIA_SCENARIO_OFFSET"] = 3
    ns["THEIA_STAGE_OFFSET"] = 9
    data_src = cells[1].split("theia_train_samples =")[0]
    exec(data_src, ns)
    model_src = cells[2].split("ckpt = torch.load")[0]
    exec(model_src, ns)
    return ns


class TestTheiaILArchitectureAndBundle(unittest.TestCase):
    def test_optc_replay_and_val_cover_all_8_stages(self) -> None:
        man = json.loads(OPT_BUNDLE_MANIFEST.read_text(encoding="utf-8"))
        expected_stages = {"0", "1", "2", "3", "4", "5", "6", "7", "9"}
        self.assertEqual(set(man["replay_train"]["stages"].keys()), expected_stages)
        self.assertEqual(set(man["val_eval"]["stages"].keys()), expected_stages)
        self.assertGreater(man["val_eval"]["stages"]["1"], 1000)

    def test_mixed_batch_pad_triplets_preserves_teacher_logits(self) -> None:
        ns = _load_nb_model_defs()
        pad_triplets = ns["pad_triplets"]
        theia_sample = {
            "incoming_ids": [11, 12],
            "parent_ids": [13],
            "current_ids": [14, 15, 16],
            "is_malicious": 1,
            "scenario_id": 5,
            "stage_id": 12,
            "is_optc": 0,
        }
        optc_sample = {
            "incoming_ids": [21],
            "parent_ids": [22, 23],
            "current_ids": [24],
            "is_malicious": 1,
            "scenario_id": 1,
            "stage_id": 1,
            "is_optc": 1,
            "t_bin": 4.25,
            "t_sc": [-2.0, 4.0, -1.0, -1.5],
            "t_st": [0.1] * 10,
        }
        batch = pad_triplets([theia_sample, optc_sample])
        self.assertEqual(tuple(batch["token_ids"].shape), (2, 3, 3))
        self.assertIn("teacher_bin", batch)
        self.assertAlmostEqual(float(batch["teacher_bin"][1]), 4.25, places=5)
        self.assertFalse(bool(batch["is_optc"][0]))
        self.assertTrue(bool(batch["is_optc"][1]))

    def test_expandable_mixhead_epoch0_exact_equivalence(self) -> None:
        ns = _load_nb_model_defs()
        ckpt = torch.load(OPT_CKPT, map_location="cpu", weights_only=False)
        arch = ckpt["arch"]
        teacher = ns["MixHeadOpTCBase"](
            vocab_size=int(ckpt.get("model_vocab_size", 10599)),
            embed_dim=int(arch["embed_dim"]),
            num_heads=int(arch["num_heads"]),
            ff_dim=int(arch["ff_dim"]),
            num_blocks=int(arch["num_transformer_blocks"]),
        )
        teacher.load_state_dict(ckpt["model_state_dict"], strict=True)
        teacher.eval()

        il = ns["ExpandableMixHeadCausalIL"](
            vocab_size=20969,
            embed_dim=int(arch["embed_dim"]),
            num_heads=int(arch["num_heads"]),
            ff_dim=int(arch["ff_dim"]),
            num_blocks=int(arch["num_transformer_blocks"]),
            num_scenarios=6,
            num_stages=14,
        )
        with torch.no_grad():
            own = il.state_dict()
            loaded = 0
            for k, v in ckpt["model_state_dict"].items():
                if k == "token_embedding.weight":
                    own[k][: v.shape[0]].copy_(v)
                    loaded += 1
                elif k in own and own[k].shape == v.shape:
                    own[k].copy_(v)
                    loaded += 1
            self.assertEqual(loaded, len(ckpt["model_state_dict"]))
        il.eval()

        tokens = torch.randint(1, 10499, (8, 3, 12), dtype=torch.long)
        with torch.no_grad():
            o_t, o_i = teacher(tokens), il(tokens)
        self.assertLess(float((o_i["binary_logits"] - o_t["binary_logits"]).abs().max()), 1e-6)
        self.assertLess(float((o_i["scenario_logits"][:, :4] - o_t["scenario_logits"]).abs().max()), 1e-6)
        self.assertLess(float((o_i["stage_logits"][:, :10] - o_t["stage_logits"]).abs().max()), 1e-6)
        self.assertEqual(len(o_i["attention_maps"]), int(arch["num_transformer_blocks"]) + 1)

        groups = il.param_groups()
        self.assertTrue(len(groups["new"]) > 0 and len(groups["base_upper"]) > 0 and len(groups["base_lower"]) > 0)

    def test_kaggle_bundle_contents_and_crc(self) -> None:
        zip_path = THEIA_ROOT / "output/kaggle/kaggle_theia_upload.zip"
        if zip_path.is_file():
            with zipfile.ZipFile(zip_path, "r") as zf:
                self.assertIsNone(zf.testzip())
                names = set(zf.namelist())
                self.assertIn("THEIA-MixHead-IL.ipynb", names)
                self.assertIn("mixhead_attention_t4x2_full.pt", names)
                self.assertIn("optc_il_eval/optc_replay_train.pt", names)
                self.assertIn("optc_il_eval/optc_val_eval.pt", names)
                optc_test_shards = [n for n in names if n.startswith("optc_test_shards/shard_") and n.endswith(".pt")]
                self.assertEqual(len(optc_test_shards), 125)


if __name__ == "__main__":
    unittest.main()
