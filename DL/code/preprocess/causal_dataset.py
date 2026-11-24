#!/usr/bin/env python3
"""PyTorch Dataset & DataLoader for Causal Triplet Sequences with Host & Network ML Features.

Extracts for each event:
  Step 1: E_incoming token bag (Thread remote create, process open, incoming edges)
  Step 2: E_parent   token bag (Parent lineage, parent image, principal, age)
  Step 3: E_current  token bag (Tokenized record: command-line AST, switches, paths, or bounded network flow)
  Labels : (is_malicious, scenario_id, stage_id) from Decoupled Sidecar Catalog
"""

from __future__ import annotations
import gzip
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Union

import torch
from torch.utils.data import Dataset, DataLoader

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = next((p for p in CURRENT_DIR.parents if (p / "AGENTS.md").is_file()), CURRENT_DIR)
for p in (CURRENT_DIR, CURRENT_DIR.parent, PROJECT_ROOT, PROJECT_ROOT / "DL/code/preprocess", PROJECT_ROOT / "DATASET/Preprocess", PROJECT_ROOT / "ML/code/preprocess"):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from dl_ecar_tokenizer import tokenize_dl_record
except ImportError:
    from DL.code.preprocess.dl_ecar_tokenizer import tokenize_dl_record

try:
    from process_context_tracker import HostProcessContextTracker, ProcessContextConfig
except ImportError:
    from ML.code.preprocess.process_context_tracker import HostProcessContextTracker, ProcessContextConfig

try:
    from label_catalog import MultiTaskLabelCatalog
except ImportError:
    from DATASET.Preprocess.label_catalog import MultiTaskLabelCatalog


class TokenVocabulary:
    """Manages string token to integer ID mapping."""

    def __init__(self, max_tokens: int = 20000):
        self.max_tokens = max_tokens
        self.tok2id: Dict[str, int] = {"<pad>": 0, "<unk>": 1, "<none>": 2}
        self.frozen = False

    @classmethod
    def from_vocab_file(cls, path: Union[str, Path], max_tokens: int = 25000) -> TokenVocabulary:
        """Loads a persisted vocabulary (e.g. dl_vocab.json or vocab.json).

        Offsets token indices by 3 to reserve 0: <pad>, 1: <unk>, 2: <none>.
        """
        vocab_path = Path(path)
        if not vocab_path.is_file():
            raise FileNotFoundError(f"Vocabulary file not found: {vocab_path}")

        with vocab_path.open("r", encoding="utf-8") as f:
            raw_vocab: Dict[str, int] = json.load(f)

        inst = cls(max_tokens=max(max_tokens, len(raw_vocab) + 10))
        for tok, raw_id in sorted(raw_vocab.items(), key=lambda x: x[1]):
            inst.tok2id[tok] = raw_id + 3
        inst.frozen = True
        return inst

    def get(self, tok: str) -> int:
        if tok in self.tok2id:
            return self.tok2id[tok]
        if not self.frozen and len(self.tok2id) < self.max_tokens:
            new_id = len(self.tok2id)
            self.tok2id[tok] = new_id
            return new_id
        return 1  # <unk>

    def __len__(self) -> int:
        return len(self.tok2id)


class CausalTripletDataset(Dataset):
    """Parses raw eCAR events into Causal Triplets of token ID bags."""

    def __init__(
        self,
        event_records: Optional[List[Dict[str, Any]]] = None,
        label_catalog: Optional[MultiTaskLabelCatalog] = None,
        vocab: Optional[TokenVocabulary] = None,
        tracker: Optional[HostProcessContextTracker] = None,
        observe_history: bool = True,
        samples: Optional[List[Dict[str, Any]]] = None,
    ):
        self.records = event_records or []
        self.catalog = label_catalog
        self.vocab = vocab or TokenVocabulary()
        self.tracker = tracker or HostProcessContextTracker(ProcessContextConfig())
        
        # If pre-extracted samples provided, use directly
        if samples is not None:
            self.samples = samples
        else:
            self.samples = []
            if self.records and self.catalog:
                self._build_triplets(observe_history)

    def _build_triplets(self, observe_history: bool):
        for record in self.records:
            if observe_history:
                self.tracker.observe(record)

            eid = record.get("id")
            is_mal, sc_id, st_id = self.catalog.lookup(eid)

            # 1. Current Event Tokens (supports both Host and FLOW records)
            tok_res = tokenize_dl_record(record)
            if isinstance(tok_res, tuple) and len(tok_res) >= 1:
                token_dict = tok_res[0]
                curr_toks = []
                for k, v_list in token_dict.items():
                    curr_toks.extend(v_list)
            else:
                curr_toks = []

            # 2. Parent & Incoming Context Tokens
            ctx_toks = self.tracker.get_context_tokens(record)
            inc_toks = [t for t in ctx_toks if "::incoming::" in t]
            parent_toks = [
                t for t in ctx_toks
                if "::parent::" in t or "::relation::lineage" in t or "::relation::path" in t
            ]

            # Convert to token IDs (add <none> if empty)
            inc_ids = [self.vocab.get(t) for t in inc_toks] if inc_toks else [2]
            parent_ids = [self.vocab.get(t) for t in parent_toks] if parent_toks else [2]
            curr_ids = [self.vocab.get(t) for t in curr_toks] if curr_toks else [2]

            self.samples.append({
                "incoming_ids": inc_ids,
                "parent_ids": parent_ids,
                "current_ids": curr_ids,
                "is_malicious": is_mal,
                "scenario_id": sc_id,
                "stage_id": st_id,
            })

    def split(
        self,
        train_ratio: float = 0.8,
        seed: int = 42,
        stratify: bool = True,
    ) -> Tuple[CausalTripletDataset, CausalTripletDataset]:
        """Split dataset into train and val splits while keeping token vocab synced."""
        from sklearn.model_selection import train_test_split
        strat = [s["is_malicious"] for s in self.samples] if stratify else None
        train_s, val_s = train_test_split(
            self.samples, train_size=train_ratio, random_state=seed, stratify=strat
        )
        return (
            CausalTripletDataset(samples=train_s, vocab=self.vocab),
            CausalTripletDataset(samples=val_s, vocab=self.vocab),
        )

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return self.samples[idx]


def collate_causal_batch(batch: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
    """Collates a list of samples into flat 1D token tensors and offsets for EmbeddingBag.

    For each event i in batch, we append:
      Step 1: incoming_ids
      Step 2: parent_ids
      Step 3: current_ids
    Total steps in batch = len(batch) * 3
    """
    all_token_ids: List[int] = []
    offsets: List[int] = []

    labels_bin: List[float] = []
    labels_sc: List[int] = []
    labels_st: List[int] = []

    curr_offset = 0

    for sample in batch:
        labels_bin.append(float(sample["is_malicious"]))
        labels_sc.append(sample["scenario_id"])
        labels_st.append(sample["stage_id"])

        for step_key in ("incoming_ids", "parent_ids", "current_ids"):
            ids = sample[step_key]
            offsets.append(curr_offset)
            all_token_ids.extend(ids)
            curr_offset += len(ids)

    return {
        "token_ids": torch.tensor(all_token_ids, dtype=torch.long),
        "offsets": torch.tensor(offsets, dtype=torch.long),
        "batch_size": len(batch),
        "target_binary": torch.tensor(labels_bin, dtype=torch.float),
        "target_scenario": torch.tensor(labels_sc, dtype=torch.long),
        "target_stage": torch.tensor(labels_st, dtype=torch.long),
    }
