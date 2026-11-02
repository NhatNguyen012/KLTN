#!/usr/bin/env python3
"""Dataset and DataLoader utilities for Network DL BiLSTM on sequence window shards.

Matches the OpTC v2 pipeline specifications with memory-efficient LRU shard caching
and shard-aware batch sampling.
"""

from __future__ import annotations

import csv
import json
import random
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import torch
from torch.utils.data import Dataset, Sampler


class PackedNetworkDataset(Dataset):
    """Memory-efficient Dataset reading sliding-window sequences from compressed .npz shards."""

    def __init__(
        self,
        dataset_root: str | Path,
        split: str,
        *,
        cache_shards: int = 2,
    ) -> None:
        self.dataset_root = Path(dataset_root)
        self.split = split.lower().strip()
        self.cache_shards = max(1, int(cache_shards))
        self.cat_idx = None
        self.drop_numeric = False
        self.zero_binary = False

        subset_file = self.dataset_root / "preprocessing" / "feature_subset.json"
        if subset_file.exists():
            cfg = json.loads(subset_file.read_text(encoding="utf-8"))
            order = cfg.get("x_cat_columns_all", [])
            keep = cfg.get("keep_categorical", order)
            if order and keep:
                self.cat_idx = [order.index(f) for f in keep if f in order]
            self.drop_numeric = bool(cfg.get("drop_numeric", False))
            self.zero_binary = bool(cfg.get("zero_binary", False))

        if self.split not in {"train", "val", "test"}:
            raise ValueError(f"Split must be train/val/test, got '{self.split}'")

        manifest = self.dataset_root / "split" / "network_sample_manifest.csv"
        if not manifest.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest}")

        self.rows: list[dict[str, Any]] = []
        with manifest.open("r", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["split"] != self.split:
                    continue
                self.rows.append({
                    "sample_id": row["sample_id"],
                    "label": int(row["label"]),
                    "event_count": int(row["event_count"]),
                    "shard_file": row["shard_file"],
                    "shard_sample_index": int(row["shard_sample_index"]),
                })

        if not self.rows:
            raise RuntimeError(f"No samples found in {manifest} for split='{self.split}'")

        self._cache: OrderedDict[str, dict[str, np.ndarray]] = OrderedDict()

    def __len__(self) -> int:
        return len(self.rows)

    def _load_shard(self, relative_path: str) -> dict[str, np.ndarray]:
        cached = self._cache.get(relative_path)
        if cached is not None:
            self._cache.move_to_end(relative_path)
            return cached

        path = self.dataset_root / relative_path
        if not path.exists():
            raise FileNotFoundError(f"Shard file not found: {path}")

        with np.load(path, allow_pickle=False) as z:
            shard = {key: z[key] for key in z.files}

        self._cache[relative_path] = shard
        self._cache.move_to_end(relative_path)
        while len(self._cache) > self.cache_shards:
            self._cache.popitem(last=False)
        return shard

    def _x_cat(self, x: np.ndarray) -> np.ndarray:
        if self.cat_idx is None:
            return x
        return x[:, self.cat_idx]

    def _x_num(self, x: np.ndarray) -> np.ndarray:
        return x[:, :0] if self.drop_numeric else x

    def _x_bin(self, x: np.ndarray) -> np.ndarray:
        return np.zeros_like(x) if self.zero_binary else x

    def __getitem__(self, index: int) -> dict[str, Any]:
        row = self.rows[index]
        shard = self._load_shard(row["shard_file"])
        i = row["shard_sample_index"]
        offsets = shard["sample_offsets"]
        start = int(offsets[i])
        end = int(offsets[i + 1])

        if end - start != row["event_count"]:
            raise RuntimeError(
                f"Manifest/shard event_count mismatch for sample {row['sample_id']}: "
                f"manifest={row['event_count']}, shard={end - start}"
            )

        return {
            "sample_id": row["sample_id"],
            "label": int(shard["sample_labels"][i]),
            "event_count": end - start,
            "x_cat": self._x_cat(shard["x_cat"][start:end]),
            "x_num": self._x_num(shard["x_num"][start:end]),
            "x_num_missing": self._x_num(shard["x_num_missing"][start:end]),
            "x_bin": self._x_bin(shard["x_bin"][start:end]),
            "delta_t_log1p": shard["delta_t_log1p"][start:end],
        }


class ReplayBufferDataset(Dataset):
    """Memory-efficient Dataset reading prototypical OpTC sequences from optc_replay_buffer.npz for Experience Replay."""

    def __init__(self, replay_buffer_path: str | Path) -> None:
        self.path = Path(replay_buffer_path)
        if not self.path.exists():
            raise FileNotFoundError(f"Replay buffer not found at {self.path}")

        z = np.load(self.path, allow_pickle=False)
        self.sample_offsets = z["sample_offsets"]
        self.sample_labels = z["sample_labels"]
        self.x_cat = z["x_cat"]
        self.x_num = z["x_num"]
        self.x_num_missing = z["x_num_missing"]
        self.x_bin = z["x_bin"]
        self.delta_t_log1p = z["delta_t_log1p"]
        self._len = len(self.sample_labels)
        self.pos_indices = np.where(self.sample_labels == 1)[0]
        self.neg_indices = np.where(self.sample_labels == 0)[0]

    def __len__(self) -> int:
        return self._len

    def __getitem__(self, index: int) -> dict[str, Any]:
        start = int(self.sample_offsets[index])
        end = int(self.sample_offsets[index + 1])
        return {
            "sample_id": f"optc_replay_{index:05d}",
            "label": int(self.sample_labels[index]),
            "event_count": end - start,
            "x_cat": self.x_cat[start:end],
            "x_num": self.x_num[start:end],
            "x_num_missing": self.x_num_missing[start:end],
            "x_bin": self.x_bin[start:end],
            "delta_t_log1p": self.delta_t_log1p[start:end],
        }

    def sample_batch(self, n_samples: int, pos_ratio: float = 0.5) -> list[dict[str, Any]]:
        """Stratified sample with specified positive ratio (default 50/50 balance)."""
        if n_samples <= 0:
            return []
        n_pos = int(round(n_samples * pos_ratio))
        n_neg = n_samples - n_pos

        chosen_indices = []
        if len(self.pos_indices) > 0 and n_pos > 0:
            replace_pos = n_pos > len(self.pos_indices)
            chosen_pos = np.random.choice(self.pos_indices, size=n_pos, replace=replace_pos)
            chosen_indices.extend(chosen_pos.tolist())
        if len(self.neg_indices) > 0 and n_neg > 0:
            replace_neg = n_neg > len(self.neg_indices)
            chosen_neg = np.random.choice(self.neg_indices, size=n_neg, replace=replace_neg)
            chosen_indices.extend(chosen_neg.tolist())

        shortfall = n_samples - len(chosen_indices)
        if shortfall > 0:
            extra = np.random.choice(self._len, size=shortfall, replace=True)
            chosen_indices.extend(extra.tolist())

        return [self[idx] for idx in chosen_indices]


class ShardAwareBatchSampler(Sampler[list[int]]):
    """Batch sampler that batches samples within the same shard to avoid thrashing I/O."""

    def __init__(
        self,
        dataset: PackedNetworkDataset,
        batch_size: int,
        *,
        shuffle: bool = True,
        seed: int = 42,
        drop_last: bool = False,
    ) -> None:
        self.dataset = dataset
        self.batch_size = int(batch_size)
        self.shuffle = bool(shuffle)
        self.seed = int(seed)
        self.drop_last = bool(drop_last)
        self.epoch = 0

        if self.batch_size <= 0:
            raise ValueError(f"batch_size must be > 0, got {self.batch_size}")

        grouped: dict[str, list[int]] = defaultdict(list)
        for idx, row in enumerate(dataset.rows):
            grouped[row["shard_file"]].append(idx)
        self.groups = list(grouped.items())

        total = 0
        for _, indices in self.groups:
            if self.drop_last:
                total += len(indices) // self.batch_size
            else:
                total += (len(indices) + self.batch_size - 1) // self.batch_size
        self._len = total

    def set_epoch(self, epoch: int) -> None:
        self.epoch = int(epoch)

    def __len__(self) -> int:
        return self._len

    def __iter__(self) -> Iterator[list[int]]:
        rng = random.Random(self.seed + self.epoch)
        groups = [(shard, list(indices)) for shard, indices in self.groups]
        if self.shuffle:
            rng.shuffle(groups)

        for _, indices in groups:
            if self.shuffle:
                rng.shuffle(indices)
            for start in range(0, len(indices), self.batch_size):
                batch = indices[start : start + self.batch_size]
                if self.drop_last and len(batch) < self.batch_size:
                    continue
                yield batch


def collate_sequence_batch(batch: list[dict[str, Any]]) -> dict[str, Any]:
    """Collates a variable-length sequence batch into padded tensors."""
    if not batch:
        raise ValueError("Cannot collate empty batch")

    lengths = torch.tensor([x["event_count"] for x in batch], dtype=torch.long)
    max_len = int(lengths.max().item())
    bsz = len(batch)
    c = batch[0]["x_cat"].shape[1]
    n = batch[0]["x_num"].shape[1]
    binary_dim = batch[0]["x_bin"].shape[1]

    x_cat = torch.zeros(bsz, max_len, c, dtype=torch.long)
    x_num = torch.zeros(bsz, max_len, n, dtype=torch.float32)
    x_missing = torch.zeros(bsz, max_len, n, dtype=torch.float32)
    x_bin = torch.zeros(bsz, max_len, binary_dim, dtype=torch.float32)
    delta = torch.zeros(bsz, max_len, 1, dtype=torch.float32)
    mask = torch.zeros(bsz, max_len, dtype=torch.bool)
    labels = torch.tensor([x["label"] for x in batch], dtype=torch.float32)

    for i, item in enumerate(batch):
        t = item["event_count"]
        if t > 0:
            x_cat[i, :t] = torch.from_numpy(np.asarray(item["x_cat"], dtype=np.int64))
            x_num[i, :t] = torch.from_numpy(np.asarray(item["x_num"], dtype=np.float32))
            x_missing[i, :t] = torch.from_numpy(np.asarray(item["x_num_missing"], dtype=np.float32))
            x_bin[i, :t] = torch.from_numpy(np.asarray(item["x_bin"], dtype=np.float32))
            delta[i, :t, 0] = torch.from_numpy(np.asarray(item["delta_t_log1p"], dtype=np.float32))
            mask[i, :t] = True

    return {
        "x_cat": x_cat,
        "x_num": x_num,
        "x_num_missing": x_missing,
        "x_bin": x_bin,
        "delta_t_log1p": delta,
        "attention_mask": mask,
        "labels": labels,
        "lengths": lengths,
        "sample_ids": [x["sample_id"] for x in batch],
    }
