from __future__ import annotations

import csv
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable

import numpy as np

try:
    import torch
    from torch.utils.data import Dataset
except ImportError as exc:
    raise RuntimeError(
        "network_dl_dataset.py cần PyTorch.\n"
        "Local: python -m pip install torch\n"
        "Kaggle: PyTorch thường đã có sẵn."
    ) from exc


class PackedNetworkDataset(Dataset):
    """
    Dataset đọc packed NPZ shards sinh bởi STEP 04D.

    Mỗi __getitem__ trả đúng một sample:
      - x_cat            [T, C]
      - x_num            [T, N]
      - x_num_missing    [T, N]
      - x_bin            [T, B]
      - delta_t_log1p    [T]
      - app_local_id     [T]
      - remote_local_id  [T]
      - label            scalar
    """

    def __init__(
        self,
        dataset_root: str | Path,
        split: str,
        *,
        cache_shards: int = 2,
    ):
        self.dataset_root = Path(dataset_root)
        self.split = split.lower().strip()
        self.cache_shards = max(1, int(cache_shards))

        if self.split not in {"train", "val", "test"}:
            raise ValueError("split must be train/val/test")

        manifest = (
            self.dataset_root
            / "split"
            / "network_sample_manifest.csv"
        )

        if not manifest.exists():
            raise FileNotFoundError(manifest)

        self.rows: list[dict[str, Any]] = []

        with manifest.open(
            "r",
            newline="",
            encoding="utf-8",
        ) as f:
            for row in csv.DictReader(f):
                if row["split"] != self.split:
                    continue

                self.rows.append({
                    "sample_id": row["sample_id"],
                    "split": row["split"],
                    "date": row["date"],
                    "hostname": row["hostname"],
                    "window_start_epoch": int(
                        row["window_start_epoch"]
                    ),
                    "chunk_index": int(row["chunk_index"]),
                    "label": int(row["label"]),
                    "event_count": int(row["event_count"]),
                    "positive_event_count": int(
                        row["positive_event_count"]
                    ),
                    "app_node_count": int(
                        row["app_node_count"]
                    ),
                    "remote_node_count": int(
                        row["remote_node_count"]
                    ),
                    "shard_file": row["shard_file"],
                    "shard_sample_index": int(
                        row["shard_sample_index"]
                    ),
                })

        if not self.rows:
            raise RuntimeError(
                f"No samples found for split={self.split}"
            )

        self._cache: OrderedDict[str, dict[str, np.ndarray]] = (
            OrderedDict()
        )

    def __len__(self) -> int:
        return len(self.rows)

    def _load_shard(
        self,
        relative_path: str,
    ) -> dict[str, np.ndarray]:
        cached = self._cache.get(relative_path)

        if cached is not None:
            self._cache.move_to_end(relative_path)
            return cached

        path = self.dataset_root / relative_path

        if not path.exists():
            raise FileNotFoundError(path)

        with np.load(path, allow_pickle=False) as z:
            shard = {
                key: z[key]
                for key in z.files
            }

        self._cache[relative_path] = shard
        self._cache.move_to_end(relative_path)

        while len(self._cache) > self.cache_shards:
            self._cache.popitem(last=False)

        return shard

    @staticmethod
    def _decode_names(arr: np.ndarray) -> list[str]:
        return [str(x) for x in arr.tolist()]

    def __getitem__(self, index: int) -> dict[str, Any]:
        row = self.rows[index]

        shard = self._load_shard(
            row["shard_file"]
        )

        i = row["shard_sample_index"]

        offsets = shard["sample_offsets"]
        start = int(offsets[i])
        end = int(offsets[i + 1])

        if end - start != row["event_count"]:
            raise RuntimeError(
                f"Manifest/shard event_count mismatch for "
                f"{row['sample_id']}"
            )

        return {
            "sample_id": row["sample_id"],
            "hostname": row["hostname"],
            "window_start_epoch":
                row["window_start_epoch"],
            "chunk_index": row["chunk_index"],
            "label": int(
                shard["sample_labels"][i]
            ),
            "event_count": end - start,
            "positive_event_count": int(
                shard["sample_positive_event_counts"][i]
            ),
            "app_node_count": int(
                shard["sample_app_node_counts"][i]
            ),
            "remote_node_count": int(
                shard["sample_remote_node_counts"][i]
            ),

            "x_cat":
                shard["x_cat"][start:end],
            "x_num":
                shard["x_num"][start:end],
            "x_num_missing":
                shard["x_num_missing"][start:end],
            "x_bin":
                shard["x_bin"][start:end],
            "delta_t_log1p":
                shard["delta_t_log1p"][start:end],
            "app_local_id":
                shard["edge_app_local"][start:end],
            "remote_local_id":
                shard["edge_remote_local"][start:end],

            "categorical_feature_names":
                self._decode_names(
                    shard[
                        "categorical_feature_names"
                    ]
                ),
            "numerical_feature_names":
                self._decode_names(
                    shard[
                        "numerical_feature_names"
                    ]
                ),
            "binary_feature_names":
                self._decode_names(
                    shard[
                        "binary_feature_names"
                    ]
                ),
        }


def collate_sequence_batch(
    batch: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Pad trong batch, không pad sẵn trên disk.

    Output:
      x_cat          [B,T,C] long
      x_num          [B,T,N] float32
      x_num_missing  [B,T,N] float32
      x_bin          [B,T,BIN] float32
      delta_t_log1p  [B,T,1] float32
      attention_mask [B,T] bool
      labels         [B] float32
      lengths        [B] long
    """

    if not batch:
        raise ValueError("Empty batch")

    lengths = torch.tensor(
        [item["event_count"] for item in batch],
        dtype=torch.long,
    )

    max_len = int(lengths.max().item())
    batch_size = len(batch)

    c = batch[0]["x_cat"].shape[1]
    n = batch[0]["x_num"].shape[1]
    b = batch[0]["x_bin"].shape[1]

    x_cat = torch.zeros(
        batch_size,
        max_len,
        c,
        dtype=torch.long,
    )

    x_num = torch.zeros(
        batch_size,
        max_len,
        n,
        dtype=torch.float32,
    )

    x_num_missing = torch.zeros(
        batch_size,
        max_len,
        n,
        dtype=torch.float32,
    )

    x_bin = torch.zeros(
        batch_size,
        max_len,
        b,
        dtype=torch.float32,
    )

    delta = torch.zeros(
        batch_size,
        max_len,
        1,
        dtype=torch.float32,
    )

    attention_mask = torch.zeros(
        batch_size,
        max_len,
        dtype=torch.bool,
    )

    labels = torch.tensor(
        [item["label"] for item in batch],
        dtype=torch.float32,
    )

    for i, item in enumerate(batch):
        length = item["event_count"]

        x_cat[i, :length] = torch.from_numpy(
            np.asarray(
                item["x_cat"],
                dtype=np.int64,
            )
        )

        x_num[i, :length] = torch.from_numpy(
            np.asarray(
                item["x_num"],
                dtype=np.float32,
            )
        )

        x_num_missing[i, :length] = (
            torch.from_numpy(
                np.asarray(
                    item["x_num_missing"],
                    dtype=np.float32,
                )
            )
        )

        x_bin[i, :length] = torch.from_numpy(
            np.asarray(
                item["x_bin"],
                dtype=np.float32,
            )
        )

        delta[i, :length, 0] = torch.from_numpy(
            np.asarray(
                item["delta_t_log1p"],
                dtype=np.float32,
            )
        )

        attention_mask[i, :length] = True

    return {
        "x_cat": x_cat,
        "x_num": x_num,
        "x_num_missing": x_num_missing,
        "x_bin": x_bin,
        "delta_t_log1p": delta,
        "attention_mask": attention_mask,
        "labels": labels,
        "lengths": lengths,
        "sample_ids": [
            item["sample_id"]
            for item in batch
        ],
        "hostnames": [
            item["hostname"]
            for item in batch
        ],
        "window_start_epoch": torch.tensor(
            [
                item["window_start_epoch"]
                for item in batch
            ],
            dtype=torch.long,
        ),
        "chunk_index": torch.tensor(
            [
                item["chunk_index"]
                for item in batch
            ],
            dtype=torch.long,
        ),
    }


def sample_to_graph_tensors(
    item: dict[str, Any],
    *,
    add_reverse_edges: bool = True,
) -> dict[str, Any]:
    """
    Common graph transport format.

    APP nodes:
      0 .. app_count-1

    REMOTE nodes:
      app_count .. app_count+remote_count-1

    Mỗi network event tạo APP -> REMOTE edge.
    Reverse edge có thể thêm để GraphSAGE/GAT message passing hai chiều.

    Node feature engineering/model specifics được để cho STEP 05C/05D.
    """

    app_count = int(item["app_node_count"])
    remote_count = int(item["remote_node_count"])

    src = np.asarray(
        item["app_local_id"],
        dtype=np.int64,
    )

    dst = (
        np.asarray(
            item["remote_local_id"],
            dtype=np.int64,
        )
        + app_count
    )

    forward = np.stack(
        [src, dst],
        axis=0,
    )

    if add_reverse_edges:
        reverse = np.stack(
            [dst, src],
            axis=0,
        )
        edge_index = np.concatenate(
            [forward, reverse],
            axis=1,
        )
    else:
        edge_index = forward

    node_type = np.concatenate([
        np.zeros(app_count, dtype=np.int64),
        np.ones(remote_count, dtype=np.int64),
    ])

    return {
        "sample_id": item["sample_id"],
        "edge_index": torch.from_numpy(edge_index),
        "node_type": torch.from_numpy(node_type),
        "num_nodes": app_count + remote_count,
        "app_node_count": app_count,
        "remote_node_count": remote_count,
        "event_x_cat": torch.from_numpy(
            np.asarray(
                item["x_cat"],
                dtype=np.int64,
            )
        ),
        "event_x_num": torch.from_numpy(
            np.asarray(
                item["x_num"],
                dtype=np.float32,
            )
        ),
        "event_x_num_missing": torch.from_numpy(
            np.asarray(
                item["x_num_missing"],
                dtype=np.float32,
            )
        ),
        "event_x_bin": torch.from_numpy(
            np.asarray(
                item["x_bin"],
                dtype=np.float32,
            )
        ),
        "delta_t_log1p": torch.from_numpy(
            np.asarray(
                item["delta_t_log1p"],
                dtype=np.float32,
            )
        ),
        "label": torch.tensor(
            float(item["label"]),
            dtype=torch.float32,
        ),
    }


def collate_graph_list(
    batch: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    STEP 05A chỉ xác nhận graph transport format.

    STEP 05C/05D sẽ quyết định PyG batching/node feature aggregation.
    """
    return [
        sample_to_graph_tensors(item)
        for item in batch
    ]
