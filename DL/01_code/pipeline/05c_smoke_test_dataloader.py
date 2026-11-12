from __future__ import annotations

import argparse
from pathlib import Path

import torch
from torch.utils.data import DataLoader

from network_dl_dataset import (
    PackedNetworkDataset,
    collate_graph_list,
    collate_sequence_batch,
)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset-root",
        required=True,
    )
    parser.add_argument(
        "--split",
        default="train",
        choices=["train", "val", "test"],
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
    )
    parser.add_argument(
        "--cache-shards",
        type=int,
        default=2,
    )

    args = parser.parse_args()

    dataset = PackedNetworkDataset(
        args.dataset_root,
        args.split,
        cache_shards=args.cache_shards,
    )

    print("=" * 92)
    print("STEP 05A — PyTorch DataLoader smoke test")
    print("=" * 92)
    print(f"[SPLIT] {args.split}")
    print(f"[SAMPLES] {len(dataset):,}")

    sequence_loader = DataLoader(
        dataset,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=0,
        collate_fn=collate_sequence_batch,
    )

    batch = next(
        iter(sequence_loader)
    )

    print()
    print("[SEQUENCE BATCH]")
    print(
        "x_cat         ",
        tuple(batch["x_cat"].shape),
        batch["x_cat"].dtype,
    )
    print(
        "x_num         ",
        tuple(batch["x_num"].shape),
        batch["x_num"].dtype,
    )
    print(
        "x_num_missing ",
        tuple(
            batch[
                "x_num_missing"
            ].shape
        ),
    )
    print(
        "x_bin         ",
        tuple(batch["x_bin"].shape),
    )
    print(
        "delta_t       ",
        tuple(
            batch[
                "delta_t_log1p"
            ].shape
        ),
    )
    print(
        "attention_mask",
        tuple(
            batch[
                "attention_mask"
            ].shape
        ),
    )
    print(
        "labels        ",
        tuple(batch["labels"].shape),
        batch["labels"].tolist(),
    )
    print(
        "lengths       ",
        batch["lengths"].tolist(),
    )

    assert (
        batch["x_cat"].shape[:2]
        == batch["attention_mask"].shape
    )
    assert (
        batch["x_num"].shape[:2]
        == batch["attention_mask"].shape
    )
    assert (
        batch["labels"].shape[0]
        == args.batch_size
    )

    graph_loader = DataLoader(
        dataset,
        batch_size=min(
            4,
            args.batch_size,
        ),
        shuffle=False,
        num_workers=0,
        collate_fn=collate_graph_list,
    )

    graphs = next(
        iter(graph_loader)
    )

    print()
    print("[GRAPH TRANSPORT BATCH]")

    for i, graph in enumerate(
        graphs[:3]
    ):
        print(
            f"graph[{i}] "
            f"nodes={graph['num_nodes']} "
            f"edges={graph['edge_index'].shape[1]} "
            f"label={graph['label'].item():.0f}"
        )

        assert (
            graph[
                "edge_index"
            ].shape[0] == 2
        )

        if (
            graph[
                "edge_index"
            ].numel()
        ):
            assert int(
                graph[
                    "edge_index"
                ].max()
            ) < graph["num_nodes"]

    print()
    print("[PASS] DataLoader + sequence collate + graph transport smoke test")


if __name__ == "__main__":
    main()
