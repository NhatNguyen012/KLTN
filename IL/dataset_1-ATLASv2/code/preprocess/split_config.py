#!/usr/bin/env python3
"""Dataset Partitioning Configuration (60% Train - 20% Val - 20% Test) for ATLASv2.

Enforces Supervised Binary Classification balance (both Benign 0 and Attack 1 present
in all partitions) while preventing Temporal and Scenario Data Leakage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SplitName = Literal["train", "val", "test"]

# Scenario assignments
TRAIN_SCENARIOS: list[str] = ["s1", "s2", "s3", "m1", "m2", "m4"]
VAL_SCENARIOS: list[str] = ["m3", "m5"]
TEST_SCENARIOS: list[str] = ["s4", "m6"]

# Benign background day assignments
TRAIN_BENIGN_DAYS: list[str] = ["day1", "day2", "benign-1", "benign-2"]
VAL_BENIGN_DAYS: list[str] = ["day3", "benign-3"]
TEST_BENIGN_DAYS: list[str] = ["day4", "benign-4", "day5_morning"]

# Sampling & Class Balance Settings
TARGET_BENIGN_RATIO: int = 30  # Keep 30 benign windows/events per 1 attack event (matches OpTC negative ratio)
REPLAY_RATIO: float = 0.20     # 20% replay buffer per mini-batch


@dataclass(frozen=True)
class PartitionSpec:
    split: SplitName
    scenarios: tuple[str, ...]
    benign_days: tuple[str, ...]


PARTITIONS: dict[SplitName, PartitionSpec] = {
    "train": PartitionSpec(
        split="train",
        scenarios=tuple(TRAIN_SCENARIOS),
        benign_days=tuple(TRAIN_BENIGN_DAYS),
    ),
    "val": PartitionSpec(
        split="val",
        scenarios=tuple(VAL_SCENARIOS),
        benign_days=tuple(VAL_BENIGN_DAYS),
    ),
    "test": PartitionSpec(
        split="test",
        scenarios=tuple(TEST_SCENARIOS),
        benign_days=tuple(TEST_BENIGN_DAYS),
    ),
}


def get_partition_for_scenario(scenario_name: str) -> SplitName:
    """Map scenario or benign day string to train/val/test split partition."""
    sc = scenario_name.lower().strip()
    for split, spec in PARTITIONS.items():
        if any(s in sc for s in spec.scenarios):
            return split
        if any(b in sc for b in spec.benign_days):
            return split
    # Default fallback to train for unmapped early benign
    return "train"
