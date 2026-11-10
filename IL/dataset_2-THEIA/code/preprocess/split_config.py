#!/usr/bin/env python3
"""Dataset Partitioning Configuration (Train / Val / Test) for DARPA TC E3 THEIA.

Enforces Supervised Binary Classification balance (both Benign 0 and Attack 1 present
in all partitions) while preventing Temporal and Scenario Data Leakage.
Holds out zero-day / unseen attack scenarios in Test to evaluate generalization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SplitName = Literal["train", "val", "test"]

# Scenario assignments across Train / Val / Test
# Train on Scenario 3.3 Stage 2 (exploit delivery, root privesc via tcexec, profile payload & persistence)
TRAIN_SCENARIOS: list[str] = [
    "theia_3.3_success_gatech_profile",  # 722 verified attack events: full attack lifecycle
    "theia_3.3_fail_allstate",           # ~3 attack events: fluxbox exploit probe
]

# Validate on Scenario 3.3 Stage 1 (clean probe) + Scenario 4.8 & 3.11 probes
# Provides 86 verified attack events for smooth, statistically robust F1-Plateau calibration under FPR <= 0.01
VAL_SCENARIOS: list[str] = [
    "theia_3.3_fail_gatech_clean",       # 66 verified attack events: clean payload probe
    "theia_4.8_fail",                    # 19 verified attack events: terminal & bash failed attempts
    "theia_3.11_fail",                   # 1 verified attack event: early extension probe
]

# Hold out unseen advanced persistence campaign for Test (pure Zero-Day campaign holdout)
TEST_SCENARIOS: list[str] = [
    "theia_3.11_success",                # 1,035 verified attack events: gtcache persistence & mail network recon
]

# Benign background day assignments
TRAIN_BENIGN_DAYS: list[str] = [
    "2018-04-03", "2018-04-04", "2018-04-05", "2018-04-06",  # T1 baseline
    "2018-04-09",                                            # T2 baseline
    "2018-04-10",                                            # Day 10 background (Scenario 3.3)
    "2018-04-11",                                            # Day 11 canonical clean T3 baseline
    "day10", "day11", "day3", "day4", "day5", "day6", "day9",
]

VAL_BENIGN_DAYS: list[str] = [
    "2018-04-13",  # Day 13 background (Scenario 4.8)
    "day13",
]

TEST_BENIGN_DAYS: list[str] = [
    "2018-04-12", "2018-04-14",  # Day 12 background (Scenario 3.11) & Day 14 holdout
    "day12", "day14",
]

# Sampling & Class Balance Settings
TARGET_BENIGN_RATIO: int = 30  # Keep 30 benign events per 1 attack event (matches OpTC negative ratio)
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
    return "train"

