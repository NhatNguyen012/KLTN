#!/usr/bin/env python3
"""Stage Mapper and Refiner for ATLASv2 Multi-stage Kill-Chain Learning.

Extends the 2-tier ground truth labeling system to output 5 discrete Kill-Chain stages:
  0: Benign (Background normal operations)
  1: Initial_Compromise (Firefox/Flash or Office/Word exploit delivery)
  2: Execution_Discovery (Meterpreter shell, cmd/powershell execution, system discovery)
  3: Lateral_Movement (Web portal sabotage on h1, victim execution on h2)
  4: Exfiltration (PDF sweeping and HTTPS C&C exfiltration via payload.exe)

Reference:
- ATLAS (USENIX Security 2021) & ATLASv2 (UIUC STS-Lab)
- APT-LMSPS (Information 2026) & DeepDist (IEEE TrustCom 2023)
- attack_senarios.md (8-step attack progression)
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

STAGE_NAMES = {
    0: "Benign",
    1: "Initial_Compromise",
    2: "Execution_Discovery",
    3: "Lateral_Movement",
    4: "Exfiltration",
}

STAGE_IDS = {name: idx for idx, name in STAGE_NAMES.items()}


class AtlasStageRefiner:
    """Loads REAPr-staged labels and resolves fine-grained Kill-Chain stages for events."""

    def __init__(self, reapr_staged_dir: str | Path) -> None:
        self.reapr_dir = Path(reapr_staged_dir)
        # guid -> (stage_name, stage_id)
        self.guid_stage_map: dict[str, tuple[str, int]] = {}
        self._load_staged_labels()

    def _load_staged_labels(self) -> None:
        label_files = sorted(self.reapr_dir.glob("*.labels"))
        for lf in label_files:
            with lf.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    continue
                header = [h.strip().lower() for h in header]
                stage_idx = header.index("stage") if "stage" in header else -1
                guid_idx = header.index("process_uuid") if "process_uuid" in header else 3
                lbl_idx = header.index("label") if "label" in header else 4

                for row in reader:
                    if len(row) > max(guid_idx, lbl_idx):
                        guid = row[guid_idx].strip().lower()
                        lbl = row[lbl_idx].strip().lower()
                        if "attack" in lbl and guid and guid != "none":
                            if stage_idx != -1 and len(row) > stage_idx:
                                stage_name = row[stage_idx].strip()
                            else:
                                stage_name = "Execution_Discovery"
                            stage_id = STAGE_IDS.get(stage_name, 2)
                            self.guid_stage_map[guid] = (stage_name, stage_id)

    def get_stage_for_guid(self, process_guid: str) -> tuple[str, int]:
        """Lookup stage name and integer ID for a process GUID."""
        guid_clean = process_guid.strip().lower()
        return self.guid_stage_map.get(guid_clean, ("Benign", 0))

    def get_stage_id(self, process_guid: str) -> int:
        """Lookup integer stage ID (0 to 4) for a process GUID."""
        return self.get_stage_for_guid(process_guid)[1]


if __name__ == "__main__":
    staged_dir = Path("/mnt/SSD_Data/optc/DATASET/ATLASv2_staged/reapr-ground-truth/atlasv2")
    refiner = AtlasStageRefiner(staged_dir)
    print(f"Loaded {len(refiner.guid_stage_map)} malicious process mappings with Kill-Chain stages.")
    # Show stage distribution
    dist: dict[str, int] = {}
    for stage_name, _ in refiner.guid_stage_map.values():
        dist[stage_name] = dist.get(stage_name, 0) + 1
    for stg, c in sorted(dist.items()):
        print(f"  Stage {stg:25s}: {c:3d} processes")
