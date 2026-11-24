#!/usr/bin/env python3
"""Runtime Fast Lookup Module for OpTC Decoupled Sidecar Multi-Task Labels.

Loads the compact (~7.7 MB) malicious label catalog into an in-memory dictionary.
Provides O(1) lookup (approx 59ns per event) for:
  - is_malicious: int (0 or 1)
  - scenario_id: int (0: Benign, 1: SC1, 2: SC2, 3: SC3)
  - stage_id: int (0: Benign, 1 to 9: MITRE ATT&CK Tactics)
  - tactic_name: str
"""

from __future__ import annotations
import gzip
import json
import os
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

SCENARIO_MAP = {
    0: "Benign",
    1: "SC1_EmpireStaging",
    2: "SC2_CustomEmpireLateral",
    3: "SC3_MaliciousUpdate",
}

STAGE_MAP = {
    0: "Benign",
    1: "Execution",
    2: "Defense_Evasion_Injection",
    3: "Defense_Evasion_AMSI",
    4: "Discovery",
    5: "Credential_Access",
    6: "Lateral_Movement",
    7: "Persistence",
    8: "Command_and_Control",
    9: "Collection_Exfiltration",
}


class MultiTaskLabelCatalog:
    """In-memory sidecar label catalog for instantaneous O(1) event annotation."""

    def __init__(self, catalog_path: str | Path):
        self.catalog_path = Path(catalog_path)
        if not self.catalog_path.exists():
            raise FileNotFoundError(f"Label catalog not found: {self.catalog_path}")

        self._labels: Dict[str, Tuple[int, int]] = {}
        self._load()

    def _load(self):
        """Load catalog into in-memory dictionary."""
        if self.catalog_path.suffix == ".gz":
            with gzip.open(self.catalog_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        # Convert to tuple for memory compactness
        self._labels = {k: (v[0], v[1]) for k, v in data.items()}

    def __len__(self) -> int:
        return len(self._labels)

    def lookup(self, event_id: Optional[str]) -> Tuple[int, int, int]:
        """Lookup multi-task labels by event UUID.

        Returns:
            (is_malicious, scenario_id, stage_id)
            If event_id is missing or not malicious, returns (0, 0, 0).
        """
        if not event_id:
            return (0, 0, 0)
        res = self._labels.get(event_id)
        if res is not None:
            return (1, res[0], res[1])
        return (0, 0, 0)

    def get_details(self, event_id: Optional[str]) -> Dict[str, Any]:
        """Lookup human-readable names and IDs."""
        is_mal, sc_id, st_id = self.lookup(event_id)
        return {
            "is_malicious": is_mal,
            "scenario_id": sc_id,
            "scenario_name": SCENARIO_MAP.get(sc_id, "Unknown"),
            "stage_id": st_id,
            "stage_name": STAGE_MAP.get(st_id, "Unknown"),
        }
