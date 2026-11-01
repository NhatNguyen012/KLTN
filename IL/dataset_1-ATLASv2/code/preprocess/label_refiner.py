#!/usr/bin/env python3
"""Two-Tier Ground Truth Label Refinement for ATLASv2.

Resolves the 'Firefox Paradox' by intersecting REAPr process-level labels with
Temporal Cutoffs (Initial Attack Step) and Known Attack Entities (IOCs).
"""

from __future__ import annotations

import csv
import glob
from pathlib import Path
from typing import Any

try:
    from preprocess.common_schema import (
        CanonicalEvent,
        INITIAL_ATTACK_TIMESTAMPS,
        KNOWN_IOCS,
        extract_basename,
        parse_timestamp_micros,
    )
except ImportError:
    from .common_schema import (
        CanonicalEvent,
        INITIAL_ATTACK_TIMESTAMPS,
        KNOWN_IOCS,
        extract_basename,
        parse_timestamp_micros,
    )


class LabelRefiner:
    """Manages ground-truth loading from REAPr and deterministic 2-tier event labeling."""

    def __init__(self, reapr_dir: str | Path) -> None:
        self.reapr_dir = Path(reapr_dir)
        self.scenario_attack_guids: dict[str, set[str]] = {}
        self.scenario_seeds: dict[str, set[str]] = {}
        self.scenario_attack_micros: dict[str, int] = {}
        self._load_ground_truth()

    def _load_ground_truth(self) -> None:
        """Load REAPr .labels and .seeds files for all scenarios."""
        # Parse initial attack timestamps
        for sc, ts_str in INITIAL_ATTACK_TIMESTAMPS.items():
            self.scenario_attack_micros[sc] = parse_timestamp_micros(ts_str)

        label_files = sorted(self.reapr_dir.glob("*.labels"))
        for lf in label_files:
            # File format e.g.: h1-m1.labels or h2-m1.labels
            prefix = lf.stem  # 'h1-m1'
            host_part, sc_part = prefix.split("-") if "-" in prefix else ("", prefix)
            sc_key = sc_part.lower()

            if sc_key not in self.scenario_attack_guids:
                self.scenario_attack_guids[sc_key] = set()

            with lf.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 5 and "attack" in row[4].strip().lower():
                        guid = row[3].strip().lower()
                        if guid and guid != "none":
                            self.scenario_attack_guids[sc_key].add(guid)

        seed_files = sorted(self.reapr_dir.glob("*.seeds"))
        for sf in seed_files:
            prefix = sf.stem  # 'h1-m1'
            host_part, sc_part = prefix.split("-") if "-" in prefix else ("", prefix)
            sc_key = sc_part.lower()

            if sc_key not in self.scenario_seeds:
                self.scenario_seeds[sc_key] = set()

            with sf.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 3:
                        name = row[2].strip().lower()
                        self.scenario_seeds[sc_key].add(name)

    def is_event_malicious(self, event: CanonicalEvent) -> bool:
        """Evaluate two-tier labeling policy on a canonical event.
        
        Returns True (1) if event is part of verified attack chain, False (0) otherwise.
        """
        sc = event.scenario.lower().strip()
        # 1. Benign background days are 100% benign
        if "benign" in sc or sc not in INITIAL_ATTACK_TIMESTAMPS:
            return False

        # 2. Temporal gate: any event before Initial Attack Step is strictly benign
        attack_t = self.scenario_attack_micros.get(sc, 0)
        if event.timestamp < attack_t:
            return False

        # 3. Check if process is flagged by REAPr
        attack_guids = self.scenario_attack_guids.get(sc, set())
        if event.process_guid.lower() not in attack_guids:
            return False

        proc_base = extract_basename(event.process_path)

        # 4. Handle Dual-Use Process: Firefox.exe (Solve Firefox Paradox)
        if proc_base == "firefox.exe":
            if event.event_type == "FLOW_START":
                # Check destination against known C2 IPs, ports, and domains
                is_c2_ip = event.remote_ip in KNOWN_IOCS["c2_ips"]
                is_c2_port = event.remote_port in KNOWN_IOCS["c2_ports"]
                is_c2_domain = any(d in (event.target_path or "").lower() for d in KNOWN_IOCS["c2_domains"])
                # Also check against scenario-specific seeds (e.g. 10.193.66.115:8080)
                is_seed = False
                seeds = self.scenario_seeds.get(sc, set())
                for s in seeds:
                    if event.remote_ip in s or (event.remote_port > 0 and str(event.remote_port) in s):
                        is_seed = True
                        break
                return is_c2_ip or is_c2_port or is_c2_domain or is_seed

            elif event.event_type in {"FILE_WRITE", "FILE_CREATE"}:
                target_base = extract_basename(event.target_path)
                return any(mal in target_base for mal in KNOWN_IOCS["malicious_files"])

            elif event.event_type == "PROCESS_START":
                # Child process spawned by Firefox
                target_base = extract_basename(event.target_path)
                return target_base in {"cmd.exe", "powershell.exe", "payload.exe", "plugin-container.exe"}

            # Any other background event from Firefox is marked Benign
            return False

        # 5. Pure attack payloads
        if proc_base in KNOWN_IOCS["attack_processes"]:
            return True

        # 6. Attacker-controlled processes in REAPr graph (cmd, powershell, excel during attack)
        return True
