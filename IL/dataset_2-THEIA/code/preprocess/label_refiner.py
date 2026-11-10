#!/usr/bin/env python3
"""Two-Tier Ground Truth Label Refinement for DARPA TC E3 THEIA.

Resolves spurious process-level correlation by intersecting REAPr process-level labels,
event-level edge labels, temporal attack gates, and known attack infrastructure.
"""

from __future__ import annotations

import csv
from pathlib import Path
import tarfile
from typing import Any

try:
    from preprocess.common_schema import (
        CanonicalEvent,
        THEIA_ATTACK_TIMESTAMPS,
        KNOWN_IOCS,
        extract_basename,
        parse_timestamp_micros,
    )
except ImportError:
    from .common_schema import (
        CanonicalEvent,
        THEIA_ATTACK_TIMESTAMPS,
        KNOWN_IOCS,
        extract_basename,
        parse_timestamp_micros,
    )


# System libraries and files accessed normally during process startup on Linux
BENIGN_OS_LOADER_FILES = frozenset({
    "ld.so.cache", "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2",
    "librt.so.1", "libselinux.so.1", "libpcre.so.3", "locale-archive",
    "gconv-modules.cache", "libgcc_s.so.1", "libm-2.15.so", "libc-2.15.so",
    "ld-2.15.so", "libqt5gui.so.5", "libstdc++.so.6",
})

# Known malicious payloads & artifacts in THEIA E3
MALICIOUS_PAYLOAD_NAMES = frozenset({
    "clean", "profile", "allstate", "meterpreter", "nc", "netcat", "tcexec",
    "gtcache", "pass_mgr", "mail", "memtrace",
})


class LabelRefiner:
    """Manages ground-truth loading from REAPr and deterministic 2-tier event labeling for THEIA."""

    def __init__(
        self,
        reapr_dir: str | Path = "/mnt/SSD_Data/optc/DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3",
    ) -> None:
        self.reapr_dir = Path(reapr_dir)
        self.attack_process_uuids: dict[str, str] = {}  # uuid -> attack_chain
        self.attack_edge_uuids: set[str] = set()       # edge_uuid -> attack
        self.scenario_attack_micros: dict[str, int] = {}
        self._load_ground_truth()

    def _load_ground_truth(self) -> None:
        """Load REAPr theia_labels.csv and theia_edge_labels.tar.gz."""
        # 1. Parse initial attack timestamps
        for sc, ts_str in THEIA_ATTACK_TIMESTAMPS.items():
            self.scenario_attack_micros[sc] = parse_timestamp_micros(ts_str)

        # 2. Load process-level ground truth (theia_labels.csv)
        labels_file = self.reapr_dir / "theia_labels.csv"
        if labels_file.exists():
            with labels_file.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 4 and "attack" in row[3].strip().lower():
                        uuid = row[1].strip().upper()
                        chain = row[0].strip()
                        if uuid:
                            self.attack_process_uuids[uuid] = chain

        # 3. Load event-level ground truth (theia_edge_labels.tar.gz) if available
        edge_tar = self.reapr_dir / "theia_edge_labels.tar.gz"
        if edge_tar.exists():
            try:
                with tarfile.open(edge_tar, "r:gz") as tar:
                    member = tar.next()
                    if member:
                        f = tar.extractfile(member)
                        if f:
                            reader = csv.reader(line.decode("utf-8", errors="replace") for line in f)
                            header = next(reader, None)
                            for row in reader:
                                if len(row) >= 4 and "attack" in row[2].strip().lower():
                                    edge_uuid = row[3].strip().upper()
                                    if edge_uuid:
                                        self.attack_edge_uuids.add(edge_uuid)
            except Exception as e:
                print(f"Warning: Failed to load theia_edge_labels.tar.gz: {e}")

    def get_attack_chain_for_process(self, process_guid: str) -> str:
        """Return the attack chain name for a process UUID if malicious, else empty."""
        return self.attack_process_uuids.get(process_guid.strip().upper(), "")

    def is_attack_process(self, process_guid: str) -> bool:
        """Check if process UUID is part of ground-truth attack processes."""
        return process_guid.strip().upper() in self.attack_process_uuids

    def refine_event_label(self, event: CanonicalEvent) -> int:
        """Deterministic 2-tier event labeling via strict intersection:
        1. Candidate check against REAPr edge ground truth OR process ground truth.
        2. Temporal gate & causal entity verification (resolves Firefox Paradox & OS loader noise).
        """
        in_edge_gt = bool(
            event.event_id and event.event_id.strip().upper() in self.attack_edge_uuids
        )
        guid_upper = event.process_guid.strip().upper()
        in_proc_gt = guid_upper in self.attack_process_uuids

        # Step 1: Must be in at least one REAPr ground truth source
        if not in_edge_gt and not in_proc_gt:
            return 0

        # Step 2: Temporal Gate (filter out pre-attack activity)
        chain = self.attack_process_uuids.get(guid_upper, "") or event.scenario
        cutoff_micros = self.scenario_attack_micros.get(chain, 0)
        if cutoff_micros > 0 and event.timestamp < cutoff_micros:
            return 0

        # Step 3: Causal Provenance Edge Verification (applies to both edge_uuids and proc_uuids)
        base_name = extract_basename(event.process_path).lower()
        target_base = extract_basename(event.target_path).lower()

        # 3a. Filter OS loader loading standard libraries for ALL processes
        if event.event_type in ("FILE_READ", "FILE_OPEN") and target_base in BENIGN_OS_LOADER_FILES:
            return 0

        # 3b. Standalone Malicious Payload (clean, profile, allstate, gtcache, mail...)
        if any(p in base_name for p in MALICIOUS_PAYLOAD_NAMES):
            return 1

        # 3c. Weaponized Browser (Resolves Firefox Paradox)
        if "firefox" in base_name:
            if event.event_type == "FLOW_START":
                if event.remote_ip in KNOWN_IOCS["c2_ips"] or event.remote_port in KNOWN_IOCS["c2_ports"]:
                    return 1
                if event.remote_port == 22 or event.remote_port >= 4444:
                    return 1
                return 0

            if event.event_type in ("PROCESS_START", "CROSS_PROCESS"):
                if any(p in target_base for p in MALICIOUS_PAYLOAD_NAMES):
                    return 1
                if target_base in ("sh", "bash", "dash", "python"):
                    return 1
                return 0

            if event.event_type in ("FILE_WRITE", "FILE_CREATE"):
                if any(p in event.target_path for p in ("/tmp", "/home", "/etc", "/var/tmp")):
                    if any(p in target_base for p in MALICIOUS_PAYLOAD_NAMES) or target_base.endswith((".sh", ".bin")):
                        return 1
                return 0

            # Firefox reading /proc/self, /proc/<pid>/stat, SQLite cache, fonts -> Benign (0)
            return 0

        # 3d. Long-running Desktop / Window Manager (e.g. fluxbox)
        if "fluxbox" in base_name:
            if event.event_type in ("PROCESS_START", "CROSS_PROCESS"):
                if any(p in target_base for p in MALICIOUS_PAYLOAD_NAMES) or target_base in ("sh", "bash", "dash", "firefox"):
                    return 1
            return 0

        # 3e. Terminal Emulators (e.g. gnome-terminal, xterm)
        if "gnome-terminal" in base_name or "terminal" in base_name:
            if event.event_type in ("PROCESS_START", "CROSS_PROCESS"):
                if any(p in target_base for p in MALICIOUS_PAYLOAD_NAMES) or target_base in ("sh", "bash", "dash", "python", "tcexec"):
                    return 1
            return 0

        # 3f. Spawning of malicious child or interactive execution
        if event.event_type == "PROCESS_START":
            if any(p in target_base for p in MALICIOUS_PAYLOAD_NAMES):
                return 1

        return 1

