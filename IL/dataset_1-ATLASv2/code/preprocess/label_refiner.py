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


SUSPICIOUS_MODULES = frozenset({
    "urlmon.dll", "wininet.dll", "vbscript.dll", "jscript.dll",
    "eqnedt32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "scrobj.dll",
})

OFFICE_SYS_MODULES = frozenset({
    "mso.dll", "wwlib.dll", "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ole32.dll", "rpcrt4.dll", "msvcrt.dll", "shell32.dll", "shlwapi.dll",
    "imm32.dll", "usp10.dll", "comctl32.dll", "riched20.dll", "mscoree.dll", "msi.dll",
    "kernelbase.dll", "mso20win32client.dll", "mso40uiwin32client.dll", "mssvp.dll",
})

EXPLOIT_CHILD_PROCS = frozenset({
    "cmd.exe", "powershell.exe", "eqnedt32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
    "rundll32.exe", "regsvr32.exe", "payload.exe", "plugin-container.exe",
})


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
        """Evaluate two-tier event-level labeling policy on a canonical event.
        
        Returns True (1) if event is part of verified attack behavior, False (0) otherwise.
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
        target_path = event.target_path or ""
        target_norm = target_path.strip().strip('"\'').replace("/", "\\").lower()
        target_base = extract_basename(target_path)
        et = event.event_type

        # 4. Handle Dual-Use Process: Firefox.exe (Solve Firefox Paradox)
        if proc_base == "firefox.exe":
            if et == "FLOW_START":
                is_c2_ip = event.remote_ip in KNOWN_IOCS["c2_ips"]
                is_c2_port = event.remote_port in KNOWN_IOCS["c2_ports"]
                is_c2_domain = any(d in target_norm for d in KNOWN_IOCS["c2_domains"])
                is_seed = False
                seeds = self.scenario_seeds.get(sc, set())
                for s in seeds:
                    if event.remote_ip in s or (event.remote_port > 0 and str(event.remote_port) in s):
                        is_seed = True
                        break
                return is_c2_ip or is_c2_port or is_c2_domain or is_seed

            elif et in {"FILE_WRITE", "FILE_CREATE"}:
                return any(mal in target_base for mal in KNOWN_IOCS["malicious_files"]) or target_base.endswith((".exe", ".zip"))

            elif et == "PROCESS_START":
                return target_base in {"cmd.exe", "powershell.exe", "payload.exe", "plugin-container.exe"}

            # Any other background event from Firefox is marked Benign (0)
            return False

        # 5. Handle Dual-Use Process: Office (Word, Excel, PowerPoint)
        if proc_base in ("winword.exe", "excel.exe", "powerpnt.exe"):
            if et == "PROCESS_START":
                return target_base in EXPLOIT_CHILD_PROCS
            elif et == "FLOW_START":
                is_c2_ip = event.remote_ip in KNOWN_IOCS["c2_ips"]
                is_c2_port = event.remote_port in KNOWN_IOCS["c2_ports"]
                is_c2_domain = any(d in target_norm for d in KNOWN_IOCS["c2_domains"])
                return is_c2_ip or is_c2_port or is_c2_domain
            elif et in {"FILE_WRITE", "FILE_CREATE"}:
                # Font loading or Office autosave draft (~*.tmp, .asd, .wbk) -> 0
                if any(target_base.endswith(ext) for ext in (".ttf", ".fon", ".tmp", ".asd", ".wbk")) or "~" in target_base or "\\fonts\\" in target_norm:
                    return False
                # Malicious payload / script write -> 1
                if any(mal in target_base for mal in KNOWN_IOCS["malicious_files"]) or target_base.endswith((".exe", ".zip", ".sct", ".vbs", ".hta", ".ps1")):
                    return True
                return False
            elif et == "MODULE_LOAD":
                if target_base in SUSPICIOUS_MODULES:
                    return True
                # Standard system / Office DLLs -> 0
                if target_base in OFFICE_SYS_MODULES or "\\system32\\" in target_norm or "\\syswow64\\" in target_norm or "\\microsoft shared\\" in target_norm:
                    return False
                return False
            elif et == "REGISTRY_WRITE":
                return any(k in target_norm for k in (r"\currentversion\run", r"\winlogon", r"\services"))
            return False

        # 6. Handle Dual-Use Process: Windows Explorer
        if proc_base == "explorer.exe":
            if et == "PROCESS_START":
                return target_base in EXPLOIT_CHILD_PROCS
            elif et == "FLOW_START":
                return event.remote_ip in KNOWN_IOCS["c2_ips"]
            elif et in {"FILE_WRITE", "FILE_CREATE"}:
                return any(mal in target_base for mal in KNOWN_IOCS["malicious_files"]) or target_base.endswith((".exe", ".zip", ".sct", ".vbs", ".hta", ".ps1"))
            elif et == "MODULE_LOAD":
                return target_base in SUSPICIOUS_MODULES
            elif et == "REGISTRY_WRITE":
                return any(k in target_norm for k in (r"\currentversion\run", r"\winlogon", r"\services"))
            return False

        # 7. Handle Background System Services (lsass, taskhost, dllhost, osppsvc, audiodg)
        if proc_base in ("lsass.exe", "taskhost.exe", "dllhost.exe", "osppsvc.exe", "audiodg.exe"):
            if et == "PROCESS_START":
                return target_base in EXPLOIT_CHILD_PROCS
            elif et == "FLOW_START":
                return event.remote_ip in KNOWN_IOCS["c2_ips"]
            elif et in {"FILE_WRITE", "FILE_CREATE"}:
                return any(mal in target_base for mal in KNOWN_IOCS["malicious_files"])
            elif et == "CROSS_PROCESS":
                return target_base in EXPLOIT_CHILD_PROCS or event.target_guid in attack_guids
            return False

        # 8. Pure attack and shell execution tools (payload.exe, powershell.exe, cmd.exe, mshta.exe, etc.)
        if proc_base in ("payload.exe", "powershell.exe", "cmd.exe", "eqnedt32.exe", "mshta.exe", "regsvr32.exe", "python.exe") or proc_base in KNOWN_IOCS["attack_processes"]:
            return True

        # Default for other attacker-flagged processes
        return True
