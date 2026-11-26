#!/usr/bin/env python3
"""3-Head Ground-Truth Label & Exclusion Resolver for DARPA TC E3 THEIA.

Enforces:
- REAPr ground truth separation: ONLY verified successful attack chains
  (`theia_3.3_success_gatech_profile` -> Scenario 1, `theia_3.11_success` -> Scenario 2)
  are retained as positives.
- Complete exclusion (dropped from both Attack and Benign) of all failed attempts
  (`theia_3.3_fail_allstate`, `theia_3.3_fail_gatech_clean`, `theia_3.11_fail`, `theia_4.8_fail`),
  all `contaminated` edges/processes shared across fail & success (`3A3530B4-...`),
  unlabeled Section 4.6 phishing traffic (`208.75.117.*`), and standard OS dynamic-linker
  `.so`/`ld.so.cache` noise (preserving attacker-planted `/tmp/memtrace.so`).
- Direction-aware (post-`EDGE_REVERSED_OPS`) MITRE ATT&CK Kill-Chain Stage resolution (Stages 1..4).
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
import tarfile
from typing import Dict, Optional, Set, Tuple

from theia_schema import (
    C2_IPS,
    EXCLUDED_COMMON_THREAT_IPS,
    EXCLUDED_FAIL_CHAINS,
    EXCLUDED_FAIL_PATH_SUBSTRS,
    INCLUDED_ATTACK_CHAINS,
    INITIAL_DELIVERY_IPS,
    RECON_EXTERNAL_IPS,
    SHARED_HOST_GUI_PROCS,
    extract_basename,
    is_os_shared_library,
)


class TheiaGroundTruthResolver:
    """Resolves REAPr exclusions and 3-Head labels (Binary, Scenario, Stage) for THEIA events."""

    def __init__(self, tar_path: Path, labels_csv_path: Optional[Path] = None):
        self.tar_path = Path(tar_path)
        self.labels_csv_path = Path(labels_csv_path) if labels_csv_path else None

        self.included_edge_scenario: Dict[str, int] = {}
        self.excluded_edge_uuids: Set[str] = set()
        self.contaminated_vertex_uuids: Set[str] = set()
        self.fail_only_process_uuids: Set[str] = set()
        self.fail_only_process_indices: Set[int] = set()
        self.contaminated_process_indices: Set[int] = set()

        self._load_reapr_ground_truth()

    def _load_reapr_ground_truth(self) -> None:
        if not self.tar_path.exists():
            raise FileNotFoundError(f"REAPr tar archive not found: {self.tar_path}")

        fail_vertices: Set[str] = set()
        succ_vertices: Set[str] = set()
        fail_edges: Set[str] = set()
        contaminated_edges: Set[str] = set()
        temp_succ_edges: Dict[str, int] = {}

        with tarfile.open(self.tar_path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith("edge_labels.csv"):
                    raw_text = tf.extractfile(member).read().decode("utf-8", errors="ignore")
                    reader = csv.DictReader(io.StringIO(raw_text))
                    for row in reader:
                        clean = {k.strip(): (v or "").strip() for k, v in row.items() if k is not None}
                        chain = clean.get("attack_chain", "")
                        v_uuid = clean.get("vertex_uuid", "")
                        v_label = clean.get("vertex_label", "").lower()
                        e_uuid = clean.get("edge_uuid", "")
                        if not e_uuid:
                            continue

                        if v_label == "contaminated":
                            contaminated_edges.add(e_uuid)
                            if v_uuid:
                                self.contaminated_vertex_uuids.add(v_uuid)

                        if chain in EXCLUDED_FAIL_CHAINS:
                            fail_edges.add(e_uuid)
                            if v_uuid:
                                fail_vertices.add(v_uuid)
                        elif chain in INCLUDED_ATTACK_CHAINS:
                            temp_succ_edges[e_uuid] = INCLUDED_ATTACK_CHAINS[chain]
                            if v_uuid:
                                succ_vertices.add(v_uuid)

        if self.labels_csv_path and self.labels_csv_path.exists():
            with self.labels_csv_path.open("r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    clean = {k.strip(): (v or "").strip() for k, v in row.items() if k is not None}
                    chain = clean.get("attack_chain", "")
                    uuid = clean.get("uuid", "")
                    pname = clean.get("process_name", "")
                    lbl = clean.get("label", "").lower()
                    if not uuid:
                        continue
                    if lbl == "contaminated":
                        self.contaminated_vertex_uuids.add(uuid)
                    if chain in EXCLUDED_FAIL_CHAINS and pname not in SHARED_HOST_GUI_PROCS:
                        fail_vertices.add(uuid)
                    elif chain in INCLUDED_ATTACK_CHAINS:
                        succ_vertices.add(uuid)

        self.excluded_edge_uuids = fail_edges | contaminated_edges
        # Priority: fail & contaminated exclusions win over any accidental overlap with success chains
        for e_uuid, sc_id in temp_succ_edges.items():
            if e_uuid not in self.excluded_edge_uuids:
                self.included_edge_scenario[e_uuid] = sc_id

        self.fail_only_process_uuids = fail_vertices - succ_vertices

    def bind_process_table(self, uuid_to_proc_idx: Dict[str, int], idx_to_proc_path: Dict[int, str]) -> None:
        """Resolve UUID-based fail-only / contaminated sets to integer Parquet `index_id`s."""
        for u in self.fail_only_process_uuids:
            idx = uuid_to_proc_idx.get(u)
            if idx is not None:
                p = idx_to_proc_path.get(idx, "")
                if p not in SHARED_HOST_GUI_PROCS:
                    self.fail_only_process_indices.add(idx)

        for u in self.contaminated_vertex_uuids:
            idx = uuid_to_proc_idx.get(u)
            if idx is not None:
                self.contaminated_process_indices.add(idx)

    def get_exclusion_reason(
        self,
        event_uuid: str,
        actor_idx: int,
        obj_idx: int,
        actor_path: str = "",
        obj_path: str = "",
        src_ip: str = "",
        dst_ip: str = "",
    ) -> Optional[str]:
        """Return exclusion category if the event must be omitted completely, else None."""
        if event_uuid in self.excluded_edge_uuids:
            return "reapr_fail_or_contaminated_edge"
        if actor_idx in self.fail_only_process_indices or obj_idx in self.fail_only_process_indices:
            return "reapr_fail_only_process"
        if src_ip in EXCLUDED_COMMON_THREAT_IPS or dst_ip in EXCLUDED_COMMON_THREAT_IPS:
            return "common_threat_4_6"
        a_low = actor_path.lower()
        o_low = obj_path.lower()
        if any(sub in a_low or sub in o_low for sub in EXCLUDED_FAIL_PATH_SUBSTRS):
            return "fail_chain_artifact"
        if obj_path and is_os_shared_library(obj_path):
            return "os_shared_lib_noise"
        return None

    def resolve_3heads(
        self,
        event_uuid: str,
        operation: str,
        actor_path: str = "",
        obj_path: str = "",
        src_ip: str = "",
        dst_ip: str = "",
    ) -> Tuple[int, int, int]:
        """Return `(is_malicious, scenario_id, stage_id)` using direction-resolved endpoints."""
        sc_id = self.included_edge_scenario.get(event_uuid)
        if sc_id is None:
            return 0, 0, 0

        stage_id = self._classify_stage(operation, actor_path, obj_path, src_ip, dst_ip)
        return 1, sc_id, stage_id

    @staticmethod
    def _classify_stage(
        operation: str,
        actor_path: str,
        obj_path: str,
        src_ip: str,
        dst_ip: str,
    ) -> int:
        op = operation.strip().upper()
        ap = actor_path.strip().lower()
        op_path = obj_path.strip().lower()
        a_base = extract_basename(actor_path)
        o_base = extract_basename(obj_path)

        # Stage 4: Persistent C2 Channels & Exfiltration
        if dst_ip in C2_IPS or src_ip in C2_IPS:
            return 4

        # Stage 1: Initial Compromise (Malvertising Delivery, Payload Dropper Download, Firefox/Extension Entry)
        if dst_ip in INITIAL_DELIVERY_IPS or src_ip in INITIAL_DELIVERY_IPS:
            return 1
        if op == "EVENT_EXECUTE" and (o_base == "pass_mgr" or (o_base == "dash" and a_base == "pass_mgr")):
            return 1
        if a_base == "firefox":
            if "glx_alsa_675" in op_path:
                return 2
            if op in {"EVENT_CLONE", "EVENT_EXECUTE"} or any(
                k in op_path for k in ("/home/admin/profile", "gtcache", "pass_mgr", "passwordfile.dat")
            ):
                return 1
        if a_base == "fluxbox" and o_base == "firefox":
            return 1

        # Stage 2: Execution, Kernel Rootkit PrivEsc & Implant Staging
        if "glx_alsa_675" in op_path or "/tmp/memtrace.so" in op_path:
            return 2
        if any(p in op_path for p in ("/var/log/xdev", "/var/log/wdev", "/var/log/mail")):
            return 2
        if op == "EVENT_EXECUTE" and (
            op_path in ("/home/admin/profile", "/etc/firefox/native-messaging-hosts/gtcache", "/var/log/mail")
            or o_base in ("profile", "gtcache", "mail")
        ):
            return 2
        if op == "EVENT_CLONE" and (
            a_base in ("profile", "pass_mgr", "dash", "mail")
            or o_base in ("profile", "gtcache", "dash", "mail")
        ):
            return 2

        # Stage 3: System & Network Discovery / Internal Subnet Portscan
        if dst_ip in RECON_EXTERNAL_IPS or dst_ip == "NA" or dst_ip.startswith("128.55.12.") or dst_ip == "127.0.0.1":
            return 3
        if op == "EVENT_CONNECT":
            return 3
        return 3
