#!/usr/bin/env python3
"""Ingestion Adapter for DARPA TC E3 THEIA provenance telemetry.

Streams and normalizes THEIA telemetry records into CanonicalEvent structures,
supporting both pre-extracted table data (CSV/Parquet) and raw CDM JSON archives.
Integrates with LabelRefiner for deterministic ground-truth labeling.

Run 7 fix — network endpoint disambiguation (RUN6_RESULTS.md Section 5 & 7):
  Previously, EVENT_CONNECT with dst_ip=NA/port=0 was inferred as CROSS_PROCESS
  (Unix IPC), which is incorrect. 'NA' or missing destination only means the
  endpoint information is unavailable; it does NOT prove Unix domain socket or
  shared-memory IPC.

  New classification:
    - Explicit Unix path (s_addr or d_addr starts with '/'): CROSS_PROCESS, net_endpoint_type='unix_domain'
    - Both src and dst are loopback: FLOW_START, net_endpoint_type='loopback'
    - Explicit NETLINK: CROSS_PROCESS; LOCAL alone is unknown, net_endpoint_type='unix_domain'
    - NA / empty / port=0 for dst: NETWORK_UNKNOWN (new event type), net_endpoint_type='unknown_endpoint'
      → skipped by Host ML shard builder (like FLOW_START), reported in manifest stats.
    - Any other non-loopback routable address: FLOW_START, net_endpoint_type='external'
    - No netflow node found at all: NETWORK_UNKNOWN (conservative), net_endpoint_type='unknown_endpoint'
"""

from __future__ import annotations

from collections import Counter
import csv
import hashlib
import ipaddress
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tarfile
from typing import Any, Generator, Iterable

try:
    from preprocess.common_schema import (
        CanonicalEvent,
        classify_image_dir,
        classify_principal,
        classify_resp_port,
        extract_basename,
        parse_timestamp_micros,
    )
    from preprocess.label_refiner import LabelRefiner
except ImportError:
    from .common_schema import (
        CanonicalEvent,
        classify_image_dir,
        classify_principal,
        classify_resp_port,
        extract_basename,
        parse_timestamp_micros,
    )
    from .label_refiner import LabelRefiner


class THEIAAdapter:
    """Parses and streams THEIA records into CanonicalEvent objects."""

    def __init__(
        self,
        label_refiner: LabelRefiner,
        data_dir: str | Path = "/mnt/SSD_Data/optc/DATASET/DARPA-TC-E3-THEIA",
        raw_context=None,
    ) -> None:
        self.raw_context = raw_context
        self.enrichment_counts = Counter()
        self.refiner = label_refiner
        self.data_dir = Path(data_dir)
        self.csv_dir = self.data_dir / "CSV"
        self.raw_dir = self.data_dir / "RAW"

        # Lookup caches for graph entities
        # index_id -> (node_uuid, path, cmd)
        self.process_nodes: dict[int, tuple[str, str, str]] = {}
        # Set of index_ids belonging to attack processes
        self.attack_proc_indices: set[int] = set()
        # index_id -> (node_uuid, path)
        self.file_nodes: dict[int, tuple[str, str]] = {}
        # index_id -> (node_uuid, src_addr, src_port, dst_addr, dst_port)
        self.netflow_nodes: dict[int, tuple[str, str, int, str, int]] = {}

        self._loaded_node_tables = False

    def load_node_tables(self) -> None:
        """Load process, file, and netflow node tables from CSV into RAM for O(1) join lookups."""
        if self._loaded_node_tables:
            return

        print("  [THEIAAdapter] Loading process_node_table.csv...")
        p_csv = self.csv_dir / "process_node_table.csv"
        if p_csv.exists():
            with p_csv.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 5:
                        try:
                            idx = int(row[4].strip())
                            proc_uuid = row[0].strip().upper()
                            self.process_nodes[idx] = (proc_uuid, row[2].strip(), row[3].strip())
                            if proc_uuid in self.refiner.attack_process_uuids:
                                self.attack_proc_indices.add(idx)
                        except ValueError:
                            continue

        print(f"  [THEIAAdapter] Loaded {len(self.process_nodes)} process nodes.")

        print("  [THEIAAdapter] Loading netflow_node_table.csv...")
        n_csv = self.csv_dir / "netflow_node_table.csv"
        if n_csv.exists():
            with n_csv.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 7:
                        try:
                            idx = int(row[6].strip())
                            src_p = int(row[3].strip()) if row[3].strip().isdigit() else 0
                            dst_p = int(row[5].strip()) if row[5].strip().isdigit() else 0
                            self.netflow_nodes[idx] = (row[0].strip().upper(), row[2].strip(), src_p, row[4].strip(), dst_p)
                        except ValueError:
                            continue

        print(f"  [THEIAAdapter] Loaded {len(self.netflow_nodes)} netflow nodes.")

        print("  [THEIAAdapter] Loading file_node_table.csv...")
        f_csv = self.csv_dir / "file_node_table.csv"
        if f_csv.exists():
            with f_csv.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 4:
                        try:
                            idx = int(row[3].strip())
                            self.file_nodes[idx] = (row[0].strip().upper(), row[2].strip())
                        except ValueError:
                            continue

        print(f"  [THEIAAdapter] Loaded {len(self.file_nodes)} file nodes.")
        self._loaded_node_tables = True

    def stream_canonical_events(
        self,
        event_csv_path: Path | None = None,
        max_events: int | None = None,
        undersample_benign_ratio: int = 1,
        context_observer=None,
        retained_source_lines=None,
    ) -> Generator[CanonicalEvent, None, None]:
        """Stream events from event_table.csv joined with node tables into CanonicalEvent objects."""
        self.load_node_tables()

        if event_csv_path is None:
            event_csv_path = self.csv_dir / "event_table.csv"

        if not event_csv_path.exists():
            raise FileNotFoundError(f"Event table not found at {event_csv_path}")

        print(f"  [THEIAAdapter] Streaming events from {event_csv_path.name} (undersample_ratio={undersample_benign_ratio})...")
        count = 0
        malicious_loop_counts: Counter[tuple[str, str]] = Counter()

        with event_csv_path.open("r", encoding="utf-8", errors="replace") as f:
            header = f.readline()
            has_source_line = header.rstrip().endswith(",source_line")
            # Columns: src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec
            for source_line, line in enumerate(f, start=2):
                row = line.rstrip("\n").split(",")
                if len(row) < 7:
                    continue

                try:
                    if has_source_line:
                        source_line = int(row[7])
                    src_idx = int(row[1])
                    op = row[2]
                    dst_idx = int(row[4])
                    event_uuid = row[5].upper()
                    ts_raw = row[6]
                    ts_micros = int(ts_raw) // 1000 if ts_raw.isdigit() else parse_timestamp_micros(ts_raw)
                except ValueError:
                    continue

                if ts_micros <= 0:
                    continue

                # Observe label-free source context before any sampling, label refinement,
                # or positive cap. Endpoint values are not passed to the host tracker.
                if context_observer is not None:
                    context_observer(op, src_idx, dst_idx, ts_micros, source_line,
                                     self.process_nodes, self.file_nodes)

                # Fast negative pre-filtering for pure background events
                # Context-bearing events must survive sampling, regardless of labels.
                context_op = op in {"EVENT_CLONE", "EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM",
                                    "EVENT_SENDMSG", "EVENT_RECVMSG", "EVENT_READ_SOCKET_PARAMS"}
                if retained_source_lines is not None and source_line not in retained_source_lines and not context_op:
                    continue
                if retained_source_lines is None and undersample_benign_ratio > 1 and not context_op:
                    if event_uuid not in self.refiner.attack_edge_uuids:
                        if src_idx not in self.attack_proc_indices and dst_idx not in self.attack_proc_indices:
                            try:
                                h_val = int(event_uuid[:8], 16)
                            except (ValueError, TypeError):
                                h_val = int.from_bytes(hashlib.sha256(event_uuid.encode()).digest()[:8], "big")
                            if h_val % undersample_benign_ratio != 0:
                                continue

                # Identify process, target, and event type
                event_type = "SYSTEM_CALL"
                process_guid = ""
                parent_guid = ""
                process_path = ""
                process_cmdline = ""
                parent_path = ""
                parent_cmdline = ""
                target_path = ""
                target_guid = ""
                proto = ""
                remote_ip = ""
                remote_port = 0
                local_port = 0
                inbound = False
                username = ""
                net_endpoint_type = ""

                # 1. Process Clone / Spawn / Execute
                if op == "EVENT_CLONE":
                    event_type = "PROCESS_START"
                    # src is parent process, dst is child process
                    if src_idx in self.process_nodes:
                        parent_guid, parent_path, parent_cmdline = self.process_nodes[src_idx]
                    if dst_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[dst_idx]
                        target_guid = process_guid
                        target_path = process_path

                elif op == "EVENT_EXECUTE":
                    event_type = "PROCESS_START"
                    if dst_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[dst_idx]
                        target_guid = process_guid
                    if src_idx in self.file_nodes:
                        f_uuid, f_path = self.file_nodes[src_idx]
                        target_path = f_path
                        if not process_path:
                            process_path = f_path

                # 2. File Operations
                elif op in ("EVENT_OPEN", "EVENT_READ", "EVENT_WRITE", "EVENT_UNLINK", "EVENT_MODIFY_FILE_ATTRIBUTES"):
                    if op == "EVENT_OPEN":
                        event_type = "FILE_OPEN"
                    elif op == "EVENT_READ":
                        event_type = "FILE_READ"
                    elif op == "EVENT_WRITE":
                        event_type = "FILE_WRITE"
                    elif op == "EVENT_UNLINK":
                        event_type = "FILE_DELETE"
                    else:
                        event_type = "FILE_MODIFY"

                    # Determine which side is process and which is file
                    if src_idx in self.process_nodes and dst_idx in self.file_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[src_idx]
                        target_guid, target_path = self.file_nodes[dst_idx]
                    elif dst_idx in self.process_nodes and src_idx in self.file_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[dst_idx]
                        target_guid, target_path = self.file_nodes[src_idx]
                    elif src_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[src_idx]
                    elif dst_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[dst_idx]

                # 3. Network Connection Operations
                elif op in ("EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG", "EVENT_READ_SOCKET_PARAMS"):
                    net_idx = None
                    proc_idx = None

                    if src_idx in self.process_nodes and dst_idx in self.netflow_nodes:
                        proc_idx, net_idx = src_idx, dst_idx
                        inbound = False
                    elif dst_idx in self.process_nodes and src_idx in self.netflow_nodes:
                        proc_idx, net_idx = dst_idx, src_idx
                        inbound = True
                    elif src_idx in self.process_nodes:
                        proc_idx = src_idx
                    elif dst_idx in self.process_nodes:
                        proc_idx = dst_idx

                    if proc_idx is not None and proc_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[proc_idx]

                    if net_idx is not None and net_idx in self.netflow_nodes:
                        n_uuid, s_addr, s_p, d_addr, d_p = self.netflow_nodes[net_idx]
                        target_guid = n_uuid

                        # Endpoint uncertainty is not evidence of process-to-process IPC.
                        def address(value):
                            try:
                                return ipaddress.ip_address(value)
                            except ValueError:
                                return None
                        src_ip, dst_ip = address(s_addr), address(d_addr)
                        if s_addr.startswith("/") or d_addr.startswith("/"):
                            event_type, net_endpoint_type = "CROSS_PROCESS", "unix_domain"
                        elif "NETLINK" in (s_addr, d_addr):
                            event_type, net_endpoint_type = "CROSS_PROCESS", "netlink"
                        elif src_ip and dst_ip:
                            event_type = "FLOW_START"
                            net_endpoint_type = "loopback" if src_ip.is_loopback and dst_ip.is_loopback else "external"
                        else:
                            event_type, net_endpoint_type = "NETWORK_UNKNOWN", "unknown_endpoint"
                        # Keep transport unknown: syscall/port heuristics do not establish TCP/UDP.
                        if not inbound:
                            remote_ip, remote_port, local_port = d_addr, d_p, s_p
                        else:
                            remote_ip, remote_port, local_port = s_addr, s_p, d_p
                    else:
                        # No netflow node resolved — cannot determine endpoint type
                        event_type = "NETWORK_UNKNOWN"
                        net_endpoint_type = "unknown_endpoint"

                elif op == "EVENT_SHM":
                    event_type = "CROSS_PROCESS"
                    if src_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[src_idx]
                    if dst_idx in self.process_nodes:
                        target_guid, target_path, _ = self.process_nodes[dst_idx]

                else:
                    if src_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[src_idx]
                    elif dst_idx in self.process_nodes:
                        process_guid, process_path, process_cmdline = self.process_nodes[dst_idx]

                if not process_guid or not process_path or not process_path.strip():
                    continue

                # Scenario assignment & Ground Truth refinement
                attack_chain = self.refiner.get_attack_chain_for_process(process_guid)
                if attack_chain:
                    scenario = attack_chain
                else:
                    # Partition by date string
                    dt = datetime.fromtimestamp(ts_micros / 1_000_000, tz=timezone.utc)
                    scenario = dt.strftime("%Y-%m-%d")

                # Enrich only with RAW snapshots observable at this event timestamp.
                # Unknown identity stays unknown; executable location does not establish UID.
                p_class, principal_role, process_pid = "NONE", "unknown", ""
                if self.raw_context is not None:
                    context = self.raw_context.subject(process_guid, ts_micros)
                    process_cmdline = ""  # CSV has no observation timestamp for command snapshots.
                    if context:
                        raw_parent, raw_principal, process_pid, raw_path, process_cmdline = context
                        self.enrichment_counts["subject_matched"] += 1
                        uid = self.raw_context.uid(raw_principal, ts_micros)
                        p_class = classify_principal(uid)
                        if uid is not None and str(uid).isdigit():
                            principal_role = "root" if int(uid) == 0 else ("service" if int(uid) < 1000 else "user")
                            self.enrichment_counts["principal_matched"] += 1
                        if not parent_guid and raw_parent != process_guid:
                            parent_guid = raw_parent
                        parent = self.raw_context.subject(parent_guid, ts_micros) if parent_guid else None
                        parent_path, parent_cmdline = "", ""
                        if parent:
                            parent_path, parent_cmdline = parent[3], parent[4]
                            self.enrichment_counts["parent_matched"] += 1
                    else:
                        parent_path, parent_cmdline = "", ""
                        self.enrichment_counts["subject_unavailable_at_event"] += 1
                username = {"root": "SYSTEM", "service": "SYSTEM", "user": "user"}.get(principal_role, "")

                file_object = (self.file_nodes.get(src_idx) or self.file_nodes.get(dst_idx)) if op in (
                    "EVENT_EXECUTE", "EVENT_OPEN", "EVENT_READ", "EVENT_WRITE", "EVENT_UNLINK", "EVENT_MODIFY_FILE_ATTRIBUTES") else None
                event = CanonicalEvent(
                    event_id=event_uuid,
                    timestamp=ts_micros,
                    hostname="theia-desktop",
                    event_type=event_type,
                    scenario=scenario,
                    process_guid=process_guid,
                    parent_guid=parent_guid,
                    process_path=process_path,
                    process_cmdline=process_cmdline,
                    parent_path=parent_path,
                    parent_cmdline=parent_cmdline,
                    username=username,
                    process_pid=process_pid,
                    principal_role=principal_role,
                    raw_operation=op,
                    principal_class=p_class,
                    target_path=target_path,
                    target_guid=target_guid,
                    target_file_guid=file_object[0] if file_object else "",
                    proto=proto,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    local_port=local_port,
                    inbound=inbound,
                    label=0,
                    source_line=source_line,
                    net_endpoint_type=net_endpoint_type,
                )

                # Deterministic label refinement
                event.label = self.refiner.refine_event_label(event)

                # Repetitive loop throttling (deduplication of excessive loop polls/scans e.g. /var/log/mail portscan)
                if retained_source_lines is not None and event.event_type not in ("FLOW_START", "NETWORK_UNKNOWN") and source_line not in retained_source_lines:
                    continue
                if retained_source_lines is None and event.label == 1:
                    loop_key = (event.process_guid, event.event_type)
                    malicious_loop_counts[loop_key] += 1
                    # After 500 events of repetitive IPC/reads from the same process, throttle excess events
                    if malicious_loop_counts[loop_key] > 500:
                        if event.event_type in ("CROSS_PROCESS", "FILE_READ", "FILE_OPEN"):
                            self.enrichment_counts[f"positive_cap_removed:{event.event_type}"] += 1
                            continue

                yield event
                count += 1
                if max_events and count >= max_events:
                    break

