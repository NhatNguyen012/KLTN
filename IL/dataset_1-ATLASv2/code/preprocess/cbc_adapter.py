#!/usr/bin/env python3
"""Ingestion Adapter for Carbon Black Cloud (CBC) EDR telemetry.

Streams and normalizes CBC JSONL records into CanonicalEvent structures,
integrating with LabelRefiner for deterministic ground-truth labeling.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Generator, Iterable

try:
    from preprocess.common_schema import (
        CanonicalEvent,
        extract_basename,
        parse_timestamp_micros,
    )
    from preprocess.label_refiner import LabelRefiner
except ImportError:
    from .common_schema import (
        CanonicalEvent,
        extract_basename,
        parse_timestamp_micros,
    )
    from .label_refiner import LabelRefiner


EVENT_TYPE_MAPPING: dict[str, str] = {
    "endpoint.event.procstart": "PROCESS_START",
    "endpoint.event.procend": "PROCESS_END",
    "endpoint.event.netconn": "FLOW_START",
    "endpoint.event.filemod": "FILE_WRITE",
    "endpoint.event.regmod": "REGISTRY_WRITE",
    "endpoint.event.moduleload": "MODULE_LOAD",
    "endpoint.event.crossproc": "CROSS_PROCESS",
}


class CBCAdapter:
    """Parses and streams CBC-EDR records into CanonicalEvent objects."""

    def __init__(self, label_refiner: LabelRefiner) -> None:
        self.refiner = label_refiner

    def parse_record(self, raw: dict[str, Any], scenario: str) -> CanonicalEvent | None:
        """Convert a single raw CBC JSON object into a CanonicalEvent."""
        raw_type = raw.get("type", "")
        if raw_type not in EVENT_TYPE_MAPPING:
            return None

        event_type = EVENT_TYPE_MAPPING[raw_type]
        ts_micros = parse_timestamp_micros(raw.get("device_timestamp"))
        if ts_micros <= 0:
            return None

        hostname = str(raw.get("device_name", "")).strip().lower()
        process_guid = str(raw.get("process_guid", "")).strip().lower()
        parent_guid = str(raw.get("parent_guid", "")).strip().lower()
        process_path = str(raw.get("process_path", "")).strip()
        process_cmdline = str(raw.get("process_cmdline", "")).strip()
        parent_path = str(raw.get("parent_path", "")).strip()
        parent_cmdline = str(raw.get("parent_cmdline", "")).strip()
        username = str(raw.get("process_username", "")).strip()

        target_path = ""
        target_guid = ""
        proto = ""
        remote_ip = ""
        remote_port = 0
        local_port = 0
        inbound = False

        if raw_type == "endpoint.event.netconn":
            raw_proto = str(raw.get("netconn_protocol", "")).upper()
            if "TCP" in raw_proto:
                proto = "tcp"
            elif "UDP" in raw_proto:
                proto = "udp"
            else:
                proto = raw_proto.lower()

            remote_ip = str(raw.get("remote_ip", "")).strip()
            target_path = str(raw.get("netconn_domain", "")).strip()
            try:
                remote_port = int(float(raw.get("remote_port", 0) or 0))
                local_port = int(float(raw.get("local_port", 0) or 0))
            except (ValueError, TypeError):
                remote_port, local_port = 0, 0
            inbound = bool(raw.get("netconn_inbound") == 1.0)

        elif raw_type == "endpoint.event.filemod":
            target_path = str(raw.get("filemod_name", "")).strip()
            action_str = str(raw.get("action", "")).upper()
            if "ACTION_FILE_CREATE" in action_str:
                event_type = "FILE_CREATE"
            elif "ACTION_FILE_OPEN_DELETE" in action_str:
                event_type = "FILE_DELETE"

        elif raw_type == "endpoint.event.regmod":
            target_path = str(raw.get("regmod_name", "")).strip()

        elif raw_type == "endpoint.event.moduleload":
            target_path = str(raw.get("modload_name", "")).strip()

        elif raw_type == "endpoint.event.crossproc":
            target_path = str(raw.get("crossproc_name", "")).strip()
            target_guid = str(raw.get("crossproc_guid", "")).strip().lower()

        elif raw_type == "endpoint.event.procstart":
            target_path = str(raw.get("childproc_name", "")).strip()
            target_guid = str(raw.get("childproc_guid", "")).strip().lower()

        event_id = f"{hostname}_{process_guid}_{ts_micros}_{raw_type}"

        event = CanonicalEvent(
            event_id=event_id,
            timestamp=ts_micros,
            hostname=hostname,
            event_type=event_type,
            scenario=scenario,
            process_guid=process_guid,
            parent_guid=parent_guid,
            process_path=process_path,
            process_cmdline=process_cmdline,
            parent_path=parent_path,
            parent_cmdline=parent_cmdline,
            username=username,
            target_path=target_path,
            target_guid=target_guid,
            proto=proto,
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            inbound=inbound,
            label=0,
        )

        # Assign verified 2-tier ground truth label
        event.label = 1 if self.refiner.is_event_malicious(event) else 0
        return event

    def stream_file(self, file_path: str | Path, scenario: str) -> Generator[CanonicalEvent, None, None]:
        """Stream canonical events from a local JSONL file."""
        p = Path(file_path)
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event = self.parse_record(raw, scenario)
                    if event is not None:
                        yield event
                except Exception:
                    continue

    def stream_tar_member(self, tar_path: str | Path, member_name: str, scenario: str) -> Generator[CanonicalEvent, None, None]:
        """Stream canonical events directly from a tar.gz member using tar extraction pipeline."""
        cmd = ["tar", "-xzf", str(tar_path), member_name, "-O"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=65536)
        if proc.stdout is None:
            return

        with io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event = self.parse_record(raw, scenario)
                    if event is not None:
                        yield event
                except Exception:
                    continue
        proc.wait()
