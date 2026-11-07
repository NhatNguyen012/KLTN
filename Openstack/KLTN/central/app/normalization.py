"""Bounded, non-executing normalization for the telemetry archive.

The adapter deliberately keeps raw evidence in ``events`` and publishes only a
small common semantic view here.  It never decodes or executes command/script
content.  Unsupported fields remain missing instead of being invented.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any
from xml.etree import ElementTree

ADAPTER_VERSION = "kltn-common-event-v1"
MAX_XML_CHARS = 1_000_000

SYSMON_TYPES = {
    1: "PROCESS_START",
    3: "FLOW_START",
    5: "PROCESS_END",
    7: "MODULE_LOAD",
    8: "CROSS_PROCESS",
    10: "CROSS_PROCESS",
    11: "FILE_CREATE",
    12: "REGISTRY_WRITE",
    13: "REGISTRY_WRITE",
    14: "REGISTRY_WRITE",
    22: "DNS_QUERY",
    23: "FILE_DELETE",
    26: "FILE_DELETE",
}

AUDIT_PAIR = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+)")
AUDIT_TIME = re.compile(r"audit\((?P<seconds>\d+(?:\.\d+)?):(?P<serial>\d+)\)")


def _text(value: Any, maximum: int = 32768) -> str | None:
    if value is None:
        return None
    value = str(value).replace("\x00", " ").strip()
    return value[:maximum] or None


def _timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Fluent Bit commonly emits seconds; tolerate milliseconds/microseconds.
        number = float(value)
        if number > 10**14:
            number /= 1_000_000
        elif number > 10**11:
            number /= 1_000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    value = str(value).strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    except ValueError:
        return None


def _xml_fields(raw: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    xml = (raw.get("xml") or raw.get("Xml") or raw.get("XML") or
           (raw.get("System") if isinstance(raw.get("System"), str) and raw.get("System", "").startswith("<Event") else None) or
           (raw.get("Event") if isinstance(raw.get("Event"), str) and raw.get("Event", "").startswith("<Event") else None))
    if (not isinstance(xml, str) or not xml or len(xml) > MAX_XML_CHARS or
            '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper()):
        return {}, {}
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {}, {}
    system: dict[str, str] = {}
    data: dict[str, str] = {}
    for item in root.iter():
        name = item.tag.rsplit("}", 1)[-1]
        if name in {"EventID", "EventRecordID", "Channel", "Computer"} and item.text:
            system[name] = item.text.strip()
        elif name == "TimeCreated":
            system["SystemTime"] = item.attrib.get("SystemTime", "")
        elif name == "Provider":
            system["Provider"] = item.attrib.get("Name", "")
        elif name == "Data":
            key = item.attrib.get("Name")
            if key:
                data[key] = (item.text or "").strip()
    return system, data


def _base(record: dict[str, Any], received_at: datetime) -> dict[str, Any]:
    return {
        "event_id": record["event_id"],
        "host_id": record["host_id"],
        "source": record["source"],
        "event_time": None,
        "received_at": received_at,
        "event_type": "UNCLASSIFIED",
        "process_id": None,
        "parent_process_id": None,
        "process_path": None,
        "parent_path": None,
        "command_line": None,
        "principal": None,
        "object_path": None,
        "network": {},
        "missing_fields": [],
        "adapter_version": ADAPTER_VERSION,
    }


def _normalize_windows(record: dict[str, Any], received_at: datetime) -> dict[str, Any]:
    raw = record.get("raw", {})
    out = _base(record, received_at)
    system, data = _xml_fields(raw)
    merged = {**raw, **system, **data}
    try:
        event_id = int(merged.get("EventID", 0))
    except (TypeError, ValueError):
        event_id = 0
    source = record["source"]
    if source == "sysmon":
        out["event_type"] = SYSMON_TYPES.get(event_id, f"SYSMON_{event_id}" if event_id else "SYSMON_UNKNOWN")
    elif source == "security" and event_id == 4688:
        out["event_type"] = "PROCESS_START"
    elif source == "powershell" and event_id == 4104:
        out["event_type"] = "SCRIPT_BLOCK"
    else:
        out["event_type"] = f"WINDOWS_{event_id}" if event_id else "WINDOWS_UNKNOWN"

    out["event_time"] = _timestamp(merged.get("UtcTime") or merged.get("SystemTime") or raw.get("date"))
    out["process_id"] = _text(merged.get("ProcessGuid") or merged.get("ProcessId") or merged.get("NewProcessId"), 256)
    out["parent_process_id"] = _text(merged.get("ParentProcessGuid") or merged.get("ParentProcessId") or merged.get("CreatorProcessId"), 256)
    out["process_path"] = _text(merged.get("Image") or merged.get("ProcessName") or merged.get("NewProcessName"))
    out["parent_path"] = _text(merged.get("ParentImage") or merged.get("CreatorProcessName"))
    out["command_line"] = _text(merged.get("CommandLine") or merged.get("ProcessCommandLine") or merged.get("ScriptBlockText"))
    out["principal"] = _text(merged.get("User") or merged.get("SubjectUserName") or merged.get("UserID"), 1024)
    out["object_path"] = _text(merged.get("TargetFilename") or merged.get("TargetObject") or merged.get("ImageLoaded") or merged.get("TargetImage") or merged.get("QueryName"))
    if out["event_type"] == "PROCESS_START":
        # Sysmon Event 1 describes the newly created process in Image while the
        # parent remains ParentImage.  This is the actor used by live scoring.
        out["process_path"] = _text(merged.get("Image") or merged.get("NewProcessName"))
    out["network"] = {
        key: value for key, value in {
            "protocol": _text(merged.get("Protocol"), 32),
            "source_ip": _text(merged.get("SourceIp"), 128),
            "source_port": _text(merged.get("SourcePort"), 16),
            "destination_ip": _text(merged.get("DestinationIp"), 128),
            "destination_port": _text(merged.get("DestinationPort"), 16),
            "query_name": _text(merged.get("QueryName"), 2048),
        }.items() if value is not None
    }
    return out


def _audit_fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in AUDIT_PAIR.finditer(line[:MAX_XML_CHARS]):
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[match.group("key")] = value
    return result


def _normalize_linux(record: dict[str, Any], received_at: datetime) -> dict[str, Any]:
    raw = record.get("raw", {})
    out = _base(record, received_at)
    source = record["source"]
    if source == "audit":
        line = str(raw.get("log") or raw.get("message") or "")
        fields = _audit_fields(line)
        kind = fields.get("type") or (line.split(None, 1)[0].removeprefix("type=") if line else "")
        syscall = fields.get("syscall", "")
        out["event_type"] = {
            "EXECVE": "PROCESS_START", "SYSCALL": "SYSCALL", "PATH": "FILE_ACCESS",
            "PROCTITLE": "PROCESS_METADATA", "USER_LOGIN": "LOGIN",
        }.get(kind, f"AUDIT_{kind}" if kind else "AUDIT_UNKNOWN")
        if kind == "SYSCALL" and syscall in {"59", "322", "execve", "execveat"}:
            out["event_type"] = "PROCESS_START"
        stamp = AUDIT_TIME.search(line)
        out["event_time"] = _timestamp(float(stamp.group("seconds"))) if stamp else _timestamp(raw.get("date"))
        out["process_id"] = _text(fields.get("pid"), 64)
        out["parent_process_id"] = _text(fields.get("ppid"), 64)
        out["process_path"] = _text(fields.get("exe") or fields.get("comm"))
        out["principal"] = _text(fields.get("auid") or fields.get("uid"), 128)
        out["object_path"] = _text(fields.get("name"))
        out["command_line"] = _text(fields.get("proctitle"))
    else:
        out["event_type"] = "JOURNAL"
        out["event_time"] = _timestamp(raw.get("date") or raw.get("_SOURCE_REALTIME_TIMESTAMP"))
        out["process_id"] = _text(raw.get("_PID"), 64)
        out["process_path"] = _text(raw.get("_EXE") or raw.get("SYSLOG_IDENTIFIER"))
        out["principal"] = _text(raw.get("_UID"), 128)
        out["command_line"] = _text(raw.get("MESSAGE"), 32768)
    return out


def normalize_record(record: dict[str, Any], received_at: datetime | None = None) -> dict[str, Any]:
    """Return a database-ready common event without mutating the raw record."""
    received_at = received_at or datetime.now(timezone.utc)
    if record.get("source") in {"sysmon", "security", "powershell"}:
        out = _normalize_windows(record, received_at)
    elif record.get("source") in {"audit", "journal"}:
        out = _normalize_linux(record, received_at)
    else:
        out = _base(record, received_at)
        out["event_time"] = _timestamp(record.get("raw", {}).get("date"))
        out["event_type"] = "SMOKE" if record.get("source") == "smoke" else "UNCLASSIFIED"
    required = ("event_time", "process_id", "process_path")
    out["missing_fields"] = [name for name in required if out.get(name) is None]
    return out


def json_view(event: dict[str, Any]) -> dict[str, Any]:
    """Convert datetimes to JSON-safe values for the normalized JSONB column."""
    return {key: (value.isoformat() if isinstance(value, datetime) else value)
            for key, value in event.items() if key not in {"received_at"}}
