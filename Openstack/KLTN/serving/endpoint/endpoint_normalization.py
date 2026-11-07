"""Live endpoint adapter for Windows records consumed by Host ML.

Only bounded XML parsing and field mapping occur here. Script or command text is
never executed. The same fixtures are also used to test the central normalizer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree

MAX_XML_CHARS = 1_000_000
SYSMON_TYPES = {
    1: 'PROCESS_START', 3: 'FLOW_START', 5: 'PROCESS_END', 7: 'MODULE_LOAD',
    8: 'CROSS_PROCESS', 10: 'CROSS_PROCESS', 11: 'FILE_CREATE',
    12: 'REGISTRY_WRITE', 13: 'REGISTRY_WRITE', 14: 'REGISTRY_WRITE',
    22: 'DNS_QUERY', 23: 'FILE_DELETE', 26: 'FILE_DELETE',
}


def _text(value: Any, maximum: int = 32768) -> str | None:
    if value is None:
        return None
    value = str(value).replace('\x00', ' ').strip()
    return value[:maximum] or None


def _xml(raw: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    value = (raw.get('xml') or raw.get('Xml') or raw.get('XML') or
             (raw.get('System') if isinstance(raw.get('System'), str) and raw.get('System', '').startswith('<Event') else None) or
             (raw.get('Event') if isinstance(raw.get('Event'), str) and raw.get('Event', '').startswith('<Event') else None))
    if (not isinstance(value, str) or not value or len(value) > MAX_XML_CHARS or
            '<!DOCTYPE' in value.upper() or '<!ENTITY' in value.upper()):
        return {}, {}
    try:
        root = ElementTree.fromstring(value)
    except ElementTree.ParseError:
        return {}, {}
    system, data = {}, {}
    for node in root.iter():
        name = node.tag.rsplit('}', 1)[-1]
        if name in {'EventID', 'EventRecordID', 'Channel', 'Computer'} and node.text:
            system[name] = node.text.strip()
        elif name == 'TimeCreated':
            system['SystemTime'] = node.attrib.get('SystemTime', '')
        elif name == 'Data' and node.attrib.get('Name'):
            data[node.attrib['Name']] = (node.text or '').strip()
    return system, data


def normalize_endpoint_event(host_id: str, identity: str, source: str,
                             raw: dict[str, Any]) -> dict[str, Any]:
    system, data = _xml(raw)
    merged = {**raw, **system, **data}
    try:
        event_number = int(merged.get('EventID', 0))
    except (TypeError, ValueError):
        event_number = 0
    if source == 'sysmon':
        event_type = SYSMON_TYPES.get(event_number, f'SYSMON_{event_number}' if event_number else 'SYSMON_UNKNOWN')
    elif source == 'security' and event_number == 4688:
        event_type = 'PROCESS_START'
    elif source == 'powershell' and event_number == 4104:
        event_type = 'SCRIPT_BLOCK'
    else:
        event_type = f'WINDOWS_{event_number}' if event_number else 'WINDOWS_UNKNOWN'
    event_time = merged.get('UtcTime') or merged.get('SystemTime') or raw.get('date')
    if isinstance(event_time, (int, float)):
        try:
            event_time = datetime.fromtimestamp(float(event_time), timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            event_time = None
    return {
        'event_id': identity, 'host_id': host_id, 'source': source,
        'event_type': event_type, 'event_time': _text(event_time, 128),
        'process_id': _text(merged.get('ProcessGuid') or merged.get('ProcessId') or merged.get('NewProcessId'), 256),
        'parent_process_id': _text(merged.get('ParentProcessGuid') or merged.get('ParentProcessId') or merged.get('CreatorProcessId'), 256),
        'process_path': _text(merged.get('Image') or merged.get('ProcessName') or merged.get('NewProcessName')),
        'parent_path': _text(merged.get('ParentImage') or merged.get('CreatorProcessName')),
        'command_line': _text(merged.get('CommandLine') or merged.get('ProcessCommandLine') or merged.get('ScriptBlockText')),
        'principal': _text(merged.get('User') or merged.get('SubjectUserName') or merged.get('UserID'), 1024),
        'object_path': _text(merged.get('TargetFilename') or merged.get('TargetObject') or merged.get('ImageLoaded') or merged.get('TargetImage') or merged.get('QueryName')),
        'network': {key: value for key, value in {
            'protocol': _text(merged.get('Protocol'), 32),
            'destination_port': _text(merged.get('DestinationPort'), 16),
            'destination_ip': _text(merged.get('DestinationIp'), 128),
        }.items() if value is not None},
        'adapter_version': 'kltn-live-windows-v1',
    }
