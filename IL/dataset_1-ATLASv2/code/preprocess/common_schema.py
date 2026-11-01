#!/usr/bin/env python3
"""Canonical Schema and IOC Definitions for ATLASv2 Preprocessing.

Defines the normalized CanonicalEvent dataclass and domain constants for
Domain-Incremental Learning (OpTC -> ATLASv2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ntpath
import re
from typing import Any, Mapping

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Initial attack timestamps per scenario (UTC) from ATLASv2 Paper Table 1 & attack_senarios.md
INITIAL_ATTACK_TIMESTAMPS: dict[str, str] = {
    "s1": "2022-07-19 13:26:00",
    "s2": "2022-07-19 14:07:00",
    "s3": "2022-07-19 15:36:00",
    "s4": "2022-07-20 00:52:00",
    "m1": "2022-07-19 17:20:00",
    "m2": "2022-07-19 19:44:00",
    "m3": "2022-07-19 20:28:00",
    "m4": "2022-07-19 22:49:00",
    "m5": "2022-07-19 23:38:00",
    "m6": "2022-07-20 00:10:00",
}

# Known attack infrastructure & artifacts (Ground Truth Entities)
KNOWN_IOCS: dict[str, Any] = {
    "c2_ips": {
        "10.193.66.115",    # Attacker Kali Linux C2 host
        "192.168.223.129",  # Internal portal host (h1) exploited for lateral movement
    },
    "c2_ports": {
        9999,   # Meterpreter reverse shell port
        8443,   # HTTPS exfiltration channel
        8000,   # SimpleHTTP server on h1 (phishing portal download)
    },
    "c2_domains": {
        "ortrta.net",
    },
    "malicious_files": {
        "payload.exe",
        "s3take2.zip",
        "s4-at-night.zip",
        "m4.zip",
        "m5-2.zip",
        "m6.zip",
        "msf.doc",
    },
    "attack_processes": {
        "payload.exe",
        "meterpreter",
    },
}


def parse_timestamp_micros(val: Any) -> int:
    """Parse ISO 8601 string or numeric timestamp to integer microseconds since UTC epoch."""
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        # If seconds float, convert to micros
        if val < 2_000_000_000:
            return int(val * 1_000_000)
        return int(val)
    try:
        s = str(val).strip()
        # Handle '2022-07-19 12:09:41.2130679 +0000 UTC' format from CBC
        s = s.replace(" UTC", "").replace("+0000", "+00:00")
        if " " in s and "T" not in s:
            parts = s.split(" ")
            if len(parts) >= 3:
                s = f"{parts[0]}T{parts[1]}{parts[2]}"
            elif len(parts) == 2:
                s = f"{parts[0]}T{parts[1]}+00:00"
        # Truncate fractional seconds to 6 digits (microseconds) if > 6 digits
        m = re.search(r"(\.\d{1,9})", s)
        if m and len(m.group(1)) > 7:
            truncated = m.group(1)[:7]
            s = s[:m.start()] + truncated + s[m.end():]
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        delta = d.astimezone(timezone.utc) - EPOCH
        return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    except Exception:
        return 0


def extract_basename(path: str) -> str:
    """Extract Windows or POSIX executable/file basename in lowercase."""
    if not path or not isinstance(path, str):
        return ""
    clean = path.strip().strip('"\'')
    base = ntpath.basename(clean.replace("/", "\\"))
    return base.lower()


def classify_image_dir(image_path: str) -> str:
    """Classify Windows image path into one of the 6 finite categories (OpTC spec)."""
    if not image_path:
        return "OTHER"
    p = image_path.lower().replace("/", "\\")
    if "\\temp\\" in p or "\\appdata\\" in p:
        return "TEMP_OR_APPDATA"
    if "\\windows\\system32\\" in p or "\\syswow64\\" in p:
        return "SYSTEM32"
    if "\\program files\\" in p or "\\program files (x86)\\" in p:
        return "PROGRAM_FILES"
    if "\\windows\\" in p:
        return "WINDOWS_OTHER"
    if "\\users\\" in p or "\\documents and settings\\" in p:
        return "USERS_OTHER"
    return "OTHER"


def classify_principal(username: str) -> str:
    """Map raw username/account to finite OpTC principal category."""
    if not username or username.strip() in {"", "-", "null", "none"}:
        return "NONE"
    u = username.lower()
    if any(k in u for k in ["nt authority", "nt service", "font driver", "window manager", "dwm-"]):
        return "SYSTEM_ACCOUNT"
    if "administrator" in u:
        return "ADMINISTRATOR"
    if "sysadmin" in u:
        return "SYSADMIN"
    return "DOMAIN_USER"


def classify_resp_port(port: int) -> str:
    """Map destination/responder port to finite OpTC port category."""
    if port == 80:
        return "HTTP_80"
    if port == 443:
        return "HTTPS_443"
    if port == 53:
        return "DNS_53"
    if port == 445:
        return "SMB_445"
    if port >= 1024:
        return "EPHEMERAL_HIGH"
    return "WELL_KNOWN_OTHER"


@dataclass
class CanonicalEvent:
    """Normalized Canonical Event Schema representing an operating system event."""
    event_id: str
    timestamp: int              # UTC microseconds
    hostname: str               # Canonical lowercase ('win-32-h1', 'win-32-h2')
    event_type: str             # 'PROCESS_START', 'PROCESS_END', 'FLOW_START', 'FILE_WRITE', etc.
    scenario: str               # 's1'-'s4', 'm1'-'m6', 'benign-day1', etc.
    process_guid: str
    parent_guid: str = ""
    process_path: str = ""
    process_cmdline: str = ""
    parent_path: str = ""
    parent_cmdline: str = ""
    username: str = ""
    target_path: str = ""
    target_guid: str = ""
    proto: str = ""             # 'tcp', 'udp', etc.
    remote_ip: str = ""
    remote_port: int = 0
    local_port: int = 0
    inbound: bool = False
    label: int = 0              # 0 = Benign, 1 = Attack
