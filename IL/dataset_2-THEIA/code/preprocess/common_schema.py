#!/usr/bin/env python3
"""Canonical Schema and IOC Definitions for DARPA TC E3 THEIA Preprocessing.

Defines the normalized CanonicalEvent dataclass and domain constants for
Domain-Incremental Learning (OpTC -> THEIA).

Run 7 additions:
  - net_endpoint_type field on CanonicalEvent: 'external' | 'loopback' | 'unix_domain'
    | 'unknown_endpoint' | '' (non-network events)
  - classify_proc_resource(): semantic roles for /proc/* paths
  - classify_system_resource(): extended with auth_db, tz_config, browser_host_config,
    system_log roles
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import posixpath
import re
from typing import Any, Mapping

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Initial attack timestamps per scenario (UTC) from DARPA TC E3 Ground Truth
THEIA_ATTACK_TIMESTAMPS: dict[str, str] = {
    # Attack Day 10 (2018-04-10)
    "theia_3.11_fail": "2018-04-10 17:00:00",
    "theia_3.11_success": "2018-04-10 17:15:00",
    "theia_3.3_fail_allstate": "2018-04-10 18:00:00",
    "theia_3.3_fail_gatech_clean": "2018-04-10 18:30:00",
    "theia_3.3_success_gatech_profile": "2018-04-10 19:00:00",
    # Attack Day 13 (2018-04-13)
    "theia_4.8_fail": "2018-04-13 15:30:00",
}

# Known attack infrastructure & artifacts (Ground Truth Entities) for THEIA
KNOWN_IOCS: dict[str, Any] = {
    "c2_ips": {
        "128.55.12.110",
        "128.55.12.111",
        "10.0.4.2",
    },
    "c2_ports": {
        22,     # SSH exploit & lateral connection
        4444,   # Metasploit shell / payload listener
        8080,   # HTTP staging / download
        80,     # Web server C2
        443,    # HTTPS C2
    },
    "malicious_binaries": {
        "clean",
        "profile",
        "allstate",
        "firefox",  # Weaponized browser exploit payload
        "netcat",
        "nc",
    },
    "malicious_paths": {
        "/home/admin/clean",
        "/home/admin/Downloads/firefox/firefox",
        "/tmp/clean",
        "/tmp/profile",
    },
}


def parse_timestamp_micros(val: Any) -> int:
    """Parse integer nanoseconds/microseconds or ISO string to integer microseconds since UTC epoch."""
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        # If nanoseconds (> 1e16), convert to microseconds
        if val > 1_000_000_000_000_000:
            return int(val // 1_000)
        # If seconds float (< 2e9), convert to microseconds
        if val < 2_000_000_000:
            return int(val * 1_000_000)
        return int(val)
    try:
        s = str(val).strip()
        if s.isdigit():
            v = int(s)
            if v > 1_000_000_000_000_000:
                return v // 1_000
            elif v < 2_000_000_000:
                return v * 1_000_000
            return v
        s = s.replace(" UTC", "").replace("+0000", "+00:00")
        if " " in s and "T" not in s:
            parts = s.split(" ")
            if len(parts) >= 3:
                s = f"{parts[0]}T{parts[1]}{parts[2]}"
            elif len(parts) == 2:
                s = f"{parts[0]}T{parts[1]}+00:00"
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
    """Extract POSIX or Windows executable/file basename in lowercase."""
    if not path or not isinstance(path, str):
        return ""
    clean = path.strip().strip('"\'')
    clean = clean.split()[0] if " " in clean and "/" not in clean else clean
    # Remove '(deleted)' suffix common in Linux /proc/pid/exe
    clean = clean.replace("(deleted)", "").strip()
    base = posixpath.basename(clean.replace("\\", "/"))
    return base.lower()


def normalize_posix_path(path: str) -> str:
    """Lexical normalization only; never touch the filesystem or resolve symlinks."""
    return posixpath.normpath(path.strip().strip('"\'').replace("\\", "/")) if path else ""


def path_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def classify_image_dir(image_path: str) -> str:
    """Finite semantic categories, with POSIX component boundaries and case preserved."""
    p = normalize_posix_path(image_path)
    for roots, category in (
        (("/proc", "/sys", "/dev"), "PSEUDO_FS"),
        (("/tmp", "/var/tmp"), "TEMP_OR_APPDATA"),
        (("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"), "SYSTEM32"),
        (("/usr/lib", "/usr/lib64", "/lib", "/lib64", "/opt"), "PROGRAM_FILES"),
        (("/home", "/root"), "USERS_OTHER"),
        (("/etc",), "WINDOWS_OTHER"),
    ):
        if any(path_under(p, r) for r in roots):
            return category
    return "OTHER"


def classify_system_resource(path: str) -> str:
    """Resource role, independent of actor/label; reads and writes retain their action.

    Run 7: Extended with auth_db, tz_config, browser_host_config, system_log roles.
    These roles are purely structural/semantic — not anomaly indicators by themselves.
    """
    p = normalize_posix_path(path)
    if p in {"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/gai.conf"}:
        return "name_service_config"
    if p in {"/etc/ld.so.cache", "/etc/ld.so.conf"} or path_under(p, "/etc/ld.so.conf.d"):
        return "dynamic_loader_config"
    # Authentication / credential database
    if p in {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
             "/etc/sudoers"} or path_under(p, "/etc/sudoers.d"):
        return "auth_db"
    # Timezone / locale configuration
    if p in {"/etc/localtime", "/etc/timezone", "/etc/locale.conf"} or path_under(p, "/usr/share/zoneinfo"):
        return "tz_config"
    # Browser native-messaging host config (e.g. /etc/firefox/native-messaging-hosts/*)
    if path_under(p, "/etc/firefox") or path_under(p, "/etc/chromium") or \
       path_under(p, "/etc/opt/chrome") or "native-messaging-hosts" in p.split("/"):
        return "browser_host_config"
    # System log files
    if path_under(p, "/var/log"):
        return "system_log"
    return ""


def classify_proc_resource(path: str, actor_pid_hint: str = "") -> str:
    """Semantic role for /proc/* paths.

    Run 7: Distinguishes self-maps, process-introspect, and sysinfo reads to break
    exact-vector collisions between normal Firefox /proc reads and attack-context reads.

    actor_pid_hint: string PID of the acting process, used to detect /proc/self/
      or /proc/<own_pid>/ accesses (self-inspection vs. cross-process introspection).
      Pass empty string when PID is unavailable — will not attempt self-classification.

    Returns a role string or '' if path is not under /proc.
    """
    p = normalize_posix_path(path)
    if not path_under(p, "/proc"):
        return ""

    # Strip /proc prefix and get the next component
    rest = p[len("/proc"):]
    rest = rest.lstrip("/")
    if not rest:
        return "proc_map::proc_root_read"

    parts = rest.split("/", 1)
    first = parts[0]
    sub = parts[1] if len(parts) > 1 else ""

    leaf = sub.split("/", 1)[0]

    # /proc/self/* or /proc/<own_pid>/* — self-inspection
    if first in ("self", "thread-self") or (actor_pid_hint and first == actor_pid_hint):
        if leaf in ("maps", "mem", "smaps", "smaps_rollup"):
            return "proc_map::self_maps"
        if leaf in ("fd", "fdinfo"):
            return "proc_map::self_fd"
        if leaf in ("status", "stat", "cmdline"):
            return "proc_map::self_status"
        return "proc_map::self_other"

    # /proc/<numeric_pid>/* — cross-process introspection (potential process injection indicator)
    if first.isdigit():
        owner = "other" if actor_pid_hint else "unknown"
        if leaf in ("maps", "mem", "smaps", "smaps_rollup"):
            return f"proc_map::{owner}_maps"
        if leaf in ("fd", "fdinfo"):
            return f"proc_map::{owner}_fd"
        if leaf in ("status", "stat", "cmdline"):
            return f"proc_map::{owner}_status"
        return f"proc_map::{owner}_pid"

    # /proc/sys/* — kernel parameter reads (sysctl)
    if first == "sys":
        return "proc_map::sysctl"

    # /proc/net/* — network state reads
    if first == "net":
        return "proc_map::net_state"

    # /proc/<known_sysinfo_name> — global system state reads
    _SYSINFO_NAMES = frozenset({
        "meminfo", "cpuinfo", "loadavg", "uptime", "stat", "version",
        "filesystems", "mounts", "partitions", "swaps", "devices",
        "interrupts", "softirqs", "vmstat", "slabinfo", "buddyinfo",
        "diskstats", "mdstat", "modules", "kallsyms", "iomem",
    })
    if first in _SYSINFO_NAMES:
        return "proc_map::sysinfo_read"

    return "proc_map::other_named"


def classify_principal(user_id_or_name: Any) -> str:
    """Map Linux UID or username to finite OpTC principal category."""
    if user_id_or_name is None:
        return "NONE"
    s = str(user_id_or_name).strip().lower()
    if s in {"", "-", "none", "null"}:
        return "NONE"
    if s == "0" or s == "root":
        return "SYSTEM_ACCOUNT"  # UID 0 root corresponds to Windows SYSTEM
    if s.isdigit():
        uid = int(s)
        if uid == 65534:
            return "DOMAIN_USER"  # nobody
        if 0 < uid < 1000:
            return "SYSTEM_ACCOUNT"  # system daemon accounts (syslog, messagebus, daemon)
        if uid >= 1000:
            return "DOMAIN_USER"  # interactive local user (admin, theia)
    if "admin" in s:
        return "ADMINISTRATOR"
    return "DOMAIN_USER"


def classify_resp_port(port: int) -> str:
    """Map destination/responder port to finite OpTC port category."""
    if port == 22:
        return "PORT_22_SSH"
    if port == 80:
        return "PORT_80_HTTP"
    if port == 443:
        return "PORT_443_HTTPS"
    if port == 53:
        return "PORT_53_DNS"
    if port == 445:
        return "PORT_445_SMB"
    if port >= 1024:
        return "EPHEMERAL_HIGH"
    return "WELL_KNOWN_OTHER"


@dataclass
class CanonicalEvent:
    """Normalized Canonical Event Schema representing an operating system event."""
    event_id: str
    timestamp: int              # UTC microseconds
    hostname: str               # 'theia-desktop' or '10.0.6.60'
    event_type: str             # 'PROCESS_START', 'PROCESS_END', 'FLOW_START', 'FILE_WRITE', etc.
    scenario: str               # e.g. 'theia_3.3_fail_gatech_clean', 'benign-day11'
    process_guid: str           # Subject UUID
    parent_guid: str = ""       # Parent Subject UUID
    process_path: str = ""
    process_pid: str = ""       # RAW tgid/cid join key, never a feature
    principal_role: str = "unknown"
    raw_operation: str = ""
    process_cmdline: str = ""
    parent_path: str = ""
    parent_cmdline: str = ""
    username: str = ""
    principal_class: str = "OTHER"
    target_path: str = ""
    target_file_guid: str = ""  # Causal write/execute object join only; never a feature
    target_guid: str = ""
    proto: str = ""             # 'tcp', 'udp'
    remote_ip: str = ""
    remote_port: int = 0
    local_port: int = 0
    inbound: bool = False
    source_line: int = 0        # Physical CSV line, including header
    label: int = 0              # 0 = Benign, 1 = Attack
    # Run 7: network endpoint classification for the adapter's IPC disambiguation
    # Values: 'external' | 'loopback' | 'unix_domain' | 'unknown_endpoint' | ''
    net_endpoint_type: str = ""

