#!/usr/bin/env python3
"""Schema definitions, index bounds, exclusion policies, and token mappers for DARPA TC E3 THEIA.

Aligns THEIA Linux CDM provenance telemetry with:
- NDSS 2027 Theseus (`create_parquet_files_e3.py`): T3 post-reboot regime & `EDGE_REVERSED_OPS` directionality.
- REAPr Ground Truth: exclusion of failed attempts (`theia_3.3_fail_*`, `theia_3.11_fail`, `theia_4.8_fail`)
  and `contaminated` artifacts.
- MAGIC / ATLASv2 noise-reduction evidence: exclusion of standard OS dynamic linker / shared libraries
  while preserving attacker-planted libraries (`/tmp/memtrace.so`).
- OpTC `dl_ecar_tokenizer.py` finite semantic token conventions for cross-domain IL transfer.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Dict, Set

# ---------------------------------------------------------------------------
# Node Index Boundaries (Parquet/event_table.parquet sequential layout)
# ---------------------------------------------------------------------------
NETFLOW_INDEX_MIN = 0
NETFLOW_INDEX_MAX = 186099

PROCESS_INDEX_MIN = 186100
PROCESS_INDEX_MAX = 465468

FILE_INDEX_MIN = 465469
FILE_INDEX_MAX = 1487423

# Post-reboot T3 start timestamp in nanoseconds (2018-04-10 16:44:33 UTC),
# eliminating pre-reboot T1/T2 workload-generator distribution shift while preserving EVENT_CLONE/UNLINK.
T3_START_NS = 1523378673_000_000_000

# Operations where `Parquet/event_table.parquet` stores `src_index_id = Object` and `dst_index_id = Actor Process`.
# Verified against NDSS 2027 Theseus `scripts/create_parquet_files_e3.py` lines 13-25.
EDGE_REVERSED_OPS: Set[str] = {
    "EVENT_EXECUTE",
    "EVENT_LSEEK",
    "EVENT_MMAP",
    "EVENT_OPEN",
    "EVENT_ACCEPT",
    "EVENT_READ",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_READ_SOCKET_PARAMS",
    "EVENT_CHECK_FILE_ATTRIBUTES",
    "READ",
}

# ---------------------------------------------------------------------------
# Head 2: Scenario Attribution Mapping (Successful Attacks Only)
# ---------------------------------------------------------------------------
SCENARIO_NAMES: Dict[int, str] = {
    0: "Benign",
    1: "NationState_Firefox_Drakon",   # Attack 3.3 (theia_3.3_success_gatech_profile, Apr 10-12)
    2: "BrowserExtension_MicroAPT",    # Attack 3.11 (theia_3.11_success, Apr 12)
}

SCENARIO_IDS: Dict[str, int] = {name: idx for idx, name in SCENARIO_NAMES.items()}

# ---------------------------------------------------------------------------
# Head 3: MITRE ATT&CK Kill-Chain Stages (Matching Unified Multi-Domain IL)
# ---------------------------------------------------------------------------
STAGE_NAMES: Dict[int, str] = {
    0: "Benign",
    1: "Initial_Compromise",
    2: "Execution_PrivilegeEscalation",
    3: "Discovery_Reconnaissance",
    4: "C2_Exfiltration",
}

STAGE_IDS: Dict[str, int] = {name: idx for idx, name in STAGE_NAMES.items()}

# ---------------------------------------------------------------------------
# REAPr Chain Inclusion & Exclusion Sets
# ---------------------------------------------------------------------------
INCLUDED_ATTACK_CHAINS: Dict[str, int] = {
    "theia_3.3_success_gatech_profile": 1,
    "theia_3.11_success": 2,
}

EXCLUDED_FAIL_CHAINS: Set[str] = {
    "theia_3.3_fail_allstate",
    "theia_3.3_fail_gatech_clean",
    "theia_3.11_fail",
    "theia_4.8_fail",
}

# Unlabeled Common Threat Section 4.6 phishing / noise IPs (must not contaminate Benign)
EXCLUDED_COMMON_THREAT_IPS: Set[str] = {
    "208.75.117.2",
    "208.75.117.3",
    "62.83.155.175",
}

# Failed-attack exclusive binary paths (defense-in-depth exclusion alongside REAPr fail edge UUIDs)
EXCLUDED_FAIL_PATH_SUBSTRS = (
    "/home/admin/clean",
    "tcexec",
    "jag_isht.bin",
    "libqt5widgets",
    "libqt5gui",
    "libqt5core",
)

# Shared benign GUI parents in fail chains that have millions of legitimate background events
SHARED_HOST_GUI_PROCS: Set[str] = {
    "/usr/bin/fluxbox",
    "/usr/bin/gnome-terminal",
}

# ---------------------------------------------------------------------------
# Attacker Infrastructure & Semantic Artifacts
# ---------------------------------------------------------------------------
INITIAL_DELIVERY_IPS: Set[str] = {
    "141.43.176.203",  # Malicious ad server (gatech.edu malvertising)
    "146.153.68.151",  # THEIA Drakon/Extension payload dropper server
}

C2_IPS: Set[str] = {
    "161.116.88.72",   # Drakon C2 operator console (Attack 3.3)
    "149.52.198.23",   # Micro APT C2 listener (Attack 3.11)
    "5.214.163.155",   # TRACE/related C2 server
    "61.130.69.232",   # Dropper C2 infrastructure
}

RECON_EXTERNAL_IPS: Set[str] = {
    "7.149.198.40",    # External probe target hit by `profile (deleted)` on Apr 11
}

KNOWN_C2_IPS: Set[str] = INITIAL_DELIVERY_IPS | C2_IPS | RECON_EXTERNAL_IPS

MALICIOUS_IMPLANT_NAMES: Set[str] = {
    "profile",
    "mail",
    "pass_mgr",
    "gtcache",
    "memtrace.so",
    "xdev",
    "wdev",
    "glx_alsa_675",
}

ATTACKER_SHELL_NAMES: Set[str] = {
    "bash",
    "dash",
    "sh",
    "uname",
}

DISCOVERY_PATHS = (
    "/etc/passwd",
    "/etc/group",
    "/proc/",
    "/stat",
    "/maps",
    "/sys/devices/system/cpu",
    "/bin/uname",
    "/var/log",
    "/tmp",
    "/dev/urandom",
    "/dev/null",
)

# Standard OpTC `PORT_ROLE_MAP` alignment for cross-domain transfer
THEIA_PORT_ROLE_MAP: Dict[int, str] = {
    80: "http_web",
    8080: "http_web",
    8000: "http_web",
    8888: "http_web",
    443: "https_web",
    8443: "https_web",
    53: "dns",
    445: "smb_cifs",
    139: "smb_cifs",
    135: "rpc_endpoint",
    137: "netbios_ns",
    138: "netbios_dgm",
    3389: "remote_desktop",
    5985: "winrm_http",
    5986: "winrm_https",
    88: "kerberos",
    389: "ldap",
    636: "ldaps",
    3268: "ldap_gc",
    3269: "ldaps_gc",
    22: "ssh",
    21: "ftp",
    20: "ftp_data",
    25: "smtp",
    465: "smtps",
    587: "smtp_sub",
    123: "ntp",
    161: "snmp",
    162: "snmp_trap",
}

THEIA_ENTERPRISE_NET = ipaddress.ip_network("128.55.12.0/24")
RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def get_node_type(index_id: int) -> str:
    """Resolve DARPA THEIA Parquet `index_id` to `netflow`, `process`, or `file`."""
    if NETFLOW_INDEX_MIN <= index_id <= NETFLOW_INDEX_MAX:
        return "netflow"
    if PROCESS_INDEX_MIN <= index_id <= PROCESS_INDEX_MAX:
        return "process"
    if FILE_INDEX_MIN <= index_id <= FILE_INDEX_MAX:
        return "file"
    return "unknown"


def is_os_shared_library(path: str) -> bool:
    """Return True for benign OS dynamic-linker / system library loads, preserving attacker payloads like `/tmp/memtrace.so`."""
    if not path:
        return False
    p = path.strip().lower()
    if p == "/etc/ld.so.cache" or p == "/etc/ld.so.conf" or p.startswith("/etc/ld.so.conf.d"):
        return True
    if ".so" in p and (
        p.startswith("/lib/")
        or p.startswith("/lib64/")
        or p.startswith("/usr/lib/")
        or p.startswith("/usr/lib64/")
    ):
        return True
    return False


def ip_scope(ip: str) -> str:
    """Classify IPv4/IPv6/special endpoint string into finite OpTC-aligned network scopes."""
    if not ip or not isinstance(ip, str):
        return "unspecified"
    cleaned = ip.strip()
    if not cleaned or cleaned in ("NA", "0.0.0.0", "::", "0"):
        return "unspecified"
    if cleaned.upper() == "LOCAL" or cleaned.startswith("/"):
        return "loopback"
    try:
        addr = ipaddress.ip_address(cleaned)
        if addr.is_loopback:
            return "loopback"
        if addr.is_multicast:
            return "multicast"
        if cleaned == "255.255.255.255" or addr.is_reserved:
            return "broadcast"
        if addr.is_link_local:
            return "link_local"
        if addr.version == 4:
            if addr in THEIA_ENTERPRISE_NET:
                return "enterprise_internal"
            for net in RFC1918_NETS:
                if addr in net:
                    return "private_internal"
            return "external_public"
        return "ipv6_other"
    except ValueError:
        return "unknown"


def network_macro_scope(src_scope: str, dst_scope: str) -> str:
    """Map endpoint scopes into OpTC `net::scope=...` macro traffic roles."""
    internal_types = {"enterprise_internal", "private_internal"}
    if src_scope in internal_types and dst_scope in internal_types:
        return "internal_to_internal"
    if src_scope in internal_types and dst_scope == "external_public":
        return "internal_to_external"
    if src_scope == "external_public" and dst_scope in internal_types:
        return "external_to_internal"
    if src_scope == "loopback" or dst_scope == "loopback":
        return "loopback"
    if dst_scope in ("multicast", "broadcast"):
        return "multicast_broadcast"
    if src_scope == "unspecified" or dst_scope == "unspecified":
        return "unspecified"
    return "unspecified"


def port_class(p: int) -> str:
    """Map port number to OpTC-aligned semantic role strings."""
    try:
        port = int(p)
    except (ValueError, TypeError):
        return "unknown"
    if port <= 0:
        return "unknown"
    if port in THEIA_PORT_ROLE_MAP:
        return THEIA_PORT_ROLE_MAP[port]
    if port < 1024:
        return "well_known_other"
    if port < 49152:
        return "registered_mid"
    return "ephemeral_high"


def is_deleted_process_path(path: str) -> bool:
    """Detect whether a THEIA process path carries the `(deleted)` suffix."""
    return bool(path and path.strip().lower().endswith("(deleted)"))


def extract_basename(path: str) -> str:
    """Extract normalized executable or file basename, stripping any ` (deleted)` marker."""
    if not path:
        return ""
    p = path.strip()
    if p.lower().endswith(" (deleted)"):
        p = p[: -len(" (deleted)")].strip()
    elif p.lower().endswith("(deleted)"):
        p = p[: -len("(deleted)")].strip()
    p = p.rstrip("/")
    if not p:
        return ""
    return os.path.basename(p).lower()


def classify_path_dir(path: str) -> str:
    """Map Linux path into OpTC-aligned high-level path categories for cross-domain transfer."""
    if not path:
        return "relative"
    p = path.strip().lower()
    if p.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/dev/")):
        return "system"
    if p.startswith(("/tmp/", "/var/tmp/")):
        return "temp"
    if p.startswith("/home/"):
        return "user_profile"
    if p.startswith("/"):
        return "other_path"
    return "relative"
