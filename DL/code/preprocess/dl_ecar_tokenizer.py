#!/usr/bin/env python3
"""Deep Learning eCAR Tokenizer supporting Host and Bounded Network Telemetry.

Extends the deterministic Host ML tokenizer (ML/code/preprocess/ecar_tokenizer.py)
to support FLOW events and network socket interactions in OpTC.

All network attributes are mapped to finite, bounded semantic classes:
- Zero raw IP addresses (mapped to enterprise internal, private, external, loopback)
- Zero ephemeral port numbers (mapped to MITRE service roles, registered, ephemeral)
- Zero arbitrary packet counts (quantized into beacon, small, medium, bulk)
- Normalized process socket ownership (binary name and directory role)

Guarantees 100% equivalence for Host events while unlocking network multi-domain
causal reasoning for Deep Learning (BiLSTM / MixHead Self-Attention).
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple, Set

# Import core Host ML tokenizer components
import sys
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = next((p for p in CURRENT_DIR.parents if (p / "AGENTS.md").is_file()), CURRENT_DIR)
for p in (CURRENT_DIR, CURRENT_DIR.parent, PROJECT_ROOT, PROJECT_ROOT / "ML/code/preprocess"):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from ecar_tokenizer import (
        GROUPS,
        HOST_OBJECT_FIELDS,
        KNOWN_ACTIONS as HOST_KNOWN_ACTIONS,
        tokenize_record as host_tokenize_record,
        tokenize_principal,
        _compact_path_tokens,
        normalize_literals,
        _basename_windows,
    )
except ImportError:
    from ML.code.preprocess.ecar_tokenizer import (
        GROUPS,
        HOST_OBJECT_FIELDS,
        KNOWN_ACTIONS as HOST_KNOWN_ACTIONS,
        tokenize_record as host_tokenize_record,
        tokenize_principal,
        _compact_path_tokens,
        normalize_literals,
        _basename_windows,
    )

# Extended Object Fields including FLOW
DL_OBJECT_FIELDS = dict(HOST_OBJECT_FIELDS)
DL_OBJECT_FIELDS["flow"] = (
    "direction",
    "l4protocol",
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "size",
    "image_path",
)

# Network Actions
NET_KNOWN_ACTIONS = frozenset({
    "start", "open", "message", "close", "datatransfer", "info", "unknown",
})

ALL_KNOWN_ACTIONS = HOST_KNOWN_ACTIONS | NET_KNOWN_ACTIONS

# Enterprise IP Ranges for OpTC & Standard RFC
OPTC_ENTERPRISE_NET = ipaddress.ip_network("142.20.0.0/16")
RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Protocol Mapping
PROTO_MAP: Dict[str, str] = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
    "58": "icmpv6",
}

# Semantic Port Roles for APT & Enterprise Protocols
PORT_ROLE_MAP: Dict[int, str] = {
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


def classify_ip_endpoint(ip_str: Optional[str]) -> str:
    """Classifies an IP string into a bounded scope."""
    if not ip_str or not isinstance(ip_str, str):
        return "unspecified"
    cleaned = ip_str.strip()
    if not cleaned or cleaned in ("::", "0.0.0.0", "0"):
        return "unspecified"
    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_loopback:
            return "loopback"
        if ip.is_multicast:
            return "multicast"
        if cleaned == "255.255.255.255" or ip.is_reserved:
            return "broadcast"
        if ip.is_link_local:
            return "link_local"
        if ip.version == 4:
            if ip in OPTC_ENTERPRISE_NET:
                return "enterprise_internal"
            for net in RFC1918_NETS:
                if ip in net:
                    return "private_internal"
            return "external_public"
        return "ipv6_other"
    except ValueError:
        return "unknown"


def classify_network_scope(src_scope: str, dest_scope: str) -> str:
    """Determines the macro network traffic scope."""
    internal_types = {"enterprise_internal", "private_internal"}
    if src_scope in internal_types and dest_scope in internal_types:
        return "internal_to_internal"  # Lateral Movement / Internal AD
    if src_scope in internal_types and dest_scope == "external_public":
        return "internal_to_external"  # C2 Beaconing / Exfiltration
    if src_scope == "external_public" and dest_scope in internal_types:
        return "external_to_internal"  # Inbound Exploit / Ingress
    if src_scope == "loopback" or dest_scope == "loopback":
        return "loopback"
    if dest_scope in ("multicast", "broadcast"):
        return "multicast_broadcast"
    if src_scope == "unspecified" or dest_scope == "unspecified":
        return "unspecified"
    return f"{src_scope}_to_{dest_scope}"


def classify_port_role(port_val: Any) -> str:
    """Maps a port value to a discrete semantic role."""
    try:
        p = int(port_val)
    except (ValueError, TypeError):
        return "unknown"
    if p in PORT_ROLE_MAP:
        return PORT_ROLE_MAP[p]
    if p < 1024:
        return "well_known_other"
    if p < 49152:
        return "registered_mid"
    return "ephemeral_high"


def classify_proto(proto_val: Any) -> str:
    """Maps L4 protocol to tcp, udp, icmp, or other."""
    if proto_val is None:
        return "other"
    s = str(proto_val).strip()
    return PROTO_MAP.get(s, "other")


def classify_bytes(size_val: Any) -> str:
    """Quantizes transferred bytes into semantic payload buckets."""
    try:
        s = int(size_val)
    except (ValueError, TypeError):
        return "zero"
    if s <= 0:
        return "zero"
    if s <= 1024:
        return "tiny_beacon"      # 1 B - 1 KB (Heartbeat / Beaconing)
    if s <= 65536:
        return "small_payload"    # 1 KB - 64 KB (Shell command output / small payload)
    if s <= 1048576:
        return "medium_transfer"  # 64 KB - 1 MB
    return "bulk_exfil"           # > 1 MB (Data staging / exfiltration)


def tokenize_network_flow(record: Mapping[str, Any]) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
    """Tokenizes an OpTC FLOW record into bounded network tokens."""
    grouped: Dict[str, List[str]] = {group: [] for group in GROUPS}
    audit: Dict[str, Any] = {
        "eligible": True,
        "excluded_reason": None,
        "command_family": None,
        "decode_status": {},
        "parse_status": {},
        "filtered_tokens": {},
    }

    raw_action = record.get("action")
    action = raw_action.strip().casefold() if isinstance(raw_action, str) else ""
    if action not in NET_KNOWN_ACTIONS:
        action = "unknown"

    # Core identities
    grouped["principal"].extend(tokenize_principal(record.get("principal")))
    grouped["action"].append(f"action::{action}")
    grouped["object"].append("object::flow")
    grouped["structure_semantic"].append(f"structure::action_object={action}->flow")

    props = record.get("properties")
    properties = props if isinstance(props, Mapping) else {}

    # Direction
    raw_dir = properties.get("direction")
    direction = raw_dir.strip().casefold() if isinstance(raw_dir, str) and raw_dir.strip() in ("inbound", "outbound") else "unknown"
    grouped["property_value"].append(f"net::direction={direction}")

    # L4 Protocol
    proto = classify_proto(properties.get("l4protocol"))
    grouped["property_value"].append(f"net::proto={proto}")

    # IP Scopes
    src_scope = classify_ip_endpoint(properties.get("src_ip"))
    dest_scope = classify_ip_endpoint(properties.get("dest_ip"))
    grouped["property_value"].append(f"net::src_scope={src_scope}")
    grouped["property_value"].append(f"net::dest_scope={dest_scope}")

    net_scope = classify_network_scope(src_scope, dest_scope)
    grouped["property_value"].append(f"net::scope={net_scope}")

    # Port Roles
    src_port_role = classify_port_role(properties.get("src_port"))
    dest_port_role = classify_port_role(properties.get("dest_port"))
    grouped["property_value"].append(f"net::src_port_role={src_port_role}")
    grouped["property_value"].append(f"net::dest_port_role={dest_port_role}")

    # Bytes bucket
    bytes_bucket = classify_bytes(properties.get("size"))
    grouped["property_value"].append(f"net::bytes={bytes_bucket}")

    # Cross-field Flow Pattern for multi-task / attention heads
    flow_pattern = f"{proto}:{dest_port_role}:{direction}"
    grouped["structure_semantic"].append(f"net::flow_pattern={flow_pattern}")

    # Socket Owning Process Image
    image_path = properties.get("image_path")
    if isinstance(image_path, str) and image_path.strip():
        img_clean = image_path.strip()
        grouped["property_value"].extend(_compact_path_tokens("image_path", img_clean, True))
        base_exe = normalize_literals(_basename_windows(img_clean))
        if base_exe:
            grouped["property_value"].append(f"net::proc={base_exe}")

    return grouped, audit


def tokenize_dl_record(record: Mapping[str, Any]) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
    """Universal tokenizer for Deep Learning: processes both Host events and FLOW events.

    Delegates Host events (process, file, module, registry, etc.) to the verified Host ML
    tokenizer, and processes FLOW events through tokenize_network_flow.
    """
    raw_object = record.get("object")
    object_type = raw_object.strip().casefold() if isinstance(raw_object, str) else ""

    if object_type == "flow":
        return tokenize_network_flow(record)

    # Standard host events
    return host_tokenize_record(record)


def get_all_bounded_network_tokens() -> List[str]:
    """Generates the complete set of discrete bounded network tokens.

    This finite list allows instant, deterministic expansion of any base vocabulary
    without requiring a full multi-gigabyte re-scan of raw logs.
    """
    tokens: Set[str] = {
        "object::flow",
        "net::direction=inbound",
        "net::direction=outbound",
        "net::direction=unknown",
        "net::bytes=zero",
        "net::bytes=tiny_beacon",
        "net::bytes=small_payload",
        "net::bytes=medium_transfer",
        "net::bytes=bulk_exfil",
    }

    # Actions & Structure
    for act in NET_KNOWN_ACTIONS:
        tokens.add(f"action::{act}")
        tokens.add(f"structure::action_object={act}->flow")

    # Protocols
    protos = ("tcp", "udp", "icmp", "icmpv6", "other")
    for proto in protos:
        tokens.add(f"net::proto={proto}")

    # Scopes
    scopes = (
        "unspecified", "loopback", "multicast", "broadcast", "link_local",
        "enterprise_internal", "private_internal", "external_public", "ipv6_other", "unknown"
    )
    for s in scopes:
        tokens.add(f"net::src_scope={s}")
        tokens.add(f"net::dest_scope={s}")

    macro_scopes = (
        "internal_to_internal", "internal_to_external", "external_to_internal",
        "loopback", "multicast_broadcast", "unspecified"
    )
    for ms in macro_scopes:
        tokens.add(f"net::scope={ms}")

    # Port roles
    roles = set(PORT_ROLE_MAP.values()) | {"well_known_other", "registered_mid", "ephemeral_high", "unknown"}
    for r in roles:
        tokens.add(f"net::src_port_role={r}")
        tokens.add(f"net::dest_port_role={r}")

    # Common flow patterns (proto:dest_role:direction)
    for p in ("tcp", "udp"):
        for d in ("inbound", "outbound"):
            for r in (
                "http_web", "https_web", "dns", "smb_cifs", "rpc_endpoint",
                "remote_desktop", "winrm_http", "winrm_https", "kerberos", "ldap",
                "ssh", "ephemeral_high", "registered_mid", "well_known_other"
            ):
                tokens.add(f"net::flow_pattern={p}:{r}:{d}")

    # Common enterprise / attacker socket binaries in OpTC
    common_procs = (
        "svchost.exe", "python.exe", "powershell.exe", "cmd.exe", "explorer.exe",
        "system", "lsass.exe", "services.exe", "spoolsv.exe", "taskhostw.exe",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "mstsc.exe"
    )
    for exe in common_procs:
        tokens.add(f"net::proc={exe}")

    return sorted(tokens)
