# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_1-ATLASv2/code/DL/optc_il/contract.py
# source sha256 ad731a6ce7bdc5654d9e3588dadf9e4fce5ca568d0c940d0a26a53453c7caf01; do not edit (re-run the vendoring script instead).
"""OpTC Network-DL input contract (model B / subsetB) applied to ATLASv2 events.

The OpTC base model reads, per event, 4 categorical fields
[app_family, proto, resp_port_class, image_dir_class] + delta_t_log1p.
Value rules are copied verbatim from DL/01_code/pipeline_v2/v2_common.py
(image_dir_class, port_class, _text) so that an ATLASv2 event is tokenised
exactly like an OpTC flow. Ids come from the frozen OpTC vocabulary
(DL/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json);
ATLASv2 values that are new are appended after the OpTC ids (vocab extension).
"""
from __future__ import annotations

import json
from pathlib import Path

OPTC_SPEC = Path("/mnt/SSD_Data/optc/DL/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json")
FIELDS = ["app_family", "proto", "resp_port_class", "image_dir_class"]
SHARD_CAT_IDX = [0, 1, 4, 5]  # positions of FIELDS in the 7-column x_cat of the OpTC v2 shards
UNK, MISSING = 0, 1

COMMON_PORTS = {20: "FTP_DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 139: "NETBIOS", 143: "IMAP",
                389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES", 5985: "WINRM_HTTP", 5986: "WINRM_HTTPS",
                8080: "HTTP_ALT", 8443: "HTTPS_ALT"}
MISSING_TOKENS = ("", "-", "(empty)", "null", "none")


def _text(v):
    if v is None:
        return "<MISSING>"
    s = str(v).strip().lower()
    return "<MISSING>" if s in MISSING_TOKENS else s


def port_class(p):
    if p is None or p == "":
        return "<MISSING>"
    p = int(p)
    if p in COMMON_PORTS:
        return f"PORT_{p}_{COMMON_PORTS[p]}"
    if 0 <= p <= 1023:
        return "WELL_KNOWN_OTHER"
    if 1024 <= p <= 49151:
        return "REGISTERED"
    if 49152 <= p <= 65535:
        return "EPHEMERAL"
    return "OTHER"


def image_dir_class(path):
    if path is None or str(path).strip() == "":
        return "MISSING"
    p = str(path)
    lo = p.lower()
    if "\\" not in p and "/" not in p:
        return "BARE_NAME"
    if p.startswith("/") and "\\" not in p:
        if lo.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            return "TEMP_LINUX"
        if lo.startswith(("/home/", "/root/")):
            return "HOME_USER"
        if lo.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/")):
            return "SYSTEM_BIN"
        if lo.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/")):
            return "SYSTEM_LIB"
        if lo.startswith("/var/"):
            return "VAR_LOG"
        if lo.startswith(("/etc/", "/opt/")):
            return "ETC_OPT"
        return "OTHER"
    if "\\temp\\" in lo or "\\appdata\\" in lo:
        return "TEMP_OR_APPDATA"
    if "\\windows\\system32\\" in lo or "\\windows\\syswow64\\" in lo:
        return "SYSTEM32"
    if "\\windows\\" in lo:
        return "WINDOWS_OTHER"
    if "\\program files" in lo:
        return "PROGRAM_FILES"
    if "\\users\\" in lo:
        return "USERS_OTHER"
    return "OTHER"


def app_family(path):
    if path is None or str(path).strip() == "":
        return "<MISSING>"
    return _text(str(path).replace("/", "\\").rsplit("\\", 1)[-1])


def optc_tokens(r: dict) -> tuple[str, str, str, str]:
    """Raw OpTC-contract values for one parsed ATLASv2 event (parse_events.py record).

    Network connections map like a Bro conn row: proto tcp/udp, responder port
    (remote port when outbound, local port when inbound). Process/file events
    have no flow, so proto and resp_port_class are <MISSING> (reserved id 1).
    """
    if r["kind"] == "netconn":
        pr = (r.get("proto") or "").upper()
        proto = "tcp" if "TCP" in pr else ("udp" if "UDP" in pr else _text(pr))
        port = r["lport"] if r.get("inbound") else r["rport"]
        rpc = port_class(port)
    else:
        proto, rpc = "<MISSING>", "<MISSING>"
    return (app_family(r.get("path")), proto, rpc, image_dir_class(r.get("path")))


def load_optc_vocab(spec_path: Path = OPTC_SPEC) -> dict[str, dict[str, int]]:
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))["categorical"]["fields"]
    return {f: {e["value"]: int(e["id"]) for e in spec[f]["vocab"]} for f in FIELDS}
