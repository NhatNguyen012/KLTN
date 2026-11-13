# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_1-ATLASv2/code/DL/bilstm_v9/build_dataset.py
# source sha256 705690555298dbf2372facd9369452ac3a5d5adce917713ae904342abcd08081; do not edit (re-run the vendoring script instead).
from __future__ import annotations

import re

from .common_schema import classify_image_dir, classify_principal, extract_basename
from .dl_port_class import map_resp_port_class


LABEL_KINDS = ("netconn", "procstart", "crossproc")


WINDOW = 180_000_000


STRIDE = 30_000_000


MAX_LEN = 512


CAT_FIELDS = ["kind", "actor", "actor_dir", "parent", "target", "target_dir", "net",
              "ip_scope", "user", "pub", "tpub"]


CMD_FLAGS = [
    ("enc", re.compile(r"\s-(e|ec|en|enc|enco|encodedcommand)\s", re.I)),
    ("hidden", re.compile(r"(-w(indowstyle)?\s+h(idden)?\b)", re.I)),
    ("bypass", re.compile(r"(-nop\b|-noprofile|bypass|-noni\b|-noninteractive)", re.I)),
    ("url", re.compile(r"https?://", re.I)),
    ("script", re.compile(r"\.(ps1|vbs|js|hta|sct|bat|cmd)\b", re.I)),
    ("download", re.compile(r"(downloadstring|downloadfile|invoke-|iex\b|webclient|bitsadmin|certutil)", re.I)),
    ("regsvr", re.compile(r"(/i:|scrobj|/s\s)", re.I)),
    ("cmd_c", re.compile(r"\s/c\s", re.I)),
    ("long", None),
]


def cmd_flags(cmd: str) -> list[float]:
    c = f" {cmd} "
    out = []
    for name, rx in CMD_FLAGS:
        out.append(float(len(cmd) > 256) if rx is None else float(bool(rx.search(c))))
    return out


def ip_scope(ip: str) -> str:
    if not ip:
        return "NONE"
    if ":" in ip:
        return "IPV6"
    try:
        a, b, c, _ = (int(x) for x in ip.split("."))
    except ValueError:
        return "BAD"
    if a == 127:
        return "LOOPBACK"
    if a == 192 and b == 168 and c == 223:
        return "LOCAL_SUBNET"
    if a == 10:
        return "PRIV_10"
    if (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return "PRIV_OTHER"
    if a == 169 and b == 254:
        return "LINK_LOCAL"
    if a >= 224 or ip == "255.255.255.255":
        return "MULTICAST"
    if a == 0:
        return "ZERO"
    return "EXTERNAL"


def file_ext_class(name: str) -> str:
    n = name.lower()
    for cls, exts in (("EXE", (".exe",)), ("DLL", (".dll",)),
                      ("SCRIPT", (".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sct")),
                      ("ARCHIVE", (".zip", ".rar", ".7z")),
                      ("DOC", (".doc", ".docx", ".xls", ".xlsx", ".rtf", ".pdf")),
                      ("HTML", (".html", ".htm"))):
        if n.endswith(exts):
            return cls
    return "OTHER"


def event_tokens(r: dict) -> dict:
    k = r["kind"]
    t = {
        "actor": extract_basename(r["path"]) or "<NONE>",
        "actor_dir": classify_image_dir(r["path"]),
        "parent": extract_basename(r["ppath"]) or "<NONE>",
        "user": classify_principal(r["user"]),
        "pub": r["pub"],
        "tpub": r["tpub"] if k in ("procstart", "crossproc") else "NA",
        "net": "NA", "ip_scope": "NA", "target": "NA", "target_dir": "NA",
    }
    if k == "netconn":
        t["kind"] = "net_in" if r["inbound"] else "net_out"
        port = r["lport"] if r["inbound"] else r["rport"]
        proto = "tcp" if "TCP" in r["proto"] else ("udp" if "UDP" in r["proto"] else "other")
        t["net"] = f"{proto}:{map_resp_port_class(port)}:{'dom' if r['domain'] else 'nodom'}"
        t["ip_scope"] = ip_scope(r["rip"])
    elif k == "procstart":
        t["kind"] = "procstart"
        t["target"] = extract_basename(r["tpath"]) or "<NONE>"
        t["target_dir"] = classify_image_dir(r["tpath"])
    elif k == "crossproc":
        a = r["action"].upper()
        t["kind"] = "xp:" + ("dup_" if "DUP" in a else "open_") + ("thread" if "THREAD" in a else "process")
        t["target"] = extract_basename(r["tpath"]) or "<NONE>"
        t["target_dir"] = classify_image_dir(r["tpath"])
    else:  # filemod
        a = r["action"].upper()
        t["kind"] = "file_create" if "CREATE" in a else ("file_delete" if "DELETE" in a else "file_write")
        t["target"] = "FILE:" + file_ext_class(r["tpath"])
        t["target_dir"] = classify_image_dir(r["tpath"])
    return t
