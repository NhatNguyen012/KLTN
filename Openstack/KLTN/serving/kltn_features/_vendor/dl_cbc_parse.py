# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_1-ATLASv2/code/DL/bilstm_v9/parse_events.py
# source sha256 0b09e869d53c120d5e5b51d47a375d594ae2b93ebf4194a14b164beaba640bbb; do not edit (re-run the vendoring script instead).
from __future__ import annotations


KEEP_TYPES = {
    b'"endpoint.event.procstart"': "procstart",
    b'"endpoint.event.crossproc"': "crossproc",
    b'"endpoint.event.netconn"': "netconn",
    b'"endpoint.event.filemod"': "filemod",
}


FILEMOD_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sct",
               ".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".rtf", ".html", ".htm", ".pdf")


def _pub_state(pubs):
    if not pubs:
        return "NONE"
    st = " ".join(str(p.get("state", "")) for p in pubs if isinstance(p, dict))
    if "TRUSTED" in st:
        return "SIGNED_TRUSTED"
    if "VERIFIED" in st:
        return "SIGNED_VERIFIED"
    if "SIGNED" in st:
        return "SIGNED"
    return "UNSIGNED"
