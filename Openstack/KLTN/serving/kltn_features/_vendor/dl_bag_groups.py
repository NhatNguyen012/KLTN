# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_2-AInception/code/rootcause/build_sl700_events_v2.py
# source sha256 b00f3cb84b5d578368e010f8b845d3c50f84acb647d85811b7729e4ade41efaf; do not edit (re-run the vendoring script instead).
from __future__ import annotations


SEP = "\x1f"


GROUPS = ("g_ev", "g_par", "g_ses", "g_scope")


def group_of(tok: str) -> str:
    if "src_scope" in tok or tok.startswith("net:scope"):
        return "g_scope"
    if tok.startswith("ctx:session"):
        return "g_ses"
    if tok.startswith("ctx:"):
        return "g_par"
    return "g_ev"
