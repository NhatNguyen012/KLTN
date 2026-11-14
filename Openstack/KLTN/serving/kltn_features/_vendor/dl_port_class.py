# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_1-ATLASv2/code/DL/preprocess/build_network_shards.py
# source sha256 52c1167ea8c37f2d5e2ec29b09e5fcd66695492eca346c189a7439fdd6f3c449; do not edit (re-run the vendoring script instead).
from __future__ import annotations


def map_resp_port_class(port: int) -> str:
    """Map destination port to OpTC category."""
    if port == 443:
        return "PORT_443_HTTPS"
    elif port == 80:
        return "PORT_80_HTTP"
    elif port == 8080:
        return "PORT_8080_HTTP_ALT"
    elif port == 53:
        return "PORT_53_DNS"
    elif port == 445:
        return "PORT_445_SMB"
    elif port == 22:
        return "PORT_22_SSH"
    elif port == 3389:
        return "PORT_3389_RDP"
    elif port >= 1024:
        return "REGISTERED"
    else:
        return "WELL_KNOWN_OTHER"
