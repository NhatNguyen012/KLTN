# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_2-AInception/code/DL/build_sl700_windows.py
# source sha256 d6ff870251132a770224275b1301c31db3024d3e2b99ad30f61633ba33a0700a; do not edit (re-run the vendoring script instead).
from __future__ import annotations

import math

import numpy as np

from .dl_atlas_events import CAT_FIELDS, CMD_FLAGS, cmd_flags, ip_scope
from .dl_contract import image_dir_class, optc_tokens
from .dl_port_class import map_resp_port_class


def _isna(v):
    return v is None or (isinstance(v, float) and v != v)


class _PdShim:
    """pd.isna for the vendored event_record (no pandas at serving time)."""
    isna = staticmethod(_isna)


pd = _PdShim()


LABEL_KINDS = ("procstart", "netconn", "crossproc", "auth", "privchange")


EXTRA_KINDS = ("filemod",)


WINDOW, STRIDE, MAX_LEN = 180_000_000, 30_000_000, 512


DELETE_SC = {84, 87, 263}


def base(p):
    return (p or "").rstrip("/").split("/")[-1].lower()


def user_class(u):
    u = (u or "").strip()
    if u in ("", "-", "unset", "4294967295"):
        return "NONE"
    if u.isdigit():
        n = int(u)
        return "SYSTEM_ACCOUNT" if n == 0 else ("SERVICE_ACCOUNT" if n < 1000 else "DOMAIN_USER")
    return "SYSTEM_ACCOUNT" if u == "root" else "DOMAIN_USER"


def event_record(r, pidx):
    k = r["kind"]
    out = {"ts": int(r["ts"]), "line": int(r["line"]), "host": r["host"], "kind_raw": k,
           "y": int(r["y"]) if k in LABEL_KINDS else -1, "stage": int(r["stage"]) if k in LABEL_KINDS else 0}
    img, cmd = r["image"] or "", r["cmd"] or ""
    pimg, pcmd = pidx.at(r["ppid"], r["ts"])
    t = {"user": user_class(r["user"]), "pub": "NONE", "tpub": "NA", "net": "NA", "ip_scope": "NA",
         "target": "NA", "target_dir": "NA"}
    path = img
    if k == "procstart":
        # parent-centric like CBC-EDR: actor = parent image, target = new image
        t.update(kind="procstart", actor=base(pimg) or "<NONE>", actor_dir=image_dir_class(pimg) if pimg else "MISSING",
                 target=base(img) or "<NONE>", target_dir=image_dir_class(img) if img else "MISSING", tpub="NONE")
        gimg, _ = pidx.at(pidx_ppid(pidx, r), r["ts"])
        t["parent"] = base(gimg) or "<NONE>"
        path = pimg
        flags = cmd_flags(pcmd) + cmd_flags(cmd)
        rec_for_optc = {"kind": "procstart", "path": pimg}
    else:
        t.update(actor=base(img) or "<NONE>", actor_dir=image_dir_class(img) if img else "MISSING", parent=base(pimg) or "<NONE>")
        flags = cmd_flags(cmd) + [0.0] * len(CMD_FLAGS)
        rec_for_optc = {"kind": "other", "path": img}
        if k == "netconn":
            inbound = not bool(r["outbound"])
            port = None if pd.isna(r["rport"]) else int(r["rport"])
            t["kind"] = "net_in" if inbound else "net_out"
            # accept(): auditd gives the peer address only, so the local (responder) port is unknown
            t["net"] = f"tcp:{'MISSING' if inbound or port is None else map_resp_port_class(port)}:nodom"
            t["ip_scope"] = ip_scope(r["rip"] or "")
            rec_for_optc = {"kind": "netconn", "path": img, "proto": "TCP", "inbound": inbound,
                            "rport": port, "lport": None}
        elif k == "crossproc":
            t["kind"] = "xp:open_process"
        elif k in ("auth", "privchange"):
            t["kind"] = k
        else:  # filemod
            sc = None if pd.isna(r["syscall"]) else int(r["syscall"])
            t["kind"] = "file_delete" if sc in DELETE_SC else "file_write"
            t["target"] = "FILE:OTHER"
            t["target_dir"] = image_dir_class(r["tpath"]) if r["tpath"] else "MISSING"
    out["tok"] = tuple(t[f] for f in CAT_FIELDS)
    out["optc"] = optc_tokens(rec_for_optc)
    out["flags"] = flags
    out["actor_path"] = path
    return out


def pidx_ppid(pidx, r):
    """ppid of the parent (grandparent pid) from the parent's own events (needed for the 'parent' context token)."""
    pp = r["ppid"]
    if pp is None or pd.isna(pp):
        return None
    return pidx.pp.get(int(pp))


def encode(s):
    evs = s["events"]
    ts = np.asarray([e["ts"] for e in evs], dtype=np.float64)
    dt = np.log1p(np.diff(ts, prepend=ts[0]) / 1e6).astype(np.float32)
    rel = np.log1p((ts - ts[0]) / 1e6).astype(np.float32) / math.log1p(180.0)
    isx = np.asarray([e["kind_raw"] == "filemod" for e in evs], dtype=np.float32)
    flags = np.asarray([e["flags"] for e in evs], dtype=np.float32)
    return {k: s[k] for k in ("sample_id", "run", "host", "start", "end", "y", "stages", "stage_last")} | {
        "tok_raw": [e["tok"] for e in evs], "optc_raw": [e["optc"] for e in evs],
        "num": np.concatenate([flags, np.stack([dt, rel, isx], 1)], 1),
        "ev_y": np.asarray([e["y"] for e in evs], dtype=np.int8),
        "ev_stage": np.asarray([e["stage"] for e in evs], dtype=np.int8),
        "is_extra": isx.astype(bool),
        "trace": [(e["line"], e["kind_raw"], e["tok"][1], e["tok"][4]) for e in evs]}
