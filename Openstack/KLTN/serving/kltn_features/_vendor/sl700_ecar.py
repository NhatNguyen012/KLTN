# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_2-AInception/code/ML/sl700_ecar.py
# source sha256 a759443eaad2b89ddb4098212d07db1d0fab0da7ba73055c3dd8e33cdf4dc7cb; do not edit (re-run the vendoring script instead).
"""SL700 auditd events -> eCAR-like records for the Base OpTC host-ML tokenizer (ML IL step 3: OpTC -> ATLASv2 -> SL700).

Same contract as the ATLASv2 step (IL/dataset_1-ATLASv2/code/ML/preprocess/build_host_shards.py):
  tokens = flatten_tokens(tokenize_record(record))           # Base OpTC tokenizer, frozen OpTC vocabulary
         + ATLASv2 domain-shift context tokens                # parent lineage, has_netconn, file extension
         + Linux tokens (linux_ctx.py, prefix "lx:")          # Linux command line/paths, uid/auid, parent and
                                                              # login-session ("incoming") context
Network flows are not rows (as in OpTC/ATLASv2 host ML); connect/accept only feed the causal has_netconn context.
Linux accounts map onto the Base OpTC principal buckets: uid 0 -> nt_system, 1..999 -> nt_service, >= 1000 -> domain_user.
"""
from __future__ import annotations

import sys
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path

from .ecar_tokenizer import flatten_tokens, tokenize_record  # noqa: E402
from .linux_ctx import LinuxContextTracker  # noqa: E402

ROW_KINDS = ("procstart", "filemod", "fileread", "auth", "privchange")
DELETE_SC = {84, 87, 263}
CREATE_SC = {85, 83, 258}            # creat, mkdir, mkdirat
AUTH_ACTION = {"USER_LOGIN": "login", "USER_START": "login", "USER_AUTH": "login", "USER_ACCT": "login",
               "CRED_ACQ": "login", "CRED_REFR": "login", "LOGIN": "login", "USER_END": "logout",
               "CRED_DISP": "logout", "USER_CMD": "command", "ADD_USER": "add", "ADD_GROUP": "add",
               "DEL_USER": "remove", "USER_CHAUTHTOK": "modify", "USER_MGMT": "modify", "ACCT_LOCK": "modify"}
UNSET = 4294967295


def principal(uid) -> str:
    """Linux account class -> a string that tokenize_principal buckets like the Windows equivalent."""
    try:
        n = int(float(uid))
    except (TypeError, ValueError):
        s = str(uid or "").strip()
        if s in ("", "?", "unset"):
            return ""
        return "NT AUTHORITY\\SYSTEM" if s == "root" else "LINUX\\user"
    if n == UNSET or n < 0:
        return ""
    return "NT AUTHORITY\\SYSTEM" if n == 0 else ("NT SERVICE\\linux_service" if n < 1000 else "LINUX\\user")


def base(p) -> str:
    return (p or "").rstrip("/").split("/")[-1].lower()


def family(b: str) -> str:
    for fam in ("powershell", "cmd", "cscript", "wscript", "rundll32", "python"):
        if fam in b:
            return fam
    return "native"


class Sl700Tokenizer:
    """Per-host causal state: parent of each pid, recent network activity, Linux context tracker."""

    def __init__(self, with_scope=False):
        self.parent = {}                       # pid -> (ppid, image) of the latest exec
        self.image = {}                        # pid -> image
        self.net = defaultdict(list)           # pid -> connect/accept timestamps
        self.lx = LinuxContextTracker(with_scope=with_scope)

    def record(self, e) -> dict:
        k = e["kind"]
        img = e["image"] or ""
        pimg = self.image.get(e["ppid"], "") if e["ppid"] is not None else ""
        if k == "procstart":
            props = {"image_path": img, "parent_image_path": pimg, "command_line": e["cmd"] or ""}
            return {"object": "process", "action": "start", "principal": principal(e["uid"]),
                    "properties": {kk: v for kk, v in props.items() if v}}
        if k in ("filemod", "fileread"):
            sc = e["syscall"]
            act = "read" if k == "fileread" else ("delete" if sc in DELETE_SC else "create" if sc in CREATE_SC else "write")
            return {"object": "file", "action": act, "principal": principal(e["uid"]),
                    "properties": {kk: v for kk, v in {"image_path": img, "file_path": e["tpath"] or ""}.items() if v}}
        if k == "auth":
            return {"object": "user_session", "action": AUTH_ACTION.get(e["tpath"] or "", "unknown"),
                    "principal": principal(e["user"]), "properties": {}}
        # privchange: set*id by a process
        return {"object": "process", "action": "modify", "principal": principal(e["uid"]),
                "properties": {"image_path": img} if img else {}}

    def context(self, e) -> list[str]:
        """ATLASv2-step domain-shift tokens (build_host_shards.extract_domain_shift_tokens), Linux inputs."""
        out = []
        pid, ts = e["pid"], e["ts"]
        actor_img = e["image"] or ""
        p_img = self.image.get(e["ppid"], "") if e["ppid"] is not None else ""
        if e["kind"] in ("filemod",):
            tb = base(e["tpath"])
            ext = ("." + tb.rsplit(".", 1)[-1]) if "." in tb else ""
            out.append("file_ext::type=" + ({".exe": "exe", ".zip": "zip", ".gz": "zip", ".tar": "zip", ".sh": "bat",
                                             ".tmp": "tmp", ".db": "sqlite", ".sqlite": "sqlite"}.get(ext, "none_or_dir" if not ext else "other")))
        if pid is not None:
            lst = self.net.get(pid, [])
            if bisect_right(lst, ts) > bisect_left(lst, ts - 300_000_000):
                out.append("proc_context::has_netconn")
        if p_img:
            pb = base(p_img)
            ab = base(actor_img)
            out += [f"parent_image_path::basename={pb}", f"parent_image::basename={pb}", "ctx::status::has_parent",
                    f"ctx::parent::family={family(pb)}", f"ctx::relation::lineage={family(pb)}->{family(ab)}",
                    "ctx::parent::path_role=other_path", "ctx::relation::path=other_path->other_path"]
        return out

    def tokens(self, e, with_lx=True) -> list[str] | None:
        """Tokens for a row event (None for non-row kinds); updates the causal state afterwards."""
        lx = self.lx.tokens(e) if with_lx else []
        out = None
        if e["kind"] in ROW_KINDS:
            out = flatten_tokens(tokenize_record(self.record(e))[0]) + self.context(e)
            if with_lx:
                out += ["lx:" + t for t in lx]
        self.observe(e)
        return out

    def observe(self, e):
        self.lx.observe(e)
        pid = e["pid"]
        if pid is None:
            return
        if e["kind"] == "procstart" or pid not in self.image:
            if e["image"] and e["kind"] != "auth":
                self.image[pid] = e["image"]
        if e["kind"] == "netconn":
            self.net[pid].append(e["ts"])
