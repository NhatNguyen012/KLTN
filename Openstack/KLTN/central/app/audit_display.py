"""Exact command lines of Linux audit events, for the SOC only.

The models read `cmd` the way the SL700 training preprocessing built it (vendored `ainception_adapters.kv/unhex`): the
auditd quoting is dropped and every even-length hex-looking value is hex-decoded, so `df -h` reads "\\xdf -h",
`tail -n 20` reads "tail -n  " and `nc -lvp 4444` reads "nc -lvp DD". The models keep that view (it is what they were
trained on; changing it would break train/serve parity), but an analyst must read the real command. auditd quotes
plain values and writes unquoted hex only for values with blanks, quotes, control or non-ASCII bytes, so the exact
value is: quoted -> literal, unquoted -> hex-decoded.
"""
from __future__ import annotations

import re

_HDR = re.compile(r"^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s?(.*)$")
_ARG = re.compile(r'(?:^|\s)a(\d+)(?:\[(\d+)\])?=(?:"([^"]*)"|(\S+))')
_PROCTITLE = re.compile(r'(?:^|\s)proctitle=(?:"([^"]*)"|(\S+))')
_USER_CMD = re.compile(r'(?:^|\s)cmd=(?:"([^"]*)"|([^\s\']+))')


def _bytes(quoted: str | None, raw: str | None) -> bytes:
    if quoted is not None:
        return quoted.encode("utf-8", "replace")
    try:
        return bytes.fromhex(raw or "")
    except ValueError:
        return (raw or "").encode("utf-8", "replace")


def _text(b: bytes) -> str:
    return b.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def exact_command(lines) -> str | None:
    """lines: raw audit lines of one event (one msg=audit(...) serial). Returns the exact command line or None:
    EXECVE arguments (also split a<i>[<j>] chunks) first, else PROCTITLE, else the sudo USER_CMD command."""
    args: dict[int, dict[int, bytes]] = {}
    proctitle = usercmd = None
    for line in lines:
        m = _HDR.match((line or "").strip())
        if not m:
            continue
        typ, body = m.group(1), m.group(5).split("\x1d")[0]
        if typ == "EXECVE":
            for a in _ARG.finditer(body):
                part = -1 if a.group(2) is None else int(a.group(2))
                args.setdefault(int(a.group(1)), {})[part] = _bytes(a.group(3), a.group(4))
        elif typ == "PROCTITLE" and proctitle is None:
            p = _PROCTITLE.search(body)
            if p:
                proctitle = _text(_bytes(p.group(1), p.group(2)))
        elif typ == "USER_CMD" and usercmd is None:
            c = _USER_CMD.search(body)
            if c:
                usercmd = _text(_bytes(c.group(1), c.group(2)))
    if args:   # arguments are joined unchanged (an argument may itself contain blanks)
        return " ".join(b"".join(chunk for _, chunk in sorted(parts.items())).decode("utf-8", "replace")
                        for _, parts in sorted(args.items()))
    return proctitle if proctitle is not None else usercmd
