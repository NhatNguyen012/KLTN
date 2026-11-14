"""AInception -> canonical host events (step 1).

Two sources, one schema:
  * Windows winlogbeat ECS lines (Sysmon + Security-Auditing), e.g. SL300 logs/labelled_logs/*.ecslogs
  * Linux auditd: raw /var/log/audit/audit.log (SL700) or filebeat ECS lines whose message is a raw
    audit record (SL300 Linux hosts). Records are grouped by msg=audit(<epoch>:<serial>) into one event
    (SYSCALL + EXECVE + PROCTITLE + PATH + SOCKADDR ...), the same grouping the OpenStack lab's
    Linux adapter needs.

Canonical event (dict): ts (us, UTC), host, os, src, code, kind, pid, ppid, guid, pguid, image, cmd,
pimage, pcmd, user, tpath, tguid, proto, lip, lport, rip, rport, outbound, domain, ses, auid, uid,
syscall, success, line, coarse_mal, coarse_tactics.
kind in {procstart, procend, netconn, dns, filemod, fileread, registry, crossproc, logon, account,
         privchange, procfork, auth, other}.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

TACTIC_ID = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}


def tactic_names(xs):
    out = []
    for x in xs or []:
        for y in str(x).split(","):
            y = y.strip()
            if y:
                out.append(TACTIC_ID.get(y, y))
    return out


def iso_us(s: str) -> int:
    s = s.replace("Z", "+00:00").replace(" ", "T")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000)


def _base(**kw):
    e = dict(ts=0, host="", os="", src="", code="", kind="other", pid=None, ppid=None, guid=None, pguid=None,
             image="", cmd="", pimage="", pcmd="", user="", tpath="", tguid=None, proto="", lip="", lport=None,
             rip="", rport=None, outbound=None, domain="", ses=None, auid=None, uid=None, syscall=None,
             success=None, line=-1, coarse_mal=0, coarse_tactics=())
    e.update(kw)
    return e


def _int(v, base=10):
    try:
        return int(str(v), base)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- Windows
SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"
LOGON_CODES = {"4624", "4625", "4634", "4647", "4648", "4672", "4768", "4769", "4771", "4776"}


def parse_windows_record(r: dict, line: int, host_alias: str | None = None):
    ev = r.get("event") or {}
    prov, code = ev.get("provider"), str(ev.get("code"))
    ed = (r.get("winlog") or {}).get("event_data") or {}
    host = host_alias or ((r.get("host") or {}).get("name") or "").split(".")[0]
    e = _base(ts=iso_us(r["@timestamp"]), host=host, os="windows", code=code, line=line,
              coarse_mal=int(r.get("malicious") in (1, True, "1")),
              coarse_tactics=tuple(tactic_names(r.get("mitre_tactics"))))
    if prov == SYSMON:
        e["src"] = "sysmon"
        g, pid = ed.get("ProcessGuid"), _int(ed.get("ProcessId"))
        if code == "1":
            e.update(kind="procstart", guid=g, pguid=ed.get("ParentProcessGuid"), pid=pid,
                     ppid=_int(ed.get("ParentProcessId")), image=ed.get("Image") or "", cmd=ed.get("CommandLine") or "",
                     pimage=ed.get("ParentImage") or "", pcmd=ed.get("ParentCommandLine") or "", user=ed.get("User") or "")
        elif code == "5":
            e.update(kind="procend", guid=g, pid=pid, image=ed.get("Image") or "")
        elif code == "3":
            e.update(kind="netconn", guid=g, pid=pid, image=ed.get("Image") or "", user=ed.get("User") or "",
                     proto=(ed.get("Protocol") or "").lower(), lip=ed.get("SourceIp") or "", lport=_int(ed.get("SourcePort")),
                     rip=ed.get("DestinationIp") or "", rport=_int(ed.get("DestinationPort")),
                     outbound=str(ed.get("Initiated")).lower() == "true", domain=ed.get("DestinationHostname") or "")
        elif code in ("11", "23", "26", "2", "15"):
            e.update(kind="filemod", guid=g, pid=pid, image=ed.get("Image") or "", tpath=ed.get("TargetFilename") or "")
        elif code in ("12", "13", "14"):
            e.update(kind="registry", guid=g, pid=pid, image=ed.get("Image") or "", tpath=ed.get("TargetObject") or "",
                     cmd=str(ed.get("Details") or ""))
        elif code == "22":
            e.update(kind="dns", guid=g, pid=pid, image=ed.get("Image") or "", domain=ed.get("QueryName") or "")
        elif code in ("8", "10"):
            e.update(kind="crossproc", guid=ed.get("SourceProcessGuid"), pid=_int(ed.get("SourceProcessId")),
                     image=ed.get("SourceImage") or "", tguid=ed.get("TargetProcessGuid"), tpath=ed.get("TargetImage") or "")
        else:
            e.update(guid=g, pid=pid, image=ed.get("Image") or "")
    elif prov == SECURITY:
        e["src"] = "security"
        if code == "4688":
            e.update(kind="procstart", pid=_int(ed.get("NewProcessId"), 16), ppid=_int(ed.get("ProcessId"), 16),
                     image=ed.get("NewProcessName") or "", pimage=ed.get("ParentProcessName") or "",
                     cmd=ed.get("CommandLine") or "", user=ed.get("TargetUserName") or ed.get("SubjectUserName") or "")
        elif code == "4689":
            e.update(kind="procend", pid=_int(ed.get("ProcessId"), 16), image=ed.get("ProcessName") or "")
        elif code in LOGON_CODES:
            e.update(kind="logon", user=ed.get("TargetUserName") or "", rip=ed.get("IpAddress") or "",
                     cmd=str(ed.get("LogonType") or ""), pid=_int(ed.get("ProcessId"), 16), image=ed.get("ProcessName") or "")
        elif code in ("4798", "4799"):
            e.update(kind="account", pid=_int(ed.get("CallerProcessId"), 16), image=ed.get("CallerProcessName") or "",
                     tpath=ed.get("TargetUserName") or "")
        else:
            e.update(pid=_int(ed.get("ProcessId"), 16) if str(ed.get("ProcessId", "")).startswith("0x") else None,
                     image=ed.get("ProcessName") or ed.get("CallerProcessName") or "")
    else:
        e["src"] = "other"
    return e


def iter_windows_ecs(path, host_alias=None):
    with open(path) as fh:
        for i, l in enumerate(fh):
            try:
                r = json.loads(l)
            except ValueError:
                continue
            if (r.get("agent") or {}).get("type") != "winlogbeat":
                continue
            yield parse_windows_record(r, i, host_alias)


# ----------------------------------------------------------------------------- Linux auditd
_HDR = re.compile(r"^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s?(.*)$")
_KV = re.compile(r'(\w+)=("([^"]*)"|\'([^\']*)\'|(\S+))')
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
SYSCALL_KIND = {59: "procstart", 322: "procstart", 42: "netconn", 43: "netconn", 288: "netconn", 49: "other",
                56: "procfork", 57: "procfork", 58: "procfork", 435: "procfork",
                82: "filemod", 84: "filemod", 87: "filemod", 263: "filemod", 264: "filemod", 316: "filemod",
                90: "filemod", 268: "filemod", 92: "filemod", 260: "filemod", 94: "filemod", 83: "filemod", 258: "filemod",
                105: "privchange", 106: "privchange", 113: "privchange", 114: "privchange", 117: "privchange", 119: "privchange",
                101: "crossproc", 62: "crossproc"}
AUTH_TYPES = {"USER_LOGIN", "USER_START", "USER_END", "USER_AUTH", "USER_ACCT", "CRED_ACQ", "CRED_DISP", "CRED_REFR",
              "LOGIN", "USER_CMD", "ADD_USER", "ADD_GROUP", "DEL_USER", "USER_CHAUTHTOK", "USER_MGMT", "ACCT_LOCK"}


def kv(s: str) -> dict:
    s = s.split("\x1d")[0]
    out = {}
    for m in _KV.finditer(s):
        k = m.group(1)
        v = m.group(3) if m.group(3) is not None else (m.group(4) if m.group(4) is not None else m.group(5))
        if k not in out:
            out[k] = v
    return out


def unhex(v: str) -> str:
    if v and _HEX.match(v) and len(v) % 2 == 0:
        try:
            return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            return v
    return v or ""


def sockaddr(h: str):
    """Return (family, ip, port) from an auditd SOCKADDR saddr hex string."""
    try:
        b = bytes.fromhex(h)
    except (ValueError, TypeError):
        return None, "", None
    if len(b) < 2:
        return None, "", None
    fam = int.from_bytes(b[0:2], "little")
    if fam == 2 and len(b) >= 8:
        return "inet", ".".join(str(x) for x in b[4:8]), int.from_bytes(b[2:4], "big")
    if fam == 10 and len(b) >= 24:
        ip6 = b[8:24]
        if ip6[:12] == b"\x00" * 10 + b"\xff\xff":
            return "inet", ".".join(str(x) for x in ip6[12:16]), int.from_bytes(b[2:4], "big")
        return "inet6", ":".join(ip6[i:i + 2].hex() for i in range(0, 16, 2)), int.from_bytes(b[2:4], "big")
    if fam == 1:
        return "unix", b[2:].split(b"\x00")[0].decode("utf-8", "replace"), None
    return str(fam), "", None


def audit_records(lines):
    """lines: iterable of (raw_line, coarse_label_dict|None) -> dict serial -> list of (type, ts_us, body, coarse)."""
    groups, order = {}, []
    for raw, coarse in lines:
        m = _HDR.match(raw.strip())
        if not m:
            continue
        typ, sec, ms, serial, body = m.groups()
        key = (int(sec), int(serial))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((typ, int(sec) * 1_000_000 + int(ms.ljust(3, "0")[:3]) * 1000, body, coarse))
    return groups, order


def build_audit_event(key, recs, host):
    ts = recs[0][1]
    types = [t for t, *_ in recs]
    e = _base(ts=ts, host=host, os="linux", src="auditd", code="+".join(sorted(set(types))), line=key[1])
    mal = [c for *_, c in recs if c]
    if mal:
        e["coarse_mal"] = int(any(c.get("malicious") in (1, True, "1") for c in mal))
        e["coarse_tactics"] = tuple(sorted({t for c in mal for t in tactic_names(c.get("mitre_tactics"))}))
    bodies = {}
    for t, _, b, _ in recs:
        bodies.setdefault(t, []).append(b)
    if "SYSCALL" in bodies:
        s = kv(bodies["SYSCALL"][0])
        sc = _int(s.get("syscall"))
        e.update(syscall=sc, success=s.get("success"), pid=_int(s.get("pid")), ppid=_int(s.get("ppid")),
                 uid=_int(s.get("uid")), auid=_int(s.get("auid")), ses=_int(s.get("ses")),
                 image=s.get("exe") or "", user=s.get("uid") or "", kind=SYSCALL_KIND.get(sc, "other"))
        if sc in (2, 257) and "PATH" in bodies:
            nt = [kv(p).get("nametype") for p in bodies["PATH"]]
            a2 = _int(s.get("a2"), 16) or 0
            e["kind"] = "filemod" if ("CREATE" in nt or "DELETE" in nt or a2 & 0o3) else "fileread"
        if "EXECVE" in bodies:
            a = kv(bodies["EXECVE"][0])
            argc = _int(a.get("argc")) or 0
            e["cmd"] = " ".join(unhex(a.get(f"a{i}", "")) for i in range(argc))
        elif "PROCTITLE" in bodies:
            e["cmd"] = unhex(kv(bodies["PROCTITLE"][0]).get("proctitle", ""))
        if "PATH" in bodies:
            names = [kv(p).get("name", "") for p in bodies["PATH"]]
            e["tpath"] = next((n for n in reversed(names) if n and n != "(null)"), "")
        if "SOCKADDR" in bodies:
            fam, ip, port = sockaddr(kv(bodies["SOCKADDR"][0]).get("saddr", ""))
            if fam in ("inet", "inet6"):
                e.update(rip=ip, rport=port, proto="tcp", outbound=(sc == 42))
            elif fam == "unix":
                e["tpath"] = e["tpath"] or ip
                if e["kind"] == "netconn":
                    e["kind"] = "other"
    else:
        t0 = types[0]
        s = kv(bodies[t0][0])
        inner = kv(s.get("msg", "")) if s.get("msg") else {}
        e.update(kind="auth" if t0 in AUTH_TYPES else "other", pid=_int(s.get("pid")), uid=_int(s.get("uid")),
                 auid=_int(s.get("auid")), ses=_int(s.get("ses")), image=inner.get("exe", "") or s.get("exe", ""),
                 rip=inner.get("addr", "") or s.get("addr", ""), user=inner.get("acct", "") or s.get("acct", ""),
                 cmd=(inner.get("op", "") or "") + (" " + unhex(inner.get("cmd", "")) if inner.get("cmd") else ""),
                 tpath=t0)
    return e


def iter_auditd_raw(path, host, coarse_index=None):
    def gen():
        with open(path, errors="replace") as fh:
            for l in fh:
                c = coarse_index.get(_coarse_key(l)) if coarse_index else None
                yield l, c
    groups, order = audit_records(gen())
    for k in order:
        yield build_audit_event(k, groups[k], host)


def iter_auditd_ecs(path, host):
    """filebeat ECS lines (SL300 Linux hosts); only records from /var/log/audit/audit.log."""
    def gen():
        with open(path) as fh:
            for l in fh:
                try:
                    r = json.loads(l)
                except ValueError:
                    continue
                if not (((r.get("log") or {}).get("file") or {}).get("path") or "").endswith("audit.log"):
                    continue
                yield r.get("message", ""), {"malicious": r.get("malicious"), "mitre_tactics": r.get("mitre_tactics")}
    groups, order = audit_records(gen())
    for k in order:
        yield build_audit_event(k, groups[k], host)


def _coarse_key(raw_line: str):
    m = _HDR.match(raw_line.strip())
    if not m:
        return None
    typ, sec, ms, _serial, body = m.groups()
    return (typ, int(sec) * 1000 + int(ms.ljust(3, "0")[:3]), body.split("\x1d")[0][:160])


def coarse_index_from_labelled_json(path):
    """SL700 labelled audit.log.json -> {(type, ts_ms, body[:160]): {malicious, mitre_tactics}}."""
    recs = json.load(open(path))
    idx = {}
    for r in recs:
        ts = iso_us(r["@timestamp"]) // 1000
        idx[(r["event"]["type"], ts, r["message"].split("\x1d")[0][:160])] = {
            "malicious": r.get("malicious"), "mitre_tactics": r.get("mitre_tactics")}
    return idx
