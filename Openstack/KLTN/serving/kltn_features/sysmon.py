"""Windows Sysmon -> CBC-EDR-like events, the Windows input contract of both IL models.

The Windows parts of the models were trained on OpTC eCAR (base) and ATLASv2 Carbon Black Cloud EDR (IL step 2), never
on Sysmon. This adapter maps each Sysmon event onto the CBC record the ATLASv2 pipelines consumed
(IL/dataset_1-ATLASv2/code/preprocess/cbc_adapter.py for host ML, DL/bilstm_v9/parse_events.py for the BiLSTM):

  Sysmon                      CBC-EDR analogue                         notes (approximations are listed in SEMANTICS)
  1  ProcessCreate            procstart, actor = PARENT, child target  CBC reports a start from the parent's side
  5  ProcessTerminate         procend
  3  NetworkConnect           netconn (Initiated -> outbound)          domain from the host's own DNS answers (EID 22)
  7  ImageLoad                moduleload                               also feeds the signer table (pub / tpub)
  8  CreateRemoteThread       crossproc ACTION_CREATE_REMOTE_THREAD
  10 ProcessAccess            crossproc ACTION_OPEN_PROCESS_HANDLE
  11 FileCreate               filemod ACTION_FILE_CREATE
  23/26 FileDelete            filemod ACTION_FILE_OPEN_DELETE
  12/13/14 RegistryEvent      regmod                                   key kept as Sysmon writes it (HKLM\\..., like CBC)
  22 DnsQuery                 (none)                                   only updates the IP -> domain table
Paths of processes and files are lower-cased like CBC; registry keys are not (CBC keeps their case).
State (process table, signers, DNS answers) is per host and causal: an event only uses what was seen before it.
"""
from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from xml.etree import ElementTree

from ._vendor.common_schema import CanonicalEvent, parse_timestamp_micros
from ._vendor.dl_cbc_parse import FILEMOD_EXT

MAX_XML_CHARS = 1_000_000
EVENT_TYPES = {1: "PROCESS_START", 3: "FLOW_START", 5: "PROCESS_END", 7: "MODULE_LOAD", 8: "CROSS_PROCESS",
               10: "CROSS_PROCESS", 11: "FILE_CREATE", 12: "REGISTRY_WRITE", 13: "REGISTRY_WRITE",
               14: "REGISTRY_WRITE", 22: "DNS_QUERY", 23: "FILE_DELETE", 26: "FILE_DELETE"}
# CBC kinds the ATLASv2 BiLSTM reads (parse_events.KEEP_TYPES); filemod only for FILEMOD_EXT names
DL_KIND = {"PROCESS_START": "procstart", "CROSS_PROCESS": "crossproc", "FLOW_START": "netconn",
           "FILE_CREATE": "filemod", "FILE_DELETE": "filemod"}
SEMANTICS = {
    "pub/tpub": "CBC signer state. Sysmon has no signer on process events; the signer table is filled from ImageLoad "
                "(EID 7, logged for unsigned or user-writable modules by the KLTN config). Unknown image: "
                "SIGNED_TRUSTED in Windows/Program Files directories (99% of ATLASv2 events), NONE elsewhere.",
    "file_write": "CBC reports file writes; Sysmon only creation (EID 11) and deletion (EID 23/26) are mapped.",
    "crossproc": "CBC crossproc ~ handle opens; Sysmon EID 10 (ProcessAccess) and EID 8 (CreateRemoteThread).",
    "netconn_domain": "CBC netconn_domain ~ the last DNS answer (EID 22) of the host containing the remote IP.",
    "user": "procstart actor user = ParentUser (Sysmon >= 13.30) else the parent's own creation event.",
}
_USER_WRITABLE = ("\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\", "\\downloads\\")
_IP_IN_ANSWER = re.compile(r"(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})|([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})", re.I)


def _xml_text(raw: dict) -> str | None:
    for key in ("xml", "Xml", "XML", "System", "Event", "log", "message"):
        value = raw.get(key)
        if isinstance(value, str) and value.lstrip().startswith("<Event"):
            return value
    return None


def parse_event(raw: dict) -> dict | None:
    """Fluent Bit winevtlog record (Render_Event_As_XML) or an already flat dict -> flat field dict with EventID int."""
    xml = _xml_text(raw)
    if xml is None:
        if "EventID" in raw:
            fields = dict(raw)
        else:
            return None
    else:
        if len(xml) > MAX_XML_CHARS or "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            return None
        try:
            root = ElementTree.fromstring(xml)
        except ElementTree.ParseError:
            return None
        fields = {}
        for node in root.iter():
            name = node.tag.rsplit("}", 1)[-1]
            if name in ("EventID", "EventRecordID", "Channel", "Computer") and node.text:
                fields[name] = node.text.strip()
            elif name == "TimeCreated":
                fields["SystemTime"] = node.attrib.get("SystemTime", "")
            elif name == "Provider":
                fields["Provider"] = node.attrib.get("Name", "")
            elif name == "Data" and node.attrib.get("Name"):
                fields[node.attrib["Name"]] = (node.text or "").strip()
    try:
        fields["EventID"] = int(str(fields.get("EventID", "0")).strip())
    except ValueError:
        return None
    return fields


def _s(v) -> str:
    v = "" if v is None else str(v).strip()
    return "" if v in ("-", "(null)") else v


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _guid(v) -> str:
    return _s(v).strip("{}").lower()


class _LRU(OrderedDict):
    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def put(self, k, v):
        self[k] = v
        self.move_to_end(k)
        if len(self) > self.cap:
            self.popitem(last=False)


class SysmonMapper:
    """Per-host causal mapper: flat Sysmon fields -> normalized Windows event (dict) or None."""

    def __init__(self, host: str = "", max_procs: int = 100_000):
        self.host = host.lower()
        self.procs = _LRU(max_procs)        # guid -> (image, cmd, parent guid, user)
        self.signer = _LRU(50_000)          # lower image path -> CBC pub state
        self.dns = _LRU(50_000)             # ip -> (ts, domain)

    def pub_of(self, path: str) -> str:
        p = (path or "").lower()
        if p in self.signer:
            return self.signer[p]
        if not p:
            return "NONE"
        if any(x in p for x in _USER_WRITABLE):
            return "NONE"
        return "SIGNED_TRUSTED" if ("\\windows\\" in p or "\\program files" in p) else "NONE"

    def _proc(self, guid):
        return self.procs.get(guid) if guid else None

    def map(self, f: dict) -> dict | None:
        eid = f.get("EventID")
        et = EVENT_TYPES.get(eid)
        if et is None:
            return None
        ts = parse_timestamp_micros(f.get("UtcTime") or f.get("SystemTime"))
        if ts <= 0:
            return None
        e = {"os": "windows", "src": "sysmon", "eid": eid, "event_type": et, "ts": ts,
             "record_id": _int(f.get("EventRecordID")), "host": (_s(f.get("Computer")) or self.host).lower(),
             "guid": "", "pguid": "", "path": "", "cmd": "", "ppath": "", "pcmd": "", "user": "",
             "tpath": "", "tguid": "", "tcmd": "", "action": "", "pub": "NONE", "tpub": "NONE",
             "proto": "", "rip": "", "rport": 0, "lport": 0, "inbound": False, "domain": "",
             "pid": _int(f.get("ProcessId") or f.get("SourceProcessId")), "ppid": _int(f.get("ParentProcessId"))}
        if eid == 1:
            pg, child = _guid(f.get("ParentProcessGuid")), _guid(f.get("ProcessGuid"))
            parent = self._proc(pg)
            pimg, pcmd = _s(f.get("ParentImage")).lower(), _s(f.get("ParentCommandLine"))
            puser = _s(f.get("ParentUser")) or (parent[3] if parent else "") or _s(f.get("User"))
            gp = self._proc(parent[2]) if parent else None
            e.update(guid=pg, path=pimg, cmd=pcmd, user=puser, pguid=parent[2] if parent else "",
                     ppath=gp[0] if gp else "", pcmd=gp[1] if gp else "", tpath=_s(f.get("Image")).lower(),
                     tguid=child, tcmd=_s(f.get("CommandLine")), action="ACTION_CREATE_PROCESS")
            e["pub"], e["tpub"] = self.pub_of(e["path"]), self.pub_of(e["tpath"])
            if pg and parent is None:
                self.procs.put(pg, (pimg, pcmd, "", puser))
            self.procs.put(child, (e["tpath"], e["tcmd"], pg, _s(f.get("User"))))
            return e
        if eid in (8, 10):
            src = _guid(f.get("SourceProcessGuid") or f.get("SourceProcessGUID"))
            proc = self._proc(src)
            e.update(guid=src, path=_s(f.get("SourceImage")).lower(), user=_s(f.get("SourceUser")) or (proc[3] if proc else ""),
                     tpath=_s(f.get("TargetImage")).lower(), tguid=_guid(f.get("TargetProcessGuid") or f.get("TargetProcessGUID")),
                     action="ACTION_CREATE_REMOTE_THREAD" if eid == 8 else "ACTION_OPEN_PROCESS_HANDLE",
                     pid=_int(f.get("SourceProcessId")))
            self._parent_fields(e, proc)
            e["pub"], e["tpub"] = self.pub_of(e["path"]), self.pub_of(e["tpath"])
            return e
        guid = _guid(f.get("ProcessGuid"))
        proc = self._proc(guid)
        e.update(guid=guid, path=_s(f.get("Image")).lower(), user=_s(f.get("User")) or (proc[3] if proc else ""))
        if proc:
            e["cmd"] = proc[1]
        self._parent_fields(e, proc)
        e["pub"] = self.pub_of(e["path"])
        if eid == 3:
            outbound = _s(f.get("Initiated")).lower() == "true"
            proto = _s(f.get("Protocol")).upper()
            e["proto"] = "PROTO_TCP" if proto == "TCP" else ("PROTO_UDP" if proto == "UDP" else proto)
            if outbound:
                e.update(rip=_s(f.get("DestinationIp")), rport=_int(f.get("DestinationPort")), lport=_int(f.get("SourcePort")))
            else:
                e.update(rip=_s(f.get("SourceIp")), rport=_int(f.get("SourcePort")), lport=_int(f.get("DestinationPort")))
            e["inbound"] = not outbound
            hit = self.dns.get(e["rip"])
            e["domain"] = hit[1] if hit and 0 <= ts - hit[0] <= 3600 * 1_000_000 else ""
        elif eid == 5:
            e["action"] = "ACTION_PROCESS_TERMINATE"
        elif eid == 7:
            loaded = _s(f.get("ImageLoaded")).lower()
            e.update(tpath=loaded, action="ACTION_LOAD_MODULE")
            signed = _s(f.get("Signed")).lower() == "true"
            status = _s(f.get("SignatureStatus")).lower()
            self.signer.put(loaded, "SIGNED_TRUSTED" if signed and status == "valid" else ("SIGNED" if signed else "UNSIGNED"))
        elif eid == 11:
            e.update(tpath=_s(f.get("TargetFilename")).lower(), action="ACTION_FILE_CREATE")
        elif eid in (23, 26):
            e.update(tpath=_s(f.get("TargetFilename")).lower(), action="ACTION_FILE_OPEN_DELETE")
        elif eid in (12, 13, 14):
            e.update(tpath=_s(f.get("TargetObject")), action="ACTION_WRITE_VALUE")
        elif eid == 22:
            name = _s(f.get("QueryName")).lower()
            for m in _IP_IN_ANSWER.finditer(_s(f.get("QueryResults"))):
                ip = m.group(1) or m.group(2)
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                self.dns.put(ip, (ts, name))
            e.update(tpath=name, action="ACTION_DNS_QUERY")
        return e

    def _parent_fields(self, e, proc):
        if proc:
            e["pguid"] = proc[2]
            pp = self._proc(proc[2])
            if pp:
                e["ppath"], e["pcmd"] = pp[0], pp[1]


def to_canonical(e: dict) -> CanonicalEvent:
    """Normalized Windows event -> CanonicalEvent exactly as cbc_adapter.CBCAdapter.parse_record builds it."""
    et = e["event_type"]
    proto = {"PROTO_TCP": "tcp", "PROTO_UDP": "udp"}.get(e["proto"], e["proto"].lower())
    return CanonicalEvent(
        event_id=f"{e['host']}_{e['guid']}_{e['ts']}_{et}", timestamp=e["ts"], hostname=e["host"], event_type=et,
        scenario="live", process_guid=e["guid"], parent_guid=e["pguid"], process_path=e["path"],
        process_cmdline=e["cmd"], parent_path=e["ppath"], parent_cmdline=e["pcmd"], username=e["user"],
        target_path=e["domain"] if et == "FLOW_START" else e["tpath"], target_guid=e["tguid"],
        proto=proto if et == "FLOW_START" else "", remote_ip=e["rip"], remote_port=e["rport"],
        local_port=e["lport"], inbound=e["inbound"], label=0)


def to_dl_record(e: dict, line: int = 0) -> dict | None:
    """Normalized Windows event -> bilstm_v9/parse_events.py record (None for kinds the BiLSTM does not read)."""
    kind = DL_KIND.get(e["event_type"])
    if kind is None:
        return None
    if kind == "filemod" and not e["tpath"].lower().endswith(FILEMOD_EXT):
        return None
    return {"line": line, "ts": e["ts"], "kind": kind, "action": e["action"], "host": e["host"], "guid": e["guid"],
            "pguid": e["pguid"], "path": e["path"], "cmd": e["cmd"][:2000], "ppath": e["ppath"], "user": e["user"],
            "pub": e["pub"], "tpath": e["tpath"] if kind != "netconn" else "", "tguid": e["tguid"],
            "tcmd": e["tcmd"][:2000] if kind == "procstart" else "", "tpub": e["tpub"] if kind in ("procstart", "crossproc") else "NONE",
            "proto": e["proto"] if kind == "netconn" else "", "rip": e["rip"] if kind == "netconn" else "",
            "rport": e["rport"] if kind == "netconn" else 0, "lport": e["lport"] if kind == "netconn" else 0,
            "inbound": bool(e["inbound"]) if kind == "netconn" else False, "domain": e["domain"] if kind == "netconn" else ""}
