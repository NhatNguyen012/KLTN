# Vendored from Docker/shared/schema_adapters.py for self-contained endpoint OpTC eCAR serving.
#!/usr/bin/env python3
"""Deterministic schema adapters converting real external logs into OpTC eCAR contracts.

Supports:
1. Kellect4APT Windows ETW JSONL (`Event`: ProcessStart, FileIO*, ImageLoad, Registry*, TcpIp*)
2. Windows Sysmon / Winlogbeat v6 & ECS v7 / Security 4688 / PowerShell 800/4103/4104
3. DARPA TC E3 CDM resolved edge JSONL (FiveDirections / CADETS)

Native OpTC eCAR and THEIA L=3 causal triplet records pass through untouched.
Never reads truth fields or accesses raw dataset directories directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Tuple
import uuid
import xml.etree.ElementTree as ET

_FILETIME_EPOCH_DIFF_US = 11644473600_000_000


def _det_uuid(*parts: Any) -> str:
    joined = "|".join(str(p or "").strip().lower() for p in parts)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, joined))


def _parse_any_ts_to_iso(raw_ts: Any, fallback: str = "") -> str:
    if isinstance(raw_ts, (int, float)):
        val = int(raw_ts)
        if val >= 1_400_000_000_000_000_000:
            # DARPA TC Unix nanoseconds (~1.52e18 in 2018)
            return datetime.fromtimestamp(val / 1_000_000_000.0, tz=timezone.utc).isoformat()
        if val >= 100_000_000_000_000_000:
            # Windows FILETIME 100ns since 1601 (~1.33e17 in 2023)
            us = (val // 10) - _FILETIME_EPOCH_DIFF_US
            return datetime.fromtimestamp(us / 1_000_000.0, tz=timezone.utc).isoformat()
        if val >= 100_000_000_000_000:
            # Unix microseconds (~1.79e15)
            return datetime.fromtimestamp(val / 1_000_000.0, tz=timezone.utc).isoformat()
        if val >= 1_000_000_000_000:
            # Unix milliseconds
            return datetime.fromtimestamp(val / 1_000.0, tz=timezone.utc).isoformat()
        if val >= 1_000_000_000:
            return datetime.fromtimestamp(float(val), tz=timezone.utc).isoformat()
    if isinstance(raw_ts, str):
        s = raw_ts.strip()
        if s.isdigit():
            return _parse_any_ts_to_iso(int(s), fallback=fallback)
        if len(s) >= 19 and s[10] == " " and s[4] == "-" and s[7] == "-":
            return s.replace(" ", "T", 1) + "Z"
        if s:
            return s
    return fallback


def _norm_principal(user: Any, domain: Any = "") -> str:
    u = str(user or "").strip()
    d = str(domain or "").strip()
    if not u:
        return ""
    if u in {"S-1-5-18", "SYSTEM"} or (d.upper() == "NT AUTHORITY" and u.upper() == "SYSTEM"):
        return "NT AUTHORITY\\SYSTEM"
    if u in {"S-1-5-19", "LOCAL SERVICE"}:
        return "NT AUTHORITY\\LOCAL SERVICE"
    if u in {"S-1-5-20", "NETWORK SERVICE"}:
        return "NT AUTHORITY\\NETWORK SERVICE"
    if "\\" in u:
        return u
    return f"{d}\\{u}" if d else u


def is_native_ecar(rec: Mapping[str, Any]) -> bool:
    return (
        isinstance(rec.get("action"), str)
        and isinstance(rec.get("object"), str)
        and ("actorID" in rec or "objectID" in rec or isinstance(rec.get("properties"), Mapping))
        and "operation" not in rec
        and "Event" not in rec
    )


def _extract_windows_xml_str(rec: Mapping[str, Any]) -> str | None:
    sys_val = rec.get("System")
    if isinstance(sys_val, str) and "<Event" in sys_val:
        return sys_val
    raw_val = rec.get("raw")
    if isinstance(raw_val, Mapping):
        inner = raw_val.get("System")
        if isinstance(inner, str) and "<Event" in inner:
            return inner
    return None


def parse_windows_xml_dict(xml_str: str, fallback_ts: Any = None, fallback_id: Any = None) -> Dict[str, Any]:
    """Convert raw Windows EVTX/Sysmon/PowerShell XML fragment into a flat Winlogbeat-compatible dict."""
    root = ET.fromstring(xml_str)
    out: Dict[str, Any] = {}
    ed: Dict[str, str] = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "EventID" and el.text:
            out["event_id"] = el.text.strip()
        elif tag == "Channel" and el.text:
            out["log_name"] = el.text.strip()
        elif tag == "Computer" and el.text:
            out["computer_name"] = el.text.strip()
        elif tag == "EventRecordID" and el.text:
            out["record_number"] = el.text.strip()
        elif tag == "TimeCreated" and el.attrib.get("SystemTime"):
            out["TimeCreated"] = el.attrib["SystemTime"]
        elif tag == "Security" and el.attrib.get("UserID"):
            out["user"] = {"name": el.attrib["UserID"]}
        elif tag == "Execution" and el.attrib.get("ProcessID"):
            out["process_id"] = el.attrib["ProcessID"]
        elif tag == "Data":
            k = el.attrib.get("Name")
            if k:
                ed[k] = (el.text or "").strip()
    if "TimeCreated" not in out and fallback_ts is not None:
        out["TimeCreated"] = fallback_ts
    if "record_number" not in out and fallback_id is not None:
        out["record_number"] = str(fallback_id)
    out["event_data"] = ed
    return out


def detect_schema_name(rec: Mapping[str, Any]) -> str:
    if any(
        k in rec
        for k in (
            "E_incoming",
            "E_parent",
            "E_current",
            "incoming_tokens",
            "parent_tokens",
            "current_tokens",
            "incoming_ids",
            "current_ids",
        )
    ):
        return "theia_l3"
    if rec.get("os") == "linux" and rec.get("src") == "auditd" and isinstance(rec.get("kind"), str):
        return "kltn_linux_audit"
    if _extract_windows_xml_str(rec) is not None:
        return "kltn_windows_xml"
    if is_native_ecar(rec):
        return "optc_ecar"
    if isinstance(rec.get("Event"), str) and ("PID" in rec or "args" in rec or "Host-UUID" in rec):
        return "kellect4apt_etw"
    if isinstance(rec.get("operation"), str) and str(rec.get("operation")).startswith("EVENT_"):
        return "darpa_cdm"
    if isinstance(rec.get("winlog"), Mapping):
        w = rec["winlog"]
        ch = str(w.get("channel") or "").lower()
        if "sysmon" in ch or "powershell" in ch or str(w.get("event_id")) in {"4688", "800"}:
            return "windows_sysmon"
    ch_flat = str(rec.get("log_name") or rec.get("Channel") or rec.get("source_name") or "").lower()
    if "sysmon" in ch_flat or "powershell" in ch_flat or str(rec.get("event_id") or rec.get("EventID")) in {"4688", "800"}:
        return "windows_sysmon"
    if "EventID" in rec and any(k in rec for k in ("Image", "TargetFilename", "TargetObject", "SourceImage", "ParentImage")):
        return "windows_sysmon"
    return "unknown"


class _ProcessTableState:
    def __init__(self) -> None:
        self.pid_to_uid: Dict[Tuple[str, str], str] = {}
        self.pid_to_img: Dict[Tuple[str, str], str] = {}
        self.uid_to_img: Dict[str, str] = {}

    def spawn(self, host: str, pid: Any, img: str, seed_extra: Any = "") -> str:
        p = str(pid or "").strip()
        uid = _det_uuid("proc", host, p, img, seed_extra)
        if p and p != "-1":
            self.pid_to_uid[(host, p)] = uid
            if img:
                self.pid_to_img[(host, p)] = img
        if img:
            self.uid_to_img[uid] = img
        return uid

    def resolve(self, host: str, pid: Any, fallback_img: str = "") -> Tuple[str, str]:
        p = str(pid or "").strip()
        key = (host, p)
        uid = self.pid_to_uid.get(key)
        img = self.pid_to_img.get(key) or fallback_img
        if not uid:
            uid = _det_uuid("proc_existing", host, p or fallback_img)
            if p and p != "-1":
                self.pid_to_uid[key] = uid
                if img:
                    self.pid_to_img[key] = img
        if img and uid not in self.uid_to_img:
            self.uid_to_img[uid] = img
        return uid, img


def _adapt_kellect4apt(rec: Mapping[str, Any], idx: int, state: _ProcessTableState) -> Dict[str, Any]:
    ev = str(rec.get("Event") or "")
    host = str(rec.get("Host-UUID") or rec.get("hostname") or "kellect-win-host")
    ts = _parse_any_ts_to_iso(rec.get("TimeStamp"))
    args = rec.get("args") if isinstance(rec.get("args"), Mapping) else {}
    pid = rec.get("PID")
    ppid = rec.get("PPID")
    pname = str(rec.get("PName") or "")
    ppname = str(rec.get("PPName") or "")
    if ppname.lower() == "unknown":
        ppname = ""

    def base_out(obj: str, act: str, actor_id: str, obj_id: str, props: Dict[str, Any], principal: str = "") -> Dict[str, Any]:
        return {
            "id": str(rec.get("id") or f"kellect-{idx}"),
            "hostname": host,
            "timestamp": ts,
            "object": obj,
            "action": act,
            "actorID": actor_id,
            "objectID": obj_id,
            "principal": principal,
            "properties": {k: v for k, v in props.items() if v is not None and str(v) != ""},
            "_adapted_from": "kellect4apt_etw",
        }

    if ev in ("ProcessStart", "ProcessStartDC"):
        child_img = str(args.get("ImageFileName") or pname)
        parent_uid, parent_img = state.resolve(host, ppid, ppname)
        child_uid = state.spawn(host, pid, child_img, rec.get("TimeStamp"))
        cmd = str(args.get("CommandLine") or child_img)
        return base_out(
            "PROCESS",
            "CREATE",
            parent_uid,
            child_uid,
            {"image_path": child_img, "parent_image_path": parent_img, "command_line": cmd},
            principal=_norm_principal(args.get("UserSID", "")),
        )

    proc_uid, proc_img = state.resolve(host, pid, pname)
    img = str(args.get("ImageFileName") or proc_img or pname)

    if ev in ("ProcessEnd", "ProcessEndDC"):
        return base_out("PROCESS", "TERMINATE", proc_uid, proc_uid, {"image_path": img})

    if ev in ("ThreadStart", "ThreadStartDC"):
        target_pid = args.get("ProcessId", pid)
        if target_pid is not None and str(target_pid) != str(pid):
            target_uid, target_img = state.resolve(host, target_pid, img)
            return base_out("THREAD", "REMOTE_CREATE", proc_uid, target_uid, {"image_path": target_img or img})
        return base_out("THREAD", "CREATE", proc_uid, _det_uuid("thread", host, pid, rec.get("TID")), {"image_path": img})

    if ev in ("ImageLoad", "ImageLoadDC"):
        mod = str(args.get("FileName") or "")
        return base_out("MODULE", "LOAD", proc_uid, _det_uuid("mod", host, mod), {"image_path": img, "module_path": mod})

    if ev in ("FileIOCreate", "FileIOFileCreate", "FileIOWrite", "FileIOWriteInit", "FileIORead", "FileIODelete", "FileIOFileDelete", "FileIORename"):
        act_map = {
            "FileIOCreate": "CREATE",
            "FileIOFileCreate": "CREATE",
            "FileIOWrite": "WRITE",
            "FileIOWriteInit": "WRITE",
            "FileIORead": "READ",
            "FileIODelete": "DELETE",
            "FileIOFileDelete": "DELETE",
            "FileIORename": "RENAME",
        }
        fpath = str(args.get("OpenPath") or args.get("FileName") or "")
        return base_out("FILE", act_map[ev], proc_uid, _det_uuid("file", host, fpath), {"image_path": img, "file_path": fpath})

    if ev in ("RegistrySetValue", "RegistrySetInformation", "RegistryKCBCreate", "RegistryDelete", "RegistryDeleteValue"):
        act_map = {
            "RegistrySetValue": "EDIT",
            "RegistrySetInformation": "EDIT",
            "RegistryKCBCreate": "ADD",
            "RegistryDelete": "REMOVE",
            "RegistryDeleteValue": "REMOVE",
        }
        rkey = str(args.get("KeyName") or "")
        return base_out("REGISTRY", act_map[ev], proc_uid, _det_uuid("reg", host, rkey), {"image_path": img, "key": rkey})

    if ev in ("TcpIpConnectIPV4", "TcpIpReconnectIPV4", "TcpIpAcceptIPV4", "TcpIpSendIPV4", "TcpIpRecvIPV4"):
        is_start = ev in ("TcpIpConnectIPV4", "TcpIpReconnectIPV4", "TcpIpAcceptIPV4")
        direction = "inbound" if ev in ("TcpIpAcceptIPV4", "TcpIpRecvIPV4") else "outbound"
        return base_out(
            "FLOW",
            "START" if is_start else "MESSAGE",
            proc_uid,
            _det_uuid("flow", host, args.get("daddr"), args.get("dport"), direction),
            {
                "image_path": img,
                "src_ip": str(args.get("saddr") or ""),
                "src_port": str(args.get("sport") or ""),
                "dest_ip": str(args.get("daddr") or ""),
                "dest_port": str(args.get("dport") or ""),
                "l4protocol": "6",
                "direction": direction,
                "size": str(args.get("size") or 0),
            },
        )

    return base_out("KERNEL_OTHER", ev.upper() or "UNKNOWN", proc_uid, proc_uid, {"image_path": img})


def _adapt_sysmon(rec: Mapping[str, Any], idx: int, state: _ProcessTableState) -> Dict[str, Any]:
    winlog = rec.get("winlog") if isinstance(rec.get("winlog"), Mapping) else None
    if winlog is not None:
        ch = str(winlog.get("channel") or winlog.get("provider_name") or "").lower()
        eid_raw = winlog.get("event_id")
        host = str(winlog.get("computer_name") or (rec.get("host") or {}).get("name") or "win-host")
        ed = winlog.get("event_data") if isinstance(winlog.get("event_data"), Mapping) else {}
        uobj = winlog.get("user") if isinstance(winlog.get("user"), Mapping) else {}
    else:
        ch = str(rec.get("log_name") or rec.get("Channel") or rec.get("source_name") or "").lower()
        eid_raw = rec.get("event_id") if "event_id" in rec else rec.get("EventID")
        hval = rec.get("host")
        hname = hval.get("name") if isinstance(hval, Mapping) else hval
        host = str(rec.get("computer_name") or rec.get("Computer") or rec.get("hostname") or hname or "win-host")
        ed = rec.get("event_data") if isinstance(rec.get("event_data"), Mapping) else rec
        uobj = rec.get("user") if isinstance(rec.get("user"), Mapping) else {}

    try:
        eid = int(str(eid_raw).strip())
    except (TypeError, ValueError):
        eid = -1

    ts = _parse_any_ts_to_iso(ed.get("UtcTime") or rec.get("@timestamp") or rec.get("SystemTime") or rec.get("TimeCreated"))
    principal = _norm_principal(ed.get("User") or uobj.get("name"), uobj.get("domain"))

    def base_out(obj: str, act: str, actor_id: str, obj_id: str, props: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(rec.get("record_number") or rec.get("EventRecordID") or f"sysmon-{idx}"),
            "hostname": host,
            "timestamp": ts,
            "object": obj,
            "action": act,
            "actorID": actor_id,
            "objectID": obj_id,
            "principal": principal,
            "properties": {k: v for k, v in props.items() if v is not None and str(v) != ""},
            "_adapted_from": "windows_sysmon",
        }

    # PowerShell Operational / Legacy pipeline telemetry -> SHELL COMMAND
    if ("powershell" in ch and eid in (800, 4103, 4104)) or eid in (4103, 4104):
        payload = ed.get("ScriptBlockText") or ed.get("Payload") or ed.get("param1") or rec.get("message") or ""
        p_pid = ed.get("ProcessId") or rec.get("process_id") or "ps"
        p_uid, _ = state.resolve(host, p_pid, "powershell.exe")
        return base_out("SHELL", "COMMAND", p_uid, _det_uuid("shell", host, idx), {"image_path": "powershell.exe", "payload": str(payload)[:32768]})

    # Security 4688: Process Creation
    if eid == 4688:
        child_img = str(ed.get("NewProcessName") or ed.get("Image") or "")
        parent_img = str(ed.get("ParentProcessName") or ed.get("ParentImage") or "")
        cmd = str(ed.get("CommandLine") or child_img)
        p_uid, _ = state.resolve(host, ed.get("ProcessId", ""), parent_img)
        c_uid = state.spawn(host, ed.get("NewProcessId", ""), child_img, ts or idx)
        return base_out("PROCESS", "CREATE", p_uid, c_uid, {"image_path": child_img, "parent_image_path": parent_img, "command_line": cmd})

    # Sysmon ProcessGuid or synthetic PID resolution
    pguid = str(ed.get("ProcessGuid") or ed.get("ProcessGUID") or "").strip()
    img = str(ed.get("Image") or "")
    if pguid:
        proc_uid = pguid
        if img:
            state.uid_to_img[proc_uid] = img
    else:
        proc_uid, cached_img = state.resolve(host, ed.get("ProcessId") or rec.get("process_id"), img)
        img = img or cached_img

    if eid == 1:
        child_guid = pguid or state.spawn(host, ed.get("ProcessId"), img, ts or idx)
        parent_guid = str(ed.get("ParentProcessGuid") or ed.get("ParentProcessGUID") or "").strip()
        parent_img = str(ed.get("ParentImage") or "")
        if not parent_guid:
            parent_guid, cached_pimg = state.resolve(host, ed.get("ParentProcessId"), parent_img)
            parent_img = parent_img or cached_pimg
        cmd = str(ed.get("CommandLine") or img)
        if not principal and ed.get("User"):
            principal = _norm_principal(ed.get("User"))
        return base_out("PROCESS", "CREATE", parent_guid, child_guid, {"image_path": img, "parent_image_path": parent_img, "command_line": cmd})

    if eid == 5:
        return base_out("PROCESS", "TERMINATE", proc_uid, proc_uid, {"image_path": img})

    if eid == 7:
        mod = str(ed.get("ImageLoaded") or "")
        return base_out("MODULE", "LOAD", proc_uid, _det_uuid("mod", host, mod), {"image_path": img, "module_path": mod})

    if eid == 8:
        sguid = str(ed.get("SourceProcessGuid") or ed.get("SourceProcessGUID") or proc_uid)
        tguid = str(ed.get("TargetProcessGuid") or ed.get("TargetProcessGUID") or _det_uuid("target", host, ed.get("TargetProcessId")))
        simg = str(ed.get("SourceImage") or img)
        timg = str(ed.get("TargetImage") or "")
        return base_out("THREAD", "REMOTE_CREATE", sguid, tguid, {"image_path": timg or simg, "parent_image_path": simg})

    if eid == 10:
        sguid = str(ed.get("SourceProcessGuid") or ed.get("SourceProcessGUID") or proc_uid)
        tguid = str(ed.get("TargetProcessGuid") or ed.get("TargetProcessGUID") or _det_uuid("target", host, ed.get("TargetProcessId")))
        simg = str(ed.get("SourceImage") or img)
        timg = str(ed.get("TargetImage") or "")
        return base_out("PROCESS", "OPEN", sguid, tguid, {"image_path": timg, "parent_image_path": simg})

    if eid in (11, 23, 26):
        act = "CREATE" if eid == 11 else "DELETE"
        fpath = str(ed.get("TargetFilename") or "")
        return base_out("FILE", act, proc_uid, _det_uuid("file", host, fpath), {"image_path": img, "file_path": fpath})

    if eid in (12, 13, 14):
        ev_type = str(ed.get("EventType") or "").lower()
        act = "ADD" if "create" in ev_type else ("REMOVE" if "delete" in ev_type else "EDIT")
        rkey = str(ed.get("TargetObject") or "")
        return base_out("REGISTRY", act, proc_uid, _det_uuid("reg", host, rkey), {"image_path": img, "key": rkey})

    if eid in (17, 18):
        pipe = str(ed.get("PipeName") or "")
        return base_out("FILE", "OPEN", proc_uid, _det_uuid("pipe", host, pipe), {"image_path": img, "file_path": pipe})

    if eid == 3:
        proto = str(ed.get("Protocol") or "").strip().lower()
        l4 = {"tcp": "6", "udp": "17", "icmp": "1"}.get(proto, "6")
        init_val = str(ed.get("Initiated") or "").strip().lower()
        direction = "inbound" if init_val in ("false", "0") else "outbound"
        return base_out(
            "FLOW",
            "START",
            proc_uid,
            _det_uuid("flow", host, ed.get("DestinationIp"), ed.get("DestinationPort"), direction),
            {
                "image_path": img,
                "src_ip": str(ed.get("SourceIp") or ""),
                "src_port": str(ed.get("SourcePort") or ""),
                "dest_ip": str(ed.get("DestinationIp") or ""),
                "dest_port": str(ed.get("DestinationPort") or ""),
                "l4protocol": l4,
                "direction": direction,
                "size": "0",
            },
        )

    return base_out("SYSMON_OTHER", f"EID_{eid}", proc_uid, proc_uid, {"image_path": img})


def _adapt_darpa_cdm(rec: Mapping[str, Any], idx: int) -> Dict[str, Any]:
    op = str(rec.get("operation") or "").upper()
    host = str(rec.get("hostname") or "darpa-e3-host")
    ts = _parse_any_ts_to_iso(rec.get("timestamp_rec") or rec.get("timestamp"))
    actor_id = str(rec.get("actorID") or rec.get("src_node") or f"src-{idx}")
    obj_id = str(rec.get("dst_node") or rec.get("objectID") or f"dst-{idx}")
    proc_img = str(rec.get("proc_path") or rec.get("proc_cmd") or rec.get("src_cmd") or rec.get("src_path") or "")
    target_path = str(rec.get("obj_path") or rec.get("dst_path") or rec.get("dst_cmd") or "")
    cmd = str(rec.get("proc_cmd") or rec.get("dst_cmd") or rec.get("cmd") or proc_img)

    if op in ("EVENT_FORK", "EVENT_CLONE"):
        obj, act = "PROCESS", "CREATE"
        props = {"parent_image_path": proc_img, "image_path": target_path or proc_img, "command_line": cmd}
    elif op == "EVENT_EXECUTE":
        obj, act = "PROCESS", "CREATE"
        props = {"image_path": target_path or proc_img, "parent_image_path": proc_img, "command_line": cmd}
    elif op in ("EVENT_LOADLIBRARY", "EVENT_MMAP"):
        obj, act = "MODULE", "LOAD"
        props = {"image_path": proc_img, "module_path": target_path}
    elif op == "EVENT_CREATE_THREAD":
        obj, act = "THREAD", "CREATE"
        props = {"image_path": proc_img}
    elif op in ("EVENT_CONNECT", "EVENT_ACCEPT", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG"):
        obj = "FLOW"
        act = "START" if op in ("EVENT_CONNECT", "EVENT_ACCEPT") else "MESSAGE"
        direction = "inbound" if op in ("EVENT_ACCEPT", "EVENT_RECVFROM", "EVENT_RECVMSG") else "outbound"
        props = {
            "image_path": proc_img,
            "src_ip": str(rec.get("src_ip") or ""),
            "src_port": str(rec.get("src_port") or ""),
            "dest_ip": str(rec.get("dest_ip") or rec.get("dst_ip") or ""),
            "dest_port": str(rec.get("dest_port") or rec.get("dst_port") or ""),
            "l4protocol": "6",
            "direction": direction,
            "size": "0",
        }
    else:
        act_map = {
            "EVENT_CREATE_OBJECT": ("FILE", "CREATE"),
            "EVENT_WRITE": ("FILE", "WRITE"),
            "EVENT_READ": ("FILE", "READ"),
            "EVENT_UNLINK": ("FILE", "DELETE"),
            "EVENT_RENAME": ("FILE", "RENAME"),
            "EVENT_MODIFY_FILE_ATTRIBUTES": ("FILE", "MODIFY"),
            "EVENT_OPEN": ("PROCESS", "OPEN") if rec.get("dst_kind") == "process" else ("FILE", "OPEN"),
            "EVENT_CLOSE": ("KERNEL_OTHER", "CLOSE"),
        }
        obj, act = act_map.get(op, ("KERNEL_OTHER", op.replace("EVENT_", "") or "UNKNOWN"))
        props = {"image_path": proc_img, **({"file_path": target_path} if obj == "FILE" and target_path else {})}

    return {
        "id": str(rec.get("event_uuid") or rec.get("id") or f"cdm-{idx}"),
        "hostname": host,
        "timestamp": ts,
        "object": obj,
        "action": act,
        "actorID": actor_id,
        "objectID": obj_id,
        "principal": "",
        "properties": {k: v for k, v in props.items() if v},
        "_adapted_from": "darpa_cdm",
    }


def _adapt_kltn_linux_audit(rec: Mapping[str, Any], idx: int, state: _ProcessTableState) -> Dict[str, Any]:
    host = str(rec.get("host") or rec.get("hostname") or "linux-host")
    ts = _parse_any_ts_to_iso(rec.get("ts") or rec.get("timestamp"))
    kind = str(rec.get("kind") or "other").lower()
    pid = rec.get("pid")
    ppid = rec.get("ppid")
    img = str(rec.get("image") or "")
    pimg = str(rec.get("pimage") or "")
    cmd = str(rec.get("cmd") or "").replace("\x00", " ").strip()
    pcmd = str(rec.get("pcmd") or "").replace("\x00", " ").strip()
    tpath = str(rec.get("tpath") or "")
    syscall = rec.get("syscall")

    if kind == "procstart":
        p_uid, p_cached = state.resolve(host, ppid, pimg)
        pimg = pimg or p_cached
        c_uid = state.spawn(host, pid, img, rec.get("ts") or idx)
        obj, act, theia_op = "PROCESS", "CREATE", "EVENT_EXECUTE"
        props: Dict[str, Any] = {
            "image_path": img,
            "parent_image_path": pimg,
            "command_line": cmd or img,
            "parent_command_line": pcmd,
            "pid": str(pid or ""),
            "ppid": str(ppid or ""),
        }
        actor_id, obj_id = p_uid, c_uid
    else:
        proc_uid, proc_cached = state.resolve(host, pid, img)
        img = img or proc_cached
        _, p_cached = state.resolve(host, ppid, pimg)
        pimg = pimg or p_cached
        actor_id = proc_uid
        if kind == "filemod":
            is_unlink = str(rec.get("code") or "") == "DELETE" or str(syscall) in {"87", "263"}
            obj = "FILE"
            act = "DELETE" if is_unlink else "WRITE"
            theia_op = "EVENT_UNLINK" if is_unlink else "EVENT_WRITE"
            obj_id = _det_uuid("file", host, tpath or idx)
            props = {"image_path": img, "parent_image_path": pimg, "file_path": tpath, "command_line": cmd, "pid": str(pid or ""), "ppid": str(ppid or "")}
        elif kind == "fileread":
            obj, act, theia_op = "FILE", "READ", "EVENT_READ"
            obj_id = _det_uuid("file", host, tpath or idx)
            props = {"image_path": img, "parent_image_path": pimg, "file_path": tpath, "command_line": cmd, "pid": str(pid or ""), "ppid": str(ppid or "")}
        elif kind == "netconn":
            is_in = rec.get("outbound") is False
            direction = "inbound" if is_in else "outbound"
            obj, act, theia_op = "FLOW", "START", "EVENT_CONNECT"
            obj_id = _det_uuid("flow", host, rec.get("rip"), rec.get("rport"), direction)
            props = {
                "image_path": img,
                "parent_image_path": pimg,
                "src_ip": str(rec.get("lip") or ""),
                "src_port": str(rec.get("lport") or ""),
                "dest_ip": str(rec.get("rip") or ""),
                "dest_port": str(rec.get("rport") or ""),
                "proto": str(rec.get("proto") or "tcp").lower() or "tcp",
                "direction": direction,
                "command_line": cmd,
                "pid": str(pid or ""),
                "ppid": str(ppid or ""),
            }
        elif kind == "privchange":
            obj, act, theia_op = "FILE", "MODIFY", "EVENT_MODIFY_FILE_ATTRIBUTES"
            obj_id = _det_uuid("priv", host, pid, tpath or idx)
            props = {"image_path": img, "parent_image_path": pimg, "file_path": tpath, "command_line": cmd, "pid": str(pid or ""), "ppid": str(ppid or "")}
        elif kind == "auth":
            obj, act, theia_op = "USER_SESSION", "LOGIN", "EVENT_OPEN"
            obj_id = _det_uuid("auth", host, rec.get("user"), tpath or idx)
            props = {"image_path": img, "parent_image_path": pimg, "file_path": tpath, "src_ip": str(rec.get("rip") or ""), "command_line": cmd, "pid": str(pid or ""), "ppid": str(ppid or "")}
        else:
            obj, act, theia_op = "FILE", "OPEN", "EVENT_OPEN"
            obj_id = _det_uuid("other", host, tpath or idx)
            props = {"image_path": img, "parent_image_path": pimg, "file_path": tpath, "command_line": cmd, "pid": str(pid or ""), "ppid": str(ppid or "")}

    uid_val = rec.get("uid")
    principal = "root" if str(uid_val) == "0" or str(rec.get("user") or "").lower() == "root" else str(rec.get("user") or uid_val or "")
    props["theia_op"] = theia_op
    if isinstance(rec.get("rule_keys"), list) and rec.get("rule_keys"):
        props["rule_keys"] = [str(k) for k in rec["rule_keys"]]

    return {
        "id": str(rec.get("id") or f"{host}:audit:{rec.get('ts') or idx}:{rec.get('line') or idx}"),
        "hostname": host,
        "timestamp": ts,
        "object": obj,
        "action": act,
        "actorID": actor_id,
        "objectID": obj_id,
        "principal": principal,
        "properties": {k: v for k, v in props.items() if v is not None and str(v) != ""},
        "_adapted_from": "kltn_linux_audit",
    }


def adapt_records(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Convert non-eCAR records to OpTC eCAR format in-memory while leaving native schemas untouched."""
    state = _ProcessTableState()
    out: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}

    for idx, rec in enumerate(records):
        schema = detect_schema_name(rec)
        counts[schema] = counts.get(schema, 0) + 1
        if schema in ("optc_ecar", "theia_l3", "unknown"):
            out.append(rec)
        elif schema == "kellect4apt_etw":
            out.append(_adapt_kellect4apt(rec, idx, state))
        elif schema == "windows_sysmon":
            out.append(_adapt_sysmon(rec, idx, state))
        elif schema == "kltn_windows_xml":
            xml_str = _extract_windows_xml_str(rec) or ""
            raw_obj = rec.get("raw") if isinstance(rec.get("raw"), Mapping) else rec
            parsed = parse_windows_xml_dict(xml_str, fallback_ts=raw_obj.get("date"), fallback_id=rec.get("event_id") or idx)
            out.append(_adapt_sysmon(parsed, idx, state))
        elif schema == "kltn_linux_audit":
            out.append(_adapt_kltn_linux_audit(rec, idx, state))
        elif schema == "darpa_cdm":
            out.append(_adapt_darpa_cdm(rec, idx))
    return out, counts
