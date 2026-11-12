"""Label-blind, bounded CBC provenance context for sequence feature enrichment.

Only whitelisted observable fields are read. IDs/path strings are join keys or
audit evidence, never model tokens. Context is extracted before a timestamp
batch is observed. CBC cross-process target views are normalized to source->target.
"""
from __future__ import annotations
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
import ipaddress
import re

FAMILIES = {
    "firefox.exe":"browser", "chrome.exe":"browser", "iexplore.exe":"browser",
    "winword.exe":"office", "excel.exe":"office", "powerpnt.exe":"office",
    "powershell.exe":"powershell", "cmd.exe":"cmd", "conhost.exe":"console",
    "regsvr32.exe":"regsvr32", "mshta.exe":"mshta", "rundll32.exe":"rundll32",
    "wscript.exe":"script_host", "cscript.exe":"script_host", "python.exe":"python",
    "explorer.exe":"explorer", "svchost.exe":"service", "lsass.exe":"security_service",
    "services.exe":"service", "wininit.exe":"session", "winlogon.exe":"session",
    "plugin-container.exe":"browser_plugin", "net.exe":"network_tool", "netstat.exe":"network_tool",
    "ipconfig.exe":"network_tool", "whoami.exe":"identity_tool", "schtasks.exe":"scheduler",
}
RELATIONS = {
    "ACTION_OPEN_PROCESS_HANDLE":"process_open",
    "ACTION_DUP_PROCESS_HANDLE":"process_duplicate",
    "ACTION_OPEN_THREAD_HANDLE":"thread_open",
    "ACTION_DUP_THREAD_HANDLE":"thread_duplicate",
    "ACTION_CREATE_REMOTE_THREAD":"remote_thread_create",
    "ACTION_API_CALL":"api_call",
}
SWITCHES = {"-enc", "-encodedcommand", "-nop", "-noprofile", "-w", "-windowstyle",
            "-executionpolicy", "-ep", "-command", "-c", "-file", "/c", "/k", "/s", "/i", "/u", "/n"}


def clean(value):
    return value.strip().lower() if isinstance(value, str) else ""


def valid_id(value):
    v = clean(value)
    return v if v and v not in {"none", "null", "0"} else ""


def normalize_path(value):
    return clean(value).replace("/", "\\").strip('"')


def family(path):
    return FAMILIES.get(normalize_path(path).rsplit("\\", 1)[-1], "other") if path else "missing"


def path_role(path):
    p = normalize_path(path)
    if not p: return "missing"
    if "\\system32\\" in p or "\\syswow64\\" in p: return "system"
    if "\\program files" in p: return "program_files"
    if "\\temp\\" in p or "\\appdata\\" in p: return "temp_appdata"
    if "\\downloads\\" in p: return "downloads"
    if "\\users\\" in p: return "user_profile"
    if "\\windows\\" in p: return "windows"
    return "other"


def age_bucket(micros):
    seconds=micros/1e6
    for limit,name in [(1,"lt1s"),(10,"lt10s"),(30,"lt30s"),(300,"lt5m"),(3600,"lt1h")]:
        if seconds < limit: return name
    return "ge1h"


def command_tokens(command):
    # No payload decoding, command execution, raw operands, domains or user values.
    text = clean(command)[:4096]
    out = {f"cmd_switch={m}" for m in re.findall(r"(?<!\w)([-/][a-z]+)",text) if m in SWITCHES}
    if re.search(r"https?://",text): out.add("cmd_operand=url")
    if re.search(r"\.(ps1|vbs|hta|sct|bat|cmd)(?:[\s\"']|$)",text):out.add("cmd_operand=script_path")
    for operator,kind in [("|","pipe"),("&&","and"),(";","semicolon"),(">","redirect")]:
        if operator in text:out.add(f"cmd_operator={kind}")
    return sorted(out)


@dataclass(frozen=True, slots=True)
class Observation:
    timestamp: int
    line: int
    host: str
    kind: str
    actor: str
    actor_path: str
    actor_command: str
    target: str = ""
    target_path: str = ""
    relation: str = ""
    direction_known: bool = True
    remote_scope: str = "missing"
    inbound: str = "missing"


def observation(raw, timestamp, line):
    """Construct a new object using only the observable allowlist."""
    typ = raw.get("type", "").removeprefix("endpoint.event.")
    if typ not in {"procstart", "crossproc", "netconn", "filemod"}: return None
    actor, path = valid_id(raw.get("process_guid")), clean(raw.get("process_path"))
    command = raw.get("process_cmdline") if isinstance(raw.get("process_cmdline"),str) else ""
    target=target_path=relation="";known=True
    if typ=="procstart":
        target,target_path=valid_id(raw.get("childproc_guid")),clean(raw.get("childproc_name"))
        relation="spawn" if raw.get("action")=="ACTION_CREATE_PROCESS" else "process_discovered"
    elif typ=="crossproc":
        target,target_path=valid_id(raw.get("crossproc_guid")),clean(raw.get("crossproc_name"))
        relation=RELATIONS.get(raw.get("crossproc_action") or raw.get("action"),"other_crossproc")
        flag=raw.get("crossproc_target")
        if flag is True or flag==1:
            actor,target=target,actor;path,target_path=target_path,path
            command=""  # Current command belongs to the viewed target, not normalized actor.
        elif flag is False or flag==0:pass
        else:known=False
    elif typ=="filemod":
        target_path=clean(raw.get("filemod_name"))
        relation="file_delete" if "DELETE" in str(raw.get("action","")) else "file_write"
    scope="missing";inbound="missing"
    if typ=="netconn":
        try:
            addr=ipaddress.ip_address(str(raw.get("remote_ip")))
            scope="loopback" if addr.is_loopback else "private" if addr.is_private else "public"
        except ValueError:pass
        flag=raw.get("netconn_inbound")
        if flag in (True,False,0,1):inbound="in" if bool(flag) else "out"
    return Observation(timestamp,line,clean(raw.get("device_name")),typ,actor,path,command,
                       target,target_path,relation,known,scope,inbound)


class ProvenanceContext:
    def __init__(self, *, ttl_micros=86_400_000_000, capacity=10000, per_kind=8, file_capacity=20000):
        self.ttl=ttl_micros;self.capacity=capacity;self.per_kind=per_kind;self.file_capacity=file_capacity
        self.parents=OrderedDict();self.incoming=OrderedDict();self.writers=OrderedDict()
        self.latest_time=-1

    def _trim(self, mapping, capacity):
        while len(mapping)>capacity:mapping.popitem(last=False)

    def features(self,e):
        event={f"event::type={e.kind}",f"event::actor_family={family(e.actor_path)}",
               f"event::actor_role={path_role(e.actor_path)}"}
        event.update(f"event::{t}" for t in command_tokens(e.actor_command))
        if e.kind in {"procstart","crossproc"}:
            event.update({f"event::relation={e.relation}",f"event::target_family={family(e.target_path)}",
                          f"event::target_role={path_role(e.target_path)}",
                          f"event::transition={family(e.actor_path)}->{family(e.target_path)}"})
        if e.kind=="netconn":event.update({f"event::remote_scope={e.remote_scope}",f"event::direction={e.inbound}"})
        tokens=set(event); evidence=[]; key=(e.host,e.actor)
        parents=[p for p in self.parents.get(key,[]) if 0<e.timestamp-p.timestamp<=self.ttl]
        if len({p.actor for p in parents})>1:tokens.add("parent::status=conflict")
        elif parents:
            p=parents[-1];tokens.update({f"parent::family={family(p.actor_path)}",f"parent::role={path_role(p.actor_path)}",
                f"parent::age={age_bucket(e.timestamp-p.timestamp)}",
                f"parent::transition={family(p.actor_path)}->{family(e.actor_path)}"})
            tokens.update(f"parent::{t}" for t in command_tokens(p.actor_command))
            evidence.append(("parent",p))
        else:tokens.add("parent::status=unobserved")
        kinds=self.incoming.get(key,{})
        for kind,history in sorted(kinds.items()):
            valid=[p for p in history if 0<e.timestamp-p.timestamp<=self.ttl]
            for p in valid:
                tokens.update({f"incoming::{kind}::source_family={family(p.actor_path)}",
                    f"incoming::{kind}::source_role={path_role(p.actor_path)}",
                    f"incoming::{kind}::age={age_bucket(e.timestamp-p.timestamp)}"})
                evidence.append(("incoming",p))
                if kind=="remote_thread_create":
                    prior=[o for o in kinds.get("process_open",[]) if o.actor==p.actor and 0<p.timestamp-o.timestamp<=self.ttl]
                    if prior:tokens.add(f"incoming::remote_thread_create::prior_open_gap={age_bucket(p.timestamp-prior[-1].timestamp)}")
        if e.kind=="procstart" and e.target_path:
            p=self.writers.get((e.host,normalize_path(e.target_path)))
            if p and 0<e.timestamp-p.timestamp<=300_000_000:
                tokens.update({f"filectx::executed_image_writer_family={family(p.actor_path)}",
                    f"filectx::write_to_start_age={age_bucket(e.timestamp-p.timestamp)}"})
                evidence.append(("image_writer",p))
        return sorted(tokens),evidence

    def observe_batch(self, events):
        if not events:return
        t=events[0].timestamp
        if any(e.timestamp!=t for e in events) or t<self.latest_time:raise ValueError("Expected chronological equal-time batches")
        self.latest_time=t;seen=set()
        for e in events:
            if not e.actor:continue
            if e.kind=="procstart" and e.target and e.target!=e.actor and e.direction_known:
                # A discovery observation documents a relationship, but is not an observed spawn time.
                k=(e.host,e.target);history=self.parents.setdefault(k,deque(maxlen=8))
                history.append(e);self.parents.move_to_end(k)
            elif e.kind=="crossproc" and e.target and e.target!=e.actor and e.direction_known:
                sig=(e.host,e.actor,e.target,e.relation)
                if sig in seen:continue
                seen.add(sig);k=(e.host,e.target)
                kinds=self.incoming.setdefault(k,{})
                kinds.setdefault(e.relation,deque(maxlen=self.per_kind)).append(e)
                self.incoming.move_to_end(k)
            elif e.kind=="filemod" and e.relation=="file_write" and e.target_path:
                k=(e.host,normalize_path(e.target_path));self.writers[k]=e;self.writers.move_to_end(k)
        self._trim(self.parents,self.capacity);self._trim(self.incoming,self.capacity);self._trim(self.writers,self.file_capacity)
