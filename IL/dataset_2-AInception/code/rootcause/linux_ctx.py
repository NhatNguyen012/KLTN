"""Linux (auditd) event tokens + causal process/parent/incoming context, after the Base OpTC host ML design
(ML/code/preprocess/ecar_tokenizer.py + process_context_tracker.py), adapted to Linux.

Base OpTC                                  | Linux / auditd here
-------------------------------------------|-----------------------------------------------------------------
event: action/object, image path category  | kind + syscall/record type, exe + Linux path category
command line: family, switches, roles,     | argv0, shell -c / interpreter inline / stdin modes, switches,
  python AST anchors, operators            |   argument roles (path category, url, ip, blob), shell operators,
                                           |   python/perl inline anchors (same anchor lists as Base OpTC)
principal class                            | uid class + auid class (login uid) + escalated (uid != auid)
ctx::actor (exe, family, cmd, age, recent) | same, from the pid's earlier events
ctx::parent (exe, family, cmd, lineage)    | same, ppid; + grandparent exe; ppid never seen -> parent_unseen
ctx::incoming (process_open,               | ptrace/kill into the process (crossproc), and the LOGIN SESSION the
  thread_remote_create into the actor)     |   process belongs to (audit ses): who opened it (sshd/cron/sudo/
                                           |   systemd), account class, age, sudo seen in it; optional source
                                           |   address scope of the login (flag `with_scope`)
All context uses evidence strictly before the event (state is updated after tokens are emitted). No labels, no
attack timeline, no host identity, no literal IPs/accounts.
"""
from __future__ import annotations

import math
import re
import shlex
from collections import defaultdict, deque

UNSET = 4294967295

# ---------------------------------------------------------------- generic helpers
_NUM = re.compile(r"(?<![a-z])\d+(?![a-z])")
_HEX = re.compile(r"\b[0-9a-f]{12,}\b")
_B64 = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"}
INTERP = {"python", "python2", "python3", "perl", "ruby", "php", "node", "lua", "awk", "gawk", "mawk"}
# same anchor sets as Base OpTC (ecar_tokenizer PYTHON_ANCHOR_MODULES / BUILTINS), plus their perl/shell spelling
ANCHORS = ("os", "sys", "subprocess", "socket", "pathlib", "shutil", "base64", "zlib", "codecs", "pty", "exec",
           "eval", "compile", "__import__", "open", "print", "b64decode", "decompress", "dup2", "spawn", "connect")
OPS = (("$(", "subst"), ("`", "backtick"), ("&&", "and"), ("||", "or"), (">>", "append"), ("|", "pipe"),
       (";", "seq"), (">", "redirect"), ("<", "input"), ("&", "background"))


def age_bucket(sec: float) -> str:
    for lim, name in ((1, "lt_1s"), (10, "lt_10s"), (60, "lt_1m"), (300, "lt_5m"), (900, "lt_15m"), (3600, "lt_1h")):
        if sec < lim:
            return name
    return "gt_1h"


def base(p) -> str:
    s = (p or "").strip().rstrip("/").split("/")[-1].lower()
    s = re.sub(r"\d+(\.\d+)*$", "", s) if s.startswith(("python", "perl", "ruby", "php")) else s  # python3.9 -> python
    return s or "<none>"


def path_cat(p: str) -> str:
    """Finite Linux location category (security-relevant locations first)."""
    p = (p or "").strip().strip("'\"")
    if not p:
        return "none"
    lo = p.lower()
    if not lo.startswith(("/", "~", "./", "../")):
        return "relative"
    if lo.startswith("~"):
        lo = "/home/u" + lo[1:]
    rules = (
        (("/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"), "cred_store"),
        (("/etc/passwd", "/etc/group"), "account_db"),
        (("/etc/sudoers",), "sudoers"),
        (("/etc/pam.d", "/lib/security", "/usr/lib/security", "/lib/x86_64-linux-gnu/security",
          "/usr/lib/x86_64-linux-gnu/security"), "pam"),
        (("/etc/ssh",), "ssh_config"),
        (("/etc/cron", "/var/spool/cron"), "cron"),
        (("/etc/systemd", "/lib/systemd", "/usr/lib/systemd", "/run/systemd/system"), "systemd"),
        (("/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/ld.so.preload"), "shell_init"),
        (("/tmp", "/var/tmp", "/dev/shm", "/run/shm"), "tmp"),
        (("/var/www", "/srv/www", "/usr/share/nginx", "/usr/lib/cgi-bin"), "web_root"),
        (("/proc",), "proc"), (("/sys",), "sys"), (("/dev",), "dev"),
        (("/var/log",), "log"),
        (("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"), "sys_bin"),
        (("/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/local/lib"), "sys_lib"),
        (("/etc",), "etc"), (("/opt",), "opt"), (("/usr/share",), "usr_share"), (("/var",), "var"), (("/run",), "run"),
    )
    for pre, cat in rules:
        if any(lo == x or lo.startswith(x.rstrip("/") + "/") or (x.endswith(("shadow", "passwd", "group", "sudoers")) and lo.startswith(x)) for x in pre):
            return cat
    if re.match(r"^/(home/[^/]+|root)/\.ssh(/|$)", lo):
        return "ssh_keys"
    if re.match(r"^/(home/[^/]+|root)/\.(bashrc|profile|bash_profile|zshrc)$", lo):
        return "shell_init"
    if lo.startswith("/root"):
        return "root_home"
    if lo.startswith("/home"):
        return "home"
    return "other"


def ip_scope(ip: str) -> str:
    ip = (ip or "").strip()
    if not ip or ip == "?":
        return "none"
    if ip in ("::1", "0000:0000:0000:0000:0000:0000:0000:0001") or ip.startswith("127."):
        return "loopback"
    if ":" in ip:
        return "ipv6"
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return "bad"
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return "private"
    if a == 169 and b == 254:
        return "link_local"
    if a == 0:
        return "zero"
    return "external"


def uid_class(u) -> str:
    try:
        n = int(float(u))
    except (TypeError, ValueError):
        s = str(u or "").strip()
        return "none" if s in ("", "?", "-", "unset") else ("root" if s == "root" else "named")
    if n == UNSET or n < 0:
        return "unset"
    return "root" if n == 0 else ("system" if n < 1000 else "user")


def port_class(p) -> str:
    try:
        p = int(p)
    except (TypeError, ValueError):
        return "none"
    if p in (21, 22, 25, 53, 80, 443, 3306, 5432, 8080):
        return f"p{p}"
    return "well_known" if p < 1024 else ("registered" if p < 49152 else "ephemeral")


def _norm_word(w: str) -> str:
    w = w.lower()
    w = _HEX.sub("<hex>", w)
    return _NUM.sub("<n>", w)


def cmd_tokens(cmd: str, prefix: str) -> list[str]:
    """Generic Linux command-line tokens (argv0, mode, switches, argument roles, operators, inline anchors)."""
    cmd = (cmd or "").strip()
    if not cmd:
        return [f"{prefix}:empty"]
    out = []
    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError:
        argv = cmd.split()
        out.append(f"{prefix}:parse=fallback")
    if not argv:
        return [f"{prefix}:empty"]
    a0 = base(argv[0])
    out.append(f"{prefix}:argv0={a0}")
    out.append(f"{prefix}:argc={min(len(argv) - 1, 6)}")
    inline = None
    if a0 in SHELLS and "-c" in argv:
        out.append(f"{prefix}:mode=shell_c")
        i = argv.index("-c")
        inline = " ".join(argv[i + 1:])
    elif a0 in INTERP:
        if any(x in ("-c", "-e", "-r", "-E") for x in argv[1:]):
            out.append(f"{prefix}:mode=interp_inline")
            inline = " ".join(argv[1:])
        elif any(x == "-" for x in argv[1:]):
            out.append(f"{prefix}:mode=interp_stdin")
        elif len(argv) > 1 and not argv[1].startswith("-"):
            out.append(f"{prefix}:mode=interp_script:{path_cat(argv[1])}")
    if len(cmd) > 256:
        out.append(f"{prefix}:long")
    for a in argv[1:24]:
        if a.startswith("-") and len(a) <= 24:
            out.append(f"{prefix}:sw={_norm_word(a.split('=')[0])}")
        elif re.match(r"^[a-z]+://", a, re.I):
            out.append(f"{prefix}:arg=url")
        elif _IP.match(a):
            out.append(f"{prefix}:arg=ip")
        elif _B64.match(a):
            out.append(f"{prefix}:arg=blob")
        elif a.startswith(("/", "~", "./", "../")):
            out.append(f"{prefix}:arg_path={path_cat(a)}")
        elif "*" in a or "?" in a:
            out.append(f"{prefix}:arg=glob")
    text = inline if inline is not None else cmd
    for op, name in OPS:
        if op in text:
            out.append(f"{prefix}:op={name}")
    if inline is not None:
        try:
            inner = shlex.split(inline, posix=True)
        except ValueError:
            inner = inline.split()
        if inner:
            out.append(f"{prefix}:inline_argv0={base(inner[0])}")
        low = inline.lower()
        for an in ANCHORS:
            if re.search(r"(?<![a-z_])" + re.escape(an) + r"(?![a-z_])", low):
                out.append(f"{prefix}:anchor={an}")
        for w in re.findall(r"(?:^|\s)(/[^\s'\";|&<>]+)", inline):
            out.append(f"{prefix}:inline_path={path_cat(w)}")
        if re.search(r"[A-Za-z0-9+/=]{60,}", inline):
            out.append(f"{prefix}:inline_blob")
    return out


# ---------------------------------------------------------------- tracker
class LinuxContextTracker:
    """Per-host causal state. `tokens(e)` uses only evidence strictly before e; call `observe(e)` afterwards."""

    def __init__(self, with_scope: bool = False, recent: int = 4):
        self.with_scope = with_scope
        self.recent = recent
        self.p = {}            # pid -> dict(exe, cmd, uid, auid, ses, ppid, first, last, acts)
        self.ses = {}          # ses -> dict(start, origin, acct, scope, sudo, n_cmd)
        self.incoming = defaultdict(lambda: deque(maxlen=8))  # pid -> deque of (t, kind, src_exe)

    # ---- helpers
    def _proc(self, pid):
        return self.p.get(pid) if pid is not None else None

    def _ctx_proc(self, role, pr, t):
        if pr is None:
            return [f"ctx:{role}:unseen"]
        out = [f"ctx:{role}:exe={base(pr['exe'])}", f"ctx:{role}:path={path_cat(pr['exe'])}",
               f"ctx:{role}:uid={uid_class(pr['uid'])}", f"ctx:{role}:age={age_bucket((t - pr['first']) / 1e6)}"]
        if pr["cmd"]:
            out += [x.replace(f"{role}cmd:", f"ctx:{role}:cmd:") for x in cmd_tokens(pr["cmd"], f"{role}cmd")
                    if ":sw=" not in x and ":argc=" not in x]
        out += [f"ctx:{role}:recent={a}" for a in list(pr["acts"])[-self.recent:]]
        return out

    # ---- tokens for one event (before observe)
    def tokens(self, e) -> list[str]:
        t, k, pid, ppid = e["ts"], e["kind"], e["pid"], e["ppid"]
        sc = e["syscall"]
        out = [f"kind={k}"]
        if k == "auth":
            out += [f"auth:type={e['tpath']}", f"auth:op={(e['cmd'] or '').split(' ')[0]}",
                    f"auth:exe={base(e['image'])}", f"auth:acct={uid_class(e['user'])}"]
            if self.with_scope:
                out.append(f"auth:src_scope={ip_scope(e['rip'])}")
            if e["tpath"] == "USER_CMD":
                out += [x.replace("sudocmd:", "auth:cmd:") for x in cmd_tokens(" ".join((e["cmd"] or "").split(" ")[1:]), "sudocmd")]
        else:
            out.append(f"syscall={sc}")
            out.append(f"exe={base(e['image'])}")
            out.append(f"exe_path={path_cat(e['image'])}")
            out.append(f"uid={uid_class(e['uid'])}")
            out.append(f"auid={uid_class(e['auid'])}")
            if uid_class(e["uid"]) == "root" and uid_class(e["auid"]) == "user":
                out.append("escalated=true")
            if k == "procstart":
                out += cmd_tokens(e["cmd"], "cmd")
            elif k == "netconn":
                out += [f"net:dir={'out' if e['outbound'] else 'in'}", f"net:port={port_class(e['rport']) if e['outbound'] else 'peer'}"]
                if self.with_scope:
                    out.append(f"net:scope={ip_scope(e['rip'])}")
            elif k in ("filemod", "fileread"):
                out.append(f"file:path={path_cat(e['tpath'])}")
            elif k == "privchange":
                out.append(f"priv:syscall={sc}")
            elif k == "crossproc":
                out.append(f"xp:syscall={sc}")
        # actor (the process itself, before this event) and parent / grandparent
        actor = self._proc(pid)
        if k == "procstart":
            # the exec'ing pid's previous image (fork-without-exec parent copy) is the actor before exec
            par = self._proc(ppid)
            out += self._ctx_proc("parent", par, t)
            gp = self._proc(par["ppid"]) if par else None
            out.append(f"ctx:gparent:exe={base(gp['exe']) if gp else '<unseen>'}")
            if par:
                out.append(f"ctx:lineage={base(par['exe'])}>{base(e['image'])}")
        else:
            out += self._ctx_proc("actor", actor, t)
            par = self._proc(ppid)
            out.append(f"ctx:parent:exe={base(par['exe']) if par else '<unseen>'}")
            if par and par["cmd"]:
                out += [x.replace("pcmd:", "ctx:parent:cmd:") for x in cmd_tokens(par["cmd"], "pcmd")
                        if ":mode=" in x or ":anchor=" in x or ":argv0=" in x or ":inline_blob" in x]
        # incoming: ptrace/kill into this process
        for (ti, kind, src) in self.incoming.get(pid, ()):
            if t - ti <= 3600e6:
                out += [f"ctx:incoming:{kind}=true", f"ctx:incoming:{kind}:src={src}"]
        # incoming: the login session (audit ses) the event belongs to
        s = e["ses"]
        if s is None or s != s or int(s) == UNSET:
            out.append("ctx:session=none")
        else:
            ss = self.ses.get(int(s))
            if ss is None:
                out.append("ctx:session=unseen")
            else:
                out += [f"ctx:session:origin={ss['origin']}", f"ctx:session:acct={ss['acct']}",
                        f"ctx:session:age={age_bucket((t - ss['start']) / 1e6)}",
                        f"ctx:session:sudo={'yes' if ss['sudo'] else 'no'}",
                        f"ctx:session:n_cmd={min(ss['n_cmd'], 5)}"]
                if self.with_scope:
                    out.append(f"ctx:session:src_scope={ss['scope']}")
        return out

    # ---- state update (after tokens)
    def observe(self, e):
        t, k, pid, ppid = e["ts"], e["kind"], e["pid"], e["ppid"]
        if pid is not None:
            pr = self.p.get(pid)
            if pr is None or (k == "procstart" and pr["exe"] and pr["exe"] != e["image"] and pr.get("ppid") != ppid):
                pr = self.p[pid] = dict(exe="", cmd="", uid=e["uid"], auid=e["auid"], ses=e["ses"], ppid=ppid, first=t, last=t,
                                        acts=deque(maxlen=8))
            if e["image"] and k != "auth":
                pr["exe"] = e["image"]
            if k == "procstart":
                pr["cmd"] = e["cmd"] or pr["cmd"]
                if ppid is not None and ppid in self.p:
                    self.p[ppid]["acts"].append(f"spawn:{base(e['image'])}")
            if ppid is not None:
                pr["ppid"] = ppid
            pr["uid"], pr["auid"], pr["ses"], pr["last"] = e["uid"], e["auid"], e["ses"], t
            if k not in ("procstart", "auth", "other"):
                pr["acts"].append(k if k != "netconn" else f"net_{'out' if e['outbound'] else 'in'}")
        if k == "crossproc" and e.get("tpid") is not None:
            self.incoming[e["tpid"]].append((t, f"sc{e['syscall']}", base(e["image"])))
        s = e["ses"]
        if k == "auth" and s is not None and s == s and int(s) != UNSET:
            s = int(s)
            ss = self.ses.get(s)
            if ss is None:
                ss = self.ses[s] = dict(start=t, origin=base(e["image"]), acct=uid_class(e["user"]),
                                        scope=ip_scope(e["rip"]), sudo=False, n_cmd=0)
            if base(e["image"]) == "sudo" or e["tpath"] == "USER_CMD":
                ss["sudo"] = True
        if k == "procstart" and s is not None and s == s and int(s) != UNSET and int(s) in self.ses:
            self.ses[int(s)]["n_cmd"] += 1
