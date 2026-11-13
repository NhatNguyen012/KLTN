#!/usr/bin/env python3
"""AInception step 2, version 2: attack labels + per-process stage, fixing the gaps found in relabel_v1.

Changes vs relabel.py (v1):
  * Lore clock. Lore writes CET local time (UTC+1, no zone); hosts log UTC. v1 (and the released coarse labels)
    read Lore times as UTC, so every action window was one hour late. Lore times are shifted by -60 min here;
    report.json:clock lists the per-variant check (C2 session active_since vs first EID 3 to the same endpoint).
    AttackMate (SL700) already logs UTC.
  * Attacker endpoints come from each Lore log (external tunnel/source IPs, incl. the vehicle 192.168.2.11 that
    runs the Impacket entry). No hand-configured implant: it is reached by lineage from the seeds below.
  * Windows seeds (in addition to v1's netconn-to-attacker):
      - processes whose Sysmon LogonId is a logon from an attacker IP (4624 TargetLogonId) -> wmiexec children;
      - the service binary installed by such a logon (4697 SubjectLogonId -> ServiceFileName, started by
        services.exe) -> Impacket/Metasploit psexec and Meterpreter getsystem;
      - logons from a host that already has a Lore C2 session, during a Lore lateral action on this host
        (exploit/*, psexec, wmiexec), user accounts only -> lateral psexec to dc;
      - shell/LOLBin children of an exploited network service (java.exe ...) during a Lore exploit on this host.
    An exploited long-running service process itself is not marked (it keeps serving benign traffic); only its
    connections to attacker endpoints are.
  * Injection: only Sysmon 8 (CreateRemoteThread) propagates (v1 also used 10 = ProcessAccess, which would mark
    lsass after a credential dump). A target created <= 5 s before the injection (hollowing) is attack from its start.
  * pid attribution (v1: any event with a pid) is accepted only when the event's image matches the Sysmon process
    (pids are reused; Sysmon skips conhost and some svchost). A 4688 without a match is labelled through its
    creator (attr='parent').
  * Events without ProcessGuid: PowerShell 4103/4104 via winlog pid, 400/403/600/800 via HostApplication,
    service install 7045/4697/7009 via the service binary, 4624/4634/4672 of attacker logons. The rest keep
    attr='none' so the dataset builder can drop them (lineage cannot label them).
  * Lore 'Remote connection established via Impacket ...' entries carry the wiper's tactics (TA0040/TA0011,
    T1485/T1561/T1486) in every variant; they are re-tagged Initial Access.
  * stage, per process (as REAPr does for ATLASv2): 1 Initial_Compromise, 2 Execution_Discovery,
    3 Lateral_Movement, 4 Exfiltration, 5 Impact (new; not in ATLASv2), 0 benign.
      - first victim (target of the Impacket entry / SL700 victim): IC = initial-access seeds within 30 s of the
        first attacker logon and their descendants started <= 60 s after their parent, or processes started in
        an Initial Access action window; Impact/Exfiltration by action window; otherwise ED;
      - any other compromised host: LM (Impact by window);
      - SL300 Impact payload (IMPACT_IMAGES, see note there) and its descendants: Impact on any host.
Writes output/relabel_v2/<scenario>/events.parquet and report.json.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapters as A  # noqa: E402
import relabel as R  # noqa: E402

X = Path("/mnt/SSD_Data/optc/DATASET/AInception/extracted")
OUT = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2")
V1 = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v1")
LORE_UTC_OFFSET_US = 60 * 60 * 1_000_000
SLACK_US = R.SLACK_US
SEC = 1_000_000
INTERNAL = ("192.168.3.", "192.168.4.")          # BnHQ client and server segments
STAGES = {0: "Benign", 1: "Initial_Compromise", 2: "Execution_Discovery", 3: "Lateral_Movement",
          4: "Exfiltration", 5: "Impact"}
SERVICE_PARENTS = {"java.exe", "javaw.exe", "w3wp.exe", "httpd.exe", "tomcat9.exe", "sqlservr.exe"}
LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
           "bitsadmin.exe", "wscript.exe", "cscript.exe"}
LATERAL_KEYS = ("exploit/", "psexec", "wmiexec", "lateral")
# SL300 Impact has no Lore action of its own: the Impact techniques (T1485/T1561/T1486) sit on the Impacket entry.
# The payload that carries them out is C:\Temp\lucifer_ransomware.exe, started by the Meterpreter on apps
# (v2 12:23:42, v4 08:52:02, v5 08:53:38 UTC). Stage-only rule: it and its descendants get stage Impact.
IMPACT_IMAGES = {"lucifer_ransomware.exe"}
HOSTAPP = re.compile(r"HostApplication=([^\r\n]*)")
SL300_VARIANTS = (2, 4, 5, 7)
SL700_RUNS = ("a_a", "a_b", "a_c", "b_a", "e_a", "f_a")
base = R.base


def norm(s):
    return " ".join((s or "").lower().split())


def is_ip(s):
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s or ""))


# ------------------------------------------------------------------ SL300 helpers
def sl300_ipmap():
    """IP -> short host name from the ansible facts of any SL300 variant (networks identical except names)."""
    ipmap = {"192.168.4.12": "media", "192.168.4.20": "apps", "192.168.4.22": "monitor", "192.168.4.5": "dc"}
    for f in sorted(X.glob("SL300_v*/variant*/cyber_terrain/facts_files/*.fact")):
        try:
            d = json.load(open(f))
        except ValueError:
            continue
        facts = d.get("ansible_facts", d)
        for ip in facts.get("all_ipv4_addresses") or facts.get("ansible_all_ipv4_addresses") or []:
            if ip.startswith(INTERNAL):
                ipmap.setdefault(ip, f.name.split(".")[0])
    return ipmap


def _host_of(v):
    v = v.get("host") if isinstance(v, dict) else v
    return str(v) if v else ""


def load_lore_v2(path, ipmap):
    acts = json.load(open(path))
    acts = acts if isinstance(acts, list) else list(acts.values())[0]
    out, attacker, retagged = [], set(), 0
    for a in acts:
        ci, ai = a.get("c2_info") or {}, a.get("action_info") or {}
        src, tgt = _host_of(ai.get("source")), _host_of(ai.get("target"))
        for ep in (ci.get("tunnel_local"), ci.get("tunnel_peer")):
            ip = str(ep or "").rsplit(":", 1)[0]
            if is_ip(ip) and not ip.startswith(INTERNAL):
                attacker.add(ip)
        if is_ip(src) and not src.startswith(INTERNAL):
            attacker.add(src)
        uid, cat, desc = a.get("action_uid") or "", a.get("action_category") or "", a.get("action_description") or ""
        tactics = A.tactic_names((a.get("mitre_att&ck") or {}).get("tactics"))
        impacket = cat == "Manual Exploit" and "impacket" in desc.lower()
        if impacket:
            tactics, retagged = ["Initial Access"], retagged + 1
        lateral = impacket or any(k in (uid + " " + cat + " " + desc).lower() for k in LATERAL_KEYS)
        exploit = uid.startswith("exploit/") or impacket
        host = (ipmap.get(tgt) if exploit else None) or ipmap.get(ci.get("session_host")) or ipmap.get(tgt)
        since = A.iso_us(ci["active_since"]) - LORE_UTC_OFFSET_US if ci.get("active_since") else None
        out.append(dict(start=A.iso_us(a["time_start"]) - LORE_UTC_OFFSET_US, end=A.iso_us(a["time_end"]) - LORE_UTC_OFFSET_US,
                        host=host, uid=uid or cat, category=cat, desc=desc[:200], tactics=tactics,
                        outcome=a.get("action_outcome"), impacket=impacket, exploit=exploit, lateral=lateral,
                        target=ipmap.get(tgt, tgt), session=ipmap.get(ci.get("session_host"), ci.get("session_host")),
                        tunnel_local=ci.get("tunnel_local"), active_since=since, src=src))
    return sorted(out, key=lambda x: x["start"]), attacker, retagged


def iter_windows_v2(path, host):
    """adapters.parse_windows_record + LogonId, service, PowerShell attribution fields."""
    with open(path) as fh:
        for i, line in enumerate(fh):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if (r.get("agent") or {}).get("type") != "winlogbeat":
                continue
            e = A.parse_windows_record(r, i, host)
            wl = r.get("winlog") or {}
            ed = wl.get("event_data") or {}
            prov = (r.get("event") or {}).get("provider") or ""
            c = e["code"]
            e.update(provider=prov, logon_id=None, svc_name="", svc_path="", hostapp="",
                     wpid=(wl.get("process") or {}).get("pid"), attr="none", sec_parent=None)
            if e["src"] == "sysmon" and c == "1":
                e["logon_id"] = (ed.get("LogonId") or "").lower() or None
            elif e["src"] == "security" and c in ("4624", "4634"):
                e["logon_id"] = (ed.get("TargetLogonId") or "").lower() or None
            elif e["src"] == "security" and c == "4672":
                e["logon_id"] = (ed.get("SubjectLogonId") or "").lower() or None
            elif e["src"] == "security" and c == "4697":
                e.update(logon_id=(ed.get("SubjectLogonId") or "").lower() or None, svc_name=ed.get("ServiceName") or "",
                         svc_path=ed.get("ServiceFileName") or "")
            elif c == "7045":
                e.update(svc_name=ed.get("ServiceName") or "", svc_path=ed.get("ImagePath") or "")
            elif c == "7009":
                e["svc_name"] = ed.get("param2") or ""
            if "PowerShell" in prov and c in ("400", "403", "600", "800"):
                m = HOSTAPP.search(r.get("message") or "")
                e["hostapp"] = m.group(1).strip() if m else ""
            yield e


def _svc_binary(path):
    p = (path or "").strip().strip('"')
    p = re.sub(r"(?i)%systemroot%|%windir%", r"C:\\Windows", p)
    p = re.sub(r"(?i)%comspec%", r"C:\\Windows\\system32\\cmd.exe", p)
    return p


def relabel_windows_v2(events, actions, host, attacker_ips, session_hosts, ip_of):
    procs, pid_index = {}, defaultdict(list)
    for e in events:
        if e["src"] == "sysmon" and e["kind"] == "procstart" and e["guid"]:
            procs[e["guid"]] = e
            pid_index[e["pid"]].append((e["ts"], e["guid"]))
    for v in pid_index.values():
        v.sort()
    starts = {p: [s for s, _ in v] for p, v in pid_index.items()}

    def guid_of(pid, ts):
        lst = pid_index.get(pid)
        if not lst:
            return None
        i = bisect_right(starts[pid], ts + 2 * SEC) - 1
        return lst[i][1] if i >= 0 else None

    # ---- attribution of events that carry no ProcessGuid
    by_cmd = defaultdict(list)
    for g, p in procs.items():
        by_cmd[norm(p["cmd"])].append((p["ts"], g))
    svc_proc = {}                                   # service name -> guid of the process the service started
    for e in events:
        if e["code"] in ("7045", "4697") and e["svc_name"] and e["svc_name"] not in svc_proc:
            b = _svc_binary(e["svc_path"])
            cands = [(p["ts"], g) for g, p in procs.items() if 0 <= p["ts"] - e["ts"] <= 120 * SEC
                     and base(p["pimage"]) == "services.exe"
                     and (norm(p["image"]) == norm(b) or (b and norm(b) in norm(p["cmd"]))
                          or (p["cmd"] and norm(p["cmd"]) in norm(b)))]
            if cands:
                svc_proc[e["svc_name"]] = min(cands)[1]
    for e in events:
        if e["guid"]:
            e["attr"] = "process"
            continue
        if e["svc_name"] in svc_proc and e["code"] in ("7045", "4697", "7009"):
            e["guid"], e["attr"] = svc_proc[e["svc_name"]], "service"
            continue
        if "PowerShell" in e["provider"]:
            if e["code"] in ("4103", "4104") and e["wpid"] is not None:
                e["pid"] = e["wpid"]
            elif e["hostapp"]:
                c = [(t, g) for t, g in by_cmd.get(norm(e["hostapp"]), []) if 0 <= e["ts"] - t <= 120 * SEC]
                if c:
                    e["guid"], e["attr"] = max(c)[1], "hostapp"
                    continue
        if e["pid"] is not None:
            g = guid_of(e["pid"], e["ts"])
            # pids are reused and Sysmon does not log every process (SwiftOnSecurity skips conhost, some svchost):
            # accept the pid match only when the event's own image agrees with the Sysmon process
            if g and (not e["image"] or e["image"] == "-" or base(e["image"]) == base(procs[g]["image"])):
                e["guid"], e["attr"] = g, "pid"
            elif e["code"] == "4688" and e["ppid"] is not None:
                pg = guid_of(e["ppid"], e["ts"])
                if pg and base(e["pimage"]) == base(procs[pg]["image"]):
                    e["sec_parent"] = pg          # labelled through its creator in finish_events

    # ---- attacker logons: from an external attacker IP, or (during a Lore lateral action on this host) from a host
    #      that already holds a Lore C2 session; user accounts only for the latter
    lat = [a for a in actions if a["lateral"] and a["target"] == host]
    att_logons, first_att_logon = {}, None
    for e in events:
        if e["code"] != "4624" or not e["logon_id"]:
            continue
        why = None
        if e["rip"] in attacker_ips:
            why = f"logon from attacker {e['rip']}"
        else:
            src = ip_of.get(e["rip"])
            since = session_hosts.get(src)
            u = (e["user"] or "")
            if since is not None and e["ts"] >= since - SLACK_US and not u.endswith("$") and u.upper() != "ANONYMOUS LOGON" \
                    and any(a["start"] - SLACK_US <= e["ts"] <= a["end"] + SLACK_US for a in lat):
                why = f"logon from compromised {src} during lateral action"
        if why:
            att_logons.setdefault(e["logon_id"], (e["ts"], why))
            if e["rip"] in attacker_ips:
                first_att_logon = e["ts"] if first_att_logon is None else min(first_att_logon, e["ts"])

    attack_from, reason, kind = {}, {}, {}

    def mark(g, t, why, k):
        if g and (g not in attack_from or t < attack_from[g]):
            attack_from[g] = t
            reason.setdefault(g, why)
            kind.setdefault(g, k)

    exp = [a for a in actions if a["exploit"] and a["host"] == host]
    for e in events:
        # an exploited long-running service (ActiveMQ java.exe fetching the attacker's XML) keeps serving benign
        # traffic: label that connection (finish_events) and the children spawned during the exploit, not the process
        if e["kind"] == "netconn" and e["rip"] in attacker_ips and base(e["image"]) not in SERVICE_PARENTS:
            mark(e["guid"], procs.get(e["guid"], e)["ts"], f"netconn to attacker {e['rip']}:{e['rport']}", "c2")
        if e["code"] == "4697" and e["logon_id"] in att_logons and e["svc_name"] in svc_proc:
            g = svc_proc[e["svc_name"]]
            mark(g, procs[g]["ts"], f"service {e['svc_name']} installed by {att_logons[e['logon_id']][1]}", "logon")
    for g, p in procs.items():
        if p["logon_id"] in att_logons:
            mark(g, p["ts"], f"runs under {att_logons[p['logon_id']][1]} (parent {base(p['pimage'])})", "logon")
        if base(p["pimage"]) in SERVICE_PARENTS and base(p["image"]) in LOLBINS and \
                any(a["start"] - SLACK_US <= p["ts"] <= a["end"] + SLACK_US for a in exp):
            mark(g, p["ts"], f"{base(p['image'])} spawned by {base(p['pimage'])} during exploit action", "exploit")
    changed = True
    while changed:
        changed = False
        written = {}
        for e in events:
            g = e["guid"]
            if g in attack_from and e["ts"] >= attack_from[g] and e["kind"] == "filemod" and e["tpath"]:
                written.setdefault(e["tpath"].lower(), e["ts"])
        for e in sorted(events, key=lambda x: x["ts"]):
            g = e["guid"]
            if e["kind"] == "procstart" and e["src"] == "sysmon" and g not in attack_from:
                pg = e["pguid"]
                if pg in attack_from and e["ts"] >= attack_from[pg]:
                    mark(g, e["ts"], "child of attack process", "child"); changed = True
                elif e["image"].lower() in written and e["ts"] >= written[e["image"].lower()]:
                    mark(g, e["ts"], "executes file written by attack process", "dropped"); changed = True
            if e["code"] == "8" and g in attack_from and e["ts"] >= attack_from[g] and e["tguid"] and e["tguid"] not in attack_from:
                tp = procs.get(e["tguid"])
                t = tp["ts"] if tp and 0 <= e["ts"] - tp["ts"] <= 5 * SEC else e["ts"]
                mark(e["tguid"], t, f"injection target of {base(e['image'])}", "inject"); changed = True
    return procs, attack_from, reason, kind, att_logons, first_att_logon


def window_has(actions, host, ts, tactic, any_host=False):
    return any((any_host or a["host"] == host) and tactic in a["tactics"] and
               a["start"] - SLACK_US <= ts <= a["end"] + SLACK_US for a in actions)


def stage_of_procs(procs_start, parent, attack_from, kind, first_victim, host, actions, ia_cut, images=None):
    """Per-process stage. procs_start: key -> start ts; parent: key -> parent key; images: key -> image basename."""
    st, ic, impact = {}, set(), set()
    for k in sorted(attack_from, key=lambda k: procs_start.get(k, attack_from[k])):
        if (images or {}).get(k) in IMPACT_IMAGES or parent.get(k) in impact:
            impact.add(k)
    if host == first_victim:
        roots = {k for k, kd in kind.items() if kd in ("logon", "c2", "exploit") and ia_cut is not None
                 and attack_from[k] <= ia_cut}
        ic |= roots
        for k in sorted(attack_from, key=lambda k: attack_from[k]):
            p = parent.get(k)
            if p in ic and 0 <= procs_start.get(k, attack_from[k]) - procs_start.get(p, attack_from[p]) <= 60 * SEC:
                ic.add(k)
    for k in attack_from:
        t = procs_start.get(k, attack_from[k])
        if k in impact or window_has(actions, host, t, "Impact"):
            st[k] = 5
        elif window_has(actions, host, t, "Exfiltration"):
            st[k] = 4
        elif host != first_victim:
            st[k] = 3
        elif k in ic or window_has(actions, host, t, "Initial Access"):
            st[k] = 1
        else:
            st[k] = 2
    return st


def finish_events(events, keyf, attack_from, stages, actions, attacker_ips, extra_attack=None, tol_attr=()):
    for e in events:
        k = keyf(e)
        tol = 120 * SEC if e.get("attr") in tol_attr else 0
        is_att = k in attack_from and e["ts"] >= attack_from[k] - tol
        st = stages.get(k, 0) if is_att else 0
        if not is_att and extra_attack is not None:
            ex = extra_attack(e)
            if ex:
                is_att, st = True, ex
        e["y"] = int(is_att)
        e["stage"] = st if is_att else 0
        tac = ()
        if is_att:
            if e["kind"] == "netconn" and e["rip"] in attacker_ips:
                tac = ("Command and Control",)
            else:
                a = R.tactic_for(actions_by_host(actions), e["host"], e["ts"])
                tac = tuple(a["tactics"]) if a else (("Initial Access",) if e["stage"] == 1 else ("UNATTRIBUTED",))
        e["tactics"] = tac


_ABH = {}


def actions_by_host(actions):
    key = id(actions)
    if key not in _ABH:
        d = defaultdict(list)
        for a in actions:
            d[a["host"]].append(a)
        _ABH[key] = d
    return _ABH[key]


def clock_anchors(actions, first_conn):
    rows = []
    for a in actions:
        tl = a["tunnel_local"]
        if a["active_since"] is None or not tl or not a["session"]:
            continue
        hc = first_conn.get((a["session"], tl))
        if hc is not None:
            rows.append(dict(host=a["session"], endpoint=tl, lore_since_utc=pd.to_datetime(a["active_since"], unit="us").isoformat(),
                             host_first_eid3=pd.to_datetime(hc, unit="us").isoformat(),
                             residual_s=round((a["active_since"] - hc) / SEC, 1)))
    uniq = {(r["host"], r["endpoint"]): r for r in rows}
    return list(uniq.values())


# ------------------------------------------------------------------ scenario runners
def run_sl300(v):
    name = f"SL300_v{v}"
    D = X / name / f"variant{v}"
    ipmap = sl300_ipmap()
    ip_of = dict(ipmap)
    actions, attacker_ips, retagged = load_lore_v2(D / f"attack_log/sl300_{v}.json", ipmap)
    first_victim = next((a["target"] for a in actions if a["impacket"]), "media")
    session_hosts = {}
    for a in actions:
        if a["session"] and a["active_since"] is not None:
            session_hosts[a["session"]] = min(session_hosts.get(a["session"], a["active_since"]), a["active_since"])
    session_hosts.setdefault(first_victim, min(a["start"] for a in actions))
    files = sorted((D / f"labelled_logs/bnhq{v}/attack").glob("*.ecslogs"))
    frames, report = [], {"scenario": name, "lore_utc_offset_min": 60, "attacker_ips": sorted(attacker_ips),
                          "first_victim": first_victim, "impacket_entries_retagged": retagged,
                          "session_hosts": {k: pd.to_datetime(t, unit="us").isoformat() for k, t in session_hosts.items()},
                          "n_actions": len(actions), "hosts": {}}
    first_conn, all_ev_for_cov = {}, []
    for f in files:
        host = f.name.split(".")[0]
        ev = list(iter_windows_v2(f, host))
        if not ev:
            continue                                  # Linux host (filebeat) -> not relabelled in v2
        for e in ev:
            if e["kind"] == "netconn" and e["rport"] is not None:
                k = (host, f"{e['rip']}:{e['rport']}")
                first_conn[k] = min(first_conn.get(k, e["ts"]), e["ts"])
        procs, af, reason, kind, att_logons, first_att = relabel_windows_v2(ev, actions, host, attacker_ips, session_hosts, ip_of)
        ia_cut = first_att + 30 * SEC if first_att is not None else None
        pstart = {g: p["ts"] for g, p in procs.items()}
        parent = {g: p["pguid"] for g, p in procs.items()}
        stages = stage_of_procs(pstart, parent, af, kind, first_victim, host, actions, ia_cut,
                                {g: base(p["image"]) for g, p in procs.items()})
        lstage = 1 if host == first_victim else 3

        def extra(e, att_logons=att_logons, lstage=lstage, ia_cut=ia_cut, af=af, stages=stages):
            if e["sec_parent"] in af and e["ts"] >= af[e["sec_parent"]]:   # 4688 of a child Sysmon did not log
                e["attr"] = "parent"
                return stages[e["sec_parent"]]
            if e["code"] in ("4624", "4634", "4672") and e["logon_id"] in att_logons and e["ts"] >= att_logons[e["logon_id"]][0] - SEC:
                e["attr"] = "logon"
                return lstage
            if e["kind"] == "netconn" and e["rip"] in attacker_ips:      # connection of an exploited service process
                return 3 if lstage == 3 else (1 if ia_cut is not None and e["ts"] <= ia_cut else 2)
            return 0
        finish_events(ev, lambda e: e["guid"], af, stages, actions, attacker_ips, extra, tol_attr=("service",))
        df = pd.DataFrame(ev)
        att = df[df.y == 1]
        rep = {"events": int(len(df)), "coarse_attack": int(df.coarse_mal.sum()), "attack": int(len(att)),
               "both": int(((df.coarse_mal == 1) & (df.y == 1)).sum()),
               "coarse_only": int(((df.coarse_mal == 1) & (df.y == 0)).sum()),
               "new_only": int(((df.coarse_mal == 0) & (df.y == 1)).sum()),
               "attr": df.attr.value_counts().to_dict(),
               "attack_processes": len(af), "attacker_logons": len(att_logons),
               "stage_events": {STAGES[k]: int(n) for k, n in att.stage.value_counts().sort_index().items()},
               "stage_processes": {STAGES[k]: int(n) for k, n in Counter(stages.values()).items()},
               "tactics": Counter(t for ts in att.tactics for t in ts).most_common(),
               "top_attack_images": att.image.map(base).value_counts().head(15).to_dict(),
               "seed_kinds": dict(Counter(kind.values())),
               "attack_process_reasons": {g[:38]: f"{reason[g]} | {base(procs[g]['image']) if g in procs else '?'} | "
                                                  f"{STAGES[stages[g]]}" for g in list(reason)[:300]}}
        if len(att):
            rep["attack_span"] = [pd.to_datetime(att.ts.min(), unit="us").isoformat(), pd.to_datetime(att.ts.max(), unit="us").isoformat()]
        report["hosts"][host] = rep
        if len(af) or rep["coarse_attack"]:
            print(name, host, {k: rep[k] for k in ("events", "coarse_attack", "attack", "attack_processes", "stage_processes")}, flush=True)
        frames.append(df)
        all_ev_for_cov.append(df[df.y == 1][["host", "ts"]])
    report["clock"] = clock_anchors(actions, first_conn)
    return name, frames, report, actions, all_ev_for_cov


def run_sl700(r):
    name = f"SL700_{r}"
    base_dir = X / name / f"run_{r}"
    am = next(base_dir.glob("*_labeled/*/gather/attacker/logs/attackmate.json"))
    cfg = dict(attack_log=am, victim="videoserver", attacker_ips={"192.42.1.174"})
    actions = R.load_attackmate(cfg)
    for a in actions:
        a.update(exploit=False, lateral=False, target=a["host"])
    frames, report = [], {"scenario": name, "attacker_ips": sorted(cfg["attacker_ips"]), "first_victim": "videoserver",
                          "n_actions": len(actions), "hosts": {}, "clock": "AttackMate logs UTC (first msf-module vs first attacker connection ~20 s)"}
    cov = []
    for h in ("videoserver", "corpdns", "inetfw", "webcam"):
        raw = next(base_dir.glob(f"attack_{r}/mnt/attack_{r}/gather/{h}/logs/log/audit/audit.log"), None)
        lab = next(base_dir.glob(f"attack_{r}_labeled/attack_{r}/gather/{h}/logs/log/audit/audit.log.json"), None)
        if raw is None:
            continue
        idx = A.coarse_index_from_labelled_json(lab) if lab else None
        ev = list(A.iter_auditd_raw(raw, h, idx))
        lo = actions[0]["start"] - 3 * 3_600 * SEC
        ev = [e for e in ev if e["ts"] >= lo]
        for e in ev:
            e.update(provider="auditd", logon_id=None, svc_name="", svc_path="", hostapp="", wpid=None,
                     attr="process" if e["pid"] is not None else "none")
        af, reason, ses = R.relabel_linux(ev, actions, cfg, h)
        first_seen, parent = {}, {}
        for e in ev:
            if e["pid"] is not None:
                first_seen.setdefault(e["pid"], e["ts"])
                if e["ppid"] is not None:
                    parent.setdefault(e["pid"], e["ppid"])
        kind = {p: ("c2" if "attacker" in reason.get(p, "") else "child") for p in af}
        ia_t = min((t for p, t in af.items() if kind[p] == "c2"), default=None)
        stages = stage_of_procs(first_seen, parent, af, kind, "videoserver", h, actions,
                                ia_t + 30 * SEC if ia_t is not None else None)

        def extra(e, ses=ses):
            if e["ses"] in ses and e["ts"] >= ses[e["ses"]][0]:
                return 2
            return 0
        finish_events(ev, lambda e: e["pid"], af, stages, actions, cfg["attacker_ips"], extra)
        df = pd.DataFrame(ev)
        att = df[df.y == 1]
        rep = {"events": int(len(df)), "coarse_attack": int(df.coarse_mal.sum()), "attack": int(len(att)),
               "both": int(((df.coarse_mal == 1) & (df.y == 1)).sum()),
               "coarse_only": int(((df.coarse_mal == 1) & (df.y == 0)).sum()),
               "new_only": int(((df.coarse_mal == 0) & (df.y == 1)).sum()),
               "attack_processes": len(af),
               "stage_events": {STAGES[k]: int(n) for k, n in att.stage.value_counts().sort_index().items()},
               "stage_processes": {STAGES[k]: int(n) for k, n in Counter(stages.values()).items()},
               "tactics": Counter(t for ts in att.tactics for t in ts).most_common(),
               "top_attack_images": att.image.map(base).value_counts().head(15).to_dict(),
               "attack_sessions": {str(k): v[1] for k, v in ses.items()},
               "attack_process_reasons": {str(k): f"{v} | {STAGES[stages[k]]}" for k, v in list(reason.items())[:300]}}
        report["hosts"][h] = rep
        if len(af) or rep["coarse_attack"]:
            print(name, h, {k: rep[k] for k in ("events", "coarse_attack", "attack", "attack_processes", "stage_processes")}, flush=True)
        frames.append(df)
        cov.append(df[df.y == 1][["host", "ts"]])
    return name, frames, report, actions, cov


def compare_v1(name, df):
    p = V1 / name / "events.parquet"
    if not p.exists():
        return None
    v1 = pd.read_parquet(p, columns=["host", "line", "code", "ts", "y_new", "image"])
    m = df[["host", "line", "code", "ts", "y", "image"]].merge(v1[["host", "line", "code", "ts", "y_new"]],
                                                                on=["host", "line", "code", "ts"], how="inner")
    added, removed = m[(m.y == 1) & (m.y_new == 0)], m[(m.y == 0) & (m.y_new == 1)]
    return {"matched_events": int(len(m)), "v1_attack": int(m.y_new.sum()), "v2_attack": int(m.y.sum()),
            "added": int(len(added)), "removed": int(len(removed)),
            "added_images": added.image.map(base).value_counts().head(12).to_dict(),
            "removed_images": removed.image.map(base).value_counts().head(12).to_dict()}


def run(name):
    if name.startswith("SL300_v"):
        name, frames, report, actions, cov = run_sl300(int(name.split("_v")[1]))
    else:
        name, frames, report, actions, cov = run_sl700(name.split("SL700_")[1])
    out = OUT / name
    out.mkdir(parents=True, exist_ok=True)
    df = pd.concat(frames, ignore_index=True)
    df["coarse_tactics"] = df.coarse_tactics.map(list)
    df["tactics"] = df.tactics.map(list)
    df["stage_name"] = df.stage.map(STAGES)
    keep = [c for c in df.columns if c not in ("wpid", "hostapp", "sec_parent")]
    df[keep].to_parquet(out / "events.parquet", index=False)
    covdf = pd.concat(cov) if cov else pd.DataFrame(columns=["host", "ts"])
    ts_by_host = {h: sorted(g.ts) for h, g in covdf.groupby("host")}
    rows = []
    for a in actions:
        if not a["tactics"]:
            continue
        v = ts_by_host.get(a["host"], [])
        n = bisect_right(v, a["end"] + SLACK_US) - bisect_right(v, a["start"] - SLACK_US - 1)
        rows.append(dict(start_utc=pd.to_datetime(a["start"], unit="us").isoformat(), host=a["host"], action=a["uid"],
                         tactics=a["tactics"], outcome=a.get("outcome"), host_attack_events=n))
    report["action_coverage"] = rows
    report["actions_with_host_evidence"] = f"{sum(r['host_attack_events'] > 0 for r in rows)}/{len(rows)}"
    report["totals"] = {"events": int(len(df)), "attack": int(df.y.sum()),
                        "stage_events": {STAGES[k]: int(n) for k, n in df[df.y == 1].stage.value_counts().sort_index().items()},
                        "attr": df.attr.value_counts().to_dict()}
    report["vs_relabel_v1"] = compare_v1(name, df)
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False))
    print(name, "DONE", report["totals"], "evidence", report["actions_with_host_evidence"], flush=True)
    return name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=",".join([f"SL300_v{v}" for v in SL300_VARIANTS] + [f"SL700_{r}" for r in SL700_RUNS]))
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    names = a.scenarios.split(",")
    if a.workers <= 1:
        for n in names:
            run(n)
    else:
        with ProcessPoolExecutor(a.workers) as ex:
            for n in ex.map(run, names):
                pass


if __name__ == "__main__":
    main()
