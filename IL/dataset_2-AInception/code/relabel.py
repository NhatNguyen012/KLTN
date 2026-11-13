#!/usr/bin/env python3
"""AInception step 2: rebuild attack/tactic labels from the attack timeline + process lineage.

The released labelled_logs mark every event inside an attack-action time window (coarse). Here an event
is ATTACK only if it belongs to an attacker-controlled process (or login session):
  Windows (Sysmon ProcessGuid lineage, Security 4688 mapped by pid/time)
    seeds  : (a) Sysmon network connection to an attacker endpoint (from the attack log)
             (b) configured implant images with written evidence (SEEDS[...]['images'])
             (c) process started by WmiPrvSE/PSEXESVC on a target host during a remote-exec action
    spread : children (ParentProcessGuid), executables written by attack processes and later started,
             injection targets (Sysmon 8/10 source in attack set) from the injection time on
  Linux (auditd pid/ppid, login sessions)
    seeds  : connect/accept to/from an attacker IP; login sessions (ses) from an attacker IP or
             from localhost right after an attack-process ssh to 127.0.0.1:22
    spread : children by ppid (first seen after the parent became attack)
Tactic = tactics of the attack-log action on that host whose window contains the event (shortest window);
C2 connections of attack processes -> Command and Control; otherwise UNATTRIBUTED.
Writes events.parquet (canonical events + coarse + rebuilt labels) and report.json per scenario.
"""
from __future__ import annotations

import argparse
import json
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapters as A  # noqa: E402

ROOT = Path("/mnt/SSD_Data/optc/DATASET/AInception/extracted")
SL300 = ROOT / "SL300_v7/variant7"
SL700 = ROOT / "SL700_f_a/run_f_a"
SCENARIOS = {
    "SL300_v7": dict(
        kind="lore",
        attack_log=SL300 / "attack_log/sl300_7.json",
        facts_dir=ROOT.parent / "facts_SL300",  # optional, ip map falls back to IPS below
        windows={h: SL300 / f"labelled_logs/bnhq7/attack/{h}.ecslogs" for h in ("media", "apps", "dc", "hq01")},
        linux_ecs={h: SL300 / f"labelled_logs/bnhq7/attack/{h}.ecslogs" for h in ("monitor", "fw1")},
        # from cyber_terrain/facts_files (ansible facts): media .12, apps .20, monitor .22, dc .5, pv1c2 vehicle 192.168.2.11
        ips={"192.168.4.12": "media", "192.168.4.20": "apps", "192.168.4.22": "monitor", "192.168.4.5": "dc"},
        attacker_ips={"25.18.17.86", "52.41.202.17", "192.168.2.11"},
        images={"media": [{"image": r"C:\Temp\wupdate.exe",
                           "evidence": "started 08:50:39 by powershell (servicetech); svchost writes registry value "
                                       "'c:\\temp\\wupdate.exe' at 08:50:40 (persistence); enumerates local accounts "
                                       "(4798) and queries _ldap._tcp at 09:33; drops C:\\Temp\\update_2.exe; creates a "
                                       "remote thread in svchost.exe at 09:40:09. Precedes the first Lore action (09:40:13)."}]},
    ),
    "SL700_f_a": dict(
        kind="attackmate",
        attack_log=SL700 / "attack_f_a_labeled/attack_f_a/gather/attacker/logs/attackmate.json",
        audit_raw={h: SL700 / f"attack_f_a/mnt/attack_f_a/gather/{h}/logs/log/audit/audit.log"
                   for h in ("videoserver", "corpdns", "inetfw", "webcam")},
        audit_labelled={h: SL700 / f"attack_f_a_labeled/attack_f_a/gather/{h}/logs/log/audit/audit.log.json"
                        for h in ("videoserver", "corpdns", "inetfw", "webcam")},
        victim="videoserver",
        attacker_ips={"192.42.1.174"},
        images={},
    ),
}
REMOTE_EXEC_PARENTS = {"wmiprvse.exe", "psexesvc.exe"}
SLACK_US = 60_000_000


def base(p):
    return (p or "").replace("/", "\\").split("\\")[-1].lower()


# ------------------------------------------------------------------ attack timelines
def load_lore(cfg):
    acts = json.load(open(cfg["attack_log"]))
    acts = acts if isinstance(acts, list) else list(acts.values())[0]
    out = []
    for a in acts:
        ci = a.get("c2_info") or {}
        ai = a.get("action_info") or {}
        tgt = ai.get("target")
        tgt = tgt.get("host") if isinstance(tgt, dict) else tgt
        host = cfg["ips"].get(ci.get("session_host")) or cfg["ips"].get(str(tgt))
        m = a.get("mitre_att&ck") or {}
        tl = str(ci.get("tunnel_local") or "")
        bind = (cfg["ips"].get(tl.split(":")[0]), int(tl.split(":")[1])) if tl.count(":") == 1 and tl.split(":")[0] in cfg["ips"] else None
        out.append(dict(start=A.iso_us(a["time_start"]), end=A.iso_us(a["time_end"]), host=host, bind=bind,
                        uid=a.get("action_uid") or a.get("action_category"), category=a.get("action_category") or "",
                        desc=a.get("action_description") or "", tactics=A.tactic_names(m.get("tactics")),
                        outcome=a.get("action_outcome")))
    return sorted(out, key=lambda x: x["start"])


def load_attackmate(cfg):
    recs = [json.loads(l) for l in open(cfg["attack_log"]) if l.strip()]
    out = []
    for r in recs:
        md = (r.get("parameters") or {}).get("metadata") or {}
        out.append(dict(start=A.iso_us(r["start-datetime"]), end=None, host=cfg["victim"], uid=r["type"],
                        category=r["type"], desc=r.get("cmd", "")[:160], tactics=A.tactic_names([md.get("tactics", "")]),
                        outcome=None))
    out.sort(key=lambda x: x["start"])
    for i, a in enumerate(out):
        a["end"] = out[i + 1]["start"] if i + 1 < len(out) else a["start"] + 3_600_000_000
    return out


def tactic_for(actions_by_host, host, ts):
    acts = actions_by_host.get(host, [])
    # Lore actions overlap (long scans run for hours): prefer the most specific (shortest) window that
    # contains the event, then the latest start.
    best = None
    for a in acts:
        if a["start"] - SLACK_US <= ts <= a["end"] + SLACK_US and a["tactics"]:
            key = (a["end"] - a["start"], -a["start"])
            if best is None or key < best[0]:
                best = (key, a)
    return best[1] if best else None


# ------------------------------------------------------------------ Windows relabel
def relabel_windows(events, actions, cfg, host):
    procs = {}                                  # guid -> procstart event (sysmon)
    pid_index = defaultdict(list)               # pid -> [(start, guid)]
    for e in events:
        if e["src"] == "sysmon" and e["kind"] == "procstart" and e["guid"]:
            procs[e["guid"]] = e
            pid_index[e["pid"]].append((e["ts"], e["guid"]))
    for v in pid_index.values():
        v.sort()

    def guid_of(pid, ts):
        lst = pid_index.get(pid)
        if not lst:
            return None
        i = bisect_right([s for s, _ in lst], ts + 2_000_000) - 1
        return lst[i][1] if i >= 0 else None

    for e in events:                            # attach a process guid to every event that has one
        if e["guid"] is None and e["pid"] is not None:
            e["guid"] = guid_of(e["pid"], e["ts"])
    attack_from, reason = {}, {}

    def mark(g, t, why):
        if g and (g not in attack_from or t < attack_from[g]):
            attack_from[g] = t
            reason.setdefault(g, why)

    imgs = {i["image"].lower(): i["evidence"] for i in cfg["images"].get(host, [])}
    remote_acts = [a for a in actions if a["host"] == host and any(k in (a["category"] + a["desc"]).lower()
                                                                    for k in ("wmiexec", "psexec", "remote", "exploit"))]
    for e in events:
        if e["kind"] == "netconn" and e["rip"] in cfg["attacker_ips"]:
            mark(e["guid"], procs.get(e["guid"], e)["ts"], f"netconn to attacker {e['rip']}:{e['rport']}")
        if e["kind"] == "procstart" and e["src"] == "sysmon":
            if e["image"].lower() in imgs:
                mark(e["guid"], e["ts"], "configured implant image")
            if base(e["pimage"]) in REMOTE_EXEC_PARENTS and any(a["start"] - SLACK_US <= e["ts"] <= a["end"] + SLACK_US for a in remote_acts):
                mark(e["guid"], e["ts"], f"spawned by {base(e['pimage'])} during remote-exec action")
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
                    mark(g, e["ts"], "child of attack process"); changed = True
                elif e["image"].lower() in written and e["ts"] >= written[e["image"].lower()]:
                    mark(g, e["ts"], "executes file written by attack process"); changed = True
            if e["kind"] == "crossproc" and g in attack_from and e["ts"] >= attack_from[g] and e["tguid"] and e["tguid"] not in attack_from:
                mark(e["tguid"], e["ts"], f"injection target of {base(e['image'])}"); changed = True
    return attack_from, reason


# ------------------------------------------------------------------ Linux relabel
def relabel_linux(events, actions, cfg, host):
    attack_from, reason, attack_ses = {}, {}, {}

    def mark(p, t, why):
        if p is not None and (p not in attack_from or t < attack_from[p]):
            attack_from[p] = t
            reason.setdefault(p, why)

    first_seen = {}
    for e in events:
        if e["pid"] is not None:
            first_seen.setdefault(e["pid"], e["ts"])
    bind_ports = {a["bind"][1] for a in actions if a.get("bind") and a["bind"][0] == host}
    for e in events:  # bind/listen on a port the attack log records as the C2 tunnel endpoint on this host
        if e["syscall"] == 49 and e["rport"] in bind_ports:
            mark(e["pid"], first_seen.get(e["pid"], e["ts"]), f"binds C2 tunnel port {e['rport']} (attack log tunnel_local)")
    for e in events:
        if e["kind"] == "netconn" and e["rip"] in cfg["attacker_ips"]:
            mark(e["pid"], first_seen.get(e["pid"], e["ts"]), f"{'connect to' if e['outbound'] else 'accept from'} attacker {e['rip']}:{e['rport']}")
        if e["kind"] == "auth" and e["rip"] in cfg["attacker_ips"] and e["ses"] not in (None, 4294967295):
            attack_ses.setdefault(e["ses"], (e["ts"], f"login session from attacker {e['rip']}"))
    # "ghost" parents: meterpreter forks without exec, so the forked pid never appears as an event pid.
    # A ppid never seen as pid, numerically after an attack seed pid, whose first child appears within 20 s
    # after an msf-session command of the attack timeline is taken as the forked attack process.
    seen = set(first_seen)
    msf_cmds = sorted(a["start"] for a in actions if a["category"] in ("msf-session", "msf-module"))
    first_child = {}
    for e in events:
        if e["ppid"] is not None and e["ppid"] not in seen and e["kind"] == "procstart":
            first_child.setdefault(e["ppid"], e["ts"])
    for pp, t in first_child.items():
        seeds_before = [p for p, ts0 in attack_from.items() if p < pp and ts0 <= t]
        if seeds_before and any(0 <= t - c <= 20_000_000 for c in msf_cmds):
            mark(pp, t, "forked attack process (ppid never exec'd) spawning a child right after an msf-session command")
    changed = True
    while changed:
        changed = False
        local_ssh = [e["ts"] for e in events if e["kind"] == "netconn" and e["pid"] in attack_from
                     and e["rip"] in ("127.0.0.1", "0000:0000:0000:0000:0000:0000:0000:0001") and e["rport"] == 22]
        for e in events:
            if e["kind"] == "auth" and e["ses"] not in (None, 4294967295) and e["ses"] not in attack_ses \
                    and e["rip"] in ("127.0.0.1", "::1") and any(0 <= e["ts"] - t <= 10_000_000 for t in local_ssh):
                attack_ses[e["ses"]] = (e["ts"], "localhost login right after attack ssh"); changed = True
        for e in sorted(events, key=lambda x: x["ts"]):
            p, pp = e["pid"], e["ppid"]
            if p is None or p in attack_from:
                continue
            if pp in attack_from and first_seen.get(p, e["ts"]) >= attack_from[pp]:
                mark(p, first_seen.get(p, e["ts"]), "child of attack process"); changed = True
            elif e["ses"] in attack_ses and e["ts"] >= attack_ses[e["ses"]][0]:
                mark(p, e["ts"], attack_ses[e["ses"]][1]); changed = True
    return attack_from, reason, attack_ses


# ------------------------------------------------------------------ driver
def assign(events, attack_from, actions_by_host, cfg, keyf, attack_ses=None):
    for e in events:
        k = keyf(e)
        is_att = (k in attack_from and e["ts"] >= attack_from[k]) or \
                 (attack_ses is not None and e["ses"] in attack_ses and e["ts"] >= attack_ses[e["ses"]][0])
        e["y_new"] = int(is_att)
        tac = ()
        if is_att:
            if e["kind"] == "netconn" and e["rip"] in cfg["attacker_ips"]:
                tac = ("Command and Control",)
            else:
                a = tactic_for(actions_by_host, e["host"], e["ts"])
                tac = tuple(a["tactics"]) if a else ("UNATTRIBUTED",)
        e["tactics_new"] = tac


def host_report(events, actions, reason):
    df = pd.DataFrame(events)
    rep = {"events": int(len(df)), "coarse_attack": int(df.coarse_mal.sum()), "new_attack": int(df.y_new.sum()),
           "both": int(((df.coarse_mal == 1) & (df.y_new == 1)).sum()),
           "coarse_only": int(((df.coarse_mal == 1) & (df.y_new == 0)).sum()),
           "new_only": int(((df.coarse_mal == 0) & (df.y_new == 1)).sum()),
           "new_attack_by_kind": df[df.y_new == 1].kind.value_counts().to_dict(),
           "new_tactics": Counter(t for ts in df[df.y_new == 1].tactics_new for t in ts).most_common(),
           "coarse_tactics": Counter(t for ts in df[df.coarse_mal == 1].coarse_tactics for t in ts).most_common(),
           "attack_processes": {str(k): v for k, v in list(reason.items())[:400]}}
    att = df[df.y_new == 1]
    if len(att):
        rep["new_attack_span"] = [pd.to_datetime(att.ts.min(), unit="us").isoformat(), pd.to_datetime(att.ts.max(), unit="us").isoformat()]
        rep["top_attack_images"] = att.image.map(base).value_counts().head(15).to_dict()
    return rep


def action_coverage(events, actions):
    ts_by_host = defaultdict(list)
    for e in events:
        if e["y_new"]:
            ts_by_host[e["host"]].append(e["ts"])
    for v in ts_by_host.values():
        v.sort()
    rows = []
    for a in actions:
        if not a["tactics"]:
            continue
        v = ts_by_host.get(a["host"], [])
        lo = bisect_right(v, a["start"] - SLACK_US - 1)
        hi = bisect_right(v, a["end"] + SLACK_US)
        rows.append(dict(start=pd.to_datetime(a["start"], unit="us").isoformat(), host=a["host"], action=a["uid"],
                         tactics=a["tactics"], outcome=a["outcome"], host_attack_events=hi - lo))
    return rows


def run(name, out_root):
    cfg = SCENARIOS[name]
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    actions = load_lore(cfg) if cfg["kind"] == "lore" else load_attackmate(cfg)
    by_host = defaultdict(list)
    for a in actions:
        by_host[a["host"]].append(a)
    all_events, report = [], {"scenario": name, "hosts": {}, "n_actions": len(actions),
                              "actions_with_tactics": sum(bool(a["tactics"]) for a in actions),
                              "action_hosts": Counter(str(a["host"]) for a in actions).most_common(),
                              "seed_config": {h: v for h, v in cfg["images"].items()},
                              "attacker_ips": sorted(cfg["attacker_ips"])}
    for host, path in cfg.get("windows", {}).items():
        ev = list(A.iter_windows_ecs(path, host))
        af, reason = relabel_windows(ev, actions, cfg, host)
        assign(ev, af, by_host, cfg, lambda e: e["guid"])
        rep = host_report(ev, actions, {k: reason[k] + " | " + base(next((x["image"] for x in ev if x["guid"] == k and x["image"]), "")) for k in reason})
        report["hosts"][host] = rep; all_events += ev
        print(host, {k: rep[k] for k in ("events", "coarse_attack", "new_attack", "both", "coarse_only", "new_only")}, flush=True)
    for host, path in cfg.get("linux_ecs", {}).items():
        ev = list(A.iter_auditd_ecs(path, host))
        af, reason, ses = relabel_linux(ev, actions, cfg, host)
        assign(ev, af, by_host, cfg, lambda e: e["pid"], ses)
        rep = host_report(ev, actions, reason); rep["attack_sessions"] = {str(k): v[1] for k, v in ses.items()}
        report["hosts"][host] = rep; all_events += ev
        print(host, {k: rep[k] for k in ("events", "coarse_attack", "new_attack", "both", "coarse_only", "new_only")}, flush=True)
    for host, path in cfg.get("audit_raw", {}).items():
        idx = A.coarse_index_from_labelled_json(cfg["audit_labelled"][host])
        ev = list(A.iter_auditd_raw(path, host, idx))
        lo = actions[0]["start"] - 3 * 3_600_000_000
        ev = [e for e in ev if e["ts"] >= lo]  # keep the simulation day (raw file also holds older history)
        af, reason, ses = relabel_linux(ev, actions, cfg, host)
        assign(ev, af, by_host, cfg, lambda e: e["pid"], ses)
        rep = host_report(ev, actions, reason); rep["attack_sessions"] = {str(k): v[1] for k, v in ses.items()}
        report["hosts"][host] = rep; all_events += ev
        print(host, {k: rep[k] for k in ("events", "coarse_attack", "new_attack", "both", "coarse_only", "new_only")}, flush=True)
    report["action_coverage"] = action_coverage(all_events, actions)
    cov = report["action_coverage"]
    report["actions_with_host_evidence"] = f"{sum(r['host_attack_events'] > 0 for r in cov)}/{len(cov)}"
    df = pd.DataFrame(all_events)
    df["coarse_tactics"] = df.coarse_tactics.map(list)
    df["tactics_new"] = df.tactics_new.map(list)
    df.to_parquet(out / "events.parquet", index=False)
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str))
    print(name, "actions with host evidence:", report["actions_with_host_evidence"], "->", out, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="SL700_f_a,SL300_v7")
    ap.add_argument("--out", default="/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v1")
    a = ap.parse_args()
    for s in a.scenarios.split(","):
        run(s, Path(a.out))


if __name__ == "__main__":
    main()
