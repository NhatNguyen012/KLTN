#!/usr/bin/env python3
"""relabel_v3 (SL700 / Linux only): fixes to relabel.relabel_linux found by the step-3 root-cause analysis
(analyst/rootcause_sl700_20261113.md). Everything else is relabel_v2 unchanged (run_sl700, stages, sessions).

Ghost parents = ppids never seen as an event pid (fork without exec; auditd here does not log fork/clone).
v2 marked a ghost only when its first child appeared <= 20 s after an msf command, which
  * missed the meterpreter payload itself (the stager forks it; first child 26 s after the msf-module command), hence
    the whole post-exploitation tree: shell -> pty.spawn -> bash -> linpeas.sh and its direct children;
  * labelled only the first ~20 s of linpeas' ~2.4k subshells (~70 % stayed benign, 3.5-4.9k processes per run);
  * marked unrelated ghosts that happened to follow a tactic-less msf housekeeping command (a_c: systemd's
    phpsessionclean at 22:09:11, 27 events).
v3, one time-ordered sweep with online propagation to children:
  1. payload: a ghost with the uid of a C2 stager, pid right after it (<= 64) and first child <= 30 s after the C2
     connection is the payload forked by the stager;
  2. burst: a ghost whose first child follows activity of an attack process of the same uid by <= 5 s continues it;
  3. msf timing: only msf commands that carry a MITRE tactic (housekeeping commands spawn no process);
  4. guard (rules 2-3): reject a ghost when the nearest lower visible pid (pids are sequential, no wrap-around in a
     day) is a benign shell started <= 2 s earlier by a visible benign parent (e.g. systemd running sessionclean);
  5. injected command: the parent of a C2 stager started <= 10 s before it (sh -c '<exploit payload> | python3 -').
Output: output/relabel_v3/SL700_<run>/{events.parquet, report.json} (RELABEL_V3_OUT overrides); v2 is not touched.
"""
from __future__ import annotations

import json
import os
import sys
from bisect import bisect_left
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import relabel as R  # noqa: E402
import relabel_v2 as R2  # noqa: E402

OUT3 = Path(os.environ.get("RELABEL_V3_OUT", "/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v3"))
SEC = 1_000_000
BURST_GAP = 5 * SEC
MSF_WIN = 20 * SEC
PRED_WIN = 2 * SEC
INJECT_WIN = 10 * SEC
PAYLOAD_WIN = 30 * SEC
PAYLOAD_PID_SPAN = 64
SHELLS = {"sh", "dash", "bash", "zsh", "ksh", "busybox"}
STATS = {}


def relabel_linux_v3(events, actions, cfg, host):
    attack_from, reason, attack_ses = {}, {}, {}

    def mark(p, t, why):
        if p is not None and (p not in attack_from or t < attack_from[p]):
            attack_from[p] = t
            reason.setdefault(p, why)

    first_seen, uid_of, procstart, image_of = {}, {}, {}, {}
    for e in events:
        if e["pid"] is not None:
            first_seen.setdefault(e["pid"], e["ts"])
            uid_of.setdefault(e["pid"], e.get("uid"))
            if e["kind"] == "procstart":
                procstart.setdefault(e["pid"], (e["ts"], e["ppid"]))
                image_of.setdefault(e["pid"], R.base(e["image"]))
    bind_ports = {a["bind"][1] for a in actions if a.get("bind") and a["bind"][0] == host}
    for e in events:
        if e["syscall"] == 49 and e["rport"] in bind_ports:
            mark(e["pid"], first_seen.get(e["pid"], e["ts"]), f"binds C2 tunnel port {e['rport']} (attack log tunnel_local)")
    for e in events:
        if e["kind"] == "netconn" and e["rip"] in cfg["attacker_ips"]:
            mark(e["pid"], first_seen.get(e["pid"], e["ts"]), f"{'connect to' if e['outbound'] else 'accept from'} attacker {e['rip']}:{e['rport']}")
        if e["kind"] == "auth" and e["rip"] in cfg["attacker_ips"] and e["ses"] not in (None, 4294967295):
            attack_ses.setdefault(e["ses"], (e["ts"], f"login session from attacker {e['rip']}"))
    # fix 3: the injected command that started a C2 seed
    n_inj = 0
    for p in [p for p in attack_from if "attacker" in reason[p]]:
        ps = procstart.get(p)
        if ps is None or ps[1] is None or ps[1] in attack_from:
            continue
        pps = procstart.get(ps[1])
        if pps is not None and 0 <= ps[0] - pps[0] <= INJECT_WIN:
            mark(ps[1], pps[0], f"parent of attacker C2 process {p}: started {(ps[0] - pps[0]) / SEC:.1f} s before it (injected command)")
            n_inj += 1
    def propagate():
        """children of attack processes and events of attack login sessions (as v2), to a fixpoint"""
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

    propagate()
    # ghost parents (fork without exec): one time-ordered sweep with online propagation
    seen = set(first_seen)
    seen_sorted = sorted(seen)
    # msf commands that carry a MITRE tactic (tactic-less ones are session housekeeping and spawn no process;
    # in a_c they fell 6 s before systemd's phpsessionclean job, whose subshells v2 then marked)
    msf_cmds = sorted(a["start"] for a in actions if a["category"] in ("msf-session", "msf-module") and a.get("tactics"))
    first_child, child_uid, children = {}, {}, {}
    for e in events:
        if e["kind"] == "procstart" and e["ppid"] is not None and e["ppid"] not in seen:
            first_child.setdefault(e["ppid"], e["ts"])
            child_uid.setdefault(e["ppid"], e.get("uid"))
            children.setdefault(e["ppid"], []).append(e["pid"])
    seeds = [(p, attack_from[p], uid_of.get(p)) for p in attack_from if reason[p].startswith(("connect to attacker", "accept from attacker"))]

    def predecessor_benign(g, t):
        """The nearest lower visible pid (pids are sequential, no wrap-around in a day) is a benign shell started
        <= 2 s before the ghost's first child by a visible benign parent, e.g. systemd running /usr/lib/php/sessionclean."""
        i = bisect_left(seen_sorted, g) - 1
        if i < 0:
            return False
        n = seen_sorted[i]
        if n in attack_from or not 0 <= t - first_seen[n] <= PRED_WIN or image_of.get(n) not in SHELLS:
            return False
        pn = procstart.get(n, (None, None))[1]
        return pn is not None and pn in first_seen and pn not in attack_from

    ghosts = sorted(first_child.items(), key=lambda x: x[1])
    gi, last_att = 0, {}
    n_payload = n_timed = n_burst = n_rej = 0
    for e in sorted(events, key=lambda x: x["ts"]):
        while gi < len(ghosts) and ghosts[gi][1] <= e["ts"]:
            g, t = ghosts[gi]; gi += 1
            u = child_uid[g]
            payload = any(us == u and p < g <= p + PAYLOAD_PID_SPAN and 0 <= t - t0 <= PAYLOAD_WIN for p, t0, us in seeds)
            timed = any(p < g and t0 <= t and uid_of.get(p) == u for p, t0 in attack_from.items()) and any(0 <= t - c <= MSF_WIN for c in msf_cmds)
            burst = u in last_att and 0 <= t - last_att[u] <= BURST_GAP
            if not (payload or timed or burst):
                continue
            if not payload and predecessor_benign(g, t):
                n_rej += 1
                continue
            why = ("payload forked by the C2 stager (same uid, pid right after it, first child <= 30 s after its connection)" if payload else
                   "first child right after an msf command" if timed else "continues attack activity of the same uid (<= 5 s)")
            mark(g, t, "forked attack process (ppid never exec'd): " + why)
            n_payload += payload; n_timed += (timed and not payload); n_burst += (burst and not payload and not timed)
        p, pp = e["pid"], e["ppid"]
        if p is not None and p not in attack_from and pp in attack_from and first_seen.get(p, e["ts"]) >= attack_from[pp]:
            mark(p, first_seen.get(p, e["ts"]), "child of attack process")
        if p in attack_from and e["ts"] >= attack_from[p]:
            last_att[e.get("uid")] = e["ts"]
    propagate()
    STATS[host] = dict(injected_parents=n_inj, ghosts_payload=n_payload, ghosts_timed=n_timed, ghosts_burst=n_burst,
                       ghosts_rejected_predecessor=n_rej, attack_processes=len(attack_from))
    return attack_from, reason, attack_ses


def main():
    runs = sys.argv[1:] or list(R2.SL700_RUNS)
    R.relabel_linux = relabel_linux_v3
    R2.OUT = OUT3
    R2.compare_v1 = lambda name, df: compare_v2(name, df)
    for r in runs:
        STATS.clear()
        name = R2.run(f"SL700_{r}")
        rep = json.loads((OUT3 / name / "report.json").read_text())
        rep["relabel_v3_linux"] = dict(STATS)
        (OUT3 / name / "report.json").write_text(json.dumps(rep, indent=2, default=str, ensure_ascii=False))
        print(name, json.dumps(STATS), json.dumps(rep["vs_relabel_v1"]), flush=True)


def compare_v2(name, df):
    v2 = pd.read_parquet(Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2") / name / "events.parquet", columns=["host", "line", "code", "ts", "y", "image", "stage"])
    m = df[["host", "line", "code", "ts", "y", "image", "stage"]].merge(v2.rename(columns={"y": "y2", "stage": "stage2"})[["host", "line", "code", "ts", "y2", "stage2"]],
                                                                     on=["host", "line", "code", "ts"], how="inner")
    add, rem = m[(m.y == 1) & (m.y2 == 0)], m[(m.y == 0) & (m.y2 == 1)]
    return {"matched": int(len(m)), "v2_attack": int(m.y2.sum()), "v3_attack": int(m.y.sum()), "added": int(len(add)), "removed": int(len(rem)),
            "added_images": add.image.map(R.base).value_counts().head(10).to_dict(),
            "removed_images": rem.image.map(R.base).value_counts().head(10).to_dict(),
            "stage_changed": int(((m.y == 1) & (m.y2 == 1) & (m.stage != m.stage2)).sum())}


if __name__ == "__main__":
    main()
