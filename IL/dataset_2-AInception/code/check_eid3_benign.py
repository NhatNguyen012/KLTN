#!/usr/bin/env python3
"""AInception SL300 v7: is Sysmon EID 3 (NetworkConnect) an attack-only shortcut on media?

On the attack day 335/335 media netconn events belong to attack processes (relabel_v1). The SwiftOnSecurity
config logs EID 3 only for listed images/ports, so the mere presence of a netconn event may encode the label.
This script streams the benign-day logs straight from the release zip (DATASET/ stays read-only) and compares
them with the attack day: event codes per day, every EID 3 record (image, RuleName, port, direction), and
whether the images that connect on the attack day (powershell, notepad, nmap) also run on benign days.
Writes code_by_day.csv, eid3_records.csv, summary.json to --out/<host>/.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapters as A  # noqa: E402

DS = Path("/mnt/SSD_Data/optc/DATASET/AInception")
ZIP = DS / "SL300_variant_7.zip"
EXTRACTED = DS / "extracted/SL300_v7/variant7"
RELABEL = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v1/SL300_v7/events.parquet")
WATCH = {"powershell.exe", "notepad.exe", "nmap.exe", "cmd.exe", "wupdate.exe", "update_2.exe", "l_test.exe"}


def base(p):
    return (p or "").replace("/", "\\").split("\\")[-1].lower()


def lines_from_zip(member):
    with zipfile.ZipFile(ZIP) as z, z.open(member) as fh:
        yield from io.TextIOWrapper(fh, encoding="utf-8", errors="replace")


def lines_from_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from fh


def scan(lines, period, host):
    codes, eid3, procs = Counter(), [], []
    for i, l in enumerate(lines):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        if (r.get("agent") or {}).get("type") != "winlogbeat":
            continue
        e = A.parse_windows_record(r, i, host)
        day = pd.to_datetime(e["ts"], unit="us").strftime("%Y-%m-%d")
        codes[(period, day, e["src"], e["code"])] += 1
        ed = (r.get("winlog") or {}).get("event_data") or {}
        if e["src"] == "sysmon" and e["code"] == "3":
            eid3.append(dict(period=period, day=day, ts=e["ts"], guid=e["guid"], image=base(e["image"]),
                             rule=ed.get("RuleName") or "", proto=e["proto"], outbound=e["outbound"],
                             lip=e["lip"], lport=e["lport"], rip=e["rip"], rport=e["rport"], user=e["user"]))
        if e["kind"] == "procstart" and base(e["image"]) in WATCH:
            procs.append(dict(period=period, day=day, ts=e["ts"], src=e["src"], guid=e["guid"],
                              image=base(e["image"]), pimage=base(e["pimage"]), cmd=e["cmd"][:200]))
    return codes, eid3, procs


def scan_all_benign(out, skip=("suricata",)):
    """Every winlogbeat host in logs/benign_days: Sysmon EID 1 / EID 3 counts per image (cheap substring prefilter)."""
    with zipfile.ZipFile(ZIP) as z:
        members = [m for m in z.namelist() if m.startswith("variant7/logs/benign_days/") and m.endswith(".ecslogs")]
    rows = []
    for m in members:
        host = m.rsplit("/", 1)[-1].split(".")[0]
        if host in skip:
            continue
        c, win = Counter(), False
        for l in lines_from_zip(m):
            if '"winlogbeat"' not in l:
                continue
            win = True
            if "Microsoft-Windows-Sysmon" not in l or ('"code": "3"' not in l and '"code": "1"' not in l):
                continue
            r = json.loads(l)
            ev = r.get("event") or {}
            if ev.get("provider") != A.SYSMON or str(ev.get("code")) not in ("1", "3"):
                continue
            ed = (r.get("winlog") or {}).get("event_data") or {}
            c[(str(ev.get("code")), base(ed.get("Image")))] += 1
        if not win:
            continue
        for (code, img), n in c.items():
            rows.append(dict(host=host, eid=code, image=img, n=n))
        n1 = sum(v for (k, _), v in c.items() if k == "1")
        n3 = sum(v for (k, _), v in c.items() if k == "3")
        print(f"benign {host}: sysmon EID1 {n1}, EID3 {n3}", flush=True)
    df = pd.DataFrame(rows, columns=["host", "eid", "image", "n"])
    df.to_csv(out / "all_benign_hosts_eid1_eid3.csv", index=False)
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", default="media,apps,dc,hq01")
    ap.add_argument("--out", default="/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/eid3_check_v1")
    ap.add_argument("--all-benign", action="store_true", help="also scan EID1/EID3 of every benign Windows host")
    a = ap.parse_args()
    for h in a.hosts.split(","):
        run(h, Path(a.out) / h)
    if a.all_benign:
        scan_all_benign(Path(a.out))


def run(host, out):
    out.mkdir(parents=True, exist_ok=True)

    cb, eb, pb = scan(lines_from_zip(f"variant7/logs/benign_days/{host}.ecslogs"), "benign", host)
    ca, ea, pa = scan(lines_from_file(EXTRACTED / f"labelled_logs/bnhq7/attack/{host}.ecslogs"), "attack", host)

    codes = pd.DataFrame([dict(period=p, day=d, src=s, code=c, n=n) for (p, d, s, c), n in (cb + ca).items()])
    codes.to_csv(out / "code_by_day.csv", index=False)
    eid3 = pd.DataFrame(eb + ea)
    procs = pd.DataFrame(pb + pa)

    # attack-day labels from relabel_v1 (guid-level, same parser)
    rl = pd.read_parquet(RELABEL, columns=["host", "src", "code", "ts", "guid", "kind", "y_new"])
    rl = rl[rl.host == host]
    att_guid = set(rl[rl.y_new == 1].guid.dropna())
    if len(eid3):
        eid3["attack_guid"] = eid3.guid.isin(att_guid) & (eid3.period == "attack")
        eid3.to_csv(out / "eid3_records.csv", index=False)
    if len(procs):
        procs["attack_guid"] = procs.guid.isin(att_guid) & (procs.period == "attack")
        procs["made_eid3"] = procs.guid.isin(set(eid3.guid)) if len(eid3) else False

    # per-day totals and EID 3 counts
    tot = codes.groupby(["period", "day"]).n.sum().rename("events")
    s3 = codes[(codes.src == "sysmon") & (codes.code == "3")].groupby(["period", "day"]).n.sum().rename("eid3")
    sys_ = codes[codes.src == "sysmon"].groupby(["period", "day"]).n.sum().rename("sysmon")
    per_day = pd.concat([tot, sys_, s3], axis=1).fillna(0).astype(int).reset_index()

    # (src, code) present on the attack day but never on a benign day -> other presence shortcuts
    bset = set(map(tuple, codes[codes.period == "benign"][["src", "code"]].values))
    att_codes = codes[codes.period == "attack"].groupby(["src", "code"]).n.sum()
    only_attack = {f"{s}:{c}": int(n) for (s, c), n in att_codes.items() if (s, c) not in bset}
    ev_lab = rl.groupby(["src", "code"]).y_new.agg(["size", "sum"])
    only_attack_lab = {k: {"events": v, "y_new": int(ev_lab.loc[tuple(k.split(":", 1)), "sum"])
                           if tuple(k.split(":", 1)) in ev_lab.index else None} for k, v in only_attack.items()}

    def grp(df, col):
        return {str(k): int(v) for k, v in df[col].value_counts().head(20).items()} if len(df) else {}

    summary = {
        "host": host,
        "per_day": per_day.to_dict("records"),
        "eid3_by_period": {p: {"n": int(len(g)), "images": grp(g, "image"), "rules": grp(g, "rule"),
                               "rport": grp(g, "rport"), "outbound": grp(g, "outbound"), "rip": grp(g, "rip"),
                               "attack_guid": int(g.attack_guid.sum())}
                           for p, g in (eid3.groupby("period") if len(eid3) else [])},
        "watch_procstart": {f"{p}|{img}|{src}": {"n": int(len(g)), "attack_guid": int(g.attack_guid.sum()),
                                                 "made_eid3": int(g.made_eid3.sum())}
                            for (p, img, src), g in (procs.groupby(["period", "image", "src"]) if len(procs) else [])},
        "benign_watch_cmd_samples": {img: g.cmd.drop_duplicates().head(8).tolist()
                                     for img, g in procs[procs.period == "benign"].groupby("image")} if len(procs) else {},
        "codes_only_on_attack_day": only_attack_lab,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(f"== {host}", flush=True)
    print(per_day.to_string(index=False))
    print(json.dumps({p: {k: v[k] for k in ("n", "images", "attack_guid")} for p, v in summary["eid3_by_period"].items()}),
          flush=True)


if __name__ == "__main__":
    main()
