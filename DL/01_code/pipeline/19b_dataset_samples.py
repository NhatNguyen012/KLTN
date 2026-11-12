#!/usr/bin/env python3
"""STEP 19b - trích mẫu (2-3 dòng mỗi nhãn) từ SAGA và Windows-APT 2025, và bảng technique -> tactic của SAGA.
Chỉ đọc 03_datasets (SAGA đọc thẳng từ zip, Windows-APT đọc từ bản giải nén tạm đã có). Ghi vào 02_artifacts/19_dataset_analysis_v1/.
Ánh xạ technique -> tactic là của người viết (theo ATT&CK Enterprise), CHƯA được thẩm định.
"""
import collections
import csv
import json
import os
import re
import sys
import zipfile

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
B = "D:/UIT/KLTNv2/03_datasets/SAGA"
OUT = "D:/UIT/KLTNv2/02_artifacts/19_dataset_analysis_v1"
WIN = "C:/Users/ADMIN/AppData/Local/Temp/claude/D--UIT-KLTNv2/edeb5b63-667d-405e-9687-a8a1691b1334/scratchpad/winapt/Windows-APT 2025 A Dataset for APT-Inspired Attack/combined.csv"
ZIPS = ["Known APT Campaigns Dataset.zip", "Generated APT Campaigns Dataset.zip", "Composite APT Campaigns Dataset.zip"]
PER_LABEL = 3

# technique -> (tên tiếng Anh, [tactic])
TT = {
    "T1005": ("Data from Local System", ["Collection"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1566.001": ("Spearphishing Attachment", ["Initial Access"]),
    "T1496": ("Resource Hijacking", ["Impact"]),
    "T1003.001": ("LSASS Memory", ["Credential Access"]),
    "T1219": ("Remote Access Software", ["Command and Control"]),
    "T1204.002": ("Malicious File", ["Execution"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1574.001": ("DLL Search Order Hijacking", ["Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1071.001": ("Web Protocols", ["Command and Control"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"]),
    "T1036.003": ("Rename System Utilities", ["Defense Evasion"]),
    "T1003.002": ("Security Account Manager", ["Credential Access"]),
    "T1112": ("Modify Registry", ["Defense Evasion"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
    "T1548.002": ("Bypass User Account Control", ["Privilege Escalation", "Defense Evasion"]),
    "T1040": ("Network Sniffing", ["Credential Access", "Discovery"]),
    "T1003": ("OS Credential Dumping", ["Credential Access"]),
    "T1547.009": ("Shortcut Modification", ["Persistence", "Privilege Escalation"]),
    "T1137": ("Office Application Startup", ["Persistence"]),
    "T1491": ("Defacement", ["Impact"]),
    "T1217": ("Browser Information Discovery", ["Discovery"]),
    "T1567": ("Exfiltration Over Web Service", ["Exfiltration"]),
    "T1007": ("System Service Discovery", ["Discovery"]),
    "T1021.001": ("Remote Desktop Protocol", ["Lateral Movement"]),
    "T1120": ("Peripheral Device Discovery", ["Discovery"]),
    "T1562.004": ("Disable or Modify System Firewall", ["Defense Evasion"]),
    "T1518": ("Software Discovery", ["Discovery"]),
    "T1137.002": ("Office Test", ["Persistence"]),
    "T1016": ("System Network Configuration Discovery", ["Discovery"]),
    "T1087.001": ("Local Account", ["Discovery"]),
    "T1047": ("Windows Management Instrumentation", ["Execution"]),
    "T1003.003": ("NTDS", ["Credential Access"]),
    "T1033": ("System Owner/User Discovery", ["Discovery"]),
    "T1053.005": ("Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1562.001": ("Disable or Modify Tools", ["Defense Evasion"]),
    "T1547.004": ("Winlogon Helper DLL", ["Persistence", "Privilege Escalation"]),
    "T1562.002": ("Disable Windows Event Logging", ["Defense Evasion"]),
    "T1057": ("Process Discovery", ["Discovery"]),
    "T1082": ("System Information Discovery", ["Discovery"]),
    "T1125": ("Video Capture", ["Collection"]),
    "T1123": ("Audio Capture", ["Collection"]),
    "T1078.001": ("Default Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1564.003": ("Hidden Window", ["Defense Evasion"]),
    "T1036.004": ("Masquerade Task or Service", ["Defense Evasion"]),
    "T1069.001": ("Local Groups", ["Discovery"]),
    "T1055.002": ("Portable Executable Injection", ["Defense Evasion", "Privilege Escalation"]),
    "T1049": ("System Network Connections Discovery", ["Discovery"]),
    "T1090.001": ("Internal Proxy", ["Command and Control"]),
    "T1518.001": ("Security Software Discovery", ["Discovery"]),
    "T1482": ("Domain Trust Discovery", ["Discovery"]),
    "T1055.001": ("Dynamic-link Library Injection", ["Defense Evasion", "Privilege Escalation"]),
    "T1201": ("Password Policy Discovery", ["Discovery"]),
    "T1135": ("Network Share Discovery", ["Discovery"]),
    "T1499": ("Endpoint Denial of Service", ["Impact"]),
    "T1552.002": ("Credentials in Registry", ["Credential Access"]),
}


def flat(o, grp, fn):
    s, d = o.get("srcNode") or {}, o.get("dstNode") or {}
    lb = o.get("label", "")
    tech = lb.split("_")[0] if lb != "benign" else ""
    return {"group": grp, "file": fn, "label": lb, "technique": tech, "technique_name": TT.get(tech, ("", []))[0],
            "tactics_mapped": "; ".join(TT.get(tech, ("", []))[1]), "timestamp_utc": pd.to_datetime(o.get("timestamp"), unit="s").strftime("%Y-%m-%d %H:%M:%S"),
            "relation": o.get("relation"), "src_type": s.get("Type"), "src_name": s.get("Name"), "src_image": s.get("Image"), "src_cmdline": s.get("Cmdline"), "src_pid": s.get("Pid"),
            "dst_type": d.get("Type"), "dst_key_or_path": d.get("Key") or d.get("Path") or d.get("Name") or d.get("File"), "dst_value": d.get("Value"),
            "dst_other_fields": json.dumps({k: v for k, v in d.items() if k not in ("UUID", "Type", "Key", "Path", "Name", "File", "Value")}, ensure_ascii=False) or "",
            "raw_json": json.dumps(o, ensure_ascii=False)}


def saga():
    got = collections.defaultdict(list)
    ben = {}
    for z in ZIPS:
        grp = z.split()[0].lower()
        with zipfile.ZipFile(f"{B}/{z}") as zf:
            for info in sorted(zf.infolist(), key=lambda i: (len(i.filename), i.filename)):
                with zf.open(info) as f:
                    for line in f:
                        if line.rstrip().endswith(b'"benign"}'):
                            # mỗi loại dstNode lấy 1 dòng benign đầu tiên của file đầu tiên chứa nó
                            m = re.search(rb'"dstNode": \{[^{}]*?"Type": "([^"]*)"', line)
                            t = m.group(1).decode() if m else "?"
                            if t not in ben and len(ben) < 6:
                                ben[t] = (grp, info.filename, json.loads(line))
                            continue
                        o = json.loads(line)
                        lb = o["label"]
                        if len(got[lb]) < PER_LABEL:
                            got[lb].append((grp, info.filename, o))
                print("scanned", info.filename, "labels so far", len(got), flush=True)
    rows = [flat(o, g, fn) for lb in sorted(got, key=lambda k: (k.split("_")[0], k)) for g, fn, o in got[lb]]
    rows += [flat(o, g, fn) for t, (g, fn, o) in ben.items()]
    pd.DataFrame(rows).to_csv(OUT + "/saga_samples_per_label.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print("SAGA sample rows", len(rows), "labels", len(got))
    # bảng technique -> tactic + thống kê
    lc = pd.read_csv(OUT + "/saga_label_counts.csv")
    tc = lc.groupby("technique")["count"].sum()
    tf = lc.groupby("technique")["file"].nunique()
    mp = pd.DataFrame([{"technique": k, "technique_name": v[0], "tactics_mapped": "; ".join(v[1]), "n_tactics": len(v[1]), "events": int(tc.get(k, 0)), "files": int(tf.get(k, 0))}
                       for k, v in TT.items()]).sort_values("events", ascending=False)
    mp.to_csv(OUT + "/saga_technique_tactic_map.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    miss = sorted(set(lc["technique"]) - set(TT))
    print("technique chưa có trong bảng ánh xạ:", miss)
    ex = mp.explode("tactics_mapped").assign(tactic=lambda d: d["tactics_mapped"].str.split("; "))
    rows2 = []
    for _, r in mp.iterrows():
        for t in r["tactics_mapped"].split("; "):
            rows2.append({"tactic": t, "technique": r["technique"], "events": r["events"], "excl_T1005": 0 if r["technique"] == "T1005" else r["events"]})
    td = pd.DataFrame(rows2).groupby("tactic").agg(techniques=("technique", "nunique"), events=("events", "sum"), events_without_T1005=("excl_T1005", "sum")).sort_values("events_without_T1005", ascending=False)
    td.to_csv(OUT + "/saga_tactic_coverage.csv", encoding="utf-8-sig", lineterminator="\n")
    print(td)


def winapt():
    cols = ["_source.agent.name", "_source.@timestamp", "_source.rule.description", "_source.rule.level", "_source.rule.id", "_source.rule.mitre.tactic",
            "_source.rule.mitre.id", "_source.rule.mitre.technique", "_source.data.win.system.eventID", "_source.data.win.system.channel",
            "_source.data.win.eventdata.image", "_source.data.win.eventdata.commandLine", "_source.data.win.eventdata.parentImage",
            "_source.data.win.eventdata.destinationIp", "_source.data.win.eventdata.destinationPort", "_source.full_log"]
    d = pd.read_csv(WIN, usecols=cols, dtype=str, low_memory=False)
    d.columns = [c.replace("_source.", "") for c in d.columns]
    for c in d.columns:
        d[c] = d[c].fillna("").str.strip()
    d["full_log"] = d["full_log"].str.slice(0, 300)
    d["commandLine_short"] = d["data.win.eventdata.commandLine"].str.slice(0, 200)

    def tl(s):
        try:
            return json.loads(s)
        except Exception:
            return []
    d["tactics"] = d["rule.mitre.tactic"].map(tl)
    d["n_tactics"] = d["tactics"].map(len)
    parts = []
    rng = pd.Series(range(len(d))).sample(frac=1, random_state=0).index  # ngẫu nhiên có seed, lặp lại được
    d = d.loc[rng]
    tactic_list = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                   "Collection", "Command and Control", "Exfiltration", "Impact"]
    for t in tactic_list:
        sub = d[d["tactics"].map(lambda L: L == [t])]  # ưu tiên event chỉ có đúng 1 tactic
        if len(sub) < 3:
            sub = d[d["tactics"].map(lambda L: t in L)]
        s = sub.head(3).copy()
        s["sample_group"] = f"tactic = {t}" + (" (chỉ 1 tactic)" if len(d[d['tactics'].map(lambda L: L == [t])]) >= 3 else " (event có nhiều tactic)")
        s["n_events_with_this_tactic"] = int(d["tactics"].map(lambda L: t in L).sum())
        parts.append(s)
    s = d[d["n_tactics"] >= 4].head(3).copy()
    s["sample_group"] = "event có >= 4 tactic cùng lúc"
    parts.append(s)
    s = d[d["n_tactics"] == 0].head(3).copy()
    s["sample_group"] = "không có tactic (không gán nhãn)"
    s["n_events_with_this_tactic"] = int((d["n_tactics"] == 0).sum())
    parts.append(s)
    out = pd.concat(parts)
    out["tactics"] = out["tactics"].map(lambda L: "; ".join(L))
    out = out[["sample_group", "n_events_with_this_tactic", "agent.name", "@timestamp", "rule.description", "rule.level", "rule.id", "tactics", "rule.mitre.id", "rule.mitre.technique",
               "data.win.system.eventID", "data.win.system.channel", "data.win.eventdata.image", "commandLine_short", "data.win.eventdata.parentImage",
               "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort", "full_log"]]
    out.to_csv(OUT + "/windows_apt_samples_per_tactic.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print("WinAPT sample rows", len(out))
    cnt = collections.Counter(t for L in d["tactics"] for t in L)
    print(cnt)


if __name__ == "__main__":
    winapt()
    saga()
    print("DONE")
