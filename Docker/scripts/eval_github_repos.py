#!/usr/bin/env python3
"""Zero-shot verification on real GitHub attack log repositories (OTRF Security-Datasets + Splunk Attack Data).

Tests:
1. OTRF empire_apt3 (HR001.shire.com: wscript -> PowerShell Empire -enc stager & post-exploitation)
2. OTRF caldera_apt3 (IT001.shire.com: powershell -> sandcat.exe C2 & discovery commands)
3. Splunk attack_data T1003.001 (win-dc-807.attackrange.local: raw XML Sysmon upload to /api/analyze-file)

All predictions run strictly zero-shot and label-blind against the live Docker containers.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.request
import xml.etree.ElementTree as ET

GH_DIR = Path("/mnt/SSD_Data/optc/Temp/github_datasets")
UI_ANALYZE = "http://127.0.0.1:8080/api/analyze"


def call_ui(records: list[dict], adapt: bool = True) -> dict:
    payload = json.dumps(
        {
            "raw_logs": "\n".join(json.dumps(r) for r in records),
            "adapt_external": adapt,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        UI_ANALYZE,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def eval_empire_apt3() -> None:
    print("================ 1. OTRF empire_apt3 (Real Windows Sysmon + PowerShell) ================")
    p = GH_DIR / "empire_apt3.tar.gz"
    hr_events = []
    anchor_idx = None
    with tarfile.open(p, "r:gz") as tf:
        f = tf.extractfile(tf.getmembers()[0])
        for raw in f:
            o = json.loads(raw)
            comp = str(o.get("computer_name") or "").lower()
            ln = str(o.get("log_name") or "").lower()
            eid = o.get("event_id")
            if comp != "hr001.shire.com":
                continue
            if "sysmon" not in ln and not ("powershell" in ln and eid in (800, 4103, 4104)):
                continue
            hr_events.append(o)
            if anchor_idx is None and "sysmon" in ln and eid == 1:
                cmd = str((o.get("event_data") or {}).get("CommandLine", "")).lower()
                if "powershell.exe" in cmd and "-enc" in cmd:
                    anchor_idx = len(hr_events) - 1
            if anchor_idx is not None and len(hr_events) - anchor_idx >= 650:
                break

    win = hr_events[max(0, anchor_idx - 500) : anchor_idx + 650]
    # Trace exact Empire PowerShell ProcessGuid subtree starting at wscript->powershell -enc
    atk_guids = set()
    for o in win:
        ed = o.get("event_data") or {}
        if o.get("event_id") == 1 and "-enc" in str(ed.get("CommandLine", "")).lower():
            g = str(ed.get("ProcessGuid") or "").lower()
            if g:
                atk_guids.add(g)
    changed = True
    while changed:
        changed = False
        for o in win:
            ed = o.get("event_data") or {}
            if o.get("event_id") == 1:
                pg = str(ed.get("ParentProcessGuid") or "").lower()
                cg = str(ed.get("ProcessGuid") or "").lower()
                if pg in atk_guids and cg and cg not in atk_guids:
                    atk_guids.add(cg)
                    changed = True

    tagged = []
    for o in win:
        rec = dict(o)
        ed = o.get("event_data") or {}
        guid = str(ed.get("ProcessGuid") or ed.get("SourceProcessGUID") or "").lower()
        ln = str(o.get("log_name") or "").lower()
        # PowerShell 800/4103 pipeline logs occurring during/after Empire launch with Empire markers also belong to Empire
        is_ps_empire = "powershell" in ln and any(
            k in str(o.get("message", "")).lower() for k in ("cachedgroups", "scriptblock", "amsi", "empire", "system.management.automation")
        )
        rec["true_binary"] = int((guid in atk_guids) or is_ps_empire)
        rec["eval_split"] = "test"
        tagged.append(rec)

    raw_res = call_ui(tagged[:300], adapt=False)
    adp_res = call_ui(tagged, adapt=True)
    ml_gt = adp_res["ml_summary"]["vs_ground_truth"]
    dl_gt = adp_res["dl_summary"]["vs_ground_truth"]
    elig_ml = [e["ml"]["oov_rate"] for e in adp_res["events"] if e["ml"]["eligible"]]
    print(f"Window={len(tagged)} atk_guids={len(atk_guids)} atk_events={sum(r['true_binary'] for r in tagged)}")
    print(f"  RAW (adapt=False, n=300): ML scored={raw_res['ml_summary']['scored_events']} mal={raw_res['ml_summary']['malicious_detected']} | DL mal={raw_res['dl_summary']['malicious_detected']}")
    print(f"  ADAPTED ML: scored={adp_res['ml_summary']['scored_events']} avg_OOV={round(sum(elig_ml)/max(1,len(elig_ml)),4)} GT={ml_gt}")
    print(f"  ADAPTED DL: scored={adp_res['dl_summary']['scored_events']} mal={adp_res['dl_summary']['malicious_detected']} GT={dl_gt} stages={list(adp_res['dl_summary']['stage_breakdown'].items())[:5]}")
    atk_hits = [e for e in adp_res["events"] if e["truth"]["true_binary"] == 1 and (e["ml"]["pred_binary"] == 1 or e["dl"]["pred_binary"] == 1)]
    atk_procs = [e for e in adp_res["events"] if e["truth"]["true_binary"] == 1 and (e["object"] in ("PROCESS", "SHELL") or e["action"] == "CREATE")]
    print(f"  Sample Empire attack events ({len(atk_hits)} caught by ML or DL):")
    for e in (atk_procs or atk_hits)[:8]:
        print(f"    [{e['action']}->{e['object']}] ml={e['ml']['prob']} dl={e['dl']['prob']} ({e['dl']['stage_name']}) | {e['summary'][:110]}")
    ben_fps = sorted({e["summary"][:85] for e in adp_res["events"] if e["truth"]["true_binary"] == 0 and (e["ml"]["pred_binary"] == 1 or e["dl"]["pred_binary"] == 1)})[:5]
    print(f"  Benign FP examples: {ben_fps}")


def eval_caldera_apt3() -> None:
    print("\n================ 2. OTRF caldera_apt3 (IT001.shire.com: sandcat.exe & discovery) ================")
    p = GH_DIR / "caldera_apt3.tar.gz"
    it_events = []
    anchor_idx = None
    with tarfile.open(p, "r:gz") as tf:
        f = tf.extractfile(tf.getmembers()[0])
        for raw in f:
            o = json.loads(raw)
            w = o.get("winlog") or {}
            comp = str(w.get("computer_name") or "").lower()
            ch = str(w.get("channel") or "").lower()
            if comp != "it001.shire.com" or "sysmon" not in ch:
                continue
            it_events.append(o)
            if anchor_idx is None and w.get("event_id") == 1:
                cmd = str((w.get("event_data") or {}).get("CommandLine", "")).lower()
                if "sandcat" in cmd:
                    anchor_idx = len(it_events) - 1
            if anchor_idx is not None and len(it_events) - anchor_idx >= 700:
                break

    win = it_events[max(0, anchor_idx - 400) : anchor_idx + 700]
    atk_guids = set()
    for o in win:
        ed = (o.get("winlog") or {}).get("event_data") or {}
        if (o.get("winlog") or {}).get("event_id") == 1 and "sandcat" in str(ed.get("CommandLine", "")).lower():
            g = str(ed.get("ProcessGuid") or "").lower()
            if g:
                atk_guids.add(g)
    changed = True
    while changed:
        changed = False
        for o in win:
            w = o.get("winlog") or {}
            ed = w.get("event_data") or {}
            if w.get("event_id") == 1:
                pg = str(ed.get("ParentProcessGuid") or "").lower()
                cg = str(ed.get("ProcessGuid") or "").lower()
                if pg in atk_guids and cg and cg not in atk_guids:
                    atk_guids.add(cg)
                    changed = True

    tagged = []
    for o in win:
        ed = (o.get("winlog") or {}).get("event_data") or {}
        guid = str(ed.get("ProcessGuid") or ed.get("SourceProcessGUID") or "").lower()
        rec = dict(o)
        rec["true_binary"] = int(guid in atk_guids)
        rec["eval_split"] = "test"
        tagged.append(rec)

    raw_res = call_ui(tagged[:300], adapt=False)
    adp_res = call_ui(tagged, adapt=True)
    ml_gt = adp_res["ml_summary"]["vs_ground_truth"]
    dl_gt = adp_res["dl_summary"]["vs_ground_truth"]
    elig_ml = [e["ml"]["oov_rate"] for e in adp_res["events"] if e["ml"]["eligible"]]
    print(f"Window={len(tagged)} atk_guids={len(atk_guids)} atk_events={sum(r['true_binary'] for r in tagged)}")
    print(f"  RAW (adapt=False, n=300): ML scored={raw_res['ml_summary']['scored_events']} mal={raw_res['ml_summary']['malicious_detected']} | DL mal={raw_res['dl_summary']['malicious_detected']}")
    print(f"  ADAPTED ML: scored={adp_res['ml_summary']['scored_events']} avg_OOV={round(sum(elig_ml)/max(1,len(elig_ml)),4)} GT={ml_gt}")
    print(f"  ADAPTED DL: scored={adp_res['dl_summary']['scored_events']} mal={adp_res['dl_summary']['malicious_detected']} GT={dl_gt} stages={list(adp_res['dl_summary']['stage_breakdown'].items())[:5]}")
    atk_procs = [e for e in adp_res["events"] if e["truth"]["true_binary"] == 1 and e["object"] == "PROCESS" and e["action"] == "CREATE"]
    for e in atk_procs[:10]:
        print(f"    CALDERA PROC: ml={e['ml']['prob']} dl={e['dl']['prob']} ({e['dl']['stage_name']}) | {e['summary'][:110]}")
    ben_fps = sorted({e["summary"][:85] for e in adp_res["events"] if e["truth"]["true_binary"] == 0 and (e["ml"]["pred_binary"] == 1 or e["dl"]["pred_binary"] == 1)})[:5]
    print(f"  Benign FP examples: {ben_fps}")


def eval_splunk_t1003_xml() -> None:
    print("\n================ 3. SPLUNK attack_data T1003.001 (Direct Raw XML Upload Test) ================")
    txt = (GH_DIR / "splunk_t1003_001_sysmon.log").read_text(errors="replace")
    blocks = re.findall(r"<Event\b.*?</Event>", txt, flags=re.S)
    # Sort blocks chronologically and take 1,200 around EID=1 / procdump / lsass EID=10
    parsed = []
    for b in blocks:
        r = ET.fromstring(b)
        ed = {el.attrib.get("Name"): (el.text or "") for el in r.iter() if el.tag.endswith("Data") and "Name" in el.attrib}
        ts = ed.get("UtcTime") or ""
        eid = next((el.text for el in r.iter() if el.tag.endswith("EventID")), "")
        parsed.append((ts, eid, ed, b))
    parsed.sort(key=lambda x: x[0])

    # Find first Atomic/procdump/powershell or non-svchost lsass EID 10
    anc = next(
        (
            i
            for i, (_, eid, ed, _) in enumerate(parsed)
            if (eid == "1" and any(k in str(ed.get("CommandLine", "")).lower() for k in ("procdump", "lsass", "invoke", "atomic")))
            or (eid == "10" and "lsass.exe" in str(ed.get("TargetImage", "")).lower() and "svchost.exe" not in str(ed.get("SourceImage", "")).lower())
        ),
        len(parsed) // 2,
    )
    slice_blocks = [b for _, _, _, b in parsed[max(0, anc - 400) : anc + 600]]
    xml_path = GH_DIR / "splunk_t1003_001_slice.xml"
    xml_path.write_text("\n".join(slice_blocks), encoding="utf-8")

    out = subprocess.check_output(
        ["curl", "-sS", "-F", f"file=@{xml_path}", "http://127.0.0.1:8080/api/analyze-file"]
    )
    res = json.loads(out)
    print(f"Uploaded raw XML slice ({res['total_events']} events) via /api/analyze-file:")
    print(f"  ML: scored={res['ml_summary']['scored_events']} mal={res['ml_summary']['malicious_detected']}")
    print(f"  DL: scored={res['dl_summary']['scored_events']} mal={res['dl_summary']['malicious_detected']} stages={list(res['dl_summary']['stage_breakdown'].items())[:5]}")
    hits = [e for e in res["events"] if e["ml"]["pred_binary"] == 1 or e["dl"]["pred_binary"] == 1]
    for e in hits[:8]:
        print(f"    ALERT [{e['action']}->{e['object']}]: ml={e['ml']['prob']} dl={e['dl']['prob']} ({e['dl']['stage_name']}) | {e['summary'][:100]}")


if __name__ == "__main__":
    eval_empire_apt3()
    eval_caldera_apt3()
    eval_splunk_t1003_xml()
