#!/usr/bin/env python3
"""Zero-shot evaluation on completely unseen local DATASET/ logs (Kellect4APT + FiveDirections).

Compares raw unconverted schema input (adapt_external=False) vs schema-adapted input
(adapt_external=True) against live Docker containers without retraining or modifying DATASET/.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import tarfile
import urllib.request

import pyarrow.parquet as pq

UI_ANALYZE_URL = "http://127.0.0.1:8080/api/analyze"


def call_ui(records: list[dict], adapt: bool = True) -> dict:
    payload = json.dumps(
        {
            "raw_logs": "\n".join(json.dumps(r) for r in records),
            "adapt_external": adapt,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        UI_ANALYZE_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def eval_kellect4apt() -> None:
    print("================ 1. KELLECT4APT (Windows ETW, 5 Unseen ATT&CK Techniques) ================")
    base = Path("/mnt/SSD_Data/optc/DATASET/Kellect4APT/public_data")
    cases = [
        ("T1003.001", "T1003.001-1.json", ["procdump"]),
        ("T1059.001", "T1059.001-11.json", ["reg.exe", "csc.exe"]),
        ("T1053.005", "T1053.005-1.json", ["schtasks"]),
        ("T1218.011", "T1218.011-1.json", ["rundll32"]),
        ("T1547.001", sorted((base / "T1547.001").glob("*.json"))[0].name, ["reg", "powershell", "cmd.exe"]),
    ]

    kept_events = {
        "ProcessStart",
        "ProcessEnd",
        "ThreadStart",
        "ImageLoad",
        "FileIOCreate",
        "FileIOWrite",
        "FileIODelete",
        "FileIORename",
        "RegistrySetValue",
        "RegistrySetInformation",
        "RegistryKCBCreate",
        "RegistryDelete",
        "TcpIpConnectIPV4",
        "TcpIpSendIPV4",
        "TcpIpRecvIPV4",
    }

    for tech, fname, hints in cases:
        p = base / tech / fname
        events = []
        anchor_idx = None
        with p.open("r", encoding="utf-8") as f:
            for raw in f:
                o = json.loads(raw)
                ev = o.get("Event")
                if ev not in kept_events:
                    continue
                events.append(o)
                if anchor_idx is None and ev == "ProcessStart":
                    cmd = str((o.get("args") or {}).get("CommandLine", "")).lower()
                    pn = str(o.get("PName", "")).lower()
                    if any(h in cmd or h in pn for h in hints) and "defender" not in cmd and "firewallcontrolpanel" not in cmd:
                        anchor_idx = len(events) - 1
                if anchor_idx is not None and len(events) - anchor_idx >= 500:
                    break
                if len(events) >= 150000 and anchor_idx is None:
                    break

        if anchor_idx is None:
            print(f"[{tech}/{fname}] Anchor ProcessStart not found.")
            continue

        win = events[max(0, anchor_idx - 550) : anchor_idx + 450]
        atk_pids = set()
        for o in win:
            if o.get("Event") == "ProcessStart":
                cmd = str((o.get("args") or {}).get("CommandLine", "")).lower()
                pn = str(o.get("PName", "")).lower()
                if "test.exe" in cmd or (any(h in cmd or h in pn for h in hints) and "firewallcontrolpanel" not in cmd):
                    atk_pids.add(o.get("PID"))

        changed = True
        while changed:
            changed = False
            for o in win:
                if o.get("Event") == "ProcessStart" and o.get("PPID") in atk_pids and o.get("PID") not in atk_pids:
                    atk_pids.add(o.get("PID"))
                    changed = True

        tagged = []
        for o in win:
            rec = dict(o)
            rec["true_binary"] = int(o.get("PID") in atk_pids)
            rec["eval_split"] = "test"
            tagged.append(rec)

        raw_res = call_ui(tagged[:300], adapt=False)
        adp_res = call_ui(tagged, adapt=True)
        ml_gt = adp_res["ml_summary"]["vs_ground_truth"]
        dl_gt = adp_res["dl_summary"]["vs_ground_truth"]
        proc_atk = [
            e
            for e in adp_res["events"]
            if e["action"] == "CREATE" and e["object"] == "PROCESS" and e["truth"]["true_binary"] == 1
        ]
        ben_fps = [
            e
            for e in adp_res["events"]
            if e["truth"]["true_binary"] == 0 and (e["ml"]["pred_binary"] == 1 or e["dl"]["pred_binary"] == 1)
        ]
        elig_ml = [e["ml"]["oov_rate"] for e in adp_res["events"] if e["ml"]["eligible"]]
        avg_ml_oov = round(sum(elig_ml) / max(1, len(elig_ml)), 4)

        atk_cnt = sum(r["true_binary"] for r in tagged)
        print(f"\n[{tech}/{fname}] window={len(tagged)} atk_pids={sorted(atk_pids)} atk_events={atk_cnt}")
        print(
            f"  RAW (adapt=False, n=300): ML scored={raw_res['ml_summary']['scored_events']} mal={raw_res['ml_summary']['malicious_detected']}"
            f" | DL mal={raw_res['dl_summary']['malicious_detected']}"
        )
        print(f"  ADAPTED ML: scored={adp_res['ml_summary']['scored_events']} avg_OOV={avg_ml_oov} GT={ml_gt}")
        print(
            f"  ADAPTED DL: scored={adp_res['dl_summary']['scored_events']} mal={adp_res['dl_summary']['malicious_detected']}"
            f" GT={dl_gt} stages={list(adp_res['dl_summary']['stage_breakdown'].items())[:4]}"
        )
        for pe in proc_atk[:6]:
            print(f"    ATK PROC: ml={pe['ml']['prob']} dl={pe['dl']['prob']} ({pe['dl']['stage_name']}) | {pe['summary'][:110]}")
        uniq_fp = sorted({e["summary"][:80] for e in ben_fps})[:5]
        print(f"  Benign FPs ({len(ben_fps)} events): {uniq_fp}")


def eval_fivedirections() -> None:
    print("\n================ 2. DARPA TC E3 FIVEDIRECTIONS (Windows REAPr Ground Truth) ================")
    fd_dir = Path("/mnt/SSD_Data/optc/DATASET/DARPA-TC-E3-FIVEDIRECTIONS/Parquet")
    reapr_dir = Path("/mnt/SSD_Data/optc/DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3")

    # Load REAPr process labels
    atk_proc_uuids = set()
    bad_proc_uuids = set()
    with (reapr_dir / "fivedirections_labels.csv").open("r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            u = r["uuid"].strip().upper()
            lbl = r["label"].strip().lower()
            ch = r["attack_chain"].strip()
            if lbl == "attack" and "success" in ch:
                atk_proc_uuids.add(u)
            else:
                bad_proc_uuids.add(u)

    proc_tbl = pq.read_table(fd_dir / "process_node_table.parquet").to_pylist()
    proc_map = {
        int(r["index_id"]): (str(r["path"] or ""), str(r["cmd"] or ""), str(r["node_uuid"] or "").upper())
        for r in proc_tbl
    }
    atk_idx_ids = sorted(idx for idx, (_, _, u) in proc_map.items() if u in atk_proc_uuids)
    bad_idx_ids = {idx for idx, (_, _, u) in proc_map.items() if u in bad_proc_uuids}

    # Exact edge UUIDs for fivedirections_3.4_success
    atk_edge_uuids = set()
    with tarfile.open(reapr_dir / "fivedirections_edge_labels.tar.gz", "r:gz") as tf:
        ef = tf.extractfile("edge_labels.csv")
        ef.readline()
        for raw in ef:
            parts = raw.decode("utf-8", "replace").strip().split(",")
            if len(parts) >= 4 and parts[0].strip() == "fivedirections_3.4_success" and parts[2].strip() == "attack":
                atk_edge_uuids.add(parts[3].strip().upper())
            if len(atk_edge_uuids) >= 250000:
                break

    # Fetch non-CLOSE edges for firefox.exe (419472) & child attack procs, plus contemporaneous benign edges
    ev_atk_tbl = pq.read_table(
        fd_dir / "event_table.parquet",
        filters=[("src_index_id", "in", atk_idx_ids)],
    ).to_pylist()
    # Select a focused chronological slice of ~350 meaningful non-CLOSE attack edges from firefox & children
    atk_rows = [
        r
        for r in ev_atk_tbl
        if r["operation"] != "EVENT_CLOSE" and str(r["event_uuid"]).upper() in atk_edge_uuids
    ]
    atk_rows.sort(key=lambda r: int(r["timestamp_rec"]))
    # Prefer rich diverse ops (FORK, EXECUTE, LOADLIBRARY, CREATE_OBJECT, WRITE, CONNECT, SENDTO)
    atk_rich = [r for r in atk_rows if r["operation"] in {"EVENT_FORK", "EVENT_EXECUTE", "EVENT_LOADLIBRARY", "EVENT_CREATE_OBJECT", "EVENT_CREATE_THREAD", "EVENT_WRITE", "EVENT_CONNECT", "EVENT_SENDTO"}]
    chosen_atk = atk_rich[:300]
    t0 = int(chosen_atk[0]["timestamp_rec"])
    t1 = int(chosen_atk[-1]["timestamp_rec"])

    # Fetch genuine benign background edges inside [t0 - 10s, t1 + 10s]
    ev_win_tbl = pq.read_table(
        fd_dir / "event_table.parquet",
        filters=[("timestamp_rec", ">=", t0 - 10_000_000_000), ("timestamp_rec", "<=", t1 + 10_000_000_000)],
    ).to_pylist()
    ben_rows = [
        r
        for r in ev_win_tbl
        if r["operation"] != "EVENT_CLOSE"
        and str(r["event_uuid"]).upper() not in atk_edge_uuids
        and int(r["src_index_id"]) not in atk_idx_ids
        and int(r["src_index_id"]) not in bad_idx_ids
        and int(r["dst_index_id"]) not in atk_idx_ids
        and int(r["dst_index_id"]) not in bad_idx_ids
    ][:400]

    file_tbl = pq.read_table(fd_dir / "file_node_table.parquet").to_pylist()
    file_map = {int(r["index_id"]): str(r["path"] or "") for r in file_tbl}
    net_tbl = pq.read_table(fd_dir / "netflow_node_table.parquet").to_pylist()
    net_map = {
        int(r["index_id"]): (str(r["src_addr"] or ""), int(r["src_port"] or 0), str(r["dst_addr"] or ""), int(r["dst_port"] or 0))
        for r in net_tbl
    }

    def enrich(row: dict, label: int) -> dict:
        si = int(row["src_index_id"])
        di = int(row["dst_index_id"])
        sp, sc, _ = proc_map.get(si, ("", "", ""))
        dp, dc, _ = proc_map.get(di, ("", "", ""))
        dst_kind = "process" if di in proc_map else ("file" if di in file_map else ("netflow" if di in net_map else "other"))
        obj_path = dp or file_map.get(di, "") or file_map.get(si, "")
        nf = net_map.get(di) or net_map.get(si)
        rec = {
            "event_uuid": str(row["event_uuid"]),
            "hostname": "fivedirections-win",
            "operation": str(row["operation"]),
            "src_node": str(row["src_node"]),
            "dst_node": str(row["dst_node"]),
            "timestamp_rec": int(row["timestamp_rec"]),
            "proc_path": sp or dp,
            "proc_cmd": sc or dc,
            "obj_path": obj_path,
            "dst_cmd": dc,
            "dst_kind": dst_kind,
            "true_binary": label,
            "eval_split": "test",
        }
        if nf:
            rec["src_ip"], rec["src_port"], rec["dest_ip"], rec["dest_port"] = nf[0], nf[1], nf[2], nf[3]
        return rec

    combined = [enrich(r, 1) for r in chosen_atk] + [enrich(r, 0) for r in ben_rows]
    combined.sort(key=lambda r: r["timestamp_rec"])

    raw_res = call_ui(combined[:300], adapt=False)
    adp_res = call_ui(combined, adapt=True)
    ml_gt = adp_res["ml_summary"]["vs_ground_truth"]
    dl_gt = adp_res["dl_summary"]["vs_ground_truth"]
    elig_ml = [e["ml"]["oov_rate"] for e in adp_res["events"] if e["ml"]["eligible"]]
    print(f"Window={len(combined)} (atk={len(chosen_atk)}, ben={len(ben_rows)})")
    print(f"  RAW (adapt=False, n=300): ML scored={raw_res['ml_summary']['scored_events']} mal={raw_res['ml_summary']['malicious_detected']} | DL mal={raw_res['dl_summary']['malicious_detected']}")
    print(f"  ADAPTED ML: scored={adp_res['ml_summary']['scored_events']} avg_OOV={round(sum(elig_ml)/max(1,len(elig_ml)),4)} GT={ml_gt}")
    print(f"  ADAPTED DL: scored={adp_res['dl_summary']['scored_events']} mal={adp_res['dl_summary']['malicious_detected']} GT={dl_gt} stages={list(adp_res['dl_summary']['stage_breakdown'].items())[:4]}")
    hits = [e for e in adp_res["events"] if e["truth"]["true_binary"] == 1 and (e["ml"]["pred_binary"] == 1 or e["dl"]["pred_binary"] == 1)]
    print(f"  Attack events flagged by ML or DL: {len(hits)}")
    for h in hits[:5]:
        print(f"    HIT: ml={h['ml']['prob']} dl={h['dl']['prob']} ({h['dl']['stage_name']}) | {h['action']}->{h['object']} {h['summary'][:90]}")


if __name__ == "__main__":
    eval_kellect4apt()
    eval_fivedirections()
