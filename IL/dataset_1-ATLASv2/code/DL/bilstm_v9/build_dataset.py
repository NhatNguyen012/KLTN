#!/usr/bin/env python3
"""Step 2 of the v9 BiLSTM pipeline: windows, labels and rich event features.

* Window grid / split / embargo reproduce build_network_shards.py exactly
  (180 s windows, 30 s stride, >=2 label-bearing events, 512-event chunks),
  so the legacy label policy reproduces the original benchmark sample-for-sample.
* Two window label policies are stored side by side:
    legacy : original LabelRefiner (all REAPr seed endpoints, configured S3 gate)
    v9     : (a) a REAPr seed endpoint does not make a connection malicious if the
                 same ip:port is contacted in the benign-day telemetry (e.g. Firefox
                 captive portal 34.107.221.82:80, 300+ benign-day connections);
             (b) the S3 time gate, which is after all S3 telemetry, is replaced by
                 the first connection to the attacker host 10.193.66.115 in S3
                 (validated against the configured gate of the other scenarios).
  Neither policy uses model output.
* Features use observable fields only. No labels, GUIDs, scenario/host identity,
  attack timestamps, exact IPs/domains or reputation verdicts.
"""
from __future__ import annotations

import argparse
import json
import math
import pickle
import re
import sys
from bisect import bisect_left, bisect_right
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

CODE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CODE_ROOT))
sys.path.insert(0, str(CODE_ROOT / "DL" / "preprocess"))
from preprocess.common_schema import (  # noqa: E402
    CanonicalEvent, classify_image_dir, classify_principal, extract_basename,
    INITIAL_ATTACK_TIMESTAMPS, parse_timestamp_micros)
from preprocess.label_refiner import LabelRefiner  # noqa: E402
from build_network_shards import get_split_from_event, map_resp_port_class  # noqa: E402

LABEL_KINDS = ("netconn", "procstart", "crossproc")
KIND_TO_TYPE = {"netconn": "FLOW_START", "procstart": "PROCESS_START", "crossproc": "CROSS_PROCESS"}
ATTACKER_IP = "10.193.66.115"
WINDOW = 180_000_000
STRIDE = 30_000_000
MAX_LEN = 512

CAT_FIELDS = ["kind", "actor", "actor_dir", "parent", "target", "target_dir", "net",
              "ip_scope", "user", "pub", "tpub"]

CMD_FLAGS = [
    ("enc", re.compile(r"\s-(e|ec|en|enc|enco|encodedcommand)\s", re.I)),
    ("hidden", re.compile(r"(-w(indowstyle)?\s+h(idden)?\b)", re.I)),
    ("bypass", re.compile(r"(-nop\b|-noprofile|bypass|-noni\b|-noninteractive)", re.I)),
    ("url", re.compile(r"https?://", re.I)),
    ("script", re.compile(r"\.(ps1|vbs|js|hta|sct|bat|cmd)\b", re.I)),
    ("download", re.compile(r"(downloadstring|downloadfile|invoke-|iex\b|webclient|bitsadmin|certutil)", re.I)),
    ("regsvr", re.compile(r"(/i:|scrobj|/s\s)", re.I)),
    ("cmd_c", re.compile(r"\s/c\s", re.I)),
    ("long", None),
]


def cmd_flags(cmd: str) -> list[float]:
    c = f" {cmd} "
    out = []
    for name, rx in CMD_FLAGS:
        out.append(float(len(cmd) > 256) if rx is None else float(bool(rx.search(c))))
    return out


def ip_scope(ip: str) -> str:
    if not ip:
        return "NONE"
    if ":" in ip:
        return "IPV6"
    try:
        a, b, c, _ = (int(x) for x in ip.split("."))
    except ValueError:
        return "BAD"
    if a == 127:
        return "LOOPBACK"
    if a == 192 and b == 168 and c == 223:
        return "LOCAL_SUBNET"
    if a == 10:
        return "PRIV_10"
    if (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return "PRIV_OTHER"
    if a == 169 and b == 254:
        return "LINK_LOCAL"
    if a >= 224 or ip == "255.255.255.255":
        return "MULTICAST"
    if a == 0:
        return "ZERO"
    return "EXTERNAL"


def file_ext_class(name: str) -> str:
    n = name.lower()
    for cls, exts in (("EXE", (".exe",)), ("DLL", (".dll",)),
                      ("SCRIPT", (".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sct")),
                      ("ARCHIVE", (".zip", ".rar", ".7z")),
                      ("DOC", (".doc", ".docx", ".xls", ".xlsx", ".rtf", ".pdf")),
                      ("HTML", (".html", ".htm"))):
        if n.endswith(exts):
            return cls
    return "OTHER"


def event_tokens(r: dict) -> dict:
    k = r["kind"]
    t = {
        "actor": extract_basename(r["path"]) or "<NONE>",
        "actor_dir": classify_image_dir(r["path"]),
        "parent": extract_basename(r["ppath"]) or "<NONE>",
        "user": classify_principal(r["user"]),
        "pub": r["pub"],
        "tpub": r["tpub"] if k in ("procstart", "crossproc") else "NA",
        "net": "NA", "ip_scope": "NA", "target": "NA", "target_dir": "NA",
    }
    if k == "netconn":
        t["kind"] = "net_in" if r["inbound"] else "net_out"
        port = r["lport"] if r["inbound"] else r["rport"]
        proto = "tcp" if "TCP" in r["proto"] else ("udp" if "UDP" in r["proto"] else "other")
        t["net"] = f"{proto}:{map_resp_port_class(port)}:{'dom' if r['domain'] else 'nodom'}"
        t["ip_scope"] = ip_scope(r["rip"])
    elif k == "procstart":
        t["kind"] = "procstart"
        t["target"] = extract_basename(r["tpath"]) or "<NONE>"
        t["target_dir"] = classify_image_dir(r["tpath"])
    elif k == "crossproc":
        a = r["action"].upper()
        t["kind"] = "xp:" + ("dup_" if "DUP" in a else "open_") + ("thread" if "THREAD" in a else "process")
        t["target"] = extract_basename(r["tpath"]) or "<NONE>"
        t["target_dir"] = classify_image_dir(r["tpath"])
    else:  # filemod
        a = r["action"].upper()
        t["kind"] = "file_create" if "CREATE" in a else ("file_delete" if "DELETE" in a else "file_write")
        t["target"] = "FILE:" + file_ext_class(r["tpath"])
        t["target_dir"] = classify_image_dir(r["tpath"])
    return t


def canonical(r: dict, sc: str) -> CanonicalEvent:
    k = r["kind"]
    proto = "tcp" if "TCP" in r["proto"] else ("udp" if "UDP" in r["proto"] else r["proto"].lower())
    return CanonicalEvent(
        event_id="", timestamp=r["ts"], hostname=r["host"], event_type=KIND_TO_TYPE[k], scenario=sc,
        process_guid=r["guid"], parent_guid=r["pguid"], process_path=r["path"], process_cmdline=r["cmd"],
        parent_path=r["ppath"], username=r["user"],
        target_path=r["domain"] if k == "netconn" else r["tpath"], target_guid=r["tguid"],
        proto=proto, remote_ip=r["rip"], remote_port=r["rport"], local_port=r["lport"], inbound=r["inbound"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True, help="dir containing events/ from parse_events.py")
    ap.add_argument("--reapr-dir", default="/mnt/SSD_Data/optc/DATASET/ATLASv2_staged/reapr-ground-truth/atlasv2")
    ap.add_argument("--min-count", type=int, default=2)
    ap.add_argument("--out-name", default="dataset.pkl")
    ap.add_argument("--window-sec", type=int, default=180)
    ap.add_argument("--stride-sec", type=int, default=30)
    ap.add_argument("--align", type=int, default=0, help="1: grid aligned to floor(ts/window) like the OpTC DL S2 step")
    args = ap.parse_args()
    work = Path(args.work)
    WINDOW, STRIDE = args.window_sec * 1_000_000, args.stride_sec * 1_000_000
    files = {p.stem: pickle.load(open(p, "rb")) for p in sorted((work / "events").glob("*.pkl"))}

    # ---- label policies -------------------------------------------------
    legacy = LabelRefiner(args.reapr_dir)
    v9 = LabelRefiner(args.reapr_dir)
    benign_endpoints = Counter()
    for stem, d in files.items():
        if stem.endswith("benign"):
            for r in d["records"]:
                if r["kind"] == "netconn" and r["rip"]:
                    benign_endpoints[f"{r['rip']}:{r['rport']}"] += 1
    removed = {}
    for sc, seeds in v9.scenario_seeds.items():
        keep = set()
        for s in seeds:
            clean = s.strip().rstrip(",")
            if clean in benign_endpoints:
                removed.setdefault(clean, benign_endpoints[clean])
            else:
                keep.add(s)
        v9.scenario_seeds[sc] = keep
    print("Seed endpoints dropped because seen in benign-day telemetry:", removed)

    gate_report = {}
    for stem, d in files.items():
        sc = stem.split("-")[-1]
        if sc == "benign":
            continue
        c2 = [r["ts"] for r in d["records"] if r["kind"] == "netconn" and r["rip"] == ATTACKER_IP]
        first = min(c2) if c2 else None
        last_ts = max(r["ts"] for r in d["records"])
        gate = parse_timestamp_micros(INITIAL_ATTACK_TIMESTAMPS[sc])
        fmt = lambda x: None if x is None else datetime.fromtimestamp(x / 1e6, tz=timezone.utc).strftime("%H:%M:%S")
        gate_report[stem] = {"configured_gate": fmt(gate), "first_attacker_conn": fmt(first),
                             "last_event": fmt(last_ts),
                             "gap_min": None if first is None else round((first - gate) / 6e7, 1)}
    print("Gate check (first connection to attacker host vs configured gate):")
    for k, v in sorted(gate_report.items()):
        print(f"  {k:12s} {v}")
    s3_first = [parse_timestamp_micros(f"2022-07-19 {gate_report['edr-h1-s3']['first_attacker_conn']}")]
    v9.scenario_attack_micros["s3"] = s3_first[0]
    # v9b: one uniform rule for every scenario: gate = min(configured gate, first
    # connection of any process to the attacker host, over both hosts' files).
    v9b = LabelRefiner(args.reapr_dir)
    v9b.scenario_seeds = v9.scenario_seeds
    gates_v9b = {}
    for stem, d in files.items():
        sc = stem.split("-")[-1]
        if sc == "benign":
            continue
        c2 = [r["ts"] for r in d["records"] if r["kind"] == "netconn" and r["rip"] == ATTACKER_IP]
        if c2:
            v9b.scenario_attack_micros[sc] = min(v9b.scenario_attack_micros[sc], min(c2))
    for sc, t in v9b.scenario_attack_micros.items():
        gates_v9b[sc] = datetime.fromtimestamp(t / 1e6, tz=timezone.utc).isoformat()
    print("v9b gates:", gates_v9b)

    # ---- windows --------------------------------------------------------
    samples = {"train": [], "val": [], "test": []}
    for stem, d in files.items():
        sc = stem.split("-")[-1]
        recs = sorted(d["records"], key=lambda r: r["ts"])
        lab = [r for r in recs if r["kind"] in LABEL_KINDS]
        extra = [r for r in recs if r["kind"] not in LABEL_KINDS]
        for r in lab:
            ce = canonical(r, sc)
            r["y_legacy"] = int(legacy.is_event_malicious(ce))
            r["y_v9"] = int(v9.is_event_malicious(ce))
            r["y_v9b"] = int(v9b.is_event_malicious(ce))
            r["stage"] = v9.get_event_stage(ce)[1] if r["y_v9"] else 0
            for pol, ref in (("legacy", legacy), ("v9", v9), ("v9b", v9b)):
                r[f"stage_{pol}"] = ref.get_event_stage(ce)[1] if r[f"y_{pol}"] == 1 else 0
            r["tok"] = event_tokens(r)
            r["flags"] = cmd_flags(r["cmd"]) + (cmd_flags(r["tcmd"]) if r["kind"] == "procstart" else [0.0] * len(CMD_FLAGS))
        for r in extra:
            r["y_legacy"] = r["y_v9"] = r["y_v9b"] = -1
            r["stage"] = 0
            r["stage_legacy"] = r["stage_v9"] = r["stage_v9b"] = 0
            r["tok"] = event_tokens(r)
            r["flags"] = cmd_flags(r["cmd"]) + [0.0] * len(CMD_FLAGS)
        if not lab:
            continue
        ts_lab = [r["ts"] for r in lab]
        ts_extra = [r["ts"] for r in extra]
        host = lab[0]["host"]
        cur, w = (ts_lab[0] // WINDOW * WINDOW if args.align else ts_lab[0]), 0
        while cur <= ts_lab[-1]:
            end = cur + WINDOW
            li = bisect_left(ts_lab, cur)
            ri = bisect_left(ts_lab, end) if args.align else bisect_right(ts_lab, end)
            if ri - li >= 2:
                evs = lab[li:ri]
                wid = w
                w += 1
                splits = {get_split_from_event(sc, e["ts"]) for e in evs}
                if len(splits) == 1:
                    split = splits.pop()
                    for ci in range(math.ceil(len(evs) / MAX_LEN)):
                        ch = evs[ci * MAX_LEN:(ci + 1) * MAX_LEN]
                        lo, hi = ch[0]["ts"], ch[-1]["ts"]
                        ex = extra[bisect_left(ts_extra, lo):bisect_right(ts_extra, hi)]
                        allev = sorted(ch + ex, key=lambda e: (e["ts"], e["kind"] == "filemod"))
                        samples[split].append({
                            "sample_id": f"{host}_{sc}_w{wid:04d}_c{ci:02d}",
                            "scenario": sc, "host": host, "start": lo, "end": hi,
                            "y_legacy": int(any(e["y_legacy"] == 1 for e in ch)),
                            "y_v9": int(any(e["y_v9"] == 1 for e in ch)),
                            "y_v9b": int(any(e["y_v9b"] == 1 for e in ch)),
                            "stages": sorted({e["stage"] for e in ch if e["y_v9"] == 1}),
                            **{f"stages_{pol}": sorted({e[f"stage_{pol}"] for e in ch if e[f"y_{pol}"] == 1})
                               for pol in ("legacy", "v9", "v9b")},
                            **{f"stage_last_{pol}": next((e[f"stage_{pol}"] for e in reversed(ch) if e[f"y_{pol}"] == 1), 0)
                               for pol in ("legacy", "v9", "v9b")},
                            "events": allev,
                        })
            cur += STRIDE

    # ---- vocab (TRAIN only) and encoding ---------------------------------
    counts = {f: Counter() for f in CAT_FIELDS}
    seen = set()
    for s in samples["train"]:
        for e in s["events"]:
            key = (e["line"], e["host"], e["ts"], e["kind"])
            if key in seen:
                continue
            seen.add(key)
            for f in CAT_FIELDS:
                counts[f][e["tok"][f]] += 1
    vocab = {}
    for f in CAT_FIELDS:
        m = {"<PAD>": 0, "<UNK>": 1}
        for tok, c in sorted(counts[f].items(), key=lambda x: (-x[1], x[0])):
            if c >= args.min_count:
                m[tok] = len(m)
        vocab[f] = m

    out = {}
    for split, lst in samples.items():
        enc = []
        for s in lst:
            evs = s["events"]
            L = len(evs)
            cat = np.zeros((L, len(CAT_FIELDS)), dtype=np.int64)
            for i, e in enumerate(evs):
                for j, f in enumerate(CAT_FIELDS):
                    cat[i, j] = vocab[f].get(e["tok"][f], 1)
            flags = np.asarray([e["flags"] for e in evs], dtype=np.float32)
            ts = np.asarray([e["ts"] for e in evs], dtype=np.float64)
            dt = np.log1p(np.diff(ts, prepend=ts[0]) / 1e6).astype(np.float32)
            rel = np.log1p((ts - ts[0]) / 1e6).astype(np.float32) / math.log1p(180.0)
            cont = np.stack([dt, rel, np.asarray([e["kind"] == "filemod" for e in evs], dtype=np.float32)], 1)
            enc.append({
                "sample_id": s["sample_id"], "scenario": s["scenario"], "host": s["host"],
                "start": s["start"], "end": s["end"], "stages": s["stages"],
                **{k: s[k] for k in s if k.startswith(("stages_", "stage_last_"))},
                **{f"ev_stage_{pol}": np.asarray([e[f"stage_{pol}"] for e in evs], dtype=np.int8)
                   for pol in ("legacy", "v9", "v9b")},
                "y_legacy": s["y_legacy"], "y_v9": s["y_v9"], "y_v9b": s["y_v9b"],
                "cat": cat, "num": np.concatenate([flags, cont], 1),
                "ev_y_legacy": np.asarray([e["y_legacy"] for e in evs], dtype=np.int8),
                "ev_y_v9": np.asarray([e["y_v9"] for e in evs], dtype=np.int8),
                "ev_y_v9b": np.asarray([e["y_v9b"] for e in evs], dtype=np.int8),
                "is_extra": np.asarray([e["kind"] == "filemod" for e in evs], dtype=bool),
                "trace": [(e["line"], e["kind"], e["tok"]["actor"], e["tok"]["target"]) for e in evs],
            })
        out[split] = enc
        n = len(enc)
        for pol in ("legacy", "v9", "v9b"):
            last = Counter(x[f"stage_last_{pol}"] for x in enc if x[f"y_{pol}"])
            pres = Counter(k for x in enc for k in x[f"stages_{pol}"])
            print(f"   {split} {pol:6s} last-stage support {dict(sorted(last.items()))}  presence {dict(sorted(pres.items()))}")
        print(f"{split:5s} windows={n:5d}  legacy_pos={sum(s['y_legacy'] for s in enc):3d}  "
              f"v9_pos={sum(s['y_v9'] for s in enc):3d}  v9b_pos={sum(s['y_v9b'] for s in enc):3d}  "
              f"median_len={int(np.median([len(s['cat']) for s in enc]))}")
    meta = {"cat_fields": CAT_FIELDS, "vocab": vocab, "num_dim": int(out["train"][0]["num"].shape[1]),
            "seed_endpoints_dropped": removed, "gate_report": gate_report,
            "gates_v9b": gates_v9b, "s3_gate_v9": datetime.fromtimestamp(s3_first[0] / 1e6, tz=timezone.utc).isoformat()}
    with open(work / args.out_name, "wb") as fh:
        pickle.dump({"meta": meta, "splits": out}, fh, protocol=pickle.HIGHEST_PROTOCOL)
    (work / (args.out_name.replace(".pkl", "") + "_meta.json")).write_text(json.dumps(meta, indent=2, default=str))
    print({f: len(v) for f, v in vocab.items()})


if __name__ == "__main__":
    main()
