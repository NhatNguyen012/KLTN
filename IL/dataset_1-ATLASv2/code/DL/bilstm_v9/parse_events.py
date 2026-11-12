#!/usr/bin/env python3
"""Step 1 of the v9 BiLSTM pipeline: stream every CBC-EDR file once and cache
compact event records (observable fields only + raw line number).

Raw files are opened read-only. Output: <out>/events/<file-stem>.pkl
Each record is a dict; labels are NOT computed here (see build_dataset.py).
"""
from __future__ import annotations

import argparse
import pickle
import sys
from multiprocessing import Pool
from pathlib import Path

import orjson

CODE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CODE_ROOT))
from preprocess.common_schema import parse_timestamp_micros  # noqa: E402

KEEP_TYPES = {
    b'"endpoint.event.procstart"': "procstart",
    b'"endpoint.event.crossproc"': "crossproc",
    b'"endpoint.event.netconn"': "netconn",
    b'"endpoint.event.filemod"': "filemod",
}
# Only file modifications of these kinds are kept as (input-only) events.
FILEMOD_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sct",
               ".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".rtf", ".html", ".htm", ".pdf")


def _s(v):
    return "" if v is None else str(v).strip()


def _f(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _pub_state(pubs):
    if not pubs:
        return "NONE"
    st = " ".join(str(p.get("state", "")) for p in pubs if isinstance(p, dict))
    if "TRUSTED" in st:
        return "SIGNED_TRUSTED"
    if "VERIFIED" in st:
        return "SIGNED_VERIFIED"
    if "SIGNED" in st:
        return "SIGNED"
    return "UNSIGNED"


def parse_file(path: str):
    out = []
    with open(path, "rb") as fh:
        for lineno, line in enumerate(fh, 1):
            head = line[:64]
            kind = None
            for key, k in KEEP_TYPES.items():
                if key in head:
                    kind = k
                    break
            if kind is None:
                continue
            try:
                r = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            ts = parse_timestamp_micros(r.get("device_timestamp"))
            if ts <= 0:
                continue
            rec = {
                "line": lineno,
                "ts": ts,
                "kind": kind,
                "action": _s(r.get("action")),
                "host": _s(r.get("device_name")).lower(),
                "guid": _s(r.get("process_guid")).lower(),
                "pguid": _s(r.get("parent_guid")).lower(),
                "path": _s(r.get("process_path")),
                "cmd": _s(r.get("process_cmdline"))[:2000],
                "ppath": _s(r.get("parent_path")),
                "user": _s(r.get("process_username")),
                "pub": _pub_state(r.get("process_publisher")),
                "tpath": "", "tguid": "", "tcmd": "", "tpub": "NONE",
                "proto": "", "rip": "", "rport": 0, "lport": 0, "inbound": False, "domain": "",
            }
            if kind == "netconn":
                rec["proto"] = _s(r.get("netconn_protocol")).upper()
                rec["rip"] = _s(r.get("remote_ip"))
                rec["rport"] = _f(r.get("remote_port"))
                rec["lport"] = _f(r.get("local_port"))
                rec["inbound"] = r.get("netconn_inbound") == 1.0
                rec["domain"] = _s(r.get("netconn_domain")).lower()
            elif kind == "procstart":
                rec["tpath"] = _s(r.get("childproc_name"))
                rec["tguid"] = _s(r.get("childproc_guid")).lower()
                rec["tcmd"] = _s(r.get("target_cmdline"))[:2000]
                rec["tpub"] = _pub_state(r.get("childproc_publisher"))
            elif kind == "crossproc":
                rec["tpath"] = _s(r.get("crossproc_name"))
                rec["tguid"] = _s(r.get("crossproc_guid")).lower()
                rec["tpub"] = _pub_state(r.get("crossproc_publisher"))
                rec["action"] = _s(r.get("crossproc_action")) or rec["action"]
            elif kind == "filemod":
                name = _s(r.get("filemod_name"))
                if not name.lower().endswith(FILEMOD_EXT):
                    continue
                rec["tpath"] = name
            out.append(rec)
    return path, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/output/raw_cbc/atlasv2/data")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out).resolve()
    if "/DATASET/" in str(out) or str(out).startswith(str(Path(args.data_dir).resolve())):
        raise SystemExit("output must be outside dataset roots")
    (out / "events").mkdir(parents=True, exist_ok=True)
    files = sorted(str(p) for p in Path(args.data_dir).rglob("*.jsonl")
                   if "cbc-edr" in str(p) and "alerts" not in str(p))
    with Pool(min(len(files), 10)) as pool:
        for path, recs in pool.imap_unordered(parse_file, files):
            stem = Path(path).stem
            with open(out / "events" / f"{stem}.pkl", "wb") as fh:
                pickle.dump({"source": path, "records": recs}, fh, protocol=pickle.HIGHEST_PROTOCOL)
            kinds = {}
            for r in recs:
                kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
            print(f"{stem:20s} {len(recs):8d} {kinds}", flush=True)


if __name__ == "__main__":
    main()
