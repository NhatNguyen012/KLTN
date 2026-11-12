#!/usr/bin/env python3
"""S31 (STEP 42) - ATLASv2: mọi loại sự kiện CBC EDR của tiến trình firefox.exe (và mọi tiến trình có nhãn), gộp theo process_guid, đối chiếu nhãn REAPr và nút gốc/tác động (.seeds).
Một lượt streaming trên atlasv2.tar.gz (chỉ đọc). Ghi JSON. Cách dùng: python -I s31_atlas_firefox_events.py <tar.gz> <thư mục REAPr atlasv2> <json ra>"""
import glob
import json
import os
import re
import sys
import tarfile
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8")
MEM = re.compile(r"atlasv2/data/(attack|benign)/(h\d)/cbc-edr/edr-(h\d)-([a-z0-9-]+)\.jsonl$")
TYPES = ("netconn", "filemod", "moduleload", "regmod", "crossproc", "procstart", "procend", "scriptload")
NAMEF = {"filemod": "filemod_name", "moduleload": "modload_name", "regmod": "regmod_name", "crossproc": "crossproc_name", "procstart": "childproc_name"}


def main():
    path, labdir, out = sys.argv[1:4]
    labels, seeds = {}, {}
    for f in glob.glob(os.path.join(labdir, "*.labels")):
        name = os.path.basename(f).replace(".labels", "")
        s = set()
        for i, line in enumerate(open(f, encoding="utf-8")):
            if i:
                p = [x.strip() for x in line.rstrip().split(",")]
                if len(p) >= 5:
                    s.add(p[3])
        labels[name] = s
    for f in glob.glob(os.path.join(labdir, "*.seeds")):
        name = os.path.basename(f).replace(".seeds", "")
        seeds[name] = {}
        for i, line in enumerate(open(f, encoding="utf-8")):
            if i:
                p = [x.strip() for x in line.rstrip().split(",")]
                if len(p) >= 4:
                    seeds[name][p[2].lower()] = p[3]
    procs = {}
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            mm = MEM.search(m.name) if m.isfile() else None
            if not mm:
                continue
            kind, host, _, sc = mm.groups()
            key = f"{host}-{sc}"
            lab = labels.get(key, set()) if kind == "attack" else set()
            seed = seeds.get(key, {})
            print("[member]", kind, key, flush=True)
            for raw in tf.extractfile(m):
                head = raw[:60]
                et = next((t for t in TYPES if b'"endpoint.event.' + t.encode() + b'"' in head), None)
                if et is None:
                    continue
                if b"firefox.exe" not in raw and b'"process_guid"' not in raw:
                    continue
                try:
                    d = json.loads(raw)
                except Exception:
                    continue
                pg = d.get("process_guid")
                is_ff = str(d.get("process_path", "")).lower().endswith("firefox.exe")
                if not (is_ff or pg in lab):
                    continue
                r = procs.get(pg)
                if r is None:
                    r = procs[pg] = {"kind": kind, "host": host, "scenario": sc, "path": d.get("process_path"), "label": int(pg in lab), "parent_guid": d.get("parent_guid"),
                                     "parent_path": d.get("parent_path"), "parent_label": int(d.get("parent_guid") in lab), "types": Counter(), "ts_min": None, "ts_max": None,
                                     "seed_conn": Counter(), "net_remote": Counter(), "filemod": Counter(), "crossproc": Counter(), "children": Counter(), "modload_names": set(),
                                     "regmod_n": 0, "scriptload": Counter(), "seed_file": 0, "exe_dll_swf_written": Counter()}
                r["types"][et] += 1
                ts = d.get("device_timestamp") or ""
                r["ts_min"] = ts if r["ts_min"] is None or ts < r["ts_min"] else r["ts_min"]
                r["ts_max"] = ts if r["ts_max"] is None or ts > r["ts_max"] else r["ts_max"]
                if et == "netconn" and d.get("remote_ip"):
                    ip = f"{d['remote_ip']}:{int(d['remote_port']) if d.get('remote_port') is not None else ''}"
                    r["net_remote"][ip] += 1
                    if ip.lower() in seed:
                        r["seed_conn"][f"{ip}={seed[ip.lower()]}"] += 1
                elif et == "filemod":
                    nm = str(d.get("filemod_name") or "").lower()
                    base = nm.split("\\")[-1]
                    r["filemod"][re.sub(r"[0-9a-f]{6,}", "#", base)[:60]] += 1
                    if nm in seed:
                        r["seed_file"] += 1
                    if re.search(r"\.(exe|dll|swf|bat|ps1|vbs|js|hta)$", nm) and ("\\users\\" in nm or "\\temp\\" in nm):
                        r["exe_dll_swf_written"][nm[-80:]] += 1
                elif et == "crossproc":
                    r["crossproc"][f"{d.get('crossproc_action')}->{str(d.get('crossproc_name') or '').split(chr(92))[-1]}"] += 1
                elif et == "procstart":
                    r["children"][str(d.get("childproc_name") or "").split("\\")[-1].lower()] += 1
                elif et == "moduleload":
                    r["modload_names"].add(str(d.get("modload_name") or "").lower().split("\\")[-1])
                elif et == "regmod":
                    r["regmod_n"] += 1
                elif et == "scriptload":
                    r["scriptload"][str(d.get("action"))] += 1
    res = {}
    for pg, r in procs.items():
        res[pg] = {k: (len(v) if isinstance(v, set) else (dict(v.most_common(12)) if isinstance(v, Counter) else v)) for k, v in r.items()}
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong] processes", len(res), flush=True)


if __name__ == "__main__":
    main()
