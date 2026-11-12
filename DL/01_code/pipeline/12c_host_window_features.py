#!/usr/bin/env python3
"""STEP 12C - trich dac trung hanh vi cua host theo cua so (host, 15 phut) tu eCAR tho (E:\\host-begnin, E:\\host-malicious).

Moi file dau vao = 1 host x 1 ngay (json.gz, moi dong 1 event). Dau ra: 1 CSV moi file, moi dong = 1 cua so 15 phut (gio EDT).
Chi dem (khong luu noi dung event). Khong fit tham so nao o day; novelty cap cha-con duoc tinh o buoc sau voi tu dien chi tu TRAIN.

Cot: host, day, win_edt, n_events, n_flow, n_proc_create, n_proc_writable, n_parent_lsass, n_remote_thread, n_reg_persist,
     n_exec_drop, n_cmd_susp, pairs_json ({"parent>child": so_lan}).
"""
import argparse
import concurrent.futures as cf
import csv
import gzip
import json
import os
import re
import sys
import time

import orjson

WRITABLE = re.compile(r"\\(temp|appdata|programdata|users\\public)\\", re.I)
EXEC_EXT = (".exe", ".dll", ".vbs", ".bat", ".ps1", ".js", ".scr", ".cmd")
REG_PERSIST = re.compile(r"\\currentversion\\run|\\services\\|\\sam\\sam\\", re.I)
CMD_SUSP = re.compile(r"net\s+user|net\s+localgroup|/add\b|-encodedcommand|\bmimikatz|\bwmic\b|invoke-", re.I)
HDR = ["host", "day", "win_edt", "n_events", "n_flow", "n_proc_create", "n_proc_writable", "n_parent_lsass",
       "n_remote_thread", "n_reg_persist", "n_exec_drop", "n_cmd_susp", "pairs_json"]


def base(p):
    p = (p or "").replace("/", "\\")
    return p.rsplit("\\", 1)[-1].lower()


def process_file(args):
    path, outdir = args
    m = re.search(r"ecar-(\d{4}-\d{2}-\d{2})-(sysclient\d+)", path)
    day, host = m.group(1), m.group(2)
    out = os.path.join(outdir, f"{host}_{day}.csv")
    if os.path.exists(out):
        return out, 0, 0.0
    t0 = time.time()
    W = {}
    n = 0
    with gzip.open(path, "rb") as f:
        for line in f:
            d = orjson.loads(line)
            n += 1
            ts = d["timestamp"]
            key = ts[:11] + ts[11:13] + ":" + "%02d" % (int(ts[14:16]) // 15 * 15)  # gio EDT
            w = W.get(key)
            if w is None:
                w = W[key] = {"n_events": 0, "n_flow": 0, "n_proc_create": 0, "n_proc_writable": 0, "n_parent_lsass": 0,
                              "n_remote_thread": 0, "n_reg_persist": 0, "n_exec_drop": 0, "n_cmd_susp": 0, "pairs": {}}
            w["n_events"] += 1
            o, a = d.get("object"), d.get("action")
            if o == "FLOW":
                if a == "START":
                    w["n_flow"] += 1
            elif o == "PROCESS":
                if a == "CREATE":
                    pr = d.get("properties") or {}
                    img, par, cmd = pr.get("image_path"), pr.get("parent_image_path"), pr.get("command_line") or ""
                    w["n_proc_create"] += 1
                    if img and WRITABLE.search(img):
                        w["n_proc_writable"] += 1
                    pb = base(par)
                    if pb == "lsass.exe":
                        w["n_parent_lsass"] += 1
                    if CMD_SUSP.search(cmd):
                        w["n_cmd_susp"] += 1
                    pk = pb + ">" + base(img)
                    w["pairs"][pk] = w["pairs"].get(pk, 0) + 1
            elif o == "THREAD":
                if a == "REMOTE_CREATE":
                    w["n_remote_thread"] += 1
            elif o == "REGISTRY":
                if a in ("ADD", "EDIT"):
                    k = (d.get("properties") or {}).get("key") or ""
                    if REG_PERSIST.search(k):
                        w["n_reg_persist"] += 1
            elif o == "FILE":
                if a in ("CREATE", "WRITE", "RENAME"):
                    fp = (d.get("properties") or {}).get("file_path") or ""
                    if fp.lower().endswith(EXEC_EXT) and WRITABLE.search(fp):
                        w["n_exec_drop"] += 1
    with open(out + ".tmp", "w", newline="\n", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(HDR)
        for key in sorted(W):
            w = W[key]
            wr.writerow([host, day, key.replace("T", " "), w["n_events"], w["n_flow"], w["n_proc_create"],
                         w["n_proc_writable"], w["n_parent_lsass"], w["n_remote_thread"], w["n_reg_persist"],
                         w["n_exec_drop"], w["n_cmd_susp"], json.dumps(w["pairs"], separators=(",", ":"))])
    os.replace(out + ".tmp", out)
    return out, n, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True, help="CSV mot cot 'path' (duong dan file json.gz)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    paths = [r["path"] for r in csv.DictReader(open(a.list, encoding="utf-8"))]
    t0 = time.time()
    done_ev = 0
    with cf.ProcessPoolExecutor(a.workers) as ex:
        for i, (o, n, s) in enumerate(ex.map(process_file, [(p, a.out) for p in paths]), 1):
            done_ev += n
            print(f"[{i}/{len(paths)}] {os.path.basename(o)} events={n} {s:.0f}s total={time.time() - t0:.0f}s", flush=True)
    print("DONE", len(paths), "files", done_ev, "events", f"{time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
