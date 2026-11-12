"""STEP 47: cau noi (source_id, source_line) -> UUID su kien eCAR (id), toan bo 106 file.

Doc E:\\host-malicious / E:\\host-begnin (chi doc). Chi trich cac dong co diem LightGBM (VAL+TEST).
Kiem tra tung file: (a) so dong file == do dai mask split; (b) mask tai dong duoc chon dung ma VAL=2/TEST=3
(tu xac dinh co so chi muc 0 hay 1); (c) hostname trong ban ghi == host cua file.
Dung: s35_bridge_uuid.py <package_root> <out_dir> [workers]
"""
from __future__ import annotations

import gzip
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np
import pandas as pd

PKG = Path(sys.argv[1])
OUT = Path(sys.argv[2])
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 6
PARTS = OUT / "parts"


def to_e(p: str) -> Path:
    i = max(p.find("host-malicious"), p.find("host-begnin"))
    return Path("E:/") / Path(*p[i:].split("/"))


def work(task):
    sid, path, host, mask_file, lines, scores, labels, splits = task
    outp = PARTS / f"{sid}.parquet"
    if outp.exists():
        return sid, "skip", 0, 0.0
    t0 = time.time()
    mask = np.frombuffer(gzip.open(mask_file).read(), dtype=np.uint8)
    order = np.argsort(lines)
    lines, scores, labels, splits = lines[order], scores[order], labels[order], splits[order]
    code = np.where(splits == "val", 2, 3).astype(np.uint8)
    base = None
    for b in (1, 0):  # b=1: dong 1-based => chi muc mask = line-1
        idx = lines - b
        if idx.min() >= 0 and idx.max() < len(mask) and (mask[idx] == code).all():
            base = b
            break
    need = {int(l): k for k, l in enumerate(lines)}
    ids = [None] * len(lines)
    ts = [None] * len(lines)
    act = [None] * len(lines)
    obj = [None] * len(lines)
    hn = [None] * len(lines)
    n = 0
    with gzip.open(path, "rb") as f:
        for n, raw in enumerate(f, start=1):
            if n in need:
                r = json.loads(raw)
                k = need[n]
                ids[k] = r.get("id")
                ts[k] = r.get("timestamp")
                act[k] = r.get("action")
                obj[k] = r.get("object")
                hn[k] = r.get("hostname")
    total = n
    df = pd.DataFrame({
        "source_id": sid, "source_line": lines, "event_id": ids, "timestamp": ts,
        "action": act, "object": obj, "hostname_raw": hn, "split": splits,
        "label": labels, "score": scores,
    })
    df["file_host"] = host
    df["mask_base"] = -1 if base is None else base
    df["file_lines"] = total
    df["mask_len"] = len(mask)
    PARTS.mkdir(parents=True, exist_ok=True)
    df.to_parquet(outp, index=False)
    return sid, ("ok" if base is not None and total == len(mask) else "WARN"), len(df), time.time() - t0


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    PARTS.mkdir(parents=True, exist_ok=True)
    mi = json.load(open(PKG / "P0_EXPERIMENT_IDENTITY" / "model_input_manifest.json", encoding="utf-8"))
    sm = json.load(open(PKG / "P0_EXPERIMENT_IDENTITY" / "split_manifest.json", encoding="utf-8"))
    art = {e["source"]["path"]: e["artifact"] for e in sm["entries"]}
    sc = pd.concat([
        pd.read_parquet(PKG / "P0_SCORES_VAL_TEST" / "val_scores.parquet"),
        pd.read_parquet(PKG / "P0_SCORES_VAL_TEST" / "test_scores.parquet"),
    ], ignore_index=True)
    g = {k: v for k, v in sc.groupby("source_id")}
    tasks = []
    for s in mi["sources"]:
        sid = s["source_id"]
        if sid not in g:
            continue
        d = g[sid]
        p = to_e(s["source"]["path"])
        mf = PKG / "P0_FROZEN_SPLIT_AND_INDEX" / "split" / art[s["source"]["path"]]
        tasks.append((sid, str(p), s["file_host"], str(mf), d.source_line.to_numpy(np.int64),
                      d.score.to_numpy(np.float64), d.label.to_numpy(np.int8), d.split.to_numpy(object)))
    tasks.sort(key=lambda t: -Path(t[1]).stat().st_size)
    print("files", len(tasks), "rows", len(sc), flush=True)
    t0 = time.time()
    done = 0
    with Pool(WORKERS) as pool:
        for sid, st, n, dt in pool.imap_unordered(work, tasks):
            done += 1
            print(f"[{done}/{len(tasks)}] {sid[:10]} {st} rows={n} {dt:.0f}s elapsed={time.time()-t0:.0f}s", flush=True)
    parts = [pd.read_parquet(p) for p in sorted(PARTS.glob("*.parquet"))]
    full = pd.concat(parts, ignore_index=True)
    full.to_parquet(OUT / "bridge_scores_uuid.parquet", index=False)
    print("TOTAL rows", len(full), "null event_id", int(full.event_id.isna().sum()),
          "mask_base counts", full.groupby("mask_base").size().to_dict(),
          "host mismatch", int((full.hostname_raw.str.lower().str.split(".").str[0] != full.file_host).sum()), flush=True)


if __name__ == "__main__":
    main()
