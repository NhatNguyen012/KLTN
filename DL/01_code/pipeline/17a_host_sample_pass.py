#!/usr/bin/env python3
"""STEP 17a - lượt quét eCAR thô để retrain nhánh Host theo split host-disjoint (bản gọn của pipeline Nguyễn).

Dùng lại tokenizer của Nguyễn (D:/UIT/KLTN/KLTN-main/code/ecar_tokenizer.py), KHÔNG sửa code của Nguyễn.
Với mỗi file (host, ngày) của host có trong host_split_seed1.csv:
  - event hợp lệ = object thuộc HOST_OBJECT_FIELDS (không phải FLOW), giống Nguyễn;
  - nhãn: đuôi dòng '"label": 1}' (bản corrected); file benign không có nhãn = 0;
  - giữ 100% event dương; event âm lấy Bernoulli q0 (kèm số ngẫu nhiên u để cắt về đúng tỉ lệ 30:1 sau);
  - riêng host TRAIN: token hóa 100% dương + âm với xác suất q_vocab để đếm tf/df cho từ điển.
Ghi: work/sample/<split>/<ngày>__<host>.jsonl.gz, work/vocab/<ngày>__<host>.json.gz, work/summary/<ngày>__<host>.json.
Chạy lại an toàn (bỏ qua file đã có summary).
"""
import argparse
import concurrent.futures as cf
import glob
import gzip
import json
import os
import sys
import time
import zlib
from collections import Counter

import numpy as np
import orjson
import pandas as pd

sys.path.insert(0, "D:/UIT/KLTN/KLTN-main/code")
from ecar_tokenizer import GROUPS, HOST_OBJECT_FIELDS, tokenize_record  # noqa: E402

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/17_host_retrain_v1"
SEED = 1
Q0 = {"train": 0.004, "val": 0.006, "test": 0.006}   # xác suất giữ event âm làm ứng viên mẫu
Q_VOCAB = 0.03                                          # xác suất event âm TRAIN dùng để đếm từ điển
BLOCK = 1 << 20


def list_files():
    sp = pd.read_csv(R + "/02_artifacts/16_host_branch_request_v1/host_split_seed1.csv").set_index("hostname")["split"]
    rows = []
    for kind in ("host-begnin", "host-malicious"):
        for p in sorted(glob.glob(f"E:/{kind}/2019-09-*/*/*.json.gz")):
            p = p.replace("\\", "/")
            b = os.path.basename(p)
            host = b.split("-")[-1].split(".")[0]
            day = b.split("ecar-")[1][:10]
            if host in sp.index:
                rows.append((p, kind, host, day, sp[host]))
    return rows


def _loads(line):
    try:
        return orjson.loads(line)
    except ValueError:
        return None


def safe_lines(f, cnt):
    """Đọc từng dòng; nếu file .gz hỏng giữa chừng thì dừng tại chỗ lỗi, đánh dấu 'truncated' và giữ phần đã đọc."""
    try:
        for line in f:
            yield line
    except (zlib.error, EOFError, OSError):
        cnt["truncated"] = 1


def _process_file(task):
    path, kind, host, day, split = task
    work = OUT + "/work"
    key = f"{day}__{host}"
    sfile = f"{work}/summary/{key}.json"
    if os.path.exists(sfile):
        return json.load(open(sfile))
    t0 = time.time()
    rng = np.random.default_rng(SEED * 1000003 + zlib.crc32(path.encode()))
    q0, qv = Q0[split], Q_VOCAB
    cnt = Counter()
    tf = {g: Counter() for g in GROUPS}
    df = {g: Counter() for g in GROUPS}
    kept = []
    us = rng.random(BLOCK)
    k = 0
    with gzip.open(path, "rb") as f:
        for line in safe_lines(f, cnt):
            cnt["lines"] += 1
            i = line.find(b'"object": "')
            if i < 0:
                continue
            j = line.find(b'"', i + 11)
            if line[i + 11:j].decode("ascii", "ignore").casefold() not in HOST_OBJECT_FIELDS:
                continue
            cnt["eligible"] += 1
            pos = b'"label": 1}' in line[-16:]
            if pos:
                cnt["pos"] += 1
                rec = _loads(line)
                if rec is None:
                    cnt["bad_json"] += 1
                    continue
                rec["label"] = 1
                rec["_u"] = -1.0
                kept.append(rec)
                if split == "train":
                    grouped, audit = tokenize_record(rec)
                    for g, toks in grouped.items():
                        tf[g].update(toks)
                        df[g].update(set(toks))
                continue
            cnt["neg"] += 1
            if k >= BLOCK:
                us = rng.random(BLOCK)
                k = 0
            u = float(us[k])
            k += 1
            if u < q0:
                rec = _loads(line)
                if rec is None:
                    cnt["bad_json"] += 1
                    continue
                rec["label"] = 0
                rec["_u"] = u
                kept.append(rec)
                cnt["neg_kept"] += 1
            if split == "train" and u < qv:
                rec = (_loads(line) if u >= q0 else rec)
                if rec is None:
                    cnt["bad_json"] += 1
                    continue
                grouped, audit = tokenize_record(rec)
                cnt["neg_vocab"] += 1
                for g, toks in grouped.items():
                    tf[g].update(toks)
                    df[g].update(set(toks))
    os.makedirs(f"{work}/sample/{split}", exist_ok=True)
    with gzip.open(f"{work}/sample/{split}/{key}.jsonl.gz", "wb", compresslevel=3) as out:
        for rec in kept:
            rec["_host"] = host
            rec["_day"] = day
            out.write(orjson.dumps(rec) + b"\n")
    if split == "train":
        os.makedirs(work + "/vocab", exist_ok=True)
        with gzip.open(f"{work}/vocab/{key}.json.gz", "wt") as out:
            json.dump({"tf": tf, "df": df}, out)
    os.makedirs(work + "/summary", exist_ok=True)
    res = {"file": path, "kind": kind, "host": host, "day": day, "split": split, **cnt, "seconds": round(time.time() - t0, 1)}
    with open(sfile + ".tmp", "w") as fo:
        json.dump(res, fo)
    os.replace(sfile + ".tmp", sfile)
    return res


def process_file(task):
    """Bọc _process_file: một file .gz hỏng không làm dừng cả lượt quét; ghi lỗi để xử lý sau."""
    path, kind, host, day, split = task
    last = None
    for attempt in range(2):
        try:
            return _process_file(task)
        except Exception as e:  # zlib.error, EOFError, OSError...
            last = f"{type(e).__name__}: {e}"
            time.sleep(2)
    os.makedirs(OUT + "/work/failed", exist_ok=True)
    with open(f"{OUT}/work/failed/{day}__{host}.txt", "w", encoding="utf-8") as fo:
        fo.write(path + "\n" + str(last) + "\n")
    return {"file": path, "kind": kind, "host": host, "day": day, "split": split, "error": last, "lines": 0, "seconds": 0}


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--limit", type=int, default=0, help="chỉ chạy N file đầu (pilot)")
    ap.add_argument("--only", default="", help="lọc theo chuỗi con của đường dẫn (pilot)")
    a = ap.parse_args()
    files = list_files()
    if a.only:
        files = [f for f in files if a.only in f[0]]
    if a.limit:
        files = files[: a.limit]
    print(len(files), "files;", Counter(f[4] for f in files), flush=True)
    t0 = time.time()
    done_lines = 0
    with cf.ProcessPoolExecutor(a.workers) as ex:
        for i, r in enumerate(ex.map(process_file, files, chunksize=1), 1):
            done_lines += r.get("lines", 0)
            if r.get("error"):
                print(f"[{i}/{len(files)}] LỖI {r['day']} {r['host']}: {r['error']}", flush=True)
                continue
            print(f"[{i}/{len(files)}] {r['day']} {r['host']} {r['split']} lines={r.get('lines')} pos={r.get('pos', 0)} "
                  f"neg_kept={r.get('neg_kept', 0)} {r['seconds']}s | total {time.time() - t0:.0f}s {done_lines / 1e6:.0f}M lines", flush=True)
    failed = sorted(glob.glob(OUT + "/work/failed/*.txt"))
    print("FAILED_FILES", len(failed), flush=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
