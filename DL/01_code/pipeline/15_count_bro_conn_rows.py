#!/usr/bin/env python3
"""STEP 15 (bước 1) - đo quy mô Bro conn.log theo ngày/giờ để ước lượng kích thước biến thể left join.
Chỉ đếm dòng (không bỏ dòng '#'), đọc E:\\bro\\<ngày>\\conn.*.log.gz. Ghi 15_leftjoin_scale_v1/conn_rows_by_file.csv."""
import concurrent.futures as cf
import csv
import glob
import gzip
import os
import time

OUT = "D:/UIT/KLTNv2/02_artifacts/15_leftjoin_scale_v1"


def count(p):
    n = 0
    with gzip.open(p, "rb") as f:
        for line in f:
            if line[:1] != b"#":
                n += 1
    return p, n, os.path.getsize(p)


def main():
    os.makedirs(OUT, exist_ok=True)
    files = sorted(glob.glob("E:/bro/*/conn.*.log.gz"))
    print(len(files), "files", flush=True)
    t0 = time.time()
    rows = []
    with cf.ProcessPoolExecutor(6) as ex:
        for i, (p, n, sz) in enumerate(ex.map(count, files), 1):
            p = p.replace("\\", "/")
            rows.append([p.split("/")[2], os.path.basename(p), n, sz])
            if i % 20 == 0:
                print(i, "/", len(files), f"{time.time() - t0:.0f}s", flush=True)
    with open(OUT + "/conn_rows_by_file.csv", "w", newline="\n", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["day_utc", "file", "rows", "compressed_bytes"])
        w.writerows(rows)
    print("DONE", sum(r[2] for r in rows), "rows", f"{time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
