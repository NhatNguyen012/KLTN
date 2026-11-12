#!/usr/bin/env python3
"""Tai processed/network-flows cua Unraveled (bucket S3 cong khai dapt2021). Da duoc nguoi dung xac nhan ngay 2026-10-06
(175 file, ~3.72 GB). Bo qua file da co dung dung luong; ghi manifest de kiem tra."""
import concurrent.futures as cf
import csv
import os
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

B = "https://dapt2021.s3.amazonaws.com/"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
PREFIX = "processed/network-flows/"
OUT = sys.argv[1] if len(sys.argv) > 1 else "D:/UIT/KLTNv2/03_datasets/unraveled_v1"


def list_keys():
    keys, marker = [], ""
    while True:
        q = {"prefix": PREFIX, "max-keys": "1000"}
        if marker:
            q["marker"] = marker
        root = ET.fromstring(urllib.request.urlopen(B + "?" + urllib.parse.urlencode(q), timeout=60).read())
        last = None
        for c in root.findall(NS + "Contents"):
            k, s = c.find(NS + "Key").text, int(c.find(NS + "Size").text)
            if s > 0 and not k.endswith("/"):
                keys.append((k, s))
            last = k
        if root.find(NS + "IsTruncated").text == "true":
            marker = last
        else:
            return keys


def fetch(k, s):
    dst = os.path.join(OUT, k.replace("processed/", "", 1))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst) and os.path.getsize(dst) == s:
        return k, s
    for attempt in range(5):
        try:
            tmp = dst + ".part"
            urllib.request.urlretrieve(B + urllib.parse.quote(k), tmp)
            if os.path.getsize(tmp) != s:
                raise IOError("size mismatch")
            os.replace(tmp, dst)
            return k, s
        except Exception as e:  # thu lai
            print("retry", k, attempt, e, flush=True)
            time.sleep(3)
    raise SystemExit("FAILED " + k)


def main():
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    keys = list_keys()
    total = sum(s for _, s in keys)
    print(f"{len(keys)} files, {total / 1e9:.2f} GB, workers={workers}", flush=True)
    os.makedirs(OUT, exist_ok=True)
    done, rows, t0 = 0, [], time.time()
    with cf.ThreadPoolExecutor(workers) as ex:
        for k, s in ex.map(lambda ks: fetch(*ks), keys):
            done += s
            rows.append((k, s))
            print(f"{done / 1e9:6.2f}/{total / 1e9:.2f} GB  {k}  ({time.time() - t0:.0f}s)", flush=True)
    with open(os.path.join(OUT, "manifest_downloaded.csv"), "w", newline="\n") as f:
        w = csv.writer(f)
        w.writerow(["key", "size_bytes"])
        w.writerows(rows)
    print("DONE", len(rows), "files", flush=True)


if __name__ == "__main__":
    main()
