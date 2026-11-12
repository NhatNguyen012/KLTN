#!/usr/bin/env python3
"""STEP 12C - lap danh sach file eCAR tho can quet (split seed_1).
TRAIN: ngay benign 22/9, mau ngau nhien 150 host (seed 42) co file host.
VAL/TEST: ngay 23, 24, 25/9 (E:\\host-malicious) cua tat ca host VAL/TEST co file host."""
import csv
import glob
import random

import pandas as pd

M = "D:/UIT/KLTNv2/03_datasets/random_network_dl_v1_1_15m/seed_1/split/network_sample_manifest.csv"
OUT = "D:/UIT/KLTNv2/02_artifacts/12c_host_features_v1/"
hs = pd.read_csv(M, usecols=["hostname", "split"]).drop_duplicates().groupby("hostname")["split"].first()


def find(day, host, kind):
    g = glob.glob(f"E:/{kind}/{day}/*/*ecar-{day}-{host}.json.gz")
    return g[0].replace("\\", "/") if g else None


rows = []
train = sorted(hs[hs == "train"].index)
tr_have = [h for h in train if find("2019-09-22", h, "host-begnin")]
random.Random(42).shuffle(tr_have)
for h in sorted(tr_have[:150]):
    rows.append(("train", h, "2019-09-22", find("2019-09-22", h, "host-begnin")))
for sp in ("val", "test"):
    for h in sorted(hs[hs == sp].index):
        for d in ("2019-09-23", "2019-09-24", "2019-09-25"):
            p = find(d, h, "host-malicious")
            if p:
                rows.append((sp, h, d, p))
with open(OUT + "scan_list.csv", "w", newline="\n", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["split", "host", "day", "path"])
    w.writerows(rows)
print("train hosts with host logs:", len(tr_have), "(of", len(train), ")")
for sp in ("train", "val", "test"):
    r = [x for x in rows if x[0] == sp]
    print(sp, "files", len(r), "hosts", len({x[1] for x in r}))
with open(OUT + "scan_paths.csv", "w", newline="\n", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["path"])
    for x in rows:
        w.writerow([x[3]])
