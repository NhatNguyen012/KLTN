#!/usr/bin/env python3
"""STEP 19a - quét nhãn SAGA (3 zip, 38 file JSONL) trực tiếp từ zip, không giải nén.
Mỗi dòng = 1 event {srcNode, dstNode, relation, timestamp, label}; label là "benign" hoặc "Txxxx[.yyy]_<ability_id>".
Chỉ đếm: số dòng, nhãn, quan hệ, loại dstNode, khoảng thời gian. Không ghi gì vào 03_datasets.
Ra: 02_artifacts/19_dataset_analysis_v1/saga_label_counts.csv, saga_file_summary.csv
"""
import collections
import csv
import os
import re
import sys
import time
import zipfile

sys.stdout.reconfigure(encoding="utf-8")
B = "D:/UIT/KLTNv2/03_datasets/SAGA"
OUT = "D:/UIT/KLTNv2/02_artifacts/19_dataset_analysis_v1"
os.makedirs(OUT, exist_ok=True)
ZIPS = [("known", "Known APT Campaigns Dataset.zip"), ("generated", "Generated APT Campaigns Dataset.zip"), ("composite", "Composite APT Campaigns Dataset.zip")]
RE_LABEL = re.compile(rb'"label": "([^"]*)"\}\s*$')
RE_TS = re.compile(rb'"timestamp": (\d+)')
RE_REL = re.compile(rb'"relation": "([^"]*)"')
RE_DST = re.compile(rb'"dstNode": \{[^{}]*?"Type": "([^"]*)"')


def main():
    lab_rows, sum_rows = [], []
    t_all = time.time()
    for grp, z in ZIPS:
        with zipfile.ZipFile(f"{B}/{z}") as zf:
            for info in sorted(zf.infolist(), key=lambda i: (len(i.filename), i.filename)):
                t0 = time.time()
                n = nb = nodata = 0
                labs = collections.Counter()
                rels_mal = collections.Counter()
                dst_mal = collections.Counter()
                tmin, tmax = 10**12, 0
                with zf.open(info) as f:
                    for line in f:
                        n += 1
                        m = RE_LABEL.search(line, max(0, len(line) - 120))
                        if not m:
                            nodata += 1
                            continue
                        lb = m.group(1)
                        mt = RE_TS.search(line, max(0, len(line) - 200))
                        if mt:
                            t = int(mt.group(1))
                            if t < tmin:
                                tmin = t
                            if t > tmax:
                                tmax = t
                        if lb == b"benign":
                            nb += 1
                        else:
                            labs[lb.decode()] += 1
                            mr = RE_REL.search(line)
                            if mr:
                                rels_mal[mr.group(1).decode()] += 1
                            md = RE_DST.search(line)
                            dst_mal[md.group(1).decode() if md else "?"] += 1
                nm = sum(labs.values())
                tech = collections.Counter()
                for k, v in labs.items():
                    tech[k.split("_")[0]] += v
                sum_rows.append({"group": grp, "file": info.filename, "n_events": n, "n_benign": nb, "n_malicious": nm, "pct_malicious": round(100 * nm / max(n, 1), 3),
                                 "n_distinct_labels": len(labs), "n_distinct_techniques": len(tech), "top_label_share_of_malicious": round(max(labs.values()) / nm, 3) if nm else 0,
                                 "unparsed_lines": nodata, "t_min": tmin, "t_max": tmax, "span_minutes": round((tmax - tmin) / 60, 1) if tmax else 0,
                                 "malicious_dst_types": dict(dst_mal.most_common(4)), "malicious_top_relations": dict(rels_mal.most_common(4))})
                for k, v in labs.items():
                    lab_rows.append({"group": grp, "file": info.filename, "label": k, "technique": k.split("_")[0], "count": v})
                print(f"{grp:9s} {info.filename:10s} n={n:>8d} mal={nm:>6d} ({100*nm/max(n,1):.2f}%) techniques={len(tech):>2d} span={sum_rows[-1]['span_minutes']} min  {time.time()-t0:.0f}s", flush=True)
    for name, rows in (("saga_label_counts.csv", lab_rows), ("saga_file_summary.csv", sum_rows)):
        with open(f"{OUT}/{name}", "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
    print("DONE", f"{time.time()-t_all:.0f}s")


if __name__ == "__main__":
    main()
