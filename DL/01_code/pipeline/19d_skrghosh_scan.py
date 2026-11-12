#!/usr/bin/env python3
"""STEP 19d - quét skrghosh/apt-dataset (5 zip JSONL, định dạng eCAR) trực tiếp từ zip, không giải nén.
Đếm: số dòng, object, action, hostname, có/không trường label, khoảng thời gian; json.loads mỗi 50 dòng để lấy tập khóa.
Ra: 02_artifacts/19_dataset_analysis_v1/skrghosh_scan.json (+ skrghosh_object_counts.csv)
"""
import collections
import csv
import json
import re
import sys
import time
import zipfile

sys.stdout.reconfigure(encoding="utf-8")
B = "D:/UIT/KLTNv2/03_datasets/skrghosh/apt-dataset-git"
OUT = "D:/UIT/KLTNv2/02_artifacts/19_dataset_analysis_v1"
NAMES = ["apt29", "fin6", "oilrig", "output_menuPass", "wizard_spider"]
RE_OBJ = re.compile(rb'"object":"([A-Z_]+)"')
RE_ACT = re.compile(rb'"action":"([A-Z_]+)"')
RE_TS = re.compile(rb'"timestamp":"([^"]+)"')


def main():
    res, rows = {}, []
    for n in NAMES:
        t0 = time.time()
        with zipfile.ZipFile(f"{B}/{n}.json.zip") as zf:
            info = [i for i in zf.infolist() if not i.filename.startswith("__MACOSX")][0]
            nl = nlab = nbad = 0
            obj, act, keys, host, pkeys = (collections.Counter() for _ in range(5))
            first_ts = last_ts = None
            label_examples = []
            with zf.open(info) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    nl += 1
                    m = RE_OBJ.search(line)
                    o = m.group(1).decode() if m else "?"
                    obj[o] += 1
                    m = RE_ACT.search(line)
                    act[(o, m.group(1).decode() if m else "?")] += 1
                    if b'"label"' in line[-40:] or b'"label"' in line:
                        nlab += 1
                        if len(label_examples) < 3:
                            label_examples.append(line[:300].decode("utf-8", "replace"))
                    if nl % 50 == 1:
                        try:
                            j = json.loads(line)
                            keys[tuple(sorted(j.keys()))] += 1
                            host[j.get("hostname")] += 1
                            for k in (j.get("properties") or {}):
                                pkeys[(o, k)] += 1
                        except Exception:
                            nbad += 1
                    if nl == 1:
                        first_ts = RE_TS.search(line).group(1).decode()
                    if nl % 1000 == 0:
                        m = RE_TS.search(line)
                        if m:
                            last_ts = m.group(1).decode()
            res[n] = {"file": info.filename, "lines": nl, "lines_with_label_key": nlab, "label_examples": label_examples, "bad_json_in_sample": nbad,
                      "objects": dict(obj.most_common()), "top_actions": {f"{k[0]}/{k[1]}": v for k, v in act.most_common(25)},
                      "key_sets_in_sample": {",".join(k): v for k, v in keys.most_common(5)}, "hostnames_sample": dict(host.most_common(5)),
                      "properties_keys_sample": {f"{k[0]}:{k[1]}": v for k, v in pkeys.most_common(30)}, "first_ts": first_ts, "last_ts_approx": last_ts}
            for o, c in obj.most_common():
                rows.append({"campaign": n, "object": o, "count": c, "pct": round(100 * c / nl, 3)})
            print(n, nl, "lines", f"{time.time()-t0:.0f}s", "label-key lines:", nlab, "| objects:", dict(obj.most_common(6)), "| ts", first_ts, "->", last_ts, flush=True)
    json.dump(res, open(f"{OUT}/skrghosh_scan.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    with open(f"{OUT}/skrghosh_object_counts.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=["campaign", "object", "count", "pct"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print("DONE")


if __name__ == "__main__":
    main()
