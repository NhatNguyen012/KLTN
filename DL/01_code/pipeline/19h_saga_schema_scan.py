#!/usr/bin/env python3
"""STEP 19h - phân tích trường (schema) thô của SAGA: kiểu, khóa, quan hệ, loại node, UUID, trùng lặp giữa file.
Phương pháp: json.loads 1 dòng trong mỗi 10 dòng (đều đặn) + TẤT CẢ dòng độc hại; đếm số lượng của phần lấy mẫu được ghi rõ.
Dùng: python 19h_saga_schema_scan.py <zip_index 0|1|2>  -> ghi scratch json; phần tổng hợp ở 19h_saga_schema_report.py
"""
import collections
import json
import pickle
import re
import sys
import zipfile

SAGA = "D:/UIT/KLTNv2/03_datasets/SAGA"
ZIPS = ["Known APT Campaigns Dataset.zip", "Generated APT Campaigns Dataset.zip", "Composite APT Campaigns Dataset.zip"]
OUT = sys.argv[2] if len(sys.argv) > 2 else "."
STEP = 10


def main():
    zi = int(sys.argv[1])
    res = {}
    with zipfile.ZipFile(f"{SAGA}/{ZIPS[zi]}") as zf:
        for info in sorted(zf.infolist(), key=lambda i: (len(i.filename), i.filename)):
            C = collections.defaultdict(collections.Counter)
            uu_src, uu_dst = set(), set()
            n = ns = nm = 0
            with zf.open(info) as f:
                for raw in f:
                    n += 1
                    mal = not raw.rstrip().endswith(b'"benign"}')
                    if not mal and n % STEP:
                        continue
                    o = json.loads(raw)
                    grp = "mal" if mal else "ben"
                    nm += mal
                    ns += not mal
                    s, d = o.get("srcNode") or {}, o.get("dstNode") or {}
                    C["top_keys"][(grp, tuple(sorted(o)))] += 1
                    C["src_keys"][(grp, tuple(sorted(s)))] += 1
                    C["src_type"][(grp, s.get("Type"))] += 1
                    dt = d.get("Type")
                    C["dst_type"][(grp, dt)] += 1
                    C["dst_keys"][(grp, dt, tuple(sorted(d)))] += 1
                    C["relation"][(grp, o.get("relation"))] += 1
                    C["rel_by_dst"][(grp, dt, o.get("relation"))] += 1
                    C["ts_type"][type(o.get("timestamp")).__name__] += 1
                    C["pid_type"][type(s.get("Pid")).__name__] += 1
                    C["label_type"][type(o.get("label")).__name__] += 1
                    if dt == "Network":
                        C["port_type"][type(d.get("Port")).__name__] += 1
                        C["net_proto_keys"][tuple(sorted(d))] += 1
                    if "Value" in d:
                        C["value_type"][(dt, type(d.get("Value")).__name__)] += 1
                    for u, st in ((s.get("UUID"), uu_src), (d.get("UUID"), uu_dst)):
                        if u:
                            C["uuid_version"][u[14:15]] += 1
                            st.add(u)
                    if grp == "mal":
                        C["mal_label_by_dst"][(o["label"].split("_")[0], dt)] += 1
                        C["mal_src_image"][(s.get("Name") or "")[:40]] += 1
            res[info.filename] = {"n_lines": n, "n_sampled_benign": ns, "n_malicious_parsed": nm, "C": {k: dict(v) for k, v in C.items()},
                                  "n_uuid_src": len(uu_src), "n_uuid_dst": len(uu_dst), "src_uuids": uu_src, "dst_uuids": uu_dst}
            print(info.filename, n, ns, nm, flush=True)
    pickle.dump(res, open(f"{OUT}/saga_schema_{zi}.pkl", "wb"))
    print("DONE")


if __name__ == "__main__":
    main()
