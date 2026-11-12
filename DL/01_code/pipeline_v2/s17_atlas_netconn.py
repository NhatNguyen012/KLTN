#!/usr/bin/env python3
"""S17e - ATLASv2: đếm sự kiện netconn của Carbon Black EDR theo (host, scenario, benign/attack) và nối nhãn REAPr (process_uuid = process_guid).

Một lượt streaming trên atlasv2.tar.gz, chỉ đọc thành viên cbc-edr/*.jsonl. Cách dùng: python -I s17_atlas_netconn.py <tar.gz> <thư mục .labels> <json ra>"""
import glob
import json
import os
import re
import sys
import tarfile
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8")
MEM = re.compile(r"atlasv2/data/(attack|benign)/(h\d)/cbc-edr/edr-(h\d)-([a-z0-9-]+)\.jsonl$")


def main():
    path, labdir, out = sys.argv[1:4]
    labels = {}
    for f in glob.glob(os.path.join(labdir, "*.labels")):
        name = os.path.basename(f).replace(".labels", "")  # h1-m1
        s = set()
        for i, line in enumerate(open(f, encoding="utf-8")):
            if i == 0:
                continue
            p = [x.strip() for x in line.rstrip().split(",")]
            if len(p) >= 5:
                s.add(p[3])
        labels[name] = s
    res = {}
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            mm = MEM.search(m.name) if m.isfile() else None
            if not mm:
                continue
            kind, host, _, sc = mm.groups()
            key = f"{kind}/{host}/{sc}"
            lab = labels.get(f"{host}-{sc}", set()) if kind == "attack" else set()
            print("[member]", key, m.size, flush=True)
            r = {"n_lines": 0, "netconn": 0, "pos_netconn": 0, "pos_procs_with_netconn": set(), "protocol": Counter(), "inbound": Counter(), "action": Counter(), "ts_min": None, "ts_max": None,
                 "pos_targets": Counter(), "paths": Counter(), "remote_port": Counter(), "users": Counter(), "has_domain": 0, "windows": set(), "pos_windows": set()}
            for raw in tf.extractfile(m):
                r["n_lines"] += 1
                if b'"endpoint.event.netconn"' not in raw[:60]:
                    continue
                try:
                    d = json.loads(raw)
                except Exception:
                    continue
                r["netconn"] += 1
                r["protocol"][str(d.get("netconn_protocol"))] += 1
                r["inbound"][str(d.get("netconn_inbound"))] += 1
                r["action"][str(d.get("action"))] += 1
                r["paths"][d.get("process_path")] += 1
                r["users"][d.get("process_username")] += 1
                r["remote_port"][d.get("remote_port")] += 1
                r["has_domain"] += bool(d.get("netconn_domain"))
                ts = d.get("device_timestamp") or ""
                r["ts_min"] = ts if r["ts_min"] is None or ts < r["ts_min"] else r["ts_min"]
                r["ts_max"] = ts if r["ts_max"] is None or ts > r["ts_max"] else r["ts_max"]
                w = ts[:15]  # YYYY-MM-DD HH:M -> cửa sổ 10 phút xấp xỉ (chỉ để đếm sơ)
                r["windows"].add(ts[:13] + ":" + str(int(ts[14:16] or 0) // 15))
                if d.get("process_guid") in lab:
                    r["pos_netconn"] += 1
                    r["pos_procs_with_netconn"].add(d["process_guid"])
                    r["pos_targets"][f"{d.get('remote_ip')}:{int(d['remote_port']) if d.get('remote_port') is not None else None}"] += 1
                    r["pos_windows"].add(ts[:13] + ":" + str(int(ts[14:16] or 0) // 15))
            res[key] = {k: (len(v) if isinstance(v, set) else (dict(v.most_common(12)) if isinstance(v, Counter) else v)) for k, v in r.items()}
            res[key]["n_labeled_procs"] = len(lab)
            json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", len(res), flush=True)


if __name__ == "__main__":
    main()
