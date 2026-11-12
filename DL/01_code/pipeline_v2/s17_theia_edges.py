#!/usr/bin/env python3
"""S17d - THEIA: nối nhãn cạnh REAPr (edge_labels.csv, theo Event.uuid) với sự kiện trong raw; đếm cạnh có nhãn chạm NetFlowObject.

Một lượt streaming trên .tar.gz (không giải nén). Cách dùng: python -I s17_theia_edges.py <raw tar.gz> <edge_labels.tar.gz> <json ra>"""
import json
import re
import sys
import tarfile
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8")
UUID_RE = re.compile(r'cdm18\.Event":\{"uuid":"([0-9A-Fa-f-]+)"')
PO_RE = re.compile(r'"predicateObject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
TS_RE = re.compile(r'"timestampNanos":(\d+)')
SUBJ_RE = re.compile(r'"subject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
TYPE_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')
RA_RE = re.compile(r'"remoteAddress":"([^"]*)"')
RP_RE = re.compile(r'"remotePort":(-?\d+)')
NF_RE = re.compile(r'^\{"datum":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.NetFlowObject":\{"uuid":"([0-9A-Fa-f-]+)"')


def main():
    raw, edges, out = sys.argv[1:4]
    lab = {}
    with tarfile.open(edges, "r:gz") as tf:
        for m in tf:
            if m.isfile():
                for i, line in enumerate(tf.extractfile(m)):
                    if i == 0:
                        continue
                    p = [x.strip() for x in line.decode("utf-8").rstrip().split(",")]
                    if len(p) >= 4:
                        lab[p[3].upper()] = (p[0], p[2])
    nfs = {}
    hit = []
    nev = 0
    with tarfile.open(raw, "r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            for raw_line in tf.extractfile(m):
                line = raw_line.decode("utf-8", "replace")
                if line.startswith('{"datum":{"com.bbn.tc.schema.avro.cdm18.NetFlowObject"'):
                    mm = NF_RE.match(line)
                    if mm:
                        nfs[mm.group(1).upper()] = (RA_RE.search(line).group(1) if RA_RE.search(line) else None, RP_RE.search(line).group(1) if RP_RE.search(line) else None)
                    continue
                if not line.startswith('{"datum":{"com.bbn.tc.schema.avro.cdm18.Event"'):
                    continue
                nev += 1
                u = UUID_RE.search(line)
                if u and u.group(1).upper() in lab:
                    po = PO_RE.search(line)
                    ts = TS_RE.search(line)
                    sj = SUBJ_RE.search(line)
                    ty = TYPE_RE.search(line)
                    hit.append((u.group(1).upper(), ty.group(1) if ty else "?", po.group(1).upper() if po else None, sj.group(1).upper() if sj else None, int(ts.group(1)) if ts else None))
    net = [h for h in hit if h[2] in nfs]
    res = {"raw": raw, "events": nev, "edge_labels_total": len(lab), "edge_labels_found_in_this_file": len(hit), "edge_labels_touching_netflow": len(net),
           "by_type_all": dict(Counter(h[1] for h in hit).most_common()), "by_type_netflow": dict(Counter(h[1] for h in net).most_common()),
           "by_chain_netflow": {f"{k[0]}|{k[1]}": v for k, v in Counter(lab[h[0]] for h in net).most_common()}, "distinct_netflows_labeled": len({h[2] for h in net}), "top_remote_labeled": dict(Counter(f"{nfs[h[2]][0]}:{nfs[h[2]][1]}" for h in net).most_common(25)), "distinct_subjects_labeled_net": len({h[3] for h in net}),
           "ts_range_net": [min((h[4] for h in net), default=None), max((h[4] for h in net), default=None)]}
    with open(out.replace(".json", "_rows.csv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("event_uuid,type,predicate_netflow,subject,ts_nanos,chain,label,remote\n")
        for h in net:
            f.write(f"{h[0]},{h[1]},{h[2]},{h[3]},{h[4]},{lab[h[0]][0]},{lab[h[0]][1]},{nfs[h[2]][0]}:{nfs[h[2]][1]}\n")
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False)[:2500], flush=True)


if __name__ == "__main__":
    main()
