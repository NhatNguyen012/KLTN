#!/usr/bin/env python3
"""S27 (STEP 40) - THEIA 6r: tiến trình có flow mạng thật (đầu xa thật), tên chương trình từ EVENT_EXECUTE, cha, nhãn (REAPr theo Subject.uuid và Event.uuid).
Một lượt streaming trên .tar.gz (chỉ đọc). Ghi: subjects_all.csv, exec_by_subject.csv, net_agg.csv.
Cách dùng: python s27_theia_why.py <raw 6r tar.gz> <edge_labels.tar.gz> <theia_labels.csv> <thư mục ra>"""
import csv
import json
import os
import re
import sys
import tarfile

sys.stdout.reconfigure(encoding="utf-8")
P = "com.bbn.tc.schema.avro.cdm18."
EV = '{"datum":{"' + P + 'Event"'
SU = '{"datum":{"' + P + 'Subject"'
NFP = '{"datum":{"' + P + 'NetFlowObject"'
UUID_RE = re.compile(r'cdm18\.Event":\{"uuid":"([0-9A-Fa-f-]+)"')
PO_RE = re.compile(r'"predicateObject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
TS_RE = re.compile(r'"timestampNanos":(\d+)')
SUBJ_RE = re.compile(r'"subject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
TYPE_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')
CMD_RE = re.compile(r'"cmdLine":"((?:[^"\\]|\\.)*)"')
RA_RE = re.compile(r'"remoteAddress":"([^"]*)"')
RP_RE = re.compile(r'"remotePort":(-?\d+)')
NF_RE = re.compile(r'^\{"datum":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.NetFlowObject":\{"uuid":"([0-9A-Fa-f-]+)"')
NET_TYPES = {"EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG", "EVENT_ACCEPT", "EVENT_BIND", "EVENT_WRITE", "EVENT_READ"}


def unwrap(v):
    while isinstance(v, dict) and len(v) == 1:
        v = next(iter(v.values()))
    return v


def real_remote(a, p):
    return a not in (None, "", "NA", "LOCAL", "NETLINK") and p not in (None, "0", "-1") and not a.startswith("127.")


def main():
    raw, edges, tlab, outdir = sys.argv[1:5]
    os.makedirs(outdir, exist_ok=True)
    lab = set()
    with tarfile.open(edges, "r:gz") as tf:
        for m in tf:
            if m.isfile():
                for i, line in enumerate(tf.extractfile(m)):
                    if i:
                        p = [x.strip() for x in line.decode("utf-8").rstrip().split(",")]
                        if len(p) >= 4:
                            lab.add(p[3].upper())
    slab = {}
    for i, line in enumerate(open(tlab, encoding="utf-8")):
        if i:
            p = [x.strip() for x in line.rstrip().split(",")]
            if len(p) >= 4:
                slab[p[1].upper()] = (p[0], p[2], p[3])
    print("[nhãn] cạnh", len(lab), "tiến trình", len(slab), flush=True)
    nfs = {}
    agg = {}
    fs = open(os.path.join(outdir, "subjects_all.csv"), "w", encoding="utf-8", newline="")
    fe = open(os.path.join(outdir, "exec_by_subject.csv"), "w", encoding="utf-8", newline="")
    ws, we = csv.writer(fs), csv.writer(fe)
    ws.writerow(["uuid", "parent", "subj_cmdline", "subj_path", "start_ns", "principal", "label_subject", "chain_subject"])
    we.writerow(["subject", "ts_ns", "cmdline"])
    nev = nsub = nexec = 0
    with tarfile.open(raw, "r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            print("[member]", m.name, flush=True)
            for raw_line in tf.extractfile(m):
                line = raw_line.decode("utf-8", "replace")
                if line.startswith(EV):
                    nev += 1
                    ty = TYPE_RE.search(line)
                    if not ty:
                        continue
                    t = ty.group(1)
                    if t == "EVENT_EXECUTE":
                        sj, ts, c = SUBJ_RE.search(line), TS_RE.search(line), CMD_RE.search(line)
                        if sj:
                            we.writerow([sj.group(1).upper(), ts.group(1) if ts else "", c.group(1) if c else ""])
                            nexec += 1
                    elif t in NET_TYPES:
                        po = PO_RE.search(line)
                        if not po or po.group(1).upper() not in nfs:
                            continue
                        nf = po.group(1).upper()
                        sj, ts, u = SUBJ_RE.search(line), TS_RE.search(line), UUID_RE.search(line)
                        key = (sj.group(1).upper() if sj else "", nf)
                        a = agg.setdefault(key, [0, 0, set(), int(ts.group(1)) if ts else 0])
                        a[0] += 1
                        a[1] += int(bool(u and u.group(1).upper() in lab))
                        a[2].add(t)
                        if nev % 5_000_000 == 0:
                            pass
                    if nev % 5_000_000 == 0:
                        print(f"  {nev/1e6:.0f}M events, subjects {nsub}, exec {nexec}, net keys {len(agg)}", flush=True)
                elif line.startswith(NFP):
                    mm = NF_RE.match(line)
                    if mm:
                        ra, rp = RA_RE.search(line), RP_RE.search(line)
                        a_, p_ = (ra.group(1) if ra else None), (rp.group(1) if rp else None)
                        if real_remote(a_, p_):
                            nfs[mm.group(1).upper()] = f"{a_}:{p_}"
                elif line.startswith(SU):
                    try:
                        d = json.loads(line)["datum"]
                        s = unwrap({k: v for k, v in d.items()})
                    except Exception:
                        continue
                    nsub += 1
                    u = (s.get("uuid") or "").upper()
                    props = (s.get("properties") or {}).get("map") or {}
                    sl = slab.get(u, ("", "", ""))
                    ws.writerow([u, (unwrap(s.get("parentSubject")) or ""), unwrap(s.get("cmdLine")) or "", props.get("path", ""), s.get("startTimestampNanos"),
                                 unwrap(s.get("localPrincipal")) or "", sl[2], sl[0]])
    fs.close()
    fe.close()
    with open(os.path.join(outdir, "net_agg.csv"), "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["subject", "netflow", "remote", "n_events", "n_labeled_events", "types", "first_ts_ns"])
        for (sj, nf), (n, nl, ty, ts) in agg.items():
            w.writerow([sj, nf, nfs.get(nf), n, nl, "|".join(sorted(ty)), ts])
    print("[xong] events", nev, "subjects", nsub, "exec", nexec, "net keys", len(agg), "real netflows", len(nfs), flush=True)


if __name__ == "__main__":
    main()
