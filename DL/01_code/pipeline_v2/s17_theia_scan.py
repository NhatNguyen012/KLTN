#!/usr/bin/env python3
"""S17b - Quét streaming raw THEIA E3 (CDM18 JSON Linux): trường của NetFlowObject, Subject (path, ppid, cmdLine), Principal, và các sự kiện chạm netflow (loại, size, subject).

Hai lượt trên cùng .tar.gz (đọc streaming, không giải nén ra đĩa): lượt A thu NetFlowObject/Subject/Principal; lượt B duyệt Event, chỉ phân tích đầy đủ sự kiện có predicateObject là netflow.
Cách dùng: python -I s17_theia_scan.py <tar.gz> <json ra>"""
import json
import re
import sys
import tarfile
import time
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8")
PFX = "com.bbn.tc.schema.avro.cdm18."
TYPE_RE = re.compile(r'^\{"datum":\{"(?:com\.bbn\.tc\.schema\.avro\.cdm18\.)?([A-Za-z]+)"')
EV_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')
PO_RE = re.compile(r'"predicateObject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
UNK = "00000000-0000-0000-0000-000000000000"


def datum(line):
    return next(iter(json.loads(line.rstrip().rstrip(","))["datum"].values()))


def val(u):
    return next(iter(u.values())) if isinstance(u, dict) and len(u) == 1 else u


def flat(obj, prefix, depth, out):
    if isinstance(obj, dict):
        if len(obj) == 1 and next(iter(obj)) in ("string", "int", "long", "boolean", "float", "double", "bytes", "map") and depth >= 0:
            k = next(iter(obj))
            if k == "map" and isinstance(obj[k], dict):
                for mk in obj[k]:
                    out.add(f"{prefix}.map.{mk}")
            else:
                out.add(prefix + ":" + k)
            return
        for k, v in obj.items():
            if k.startswith(PFX):
                flat(v, prefix, depth, out)
                continue
            p = f"{prefix}.{k}" if prefix else k
            if depth <= 0 or v is None or not isinstance(v, (dict, list)):
                out.add(p + (":null" if v is None else ""))
            else:
                flat(v, p, depth - 1, out)
    elif isinstance(obj, list):
        out.add(prefix + "[]" + ("" if obj else ":empty"))


def members(path):
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            if m.isfile():
                yield m.name, tf.extractfile(m)


def main():
    path, out = sys.argv[1], sys.argv[2]
    t0 = time.time()
    type_counts, ev_all = Counter(), Counter()
    fields = defaultdict(Counter)
    nf, subj, princ = {}, {}, {}
    host = None
    prop_keys = defaultdict(Counter)
    for name, f in members(path):
        print(f"[A] {name}", flush=True)
        for n, raw in enumerate(f, 1):
            line = raw.decode("utf-8", "replace")
            mt = TYPE_RE.match(line)
            t = mt.group(1) if mt else "?"
            type_counts[t] += 1
            if t == "Event":
                et = EV_RE.search(line)
                ev_all[et.group(1) if et else "?"] += 1
            elif t == "NetFlowObject":
                r = datum(line)
                nf[r["uuid"]] = (val(r.get("localAddress")), val(r.get("localPort")), val(r.get("remoteAddress")), val(r.get("remotePort")), val(r.get("ipProtocol")))
                if type_counts[t] <= 200000:
                    s = set()
                    flat(r, "", 2, s)
                    for p in s:
                        fields[t][p] += 1
            elif t == "Subject":
                r = datum(line)
                pm = (val(r.get("properties")) or {})
                pm = pm.get("map", pm) if isinstance(pm, dict) else {}
                subj[r["uuid"]] = (pm.get("path"), val(r.get("cmdLine")), pm.get("ppid"), val(r.get("localPrincipal")), val(r.get("parentSubject")), r.get("type"))
                for k in pm:
                    prop_keys["Subject"][k] += 1
                if type_counts[t] <= 200000:
                    s = set()
                    flat(r, "", 3, s)
                    for p in s:
                        fields[t][p] += 1
            elif t == "Principal":
                r = datum(line)
                princ[r["uuid"]] = (r.get("type"), r.get("userId"), val(r.get("username")))
                s = set()
                flat(r, "", 3, s)
                for p in s:
                    fields[t][p] += 1
            elif t == "Host":
                host = line[:700]
            if n % 5_000_000 == 0:
                print(f"[A] {n:,} dòng {time.time() - t0:.0f}s netflow {len(nf):,} subject {len(subj):,}", flush=True)
    # lượt B
    net_ev = defaultdict(lambda: {"n": 0, "size_nonnull": 0, "size_sum": 0, "size_max": 0})
    net_ev_fields = defaultdict(Counter)
    ts = [None, None]
    joined = Counter()
    per_nf = Counter()
    subj_of_net = Counter()
    for name, f in members(path):
        print(f"[B] {name}", flush=True)
        for n, raw in enumerate(f, 1):
            line = raw.decode("utf-8", "replace")
            if not line.startswith('{"datum":{"com.bbn.tc.schema.avro.cdm18.Event"'):
                continue
            m = PO_RE.search(line)
            if not m or m.group(1) not in nf:
                continue
            r = datum(line)
            et = r.get("type")
            e = net_ev[et]
            e["n"] += 1
            sz = val(r.get("size"))
            if sz is not None:
                e["size_nonnull"] += 1
                e["size_sum"] += int(sz)
                e["size_max"] = max(e["size_max"], int(sz))
            if e["n"] <= 100000:
                s = set()
                flat(r, "", 2, s)
                for p in s:
                    net_ev_fields[et][p] += 1
            t = r.get("timestampNanos")
            if isinstance(t, int) and t > 0:
                ts[0] = t if ts[0] is None else min(ts[0], t)
                ts[1] = t if ts[1] is None else max(ts[1], t)
            per_nf[m.group(1)] += 1
            sj = val(r.get("subject"))
            subj_of_net[sj] += 1
            if n % 5_000_000 == 0:
                print(f"[B] {n:,} dòng {time.time() - t0:.0f}s", flush=True)
    tot = sum(subj_of_net.values())
    known = sum(c for u, c in subj_of_net.items() if u in subj)
    with_path = sum(c for u, c in subj_of_net.items() if u in subj and subj[u][0])
    with_cmd = sum(c for u, c in subj_of_net.items() if u in subj and subj[u][1] and subj[u][1] != "N/A")
    with_ppid = sum(c for u, c in subj_of_net.items() if u in subj and subj[u][2])
    with_pr = sum(c for u, c in subj_of_net.items() if u in subj and subj[u][3] in princ)
    path_cnt = Counter()
    for u, c in subj_of_net.items():
        if u in subj:
            path_cnt[subj[u][0]] += c
    ipp = Counter(str(v[4]) for v in nf.values())
    rp = Counter()
    for v in nf.values():
        rp[v[3]] += 1
    res = {"file": path, "seconds": round(time.time() - t0), "type_counts": dict(type_counts), "event_types_all": dict(ev_all.most_common(40)),
           "netflow": {"n": len(nf), "ipProtocol": dict(ipp), "remote_addr_empty": sum(1 for v in nf.values() if not v[2]), "remote_port_top": dict(rp.most_common(10)), "example": list(nf.items())[:3]},
           "subject": {"n": len(subj), "types": dict(Counter(v[5] for v in subj.values())), "cmd_not_NA": sum(1 for v in subj.values() if v[1] and v[1] != "N/A"), "path_present": sum(1 for v in subj.values() if v[0]),
                       "ppid_present": sum(1 for v in subj.values() if v[2]), "parent_nonzero": sum(1 for v in subj.values() if v[4] and v[4] != UNK), "property_keys": dict(prop_keys["Subject"])},
           "principal": {"n": len(princ), "types": dict(Counter(v[0] for v in princ.values())), "username_present": sum(1 for v in princ.values() if v[2]), "examples": list(princ.items())[:5]},
           "net_events": {"by_type": {k: dict(v) for k, v in net_ev.items()}, "total": tot, "subject_known": known, "subject_with_path": with_path, "subject_with_cmd_not_NA": with_cmd,
                          "subject_with_ppid": with_ppid, "subject_principal_known": with_pr, "ts_nanos_range": ts, "distinct_netflows_touched": len(per_nf), "top_subject_paths": dict(path_cnt.most_common(25))},
           "fields": {k: dict(v.most_common()) for k, v in fields.items()}, "net_event_fields": {k: dict(v.most_common(40)) for k, v in net_ev_fields.items()}, "host": host}
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print("[xong]", json.dumps({k: res[k] for k in ("seconds", "type_counts", "netflow", "net_events")}, ensure_ascii=False, default=str)[:3500], flush=True)


if __name__ == "__main__":
    main()
