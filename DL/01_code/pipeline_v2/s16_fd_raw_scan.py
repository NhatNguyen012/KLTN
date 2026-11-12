#!/usr/bin/env python3
"""S16b - Quét streaming file raw FiveDirections E3 (CDM18 JSON trong .tar.gz): loại bản ghi, trường có mặt, ipProtocol, kích thước (size) của sự kiện mạng, cmdLine/parentSubject, khả năng nối flow -> tiến trình.

Chỉ đọc, không giải nén ra đĩa. Phân tích toàn bộ bản ghi NetFlowObject, Subject, Principal, Host; Event: phân tích toàn bộ sự kiện mạng (CONNECT, ACCEPT, SENDTO, RECVFROM, SENDMSG, RECVMSG, BIND, READ_SOCKET_PARAMS, WRITE/READ trên netflow nếu có) và 1/200 sự kiện khác.
Output: JSON tổng hợp (--out) kèm log tiến độ. Cách dùng: python -I s16_fd_raw_scan.py <tar.gz> --out <json> [--max-lines N]"""
import argparse
import json
import re
import sys
import tarfile
import time
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8")
NET_EVENTS = {"EVENT_CONNECT", "EVENT_ACCEPT", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG", "EVENT_BIND", "EVENT_READ_SOCKET_PARAMS", "EVENT_WRITE_SOCKET_PARAMS",
              "EVENT_FLOWS_TO"}
TYPE_RE = re.compile(r'^\{"datum":\{"(?:com\.bbn\.tc\.schema\.avro\.cdm18\.)?([A-Za-z]+)"')
EVTYPE_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')
SAMPLE_EVERY = 200
NF_PREFIX = "com.bbn.tc.schema.avro.cdm18."


def flatten(obj, prefix, depth, out):
    """Ghi tên đường dẫn của các trường (mở lớp union {"string": x}); map giữ tên khóa."""
    if isinstance(obj, dict):
        if len(obj) == 1 and next(iter(obj)) in ("string", "int", "long", "boolean", "float", "double", "bytes") and depth >= 0:
            out.add(prefix + ":" + next(iter(obj)))
            return
        for k, v in obj.items():
            if k.startswith(NF_PREFIX):
                flatten(v, prefix, depth, out)
                continue
            p = f"{prefix}.{k}" if prefix else k
            if depth <= 0 or v is None or not isinstance(v, (dict, list)):
                out.add(p + (":null" if v is None else ""))
            else:
                flatten(v, p, depth - 1, out)
    elif isinstance(obj, list):
        out.add(prefix + "[]" + ("" if obj else ":empty"))
        for it in obj[:1]:
            flatten(it, prefix + "[]", depth - 1, out)


def datum(line):
    """Bản ghi bên trong "datum": file -3 dùng khóa có tiền tố cdm18, file chính không có tiền tố và mỗi dòng kết thúc bằng dấu phẩy."""
    return next(iter(json.loads(line.rstrip().rstrip(","))["datum"].values()))


def val(u):
    if isinstance(u, dict) and len(u) == 1:
        return next(iter(u.values()))
    return u


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-lines", type=int, default=0)
    ap.add_argument("--progress", type=int, default=5_000_000)
    a = ap.parse_args()
    t0 = time.time()
    type_counts = Counter()
    fields = defaultdict(Counter)          # kiểu bản ghi -> đường dẫn trường -> số bản ghi có
    parsed_counts = Counter()              # số bản ghi đã phân tích theo kiểu
    ev_type = Counter()                    # tất cả sự kiện, theo loại (regex trên chuỗi)
    ev_type_parsed = Counter()
    ev_fields = defaultdict(Counter)       # loại sự kiện đã phân tích -> trường
    ev_size = defaultdict(lambda: {"n": 0, "with_size": 0, "sum": 0, "max": 0})
    ev_ts = [None, None]
    nf = {"ip_protocol": Counter(), "local_addr_present": 0, "remote_addr_present": 0, "n": 0, "remote_port_present": 0, "local_port_present": 0, "inbound_like": 0}
    netflow_uuids = {}
    subj_info = {}                          # uuid -> (has_cmd, has_parent, has_principal)
    subj_cmd_examples = []
    subj_type = Counter()
    props_keys = Counter()
    principal_n = 0
    pred_cnt = Counter()                    # predicateObject của sự kiện mạng
    subj_cnt = Counter()
    net_ev_by_type = Counter()
    host = None
    marker_ts = []
    first_events = []
    with tarfile.open(a.path, "r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            print(f"[member] {m.name} size={m.size}", flush=True)
            f = tf.extractfile(m)
            for n, raw in enumerate(f, 1):
                if a.max_lines and n > a.max_lines:
                    break
                line = raw.decode("utf-8", "replace")
                mt = TYPE_RE.match(line)
                typ = mt.group(1) if mt else "?"
                type_counts[typ] += 1
                if typ == "Event":
                    et = EVTYPE_RE.search(line)
                    et = et.group(1) if et else "?"
                    ev_type[et] += 1
                    if et not in NET_EVENTS and ev_type[et] % SAMPLE_EVERY != 1:
                        continue
                    rec = datum(line)
                    ev_type_parsed[et] += 1
                    fs = set()
                    flatten(rec, "", 2, fs)
                    for p in fs:
                        ev_fields[et][p] += 1
                    ts = rec.get("timestampNanos")
                    if isinstance(ts, int) and ts > 0:
                        ev_ts[0] = ts if ev_ts[0] is None else min(ev_ts[0], ts)
                        ev_ts[1] = ts if ev_ts[1] is None else max(ev_ts[1], ts)
                    sz = val(rec.get("size"))
                    s = ev_size[et]
                    s["n"] += 1
                    if sz is not None:
                        s["with_size"] += 1
                        s["sum"] += int(sz)
                        s["max"] = max(s["max"], int(sz))
                    if et in NET_EVENTS:
                        net_ev_by_type[et] += 1
                        po = val(rec.get("predicateObject"))
                        sj = val(rec.get("subject"))
                        if po:
                            pred_cnt[po] += 1
                        if sj:
                            subj_cnt[sj] += 1
                        if len(first_events) < 3:
                            first_events.append(line[:2500])
                elif typ == "NetFlowObject":
                    rec = datum(line)
                    parsed_counts[typ] += 1
                    fs = set()
                    flatten(rec, "", 2, fs)
                    for p in fs:
                        fields[typ][p] += 1
                    nf["n"] += 1
                    ip = val(rec.get("ipProtocol"))
                    nf["ip_protocol"][str(ip)] += 1
                    la, ra = val(rec.get("localAddress")), val(rec.get("remoteAddress"))
                    nf["local_addr_present"] += bool(la)
                    nf["remote_addr_present"] += bool(ra) and ra not in ("", "NA")
                    nf["local_port_present"] += val(rec.get("localPort")) not in (None, -1)
                    nf["remote_port_present"] += val(rec.get("remotePort")) not in (None, -1)
                    netflow_uuids[rec["uuid"]] = 1
                elif typ == "Subject":
                    rec = datum(line)
                    parsed_counts[typ] += 1
                    fs = set()
                    flatten(rec, "", 3, fs)
                    for p in fs:
                        fields[typ][p] += 1
                    cmd = val(rec.get("cmdLine"))
                    ps = val(rec.get("parentSubject"))
                    lp = val(rec.get("localPrincipal"))
                    subj_info[rec["uuid"]] = (bool(cmd), bool(ps), bool(lp))
                    subj_type[str(rec.get("type"))] += 1
                    pm = val(rec.get("properties"))
                    if isinstance(pm, dict):
                        for k in pm:
                            props_keys[k] += 1
                    if cmd and len(subj_cmd_examples) < 5 and ("powershell" in cmd.lower() or "cmd" in cmd.lower()):
                        subj_cmd_examples.append(cmd[:300])
                elif typ in ("Principal", "Host", "FileObject", "SrcSinkObject", "MemoryObject", "UnnamedPipeObject", "RegistryKeyObject", "TimeMarker", "StartMarker", "EndMarker", "UnitDependency", "ProvenanceTagNode"):
                    if parsed_counts[typ] < 20000 or typ in ("Host", "Principal"):
                        rec = datum(line)
                        parsed_counts[typ] += 1
                        fs = set()
                        flatten(rec, "", 2, fs)
                        for p in fs:
                            fields[typ][p] += 1
                        if typ == "TimeMarker":
                            marker_ts.append(rec.get("tsNanos"))
                        if typ == "Host":
                            host = line[:600]
                if n % a.progress == 0:
                    print(f"[progress] {n:,} dòng, {time.time() - t0:.0f}s, Event {type_counts['Event']:,}, NetFlow {nf['n']:,}, Subject {len(subj_info):,}", flush=True)
    # nối: sự kiện mạng -> netflow, -> subject có cmdLine
    n_net = sum(pred_cnt.values())
    in_nf = sum(c for u, c in pred_cnt.items() if u in netflow_uuids)
    sj_known = sum(c for u, c in subj_cnt.items() if u in subj_info)
    sj_cmd = sum(c for u, c in subj_cnt.items() if u in subj_info and subj_info[u][0])
    sj_parent = sum(c for u, c in subj_cnt.items() if u in subj_info and subj_info[u][1])
    sj_all = sum(subj_cnt.values())
    n_subj = len(subj_info)
    res = {
        "file": a.path, "seconds": round(time.time() - t0), "type_counts": dict(type_counts), "parsed_counts": dict(parsed_counts),
        "event_types_all": dict(ev_type.most_common()), "event_types_parsed": dict(ev_type_parsed), "event_ts_nanos_range_from_parsed": ev_ts, "time_markers_sample": [marker_ts[:3], marker_ts[-3:]],
        "netflow": {**{k: v for k, v in nf.items() if k != "ip_protocol"}, "ip_protocol": dict(nf["ip_protocol"]), "n_unique_uuid": len(netflow_uuids)},
        "subject": {"n": n_subj, "types": dict(subj_type), "with_cmdLine": sum(1 for v in subj_info.values() if v[0]), "with_parentSubject": sum(1 for v in subj_info.values() if v[1]),
                    "with_localPrincipal": sum(1 for v in subj_info.values() if v[2]), "properties_map_keys": dict(props_keys.most_common(30)), "cmd_examples": subj_cmd_examples},
        "net_events": {"parsed_by_type": dict(net_ev_by_type), "total": sj_all, "predicateObject_is_netflow": in_nf, "of_total_with_predicate": n_net,
                       "subject_known": sj_known, "subject_with_cmdLine": sj_cmd, "subject_with_parentSubject": sj_parent},
        "event_size_by_type": {k: v for k, v in ev_size.items() if k in NET_EVENTS or v["with_size"]},
        "fields": {k: dict(v.most_common()) for k, v in fields.items()},
        "event_fields_by_type": {k: dict(v.most_common(40)) for k, v in ev_fields.items() if k in NET_EVENTS or k in ("EVENT_READ", "EVENT_WRITE", "EVENT_EXECUTE")},
        "host_record": host, "first_net_events": first_events,
    }
    json.dump(res, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", json.dumps({k: res[k] for k in ("seconds", "type_counts", "net_events")}, ensure_ascii=False)[:3000], flush=True)


if __name__ == "__main__":
    main()
