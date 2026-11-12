#!/usr/bin/env python3
"""S24 (STEP 41) - Đo độ phủ ánh xạ flow -> tiến trình tạo flow -> cha / dòng lệnh trên MỘT máy OpTC, bằng tracker của Nguyễn (KLTN-main.zip).

Cách làm: replay log host eCAR của máy theo thứ tự thời gian (nhiều ngày liên tiếp, benign trước), nạp từng bản ghi vào HostProcessContextTracker
(observe). Trước khi nạp bản ghi thời điểm t, trả lời mọi flow (flows_joined.parquet, cùng máy) có ts <= t: tra actor_id trong trạng thái tracker
(chỉ bằng chứng thời điểm < ts của flow, nhân quả). Không dùng nhãn trong tracker. Ghi: độ phủ theo (ngày UTC, nhãn, app_family).
Chỉ đọc E:. Cách dùng: python s24_parent_coverage.py <host> <ngày_đầu> <ngày_cuối> <thư mục ra> [giới_hạn_dòng_mỗi_file]
"""
import collections
import glob
import gzip
import json
import os
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"C:\Users\ADMIN\AppData\Local\Temp\claude\D--UIT-KLTNv2\kz\x\KLTN-main")
from ML.code.preprocess.process_context_tracker import (  # noqa: E402
    HostProcessContextTracker, ProcessContextConfig, canonical_uuid, parse_timestamp)
import duckdb  # noqa: E402

FLOWS = r"D:\UIT\KLTNv2\02_artifacts\22_v2_pipeline\S1_join\data\flows_joined.parquet"
FIELDS = ["n", "created_seen", "actor_found", "actor_img", "actor_cmd", "parent_edge", "parent_node", "parent_img", "parent_cmd", "gparent_edge"]


def find_files(host, d0, d1):
    out = []
    for root in (r"E:\host-begnin", r"E:\host-malicious"):
        for p in sorted(glob.glob(os.path.join(root, "*", "*", f"*ecar-*-{host}.json.gz"))):
            day = os.path.basename(p).split("ecar-")[1][:10]
            if d0 <= day <= d1:
                out.append((day, p))
    return sorted(out)


def evaluate(tr, host, actor):
    procs = tr.hosts.get(host, {})
    node = procs.get(canonical_uuid(actor))
    f = dict.fromkeys(FIELDS, 0)
    f["n"] = 1
    if node is None:
        return f
    f["actor_found"] = 1
    f["created_seen"] = int(node.created_t is not None)
    f["actor_img"] = int(bool(node.image_path))
    f["actor_cmd"] = int(bool(node.command_line))
    if node.parent_edges:
        f["parent_edge"] = 1
        pu = node.parent_edges[-1][0]
        pn = procs.get(pu)
        if pn is not None:
            f["parent_node"] = 1
            f["parent_img"] = int(bool(pn.image_path))
            f["parent_cmd"] = int(bool(pn.command_line))
            if pn.parent_edges:
                f["gparent_edge"] = 1
    return f


def main():
    host, d0, d1, outdir = sys.argv[1:5]
    limit = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    os.makedirs(outdir, exist_ok=True)
    files = find_files(host, d0, d1)
    print("[files]", [(d, os.path.getsize(p) // 2**20) for d, p in files], flush=True)
    q = duckdb.connect().execute(
        f"select ts, date_utc, label, app_family, actor_id, resp_h, resp_p from read_parquet('{FLOWS}') "
        f"where hostname='{host}' order by ts").fetchall()
    print("[flows máy]", len(q), flush=True)
    tr = HostProcessContextTracker(ProcessContextConfig())
    agg = collections.defaultdict(collections.Counter)
    examples = []
    actors = {}
    qi = 0
    # bỏ các flow trước bản ghi đầu tiên của file đầu (không có trạng thái)
    first_ts = None
    t0 = time.time()
    nrec = 0
    for day, p in files:
        print("[file]", day, flush=True)
        with gzip.open(p, "rt", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if limit and i >= limit:
                    break
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                t = parse_timestamp(rec.get("timestamp"))
                if t is None:
                    continue
                if first_ts is None:
                    first_ts = t
                    while qi < len(q) and q[qi][0] * 1e6 < first_ts:
                        qi += 1
                while qi < len(q) and q[qi][0] * 1e6 <= t:
                    ts, date_utc, label, app, actor, rh, rp = q[qi]
                    f = evaluate(tr, host, actor)
                    key = (date_utc, int(label), app)
                    a = actors.setdefault(actor, {"app": app, "label": int(label), "n": 0, "created": 0, "cmd": 0, "parent": 0, "first_ts": ts})
                    a["n"] += 1
                    a["created"] = f["created_seen"]; a["cmd"] = f["actor_cmd"]; a["parent"] = f["parent_edge"]
                    for k, v in f.items():
                        agg[key][k] += v
                    if label == 1 and len(examples) < 25 and f["actor_found"]:
                        examples.append({"ts": ts, "app": app, "dest": f"{rh}:{rp}", "tokens": [t for t in tr.get_context_tokens({"hostname": host, "actorID": actor, "timestamp": int(ts * 1e6)}, query_t=int(ts * 1e6)) if "recent_action" not in t][:30]})
                    qi += 1
                tr.observe(rec, event_t=t)
                nrec += 1
                if nrec % 1_000_000 == 0:
                    print(f"[{day}] {nrec/1e6:.1f}M bản ghi, {time.time()-t0:.0f}s, flows đã trả lời {qi}", flush=True)
        # lưu trung gian sau mỗi file
        write(outdir, agg, examples, tr, qi, len(q), host, files, actors)
    write(outdir, agg, examples, tr, qi, len(q), host, files, actors)
    print("[xong]", f"{time.time()-t0:.0f}s", flush=True)


def write(outdir, agg, examples, tr, qi, nq, host, files, actors):
    with open(os.path.join(outdir, "actors.csv"), "w", encoding="utf-8", newline="\n") as fa:
        fa.write("actor_id,app_family,label,n_flows,created_seen,has_cmd,has_parent_edge\n")
        for k, a in actors.items():
            fa.write(f"{k},{a['app']},{a['label']},{a['n']},{a['created']},{a['cmd']},{a['parent']}\n")
    with open(os.path.join(outdir, "coverage_by_day_label_app.csv"), "w", encoding="utf-8", newline="\n") as fo:
        fo.write("date_utc,label,app_family," + ",".join(FIELDS) + "\n")
        for (d, l, a), c in sorted(agg.items()):
            fo.write(f"{d},{l},{a}," + ",".join(str(c[k]) for k in FIELDS) + "\n")
    json.dump({"host": host, "files": [d for d, _ in files], "flows_answered": qi, "flows_total_host": nq, "tracker_stats": tr.stats, "examples_positive": examples},
              open(os.path.join(outdir, "run_summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
