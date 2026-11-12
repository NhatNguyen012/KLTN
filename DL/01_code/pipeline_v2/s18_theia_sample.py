#!/usr/bin/env python3
"""S18a - Lấy mẫu NGUYÊN VĂN (từng dòng JSON, không sửa trường) từ THEIA raw 6r cho các loại nhãn attack / contaminated / benign (không có trong file nhãn).

Một lượt streaming trên .tar.gz (không giải nén ra đĩa). Gom:
  - mọi dòng Principal, Subject, NetFlowObject (theo uuid) để dựng ngữ cảnh,
  - sự kiện (Event) có nhãn attack được chọn trước (từ theia_edges_6r_rows.csv) và 2 sự kiện contaminated,
  - ứng viên benign: sự kiện mạng không có nhãn, tiến trình không có nhãn, đầu xa thật, trong cửa sổ giờ cho trước.
Output: pool JSON (dòng gốc). Cách dùng: python -I s18_theia_sample.py <6r.tar.gz> <rows.csv> <edge_labels.tar.gz> <theia_labels.csv> <pool.json>"""
import csv
import json
import re
import sys
import tarfile
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8")
PFX = '{"datum":{"com.bbn.tc.schema.avro.cdm18.'
UUID_RE = re.compile(r'^\{"datum":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.[A-Za-z]+":\{"uuid":"([0-9A-Fa-f-]+)"')
TS_RE = re.compile(r'"timestampNanos":(\d+)')
PO_RE = re.compile(r'"predicateObject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
SJ_RE = re.compile(r'"subject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
TYPE_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')
RA_RE = re.compile(r'"remoteAddress":"([^"]*)"')
NET = {"EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG"}
T0, T1 = 1523384400 * 10**9, 1523388000 * 10**9  # 04-10 18:20 -> 19:20 UTC


def pick_attack(rows):
    by = defaultdict(list)
    for r in rows:
        by[r["subject"]].append(r)
    for v in by.values():
        v.sort(key=lambda r: int(r["ts_nanos"]))
    picks = {}
    spec = {"attack1": ("7F1FD92F-0000-0000-0000-000000000020", None), "attack2": ("B73501B6-0200-0000-0000-000000000020", None), "attack3": ("283847BC-0200-0000-0000-000000000020", None)}
    for tag, (sj, _) in spec.items():
        v = by[sj]
        if tag == "attack3":
            na = [r for r in v if r["remote"].startswith("NA:")][:5]
            real = [r for r in v if not r["remote"].startswith("NA:")][:3]
            sel = na + real
        else:
            sel, seen = [], set()
            for r in v:  # ưu tiên netflow khác nhau
                if r["predicate_netflow"] not in seen:
                    seen.add(r["predicate_netflow"])
                    sel.append(r)
                if len(sel) >= 6:
                    break
            for r in v:
                if len(sel) >= 8:
                    break
                if r not in sel:
                    sel.append(r)
        picks[tag] = {"subject": sj, "events": [r["event_uuid"] for r in sel], "rows": sel}
    return picks


def main():
    raw, rows_csv, edge_tar, labels_csv, out = sys.argv[1:6]
    rows = list(csv.DictReader(open(rows_csv, encoding="utf-8")))
    picks = pick_attack(rows)
    want_ev = {u: tag for tag, p in picks.items() for u in p["events"]}
    lab_proc = {r["uuid"].upper() for r in csv.DictReader(open(labels_csv, encoding="utf-8"), skipinitialspace=True)}
    edge_uuids = set()
    with tarfile.open(edge_tar, "r:gz") as tf:
        for m in tf:
            if m.isfile():
                for i, line in enumerate(tf.extractfile(m)):
                    if i:
                        edge_uuids.add(line.decode().split(",")[3].strip().upper())
    contam_ev = {"6E78BB15-00BE-2415-2964-620200000010", "F773529B-4EBE-2415-46F6-620200000010"}
    contam_subject = "3A3530B4-0200-0000-0000-000000000020"
    subj, nf, princ, host = defaultdict(list), {}, [], None
    ev_lines = {}
    benign = defaultdict(list)   # subject -> dòng sự kiện
    contam_subj_events = []
    n = 0
    with tarfile.open(raw, "r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            print("[member]", m.name, flush=True)
            for rl in tf.extractfile(m):
                n += 1
                line = rl.decode("utf-8", "replace").rstrip("\n")
                if not line.startswith(PFX):
                    continue
                k = line[len(PFX):len(PFX) + 14]
                if k.startswith("Event"):
                    u = UUID_RE.match(line)
                    uu = u.group(1).upper() if u else None
                    if uu in want_ev or uu in contam_ev:
                        ev_lines[uu] = line
                        continue
                    ts = TS_RE.search(line)
                    if ts and T0 <= int(ts.group(1)) <= T1 and uu not in edge_uuids:
                        ty = TYPE_RE.search(line)
                        if ty and ty.group(1) in NET:
                            po = PO_RE.search(line)
                            sj = SJ_RE.search(line)
                            if po and sj and po.group(1).upper() in nf and sj.group(1).upper() not in lab_proc:
                                ra = RA_RE.search(nf[po.group(1).upper()])
                                if ra and ra.group(1) not in ("NA", "", "NETLINK", "LOCAL") and not ra.group(1).startswith("127."):
                                    key = sj.group(1).upper()
                                    if len(benign[key]) < 8 and len(benign) < 400:
                                        benign[key].append(line)
                elif k.startswith("NetFlowObject"):
                    u = UUID_RE.match(line)
                    if u:
                        nf[u.group(1).upper()] = line
                elif k.startswith("Subject"):
                    u = UUID_RE.match(line)
                    if u:
                        subj[u.group(1).upper()].append(line)
                elif k.startswith("Principal"):
                    princ.append(line)
                elif k.startswith("Host"):
                    host = line
    # chọn benign: ưu tiên firefox, thunderbird, sshd; mỗi loại một tiến trình có >= 6 sự kiện
    def path_of(sj):
        for ln in subj.get(sj, []):
            m = re.search(r'"path":"([^"]*)"', ln)
            if m:
                return m.group(1)
        return None
    prefer = ["/home/admin/Downloads/firefox/firefox", "/usr/lib/thunderbird/thunderbird", "/usr/sbin/sshd", "/usr/bin/firefox", "/usr/sbin/NetworkManager"]
    chosen = {}
    for p in prefer:
        for sj, lines in sorted(benign.items(), key=lambda kv: -len(kv[1])):
            if path_of(sj) == p and len(lines) >= 4 and sj not in chosen.values() and p not in chosen:
                chosen[p] = sj
    benign_pick = {p: {"subject": sj, "events": benign[sj]} for p, sj in list(chosen.items())[:3]}
    needed_nf = set()
    for ln in ev_lines.values():
        po = PO_RE.search(ln)
        if po:
            needed_nf.add(po.group(1).upper())
    for b in benign_pick.values():
        for ln in b["events"]:
            needed_nf.add(PO_RE.search(ln).group(1).upper())
    needed_subj = {p["subject"] for p in picks.values()} | {b["subject"] for b in benign_pick.values()} | {contam_subject}
    res = {"raw": raw, "lines_read": n, "picks": {t: {"subject": p["subject"], "events": p["events"], "remote": [r["remote"] for r in p["rows"]], "chain": p["rows"][0]["chain"]} for t, p in picks.items()},
           "ev_lines": ev_lines, "benign_pick": benign_pick, "benign_subjects_with_events": len(benign),
           "subject_lines": {u: subj[u] for u in needed_subj}, "netflow_lines": {u: nf[u] for u in needed_nf if u in nf}, "principal_lines": princ, "host_line": host, "contam_events": sorted(contam_ev), "contam_subject": contam_subject}
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", len(ev_lines), len(benign_pick), flush=True)


if __name__ == "__main__":
    main()
