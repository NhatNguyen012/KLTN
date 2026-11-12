#!/usr/bin/env python3
"""S18b - Lấy mẫu NGUYÊN VĂN từ ATLASv2 (dòng jsonl Carbon Black netconn; xml Security 5156/4688, Sysmon 1/5) cho nhãn attack (tiến trình có trong .labels) và benign.

Một lượt streaming trên atlasv2.tar.gz (không giải nén). Cách dùng: python -I s18_atlas_sample.py <tar.gz> <thư mục reapr atlasv2> <pool.json>"""
import csv
import json
import re
import sys
import tarfile
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8")
A = "atlasv2/data/attack/h1/"
B = "atlasv2/data/benign/h1/"
WANT = {A + "cbc-edr/edr-h1-m1.jsonl": "edr_attack", B + "cbc-edr/edr-h1-benign.jsonl": "edr_benign", A + "msft-security/msft-security-h1-m1.xml": "sec", A + "sysmon/sysmon-h1-m1.xml": "sysmon",
        A + "dns/dns-h1-m1": "dns", A + "msft-security/groundtruth/h1_m1": "sec_gt"}


def main():
    path, labdir, out = sys.argv[1:4]
    lab_lines, lab = {}, set()
    with open(f"{labdir}/h1-m1.labels", encoding="utf-8") as f:
        lab_header = f.readline().rstrip("\n")
        for line in f:
            line = line.rstrip("\n")
            p = [x.strip() for x in line.split(",")]
            if len(p) >= 5:
                lab.add(p[3])
                lab_lines[p[3]] = line
    res = {"label_header": lab_header, "label_lines": lab_lines}
    done = set()
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            kind = WANT.get(m.name)
            if not kind:
                continue
            print("[member]", m.name, m.size, flush=True)
            f = tf.extractfile(m)
            if kind == "edr_attack":
                pos, neg = defaultdict(list), defaultdict(list)
                for raw in f:
                    if b'"endpoint.event.netconn"' not in raw[:60]:
                        continue
                    d = json.loads(raw)
                    g = d["process_guid"]
                    tgt = pos if g in lab else neg
                    if len(tgt[g]) < 12:
                        tgt[g].append(raw.decode("utf-8").rstrip("\n"))
                res["attack_file_labeled"] = dict(pos)
                res["attack_file_unlabeled"] = {g: v for g, v in list(neg.items())[:40]}
            elif kind == "edr_benign":
                neg = defaultdict(list)
                for i, raw in enumerate(f):
                    if b'"endpoint.event.netconn"' not in raw[:60]:
                        continue
                    d = json.loads(raw)
                    g = d["process_guid"]
                    if len(neg[g]) < 12:
                        neg[g].append(raw.decode("utf-8").rstrip("\n"))
                    if i > 700000 and len(neg) > 60:
                        break
                res["benign_file"] = dict(neg)
            elif kind == "sec":
                head = f.read(6_000_000).decode("utf-8", "replace")
                ev = {}
                for e in re.findall(r"<Event .*?</Event>", head, flags=re.S):
                    i = re.search(r"<EventID[^>]*>(\d+)</EventID>", e)
                    if i and i.group(1) in ("5156", "4688") and i.group(1) not in ev:
                        ev[i.group(1)] = e
                res["security_events"] = ev
                res["security_head"] = head[:400]
            elif kind == "sysmon":
                text = f.read().decode("utf-8", "replace")
                ev = {}
                for e in re.findall(r"<Event .*?</Event>", text, flags=re.S):
                    i = re.search(r"<EventID>(\d+)</EventID>", e)
                    if i and i.group(1) in ("1", "5") and i.group(1) not in ev:
                        ev[i.group(1)] = e
                res["sysmon_events"] = ev
            elif kind == "dns":
                res["dns_head"] = f.read(3000).decode("utf-8", "replace").split("\n")[:8]
            elif kind == "sec_gt":
                res["sec_gt_head"] = f.read(300).decode("utf-8", "replace").split("\n")[:6]
            done.add(kind)
            if len(done) == len(WANT):
                break
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", sorted(done), flush=True)


if __name__ == "__main__":
    main()
