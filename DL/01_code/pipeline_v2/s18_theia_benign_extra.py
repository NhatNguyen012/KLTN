#!/usr/bin/env python3
"""S18d - Bổ sung mẫu benign THEIA từ các lát cắt không có nhãn (3, 5m): lấy NGUYÊN VĂN dòng Subject, Principal, NetFlowObject, Event của tiến trình có kết nối tới đầu xa thật.

Cách dùng: python -I s18_theia_benign_extra.py <out.json> <tar.gz> [<tar.gz> ...]"""
import json
import re
import sys
import tarfile
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8")
PFX = '{"datum":{"com.bbn.tc.schema.avro.cdm18.'
UUID_RE = re.compile(r'^\{"datum":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.[A-Za-z]+":\{"uuid":"([0-9A-Fa-f-]+)"')
PO_RE = re.compile(r'"predicateObject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
SJ_RE = re.compile(r'"subject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
TYPE_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')
RA_RE = re.compile(r'"remoteAddress":"([^"]*)"')
LP_RE = re.compile(r'"localPrincipal":"([0-9A-Fa-f-]+)"')
PATH_RE = re.compile(r'"path":"([^"]*)"')
NET = {"EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG"}
SKIP = {"/home/admin/Downloads/firefox/firefox", "/usr/lib/thunderbird/thunderbird"}
PREFER = ["/usr/sbin/sshd", "/usr/sbin/console-kit-daemon", "/usr/sbin/NetworkManager", "/usr/bin/python2.7", "/usr/lib/postgresql/9.1/bin/postgres", "/bin/bash", "/usr/bin/firefox"]


def main():
    out = sys.argv[1]
    res = {}
    for tarp in sys.argv[2:]:
        subj, nf, princ = defaultdict(list), {}, []
        ev = defaultdict(list)
        with tarfile.open(tarp, "r|gz") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                for rl in tf.extractfile(m):
                    line = rl.decode("utf-8", "replace").rstrip("\n")
                    if not line.startswith(PFX):
                        continue
                    k = line[len(PFX):len(PFX) + 14]
                    if k.startswith("Event"):
                        ty = TYPE_RE.search(line)
                        if ty and ty.group(1) in NET:
                            po, sj = PO_RE.search(line), SJ_RE.search(line)
                            if po and sj and po.group(1).upper() in nf:
                                ra = RA_RE.search(nf[po.group(1).upper()])
                                if ra and ra.group(1) not in ("NA", "", "NETLINK", "LOCAL") and not ra.group(1).startswith("127.") and len(ev[sj.group(1).upper()]) < 8:
                                    ev[sj.group(1).upper()].append(line)
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

        def path_of(sj):
            for ln in subj.get(sj, []):
                m = PATH_RE.search(ln)
                if m:
                    return m.group(1)
        picks = {}
        for p in PREFER:
            for sj, lines in sorted(ev.items(), key=lambda kv: -len(kv[1])):
                if path_of(sj) == p and len(lines) >= 4 and p not in picks:
                    picks[p] = sj
        pool = {}
        for p, sj in picks.items():
            nfl = {}
            for ln in ev[sj]:
                u = PO_RE.search(ln).group(1).upper()
                nfl[u] = nf[u]
            pr = [x for x in princ if any(f'"uuid":"{m}"' in x for m in {m.upper() for ln in subj[sj] for m in LP_RE.findall(ln)} | {m for ln in subj[sj] for m in LP_RE.findall(ln)})]
            pool[p] = {"subject": sj, "subject_lines": subj[sj], "events": ev[sj], "netflow_lines": nfl, "principal_lines": pr}
        res[tarp.split("/")[-1]] = {"candidates_subjects": len(ev), "picks": pool}
        print("[done]", tarp, len(ev), list(picks), flush=True)
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
