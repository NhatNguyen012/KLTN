#!/usr/bin/env python3
"""STEP 13 - sua loi CSV cua Unraveled (network-flows). Khong sua file goc; ghi ban sach sang thu muc moi.

Loi: mot so truong van ban chua dau phay khong duoc bao trong dau nhay, nen dong bi tach thanh >89 truong:
  (a) user_agent co dau phay ("... (KHTML, like Gecko) ...")           -> 90 truong
  (b) client_fingerprint cua DHCP la danh sach option "1,3,6,15,..."    -> 99..107 truong
Cach sua (neo theo cot):
  - 4 truong cuoi luon la nhan (Activity, Stage, DefenderResponse, Signature); truong ke cuoi la content_type.
  - Dong DHCP (application_name == 'DHCP'): server_fingerprint = row[n-7], user_agent = row[n-6],
    client_fingerprint = ','.join(row[81:n-7]).
  - Dong khac: user_agent = ','.join(row[83:n-5]).
Moi dong sau sua phai co dung 89 truong va Stage thuoc tap hop hop le, neu khong se bi dua vao quarantine.csv.
"""
import collections
import concurrent.futures as cf
import csv
import glob
import json
import os
import sys

SRC = "D:/UIT/KLTNv2/03_datasets/unraveled_v1/network-flows/"
DST = "D:/UIT/KLTNv2/03_datasets/unraveled_v1_clean/network-flows/"
NCOL = 89
VALID_STAGE = {"Benign", "Reconnaissance", "Lateral Movement", "Establish Foothold", "Data Exfiltration", "Cover up"}
APP, REQ, CLI, SRV, UA, CT = 77, 80, 81, 82, 83, 84


def fix(row):
    n = len(row)
    if n == NCOL:
        return row, "ok"
    if n < NCOL:
        return None, "too_short"
    if row[APP] == "DHCP":
        fixed = row[:CLI] + [",".join(row[CLI:n - 7]), row[n - 7], row[n - 6]] + row[n - 5:]
        kind = "dhcp_fingerprint"
    else:
        fixed = row[:UA] + [",".join(row[UA:n - 5])] + row[n - 5:]
        kind = "user_agent_comma"
    return (fixed if len(fixed) == NCOL else None), kind


def do_file(f):
    rel = f.replace("\\", "/").split("network-flows/")[1]
    out = DST + rel
    os.makedirs(os.path.dirname(out), exist_ok=True)
    kinds, stages, quarantine = collections.Counter(), collections.Counter(), []
    with open(f, newline="", encoding="utf-8", errors="replace") as fi, open(out, "w", newline="", encoding="utf-8") as fo:
        r = csv.reader(fi)
        w = csv.writer(fo, lineterminator="\n")
        h = next(r)
        w.writerow(h)
        for i, row in enumerate(r):
            fixed, kind = fix(row)
            if fixed is None or fixed[86] not in VALID_STAGE:
                quarantine.append((rel, i + 2, len(row), "|".join(row[-6:])))
                kinds["quarantine"] += 1
                continue
            kinds[kind] += 1
            stages[fixed[86]] += 1
            w.writerow(fixed)
    return rel, kinds, stages, quarantine


def main():
    files = sorted(glob.glob(SRC + "*/*.csv"))
    tot_k, tot_s, tot_q = collections.Counter(), collections.Counter(), []
    with cf.ProcessPoolExecutor(10) as ex:
        for i, (rel, k, s, q) in enumerate(ex.map(do_file, files), 1):
            tot_k.update(k)
            tot_s.update(s)
            tot_q += q
            print(f"[{i}/{len(files)}] {rel} {dict(k)}", flush=True)
    with open(DST + "../quarantine.csv", "w", newline="\n", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "line_in_file", "n_fields", "last_6_fields"])
        w.writerows(tot_q)
    rep = {"files": len(files), "row_repairs": dict(tot_k), "stage_counts": dict(tot_s), "quarantined": len(tot_q)}
    with open(DST + "../clean_report.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
