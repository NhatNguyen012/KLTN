#!/usr/bin/env python3
"""STEP 19e - trích mẫu THÔ NGUYÊN BẢN (verbatim) từ 3 dataset: không thêm, không bớt cột, không sửa giá trị.
  saga  : dòng JSONL gốc (byte nguyên bản), 2-3 dòng mỗi nhãn Txxxx_ability trong file đầu tiên chứa nhãn đó, + benign mỗi loại dstNode 1 dòng.
  win   : dòng CSV gốc của combined.csv (đủ 377 cột + dòng tiêu đề gốc), 3 dòng mỗi giá trị nhãn `_source.rule.mitre.tactic` (đầu / giữa / cuối trong file).
  skr   : dòng JSONL gốc, 3 dòng ngẫu nhiên (seed 0) mỗi (chiến dịch, object) + với FIN6 vài dòng PROCESS trong cửa sổ tấn công theo PDF ground truth.
Thông tin chọn dòng (nguồn, số dòng, lý do) nằm trong file *_index.csv RIÊNG, không chèn vào file mẫu.
Dùng: python 19e_raw_samples.py saga|win|skr
"""
import collections
import csv
import io
import os
import random
import re
import sys
import zipfile

sys.stdout.reconfigure(encoding="utf-8")
csv.field_size_limit(10**9)
OUT = "D:/UIT/KLTNv2/02_artifacts/19_dataset_analysis_v1/raw_samples"
os.makedirs(OUT, exist_ok=True)
SAGA = "D:/UIT/KLTNv2/03_datasets/SAGA"
SAGA_ZIPS = ["Known APT Campaigns Dataset.zip", "Generated APT Campaigns Dataset.zip", "Composite APT Campaigns Dataset.zip"]
WIN = ("C:/Users/ADMIN/AppData/Local/Temp/claude/D--UIT-KLTNv2/edeb5b63-667d-405e-9687-a8a1691b1334/scratchpad/winapt/"
       "Windows-APT 2025 A Dataset for APT-Inspired Attack/combined.csv")
SKR = "D:/UIT/KLTNv2/03_datasets/skrghosh/apt-dataset-git"
RE_LABEL = re.compile(rb'"label": "([^"]*)"\}\s*$')
RE_DST = re.compile(rb'"dstNode": \{[^{}]*?"Type": "([^"]*)"')


def spread(n, k=3):
    if n <= k:
        return list(range(n))
    return sorted({0, n // 2, n - 1})


def write_index(name, rows, fields):
    with open(f"{OUT}/{name}", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def saga():
    chosen_labels = set()
    out_lines, idx = [], []
    ben = {}
    for z in SAGA_ZIPS:
        with zipfile.ZipFile(f"{SAGA}/{z}") as zf:
            for info in sorted(zf.infolist(), key=lambda i: (len(i.filename), i.filename)):
                per = collections.defaultdict(list)
                with zf.open(info) as f:
                    for ln, raw in enumerate(f, 1):
                        line = raw.rstrip(b"\r\n")
                        if not line:
                            continue
                        m = RE_LABEL.search(line, max(0, len(line) - 120))
                        if not m:
                            continue
                        lb = m.group(1).decode()
                        if lb == "benign":
                            md = RE_DST.search(line)
                            t = md.group(1).decode() if md else "?"
                            if t not in ben and t in ("Registry", "File", "Network", "Process"):
                                ben[t] = (z, info.filename, ln, line)
                            continue
                        if lb in chosen_labels:
                            continue
                        per[lb].append((ln, line))
                for lb, items in per.items():
                    chosen_labels.add(lb)
                    for i in spread(len(items)):
                        ln, line = items[i]
                        out_lines.append(line)
                        idx.append({"sample_row": len(out_lines), "dataset": "SAGA", "source_zip": z, "source_file": info.filename, "source_line_number": ln, "label": lb,
                                    "selection": f"vị trí {i + 1}/{len(items)} của nhãn này trong file (đầu, giữa, cuối)"})
                print(info.filename, "labels so far", len(chosen_labels), flush=True)
    for t, (z, fn, ln, line) in ben.items():
        out_lines.append(line)
        idx.append({"sample_row": len(out_lines), "dataset": "SAGA", "source_zip": z, "source_file": fn, "source_line_number": ln, "label": "benign",
                    "selection": f"dòng benign đầu tiên có dstNode.Type = {t}"})
    with open(f"{OUT}/saga_raw_samples.jsonl", "wb") as fh:
        for line in out_lines:
            fh.write(line + b"\n")
    write_index("saga_raw_samples_index.csv", idx, ["sample_row", "dataset", "source_zip", "source_file", "source_line_number", "label", "selection"])
    print("SAGA rows", len(out_lines), "labels", len(chosen_labels))


def win():
    with open(WIN, "r", encoding="utf-8-sig", newline="") as fh:
        head = fh.readline()
    term = "\r\n" if head.endswith("\r\n") else "\n"
    with open(WIN, "r", encoding="utf-8-sig", newline="") as fh:
        rd = csv.reader(fh)
        header = next(rd)
        col = header.index("_source.rule.mitre.tactic")
        groups = collections.defaultdict(list)
        for i, row in enumerate(rd, 1):
            groups[row[col].strip()].append((i, row))
    rows_out, idx = [], []
    for lab in sorted(groups, key=lambda k: (k == "", -len(groups[k]))):
        items = groups[lab]
        for p in spread(len(items)):
            i, row = items[p]
            rows_out.append(row)
            idx.append({"sample_row": len(rows_out), "dataset": "Windows-APT 2025", "source_file": "combined.csv", "source_data_row_number": i,
                        "label_value_of__source.rule.mitre.tactic": lab if lab else "(trống: không có tactic)", "n_rows_with_this_label": len(items),
                        "selection": f"vị trí {p + 1}/{len(items)} (đầu, giữa, cuối trong file)"})
    with open(f"{OUT}/windows_apt_raw_samples.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, lineterminator=term)
        w.writerow(header)
        w.writerows(rows_out)
    write_index("windows_apt_raw_samples_index.csv", idx, ["sample_row", "dataset", "source_file", "source_data_row_number", "label_value_of__source.rule.mitre.tactic",
                                                           "n_rows_with_this_label", "selection"])
    print("WIN rows", len(rows_out), "cols", len(header), "labels", len(groups), "terminator", repr(term))


RE_OBJ = re.compile(rb'"object":"([A-Z_]+)"')
RE_TS = re.compile(rb'"timestamp":"([^"]+)"')
RE_CMD = re.compile(rb'"command_line":"')


def skr():
    rnd = random.Random(0)
    out_lines, idx = [], []
    for n in ["apt29", "fin6", "oilrig", "output_menuPass", "wizard_spider"]:
        res = collections.defaultdict(list)  # object -> list of (ln, line) reservoir k=3
        seen = collections.Counter()
        attack = []
        with zipfile.ZipFile(f"{SKR}/{n}.json.zip") as zf:
            info = [i for i in zf.infolist() if not i.filename.startswith("__MACOSX")][0]
            with zf.open(info) as f:
                for ln, raw in enumerate(f, 1):
                    line = raw.rstrip(b"\r\n")
                    if not line:
                        continue
                    m = RE_OBJ.search(line)
                    o = m.group(1).decode() if m else "?"
                    seen[o] += 1
                    r = res[o]
                    if len(r) < 3:
                        r.append((ln, line))
                    else:
                        j = rnd.randint(1, seen[o])
                        if j <= 3:
                            r[j - 1] = (ln, line)
                    if n == "fin6" and o == "PROCESS" and len(attack) < 6 and RE_CMD.search(line):
                        mt = RE_TS.search(line)
                        ts = mt.group(1).decode()[:19] if mt else ""
                        if "2023-07-25T11:12:18" <= ts <= "2023-07-25T11:13:55" and re.search(rb"adfind|powershell|wce\.exe|7za", line, re.I):
                            attack.append((ln, line))
        for o in sorted(res):
            for ln, line in sorted(res[o]):
                out_lines.append(line)
                idx.append({"sample_row": len(out_lines), "dataset": "skrghosh", "source_zip": f"{n}.json.zip", "source_line_number": ln, "campaign": n, "object": o,
                            "selection": f"ngẫu nhiên (seed 0) trong {seen[o]:,} dòng object={o} của chiến dịch; dataset KHÔNG có cột nhãn"})
        for ln, line in attack:
            out_lines.append(line)
            idx.append({"sample_row": len(out_lines), "dataset": "skrghosh", "source_zip": f"{n}.json.zip", "source_line_number": ln, "campaign": n, "object": "PROCESS",
                        "selection": "FIN6, trong cửa sổ tấn công 11:12:18 đến 11:13:55 (-07:00) theo PDF ground truth, lệnh chứa adfind/powershell/wce/7za (nhãn suy từ PDF, không có trong dữ liệu)"})
        print(n, dict(seen), "attack-window rows", len(attack), flush=True)
    with open(f"{OUT}/skrghosh_raw_samples.jsonl", "wb") as fh:
        for line in out_lines:
            fh.write(line + b"\n")
    write_index("skrghosh_raw_samples_index.csv", idx, ["sample_row", "dataset", "source_zip", "source_line_number", "campaign", "object", "selection"])
    print("SKR rows", len(out_lines))


if __name__ == "__main__":
    {"saga": saga, "win": win, "skr": skr}[sys.argv[1]]()
    print("DONE")
