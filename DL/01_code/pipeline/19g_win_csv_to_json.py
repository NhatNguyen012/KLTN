#!/usr/bin/env python3
"""STEP 19g - đổi windows_apt_raw_samples.csv sang JSON cho dễ nhìn.
 - windows_apt_raw_samples.json: mảng 79 object, MỖI object đủ 377 khóa theo đúng tên cột gốc, giá trị là chuỗi nguyên văn (không parse, không bỏ cột).
 - windows_apt_raw_samples_readable.json: cùng 79 dòng nhưng chỉ in các khóa có giá trị khác rỗng (bỏ khóa có giá trị rỗng hoặc chỉ là dấu cách); đây là bản RÚT GỌN để đọc, không phải bản nguyên vẹn.
"""
import csv
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")
csv.field_size_limit(10**9)
D = "D:/UIT/KLTNv2/02_artifacts/19_dataset_analysis_v1/raw_samples/"
with open(D + "windows_apt_raw_samples.csv", encoding="utf-8-sig", newline="") as fh:
    rd = csv.reader(fh)
    header = next(rd)
    rows = [dict(zip(header, r)) for r in rd]
with open(D + "windows_apt_raw_samples.json", "w", encoding="utf-8", newline="\n") as fh:
    json.dump(rows, fh, ensure_ascii=False, indent=2)
slim = [{k: v for k, v in r.items() if v.strip() != ""} for r in rows]
with open(D + "windows_apt_raw_samples_readable.json", "w", encoding="utf-8", newline="\n") as fh:
    json.dump(slim, fh, ensure_ascii=False, indent=2)
# kiểm tra vòng về: JSON đầy đủ -> CSV phải trùng từng ô
back = json.load(open(D + "windows_apt_raw_samples.json", encoding="utf-8"))
same = all([r[h] for h in header] == c for r, c in zip(back, csv.reader(open(D + "windows_apt_raw_samples.csv", encoding="utf-8-sig", newline=""))) if False) or True
with open(D + "windows_apt_raw_samples.csv", encoding="utf-8-sig", newline="") as fh:
    rd = csv.reader(fh)
    next(rd)
    ok = sum([r[h] for h in header] == c for r, c in zip(back, rd))
print("rows", len(rows), "| khóa mỗi object", {len(r) for r in back}, "| khớp CSV", ok, "/", len(rows))
print("số khóa còn lại ở bản readable (min/trung bình/max):", min(map(len, slim)), round(sum(map(len, slim)) / len(slim), 1), max(map(len, slim)))
