#!/usr/bin/env python3
"""S17a - Liệt kê thành viên của .tar.gz (streaming, không giải nén). Cách dùng: python -I s17_tar_list.py <tar.gz> <csv ra>"""
import csv
import sys
import tarfile

with tarfile.open(sys.argv[1], "r|gz") as tf, open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["name", "size", "isfile"])
    for m in tf:
        w.writerow([m.name, m.size, int(m.isfile())])
print("xong")
