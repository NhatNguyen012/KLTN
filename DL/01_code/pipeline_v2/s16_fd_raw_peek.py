#!/usr/bin/env python3
"""S16a - Đọc streaming file raw FiveDirections E3 (.json.tar.gz) và liệt kê thành viên, vài dòng đầu mỗi file, loại bản ghi CDM.

Chỉ đọc, không giải nén ra đĩa. Cách dùng: python -I s16_fd_raw_peek.py <đường dẫn .tar.gz> <số dòng đầu>"""
import gzip
import json
import sys
import tarfile
import time

sys.stdout.reconfigure(encoding="utf-8")


def main():
    path, nlines = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3
    t0 = time.time()
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            print(f"[member] {m.name} size={m.size} isfile={m.isfile()} t={time.time() - t0:.0f}s", flush=True)
            if not m.isfile():
                continue
            f = tf.extractfile(m)
            for i, line in enumerate(f):
                if i >= nlines:
                    break
                s = line.decode("utf-8", "replace").rstrip()
                print(f"  line{i} len={len(s)}: {s[:1500]}", flush=True)


if __name__ == "__main__":
    main()
