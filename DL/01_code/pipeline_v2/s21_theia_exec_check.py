#!/usr/bin/env python3
"""S21 - THEIA: Subject của tiến trình 7F1FD92F có EVENT_EXECUTE nào không và đường dẫn thực thi là gì (kiểm tra fork-rồi-exec).

Đọc streaming 6r, dừng khi thấy. Cách dùng: python -I s21_theia_exec_check.py <6r.tar.gz> <subject uuid> <json ra>"""
import json
import re
import sys
import tarfile

sys.stdout.reconfigure(encoding="utf-8")
raw, sj, out = sys.argv[1:4]
SJ = re.compile(r'"subject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"' + re.escape(sj) + '"', re.I)
found = []
subj_lines = []
n = 0
with tarfile.open(raw, "r|gz") as tf:
    for m in tf:
        if not m.isfile():
            continue
        print("[member]", m.name, flush=True)
        for rl in tf.extractfile(m):
            n += 1
            line = rl.decode("utf-8", "replace").rstrip("\n")
            if sj in line:
                if line.startswith('{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject"'):
                    subj_lines.append(line)
                elif '"type":"EVENT_EXECUTE"' in line and SJ.search(line):
                    found.append(line)
                    if len(found) >= 5:
                        break
        if found:
            break
json.dump({"subject": sj, "subject_lines": subj_lines, "execute_events": found, "lines_read": n}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("[xong]", len(found), len(subj_lines), flush=True)
