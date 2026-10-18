#!/usr/bin/env python3
"""Chạy tuần tự S2 -> S5 sau khi S1 xong; dừng ở bước đầu tiên lỗi hoặc không PASS. Nhật ký: 02_artifacts/22_v2_pipeline/run_s2_to_s5.log"""
import os
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}

V2 = Path("D:/UIT/KLTNv2/02_artifacts/22_v2_pipeline")
PY = "D:/UIT/KLTNv2/.venv-host/Scripts/python.exe"
CODE = Path("D:/UIT/KLTNv2/01_code/pipeline_v2")
LOG = open(V2 / "run_s2_to_s5.log", "a", encoding="utf-8")


def log(m):
    line = f"[{time.strftime('%H:%M:%S')}] {m}"
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def wait_s1():
    p = V2 / "S1_join/stdout.txt"
    while True:
        t = p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""
        if "S1 xong" in t:
            return True
        if "Traceback" in t or "Error" in t:
            return False
        time.sleep(15)


def run(step, script):
    log(f"=== {step}: bắt đầu")
    r = subprocess.run([PY, "-I", str(CODE / script)], capture_output=True, text=True, encoding="utf-8", errors="replace", env=ENV)
    (V2 / f"{step}_stdout.txt").write_text(r.stdout, encoding="utf-8")
    (V2 / f"{step}_stderr.txt").write_text(r.stderr, encoding="utf-8")
    ok = r.returncode == 0 and "PASS=True" in r.stdout
    log(f"=== {step}: returncode={r.returncode}, PASS={'PASS=True' in r.stdout}")
    if not ok:
        log(r.stdout[-1500:] + "\n" + r.stderr[-2500:])
    return ok


if __name__ == "__main__":
    if not wait_s1():
        log("S1 lỗi, dừng")
        sys.exit(1)
    log("S1 xong")
    for step, script in (("S2", "s2_windows_split.py"), ("S3", "s3_preprocess.py"), ("S4", "s4_shards.py"), ("S5", "s5_validate.py")):
        if not run(step, script):
            log(f"{step} lỗi hoặc không PASS, dừng")
            sys.exit(2)
    log("S2-S5 xong, tất cả PASS")
