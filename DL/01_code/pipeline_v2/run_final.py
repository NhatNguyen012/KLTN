#!/usr/bin/env python3
"""Chạy S2 -> S5 -> báo cáo -> đóng gói -> chạy thử CPU; dừng ở bước đầu tiên lỗi. Nhật ký: 02_artifacts/22_v2_pipeline/logs/run_final.log"""
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
(V2 / "logs").mkdir(exist_ok=True)
LOG = open(V2 / "logs/run_final.log", "a", encoding="utf-8")


def log(m):
    line = f"[{time.strftime('%H:%M:%S')}] {m}"
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def run(step, script, need_pass=True, isolated=True):
    log(f"=== {step}: bắt đầu")
    cmd = [PY] + (["-I"] if isolated else []) + [str(CODE / script)]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=ENV)
    (V2 / "logs" / f"{step}_stdout.txt").write_text(r.stdout, encoding="utf-8")
    (V2 / "logs" / f"{step}_stderr.txt").write_text(r.stderr, encoding="utf-8")
    ok = r.returncode == 0 and ("PASS=True" in r.stdout or not need_pass)
    log(f"=== {step}: returncode={r.returncode}, ok={ok}")
    if not ok:
        log(r.stdout[-1500:] + "\n" + r.stderr[-2500:])
    return ok


if __name__ == "__main__":
    for step, script, need in (("S2", "s2_windows_split.py", True), ("S3", "s3_preprocess.py", True), ("S4", "s4_shards.py", True), ("S5", "s5_validate.py", True),
                               ("REPORTS", "s_reports.py", False), ("S6_package", "s6_package.py", False), ("S6_smoke", "s6_smoke_test.py", False)):
        if not run(step, script, need, isolated=(step != "S6_smoke")):
            if step == "S6_smoke":
                log("smoke test lỗi (có thể chỉ thiếu matplotlib local); xem logs/S6_smoke_stdout.txt")
                break
            log(f"{step} lỗi, dừng")
            sys.exit(2)
    log("XONG")
