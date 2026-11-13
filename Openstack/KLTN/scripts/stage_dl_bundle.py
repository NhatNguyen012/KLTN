#!/usr/bin/env python3
"""Stage a verified host-dl bundle for the central DL worker: copy to runtime/models/dl/releases/<bundle_id> (immutable,
read-only), atomically repoint runtime/models/dl/current, restart the dl-worker container. Rollback = stage the
previous release again."""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DL = ROOT / "runtime/models/dl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--no-restart", action="store_true")
    a = ap.parse_args()
    src = Path(a.bundle).resolve()
    v = subprocess.run([sys.executable, str(ROOT / "scripts/verify_model_bundle.py"), str(src), "--branch", "host_dl",
                        "--require-eligible"], capture_output=True, text=True)
    if v.returncode:
        sys.exit(v.stdout or v.stderr)
    bid = json.loads((src / "manifest.json").read_text())["bundle_id"]
    dst = DL / "releases" / bid
    if not dst.exists():
        tmp = dst.with_name(bid + ".staging")
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.copytree(src, tmp)
        for p in sorted(tmp.rglob("*"), reverse=True):
            os.chmod(p, 0o555 if p.is_dir() else 0o444)
        os.chmod(tmp, 0o555)
        tmp.rename(dst)
    link = DL / "current"
    new = DL / ".current.new"
    if new.is_symlink() or new.exists():
        new.unlink()
    new.symlink_to(Path("releases") / bid)
    os.replace(new, link)
    print(json.dumps({"staged": bid, "current": os.readlink(link)}))
    if not a.no_restart:
        subprocess.run(["docker", "compose", "-f", str(ROOT / "central/compose.yaml"), "restart", "dl-worker"], check=True)


if __name__ == "__main__":
    main()
