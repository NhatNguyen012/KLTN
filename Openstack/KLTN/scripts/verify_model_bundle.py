#!/usr/bin/env python3
"""Verify an immutable model bundle (bundle.v2) on the controller before any rollout.

Always: schema, branch, artifact containment / no symlinks / byte size / sha256 for every listed file, no unlisted
files, the vendored featurizer files referenced by runtime_code_sha256 are the ones in this checkout.
--require-eligible: activation.eligible and parity.passed must be true (computed by scripts/build_il_bundles.py).
Prints a JSON verdict; exit status 1 on any failure.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def verify(root: Path, branch: str | None, require_eligible: bool) -> list[str]:
    errors = []
    root = root.resolve()
    try:
        m = json.loads((root / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        return [f"manifest unreadable: {exc}"]
    if m.get("schema_version") != "bundle.v2":
        errors.append("schema_version != bundle.v2")
    if branch and m.get("branch") != branch:
        errors.append(f"branch {m.get('branch')} != {branch}")
    arts = m.get("artifacts") or {}
    listed = set()
    for rel, meta in arts.items():
        p = (root / rel)
        try:
            p.resolve().relative_to(root)
        except ValueError:
            errors.append(f"{rel}: escapes the bundle")
            continue
        if p.is_symlink() or not p.is_file():
            errors.append(f"{rel}: missing or symlink")
            continue
        if p.stat().st_size != meta.get("bytes") or sha256(p) != meta.get("sha256"):
            errors.append(f"{rel}: size/sha256 mismatch")
        listed.add(p.resolve())
    extra = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and p.name != "manifest.json"
             and p.resolve() not in listed]
    if extra:
        errors.append(f"unlisted files: {extra[:5]}")
    for rel, expected in (m.get("runtime_code_sha256") or {}).items():
        p = ROOT / "serving" / rel
        if not p.is_file() or sha256(p) != expected:
            errors.append(f"runtime code {rel} differs from this checkout (rebuild the bundle or deploy matching code)")
    if require_eligible:
        if not m.get("activation", {}).get("eligible"):
            errors.append(f"not eligible: {m.get('activation', {}).get('blockers')}")
        if m.get("parity", {}).get("passed") is not True:
            errors.append("parity not passed")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--branch", choices=["host_ml", "host_dl"])
    ap.add_argument("--require-eligible", action="store_true")
    a = ap.parse_args()
    errors = verify(Path(a.bundle), a.branch, a.require_eligible)
    print(json.dumps({"bundle": a.bundle, "ok": not errors, "errors": errors}))
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
