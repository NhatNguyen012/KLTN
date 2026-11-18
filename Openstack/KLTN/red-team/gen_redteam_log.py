#!/usr/bin/env python3
"""Build the red-team ground-truth log from the playbooks (+ optional Windows ART CSV).

Each AttackMate command's `metadata` and each Windows plan line becomes one row with the
model stage (IC/ED/LM/EX/Impact), ATT&CK techniques and expected telemetry. Fill utc_start/
utc_end from the AttackMate run log (or the ART CSV, which already has them), then use the
rows to tick attack events on /soc. Columns match docs/hunting_reading_list.md section 8.

Usage:
  python3 gen_redteam_log.py linux/*.yml --win-csv windows/redteam_*.csv -o redteam_log.csv
"""
import argparse, csv, glob, sys
try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

TACTIC_TO_STAGE = {
    "initial access": "initial_compromise",
    "lateral movement": "lateral_movement",
    "exfiltration": "exfiltration",
    "impact": "impact",
}  # everything else -> execution_discovery


def stage_of(tactics: str) -> str:
    for t in (tactics or "").lower().split(","):
        s = TACTIC_TO_STAGE.get(t.strip())
        if s:
            return s
    return "execution_discovery"


def rows_from_playbook(path):
    doc = yaml.safe_load(open(path)) or {}
    run = path.split("/")[-1].rsplit(".", 1)[0]
    for i, cmd in enumerate(doc.get("commands", []), 1):
        m = cmd.get("metadata") or {}
        if not m:
            continue
        yield {
            "run": run, "step": i, "utc_start": "", "utc_end": "",
            "host": cmd.get("hostname", "session"),
            "stage": stage_of(m.get("tactics", "")),
            "technique": m.get("techniques", ""), "tactic": m.get("tactics", ""),
            "action": m.get("description", ""), "telemetry": m.get("telemetry", ""),
            "note": cmd.get("type", ""),
        }


def rows_from_win_csv(path):
    for r in csv.DictReader(open(path)):
        yield {
            "run": path.split("/")[-1], "step": "", "utc_start": r.get("utc_start", ""),
            "utc_end": r.get("utc_end", ""), "host": "kltn-windows-1",
            "stage": "", "technique": r.get("technique", ""), "tactic": r.get("tactic", ""),
            "action": r.get("note", ""), "telemetry": "Sysmon", "note": "ART",
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("playbooks", nargs="*", help="AttackMate .yml playbooks (globs ok)")
    ap.add_argument("--win-csv", nargs="*", default=[], help="run_atomics.ps1 CSV logs")
    ap.add_argument("-o", "--out", default="redteam_log.csv")
    a = ap.parse_args()

    cols = ["run", "step", "utc_start", "utc_end", "host", "stage", "technique",
            "tactic", "action", "telemetry", "note"]
    rows = []
    for pat in a.playbooks:
        for p in sorted(glob.glob(pat)):
            rows += list(rows_from_playbook(p))
    for pat in a.win_csv:
        for p in sorted(glob.glob(pat)):
            rows += list(rows_from_win_csv(p))

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
