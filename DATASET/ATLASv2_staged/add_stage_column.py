#!/usr/bin/env python3
"""Add Kill-Chain 'stage' column to ATLASv2 REAPr ground truth labels.

Ground truth mapping derived from:
1. ATLASv2 attack descriptions (S-1 to S-4, M-1 to M-6 in attack_descriptions/)
2. USENIX Security 2021 ATLAS paper (Attack Story Recovery & 8-step attack chain)
3. UIUC ATLASv2 Technical Report (CVE-2015-5122/5119/3105, CVE-2017-11882/0199, CVE-2018-8174)
4. APT-LMSPS (Information 2026) and DeepDist (IEEE TrustCom 2023) research papers.

Stage Taxonomy (Cyber Kill-Chain & MITRE ATT&CK):
- Stage 0: Benign (Non-attack background system activity)
- Stage 1: Initial_Compromise (Phishing link/attachment exploitation via Firefox Flash or Office Word/Excel/HTA)
- Stage 2: Execution_Discovery (Meterpreter remote shell, cmd.exe, PowerShell, recon/info gathering, living-off-the-land)
- Stage 3: Lateral_Movement (Web portal sabotage on h1 via python SimpleHTTP, victim download & execution on h2)
- Stage 4: Exfiltration (payload.exe sweeping high-profile .pdf files and HTTPS egress communication to C&C)
"""

from __future__ import annotations

import csv
import glob
from pathlib import Path

STAGE_MAPPING = {
    0: "Benign",
    1: "Initial_Compromise",
    2: "Execution_Discovery",
    3: "Lateral_Movement",
    4: "Exfiltration",
}


def classify_process_stage(scenario: str, host: str, process_name: str, label: str) -> str:
    """Classify an ATLASv2 process into its specific APT Kill-Chain stage."""
    p = process_name.lower().replace("/", "\\")
    lbl = label.lower().strip()

    if "attack" not in lbl:
        return "Benign"

    # Stage 4: Malicious payload sweeping PDFs and connecting out to C&C
    if "payload.exe" in p:
        return "Exfiltration"

    # Stage 3: Python SimpleHTTP internal web portal server on h1 (used for lateral infection)
    if "python.exe" in p:
        return "Lateral_Movement"

    # Stage 3: Secondary victim host (h2) browsing to compromised portal and executing update
    if host == "h2":
        if "firefox.exe" in p or "explorer.exe" in p:
            return "Lateral_Movement"
        return "Lateral_Movement"

    # Stage 1: Initial exploitation vectors on h1
    # Adobe Flash container and Firefox browser exploitation
    if "plugin-container.exe" in p:
        return "Initial_Compromise"
    if "firefox.exe" in p:
        return "Initial_Compromise"

    # Office document exploits (CVE-2017-11882, CVE-2017-0199, CVE-2018-8174)
    if any(k in p for k in [
        "winword.exe",
        "excel.exe",
        "eqnedt32.exe",
        "mshta.exe",
        "osppsvc.exe",
    ]):
        return "Initial_Compromise"

    # Stage 3: Explorer on h1 in multi-host scenarios (interacting with web portal directory)
    if "explorer.exe" in p and scenario.startswith("m"):
        return "Lateral_Movement"

    # Stage 2: Post-exploitation commands, shells, discovery and injected processes
    if any(k in p for k in [
        "cmd.exe",
        "conhost.exe",
        "powershell.exe",
        "regsvr32.exe",
        "schtasks.exe",
        "dllhost.exe",
        "taskhost.exe",
        "lsass.exe",
        "audiodg.exe",
        "explorer.exe",
    ]):
        return "Execution_Discovery"

    return "Execution_Discovery"


def process_labels_directory(labels_dir: Path) -> dict[str, int]:
    """Iterate through all .labels files in labels_dir and add the 'stage' column."""
    label_files = sorted(labels_dir.glob("*.labels"))
    if not label_files:
        raise FileNotFoundError(f"No .labels files found in {labels_dir}")

    total_stage_counts: dict[str, int] = {}

    for lf in label_files:
        stem = lf.stem  # e.g., 'h1-m1'
        if "-" in stem:
            host, sc = stem.split("-", 1)
        else:
            host, sc = "h1", stem

        with lf.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header is None:
                continue

            # Strip whitespace from headers
            headers = [h.strip() for h in header]

            # Check if 'stage' already present
            stage_idx = None
            for idx, h in enumerate(headers):
                if h.lower() == "stage":
                    stage_idx = idx
                    break

            rows = []
            for row in reader:
                if not row:
                    continue
                clean_row = [c.strip() for c in row]
                p_name = clean_row[1] if len(clean_row) > 1 else ""
                lbl = clean_row[4] if len(clean_row) > 4 else "benign"

                stage = classify_process_stage(sc, host, p_name, lbl)
                total_stage_counts[stage] = total_stage_counts.get(stage, 0) + 1

                if stage_idx is not None:
                    clean_row[stage_idx] = stage
                else:
                    clean_row.append(stage)
                rows.append(clean_row)

        if stage_idx is None:
            headers.append("stage")

        with lf.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

        print(f"Updated {lf.name:15s} -> {len(rows)} records with 'stage' column.")

    return total_stage_counts


def main():
    base_dir = Path(__file__).resolve().parent
    reapr_dir = base_dir / "reapr-ground-truth" / "atlasv2"
    if not reapr_dir.exists():
        # Fallback to local directory
        reapr_dir = base_dir

    print(f"Processing REAPr labels in: {reapr_dir}")
    counts = process_labels_directory(reapr_dir)
    print("\nTotal Process Distribution by Kill-Chain Stage:")
    for stg, cnt in sorted(counts.items()):
        print(f"  {stg:25s}: {cnt:4d} processes")


if __name__ == "__main__":
    main()
