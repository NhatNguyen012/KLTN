#!/usr/bin/env python3
"""Host ML shards with the v9b label policy (see analyst/dl_bilstm_v9_20261112.md).

Thin wrapper around build_host_shards.py: identical tokenisation, sampling,
split and vocabulary logic; only the LabelRefiner differs:
  * REAPr seed endpoints contacted in benign-day telemetry are not evidence;
  * attack start per scenario = min(configured gate, first connection of any
    process to the attacker host 10.193.66.115), read from the v9b dataset meta.
Workers are forked, so the patched class is inherited by every worker.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_host_shards as bhs  # noqa: E402

# ATLAS_LABEL_META: meta of another label build, e.g. the v9c correction (2026-11-20): gate from OUTBOUND attacker
# connections only, and inbound connections whose (remote ip, local port) occur on the benign days are not malicious.
META = Path(os.environ.get("ATLAS_LABEL_META", "/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/output/bilstm_v9_20261112/dataset_v9b_meta.json"))
_meta = json.loads(META.read_text())
_GATES = {sc: int(datetime.fromisoformat(t).timestamp() * 1_000_000) for sc, t in _meta["gates_v9b"].items()}
_DROP = set(_meta["seed_endpoints_dropped"])
_INB = set(_meta.get("v9c_benign_inbound_endpoints") or ())
_V9D = bool(_meta.get("v9d"))
_USER = set(_meta.get("v9d_user_lineage_guids") or ())
from preprocess.label_refiner import EXPLOIT_CHILD_PROCS as _EXPLOIT_CHILD  # noqa: E402


class PolicyRefinerV9b(bhs.LabelRefiner):
    def _load_ground_truth(self) -> None:
        super()._load_ground_truth()
        for sc, t in _GATES.items():
            self.scenario_attack_micros[sc] = min(self.scenario_attack_micros.get(sc, t), t)
        for sc, seeds in self.scenario_seeds.items():
            self.scenario_seeds[sc] = {s for s in seeds if s.strip().rstrip(",") not in _DROP}

    def is_event_malicious(self, event) -> bool:
        if _INB and event.event_type == "FLOW_START" and event.inbound and f"{event.remote_ip}->:{event.local_port}" in _INB:
            return False
        y = super().is_event_malicious(event)
        if y and _V9D:      # v9d R1/R2, same rules as bilstm_v9/build_dataset.py --v9d (user-shell lineage read from its meta)
            a = bhs.extract_basename(event.process_path)
            t = bhs.extract_basename(event.target_path or "")
            if (event.process_guid or "").lower() in _USER:
                return False
            if event.event_type in ("PROCESS_START", "CROSS_PROCESS"):
                if (event.target_guid or "").lower() in _USER and a in ("explorer.exe", "conhost.exe", "lsass.exe"):
                    return False
                if event.event_type == "CROSS_PROCESS" and a in ("lsass.exe", "conhost.exe") and t not in _EXPLOIT_CHILD:
                    return False
        return y


bhs.LabelRefiner = PolicyRefinerV9b

if __name__ == "__main__":
    import multiprocessing as mp
    mp.set_start_method("fork", force=True)
    out = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--output-dir=")), None)
    if out is None and "--output-dir" in sys.argv:
        out = sys.argv[sys.argv.index("--output-dir") + 1]
    if out is None or Path(out).resolve() == (HERE / "output").resolve():
        raise SystemExit("pass a NEW --output-dir; the published legacy shards are not overwritten")
    if Path(out).exists() and any(Path(out).iterdir()):
        raise SystemExit(f"output dir not empty: {out}")
    print("v9b gates:", _meta["gates_v9b"])
    bhs.main()
