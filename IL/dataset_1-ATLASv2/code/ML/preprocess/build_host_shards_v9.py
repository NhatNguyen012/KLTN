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
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_host_shards as bhs  # noqa: E402

META = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/output/bilstm_v9_20261112/dataset_v9b_meta.json")
_meta = json.loads(META.read_text())
_GATES = {sc: int(datetime.fromisoformat(t).timestamp() * 1_000_000) for sc, t in _meta["gates_v9b"].items()}
_DROP = set(_meta["seed_endpoints_dropped"])


class PolicyRefinerV9b(bhs.LabelRefiner):
    def _load_ground_truth(self) -> None:
        super()._load_ground_truth()
        for sc, t in _GATES.items():
            self.scenario_attack_micros[sc] = min(self.scenario_attack_micros.get(sc, t), t)
        for sc, seeds in self.scenario_seeds.items():
            self.scenario_seeds[sc] = {s for s in seeds if s.strip().rstrip(",") not in _DROP}


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
