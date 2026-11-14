#!/usr/bin/env python3
"""sl700_windows_v3: build_sl700_windows.py (same recipe) on relabel_v3 labels (code/relabel_v3_linux.py).
Default split as v1 (train a_a,a_b,b_a,e_a / val a_c / test f_a); --split overrides it, e.g. for a held-out-variant check:
  --split a_a=train,a_b=train,b_a=train,f_a=train,a_c=val,e_a=test --out .../sl700_windows_v3_test_ea"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_sl700_windows as V1  # noqa: E402

V1.RELABEL = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v3")
if __name__ == "__main__":
    if "--split" in sys.argv:
        i = sys.argv.index("--split")
        V1.SPLIT = dict(kv.split("=") for kv in sys.argv[i + 1].split(","))
        del sys.argv[i:i + 2]
    if "--out" not in sys.argv:
        sys.argv += ["--out", "/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/sl700_windows_v3"]
    V1.main()
