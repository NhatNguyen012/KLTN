#!/usr/bin/env python3
"""Inference cost of the final ML IL model: z2 = 0.8*(0.8*z_OpTC + z_ATLASv2) + z_SL700 on SL700 TEST events."""
import sys, time, json, resource
from pathlib import Path
import numpy as np, lightgbm as lgb
sys.path.insert(0, "/mnt/SSD_Data/optc/IL/dataset_2-AInception/code/ML")
import train_ml_il_step3 as M
run = Path(sys.argv[1])
bo, ba = M.boosters(); bs = lgb.Booster(model_file=str(run / "model.txt"))
cols = json.loads((M.DATA / "columns.json").read_text())
X, y = M.load_npz(M.DATA / "test.npz"); Xs, W = M.select_columns(X, cols, M.CONFIGS["ecar_lx"])
res = {"events": int(Xs.shape[0]), "width": int(W), "nnz_per_row": round(Xs.nnz / Xs.shape[0], 1),
       "model_bytes": {"optc": M.OPTC_MODEL.stat().st_size, "sl700": (run / "model.txt").stat().st_size}}
for th in (1, 10):
    t = time.perf_counter()
    z1 = M.ALPHA * bo.predict(M.width(Xs, M.W_OPTC), raw_score=True, num_threads=th) + ba.predict(M.width(Xs, M.W_ATLAS), raw_score=True, num_threads=th)
    z2 = M.ALPHA * z1 + bs.predict(M.width(Xs, W), raw_score=True, num_threads=th)
    dt = time.perf_counter() - t
    res[f"threads_{th}"] = {"sec": round(dt, 3), "events_per_s": round(Xs.shape[0] / dt), "us_per_event": round(1e6 * dt / Xs.shape[0], 2)}
    print(th, res[f"threads_{th}"], flush=True)
res["max_rss_MiB"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
Path(sys.argv[2]).write_text(json.dumps(res, indent=1)); print(json.dumps(res))
