#!/usr/bin/env python3
"""Old-domain VALIDATION scores for ML IL step-3 runs (no TEST data): ATLASv2 v9b VAL at the step-2 frozen threshold
0.94073 and OpTC host-ML VAL (833,125 events) at the frozen OpTC threshold 0.87427, for Task-1 (before step 3) and
each run's Task-2 (after). Writes <run>/old_val.json. Used to choose the replay rule on VALIDATION only.
Usage: eval_old_val.py <run_dir> [<run_dir> ...]"""
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
from scipy.special import expit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train_ml_il_step3 as M  # noqa: E402

OPTC_VAL_MANIFEST = Path("/mnt/SSD_Data/optc/ML/code/output/host_ml_parent_incoming_seed02/model_input/manifest.json")


def load_optc_val():
    from ML.code.preprocess.host_shards import decode_shard
    from scipy import sparse
    m = json.loads(OPTC_VAL_MANIFEST.read_text())
    Xs, ys = [], []
    for s in [s for s in m["shards"] if s["split"] == "val"]:
        X, y, _ = decode_shard(Path(m["volumes"][s["volume"]]) / s["path"], M.W_OPTC, s)
        Xs.append(X); ys.append(y.astype(np.int8))
    return sparse.vstack(Xs, format="csr"), np.concatenate(ys)


def main():
    bo, ba = M.boosters()
    Xa, ya = M.load_shards(M.ATLAS_MANIFEST, "val", M.W_ATLAS)
    za = M.cached("z1_atlas_val", lambda: M.z_task1(bo, ba, Xa, 10))
    Xo, yo = load_optc_val()
    zo = M.cached("z1_optc_val", lambda: M.z_task1(bo, ba, Xo, 10))
    before = {"atlas_val": M.met(ya, expit(za), M.TH_ATLAS), "optc_val": M.met(yo, expit(zo), M.TH_OPTC)}
    print("Task-1 VAL:", {k: round(v["f1"], 4) for k, v in before.items()}, flush=True)
    for d in map(Path, sys.argv[1:]):
        r = json.loads((d / "result.json").read_text())
        if r["args"]["mode"] != "inc":
            continue
        model = lgb.Booster(model_file=str(d / "model.txt"))
        W = model.num_feature()
        f = lambda X, z1: expit(M.ALPHA * z1 + model.predict(M.width(X, W), raw_score=True, num_threads=10))
        after = {"atlas_val": M.met(ya, f(Xa, za), M.TH_ATLAS), "optc_val": M.met(yo, f(Xo, zo), M.TH_OPTC)}
        sl_val = r["sl700"]["val_f1"]
        out = {"before": before, "after": after, "sl700_val_f1": sl_val,
               "val_score_mean3": float(np.mean([sl_val, after["atlas_val"]["f1"], after["optc_val"]["f1"]]))}
        (d / "old_val.json").write_text(json.dumps(out, indent=1, default=float))
        print(f"{d.name:24s} SL700 val {sl_val:.4f}  ATLASv2 val {after['atlas_val']['f1']:.4f}  OpTC val {after['optc_val']['f1']:.4f}"
              f"  mean {out['val_score_mean3']:.4f}", flush=True)


if __name__ == "__main__":
    main()
