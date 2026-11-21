#!/usr/bin/env python3
"""Plain print of the final ML model (three LightGBM boosters of the incremental chain), the counterpart of
print(model) / torchinfo for the DL model. Usage: python3 ml_model_print.py <ml step3 run dir> <atlas .../lgbm-kaggle>"""
import json, sys
from pathlib import Path
import lightgbm as lgb

IL = Path(__file__).resolve().parent
step3, atlas = Path(sys.argv[1]), Path(sys.argv[2])
latest = json.loads((atlas / "incremental/model/latest.json").read_text())
parts = [("OpTC booster (Task 0)", IL / "dataset_1-ATLASv2/code/ML/pretrained_optc_model/model-slot-0.txt", 0.64),
         ("ATLASv2 booster (Task 1)", atlas / "incremental/model" / latest["path"], 0.80),
         ("SL700 booster (Task 2)", step3 / "model.txt", 1.00)]
KEYS = ["objective", "boosting", "num_iterations", "learning_rate", "num_leaves", "max_depth", "min_data_in_leaf",
        "max_delta_step", "lambda_l1", "lambda_l2", "feature_fraction", "bagging_fraction", "scale_pos_weight", "max_bin"]
print("# Final ML model after OpTC -> ATLASv2 -> SL700: chain of 3 LightGBM boosters")
print("# z(x) = 0.8 * (0.8 * z_OpTC(x[:w0]) + z_ATLASv2(x[:w1])) + z_SL700(x);   p = sigmoid(z)")
print("# input x: one event = multi-hot token vector; w0, w1 = number of features of the older boosters\n")
rows = []
for name, path, w in parts:
    b = lgb.Booster(model_file=str(path)); df = b.trees_to_dataframe()
    leaves = df[df.split_feature.isna()]; depth = df.groupby("tree_index").node_depth.max()
    used = int((b.feature_importance("split") > 0).sum())
    rows.append((name, w, b.num_trees(), b.num_feature(), used, len(df) - len(leaves), len(leaves), depth.mean(), depth.max()))
    print(f"{name}  (weight in the chain {w:.2f})")
    print(f"  lightgbm.Booster: num_trees={b.num_trees()}, num_feature={b.num_feature()}, num_model_per_iteration={b.num_model_per_iteration()}")
    print("  params: " + ", ".join(f"{k}={b.params[k]}" for k in KEYS if k in b.params) + "\n")
print("=" * 118)
print(f"{'Booster':<28s}{'Weight':>7s}{'Trees':>7s}{'Features':>10s}{'Used':>7s}{'Split nodes':>13s}{'Leaves':>9s}{'Depth mean':>12s}{'Depth max':>11s}")
print("=" * 118)
for n, w, t, f, u, sp, lv, dm, dx in rows:
    print(f"{n:<28s}{w:>7.2f}{t:>7d}{f:>10,d}{u:>7,d}{sp:>13,d}{lv:>9,d}{dm:>12.1f}{dx:>11d}")
print("=" * 118)
print(f"{'Total':<28s}{'':>7s}{sum(r[2] for r in rows):>7d}{'':>10s}{'':>7s}{sum(r[5] for r in rows):>13,d}{sum(r[6] for r in rows):>9,d}")
