#!/usr/bin/env python3
"""S5 - VALIDATE: kiểm tra chéo S1-S4 và giải mã ngược shards về flow raw.

Kiểm: (1) checks.json của S1-S4 đều PASS; (2) phạm vi fit của S3 = đúng các cửa sổ TRAIN của S2 (số cửa sổ, số flow); (3) mỗi cửa sổ chỉ ở một split, samples.csv khớp windows.csv;
(4) mọi scenario có mặt ở cả 3 split ở mức sample dương; (5) lấy ngẫu nhiên N sample từ shards, truy lại flow raw trong S1, mã hóa lại bằng Python theo preprocess_spec và so từng giá trị.
Output: S5_validate/checks.json (PASS tổng) và S5_validate/sample_verification.csv (từng sample đã so).
"""
import json
import sys
import time
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import v2_common as C  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
FLOWS = str(V2 / "S1_join/data/flows_joined.parquet").replace("\\", "/")
OUT = V2 / "S5_validate"
N_POS, N_NEG = 150, 250


def main():
    t0 = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    ck = {}
    for s in ("S1_join", "S2_windows_split", "S3_preprocess", "S4_shards"):
        try:
            ck[f"{s}_PASS"] = bool(json.load(open(V2 / s / "checks.json", encoding="utf-8"))["PASS"])
        except Exception as e:  # noqa: BLE001
            ck[f"{s}_PASS"] = False
            ck[f"{s}_error"] = str(e)
    spec = json.load(open(V2 / "S3_preprocess/data/preprocess_spec.json", encoding="utf-8"))
    w = pd.read_csv(V2 / "S2_windows_split/data/windows.csv")
    sm = pd.read_csv(V2 / "S4_shards/data/samples.csv")
    tr = w[w.split == "train"]
    ck["fit_windows_equal_train_windows"] = bool(spec["fit"]["n_windows"] == len(tr))
    ck["fit_flows_equal_train_flows"] = bool(spec["fit"]["n_flows"] == int(tr.n_flows.sum()))
    ck["fit_used_label_val_test"] = bool(spec["fit"]["label_used_for_fit"] or spec["fit"]["val_used_for_fit"] or spec["fit"]["test_used_for_fit"])
    ck["window_unique_key"] = bool(not w.duplicated(["hostname", "window_start_epoch"]).any())
    m = sm.merge(w[["hostname", "window_start_epoch", "split", "scenario", "label"]].rename(columns={"split": "split_w", "label": "label_w"}), on=["hostname", "window_start_epoch"], how="left")
    ck["samples_match_windows_split"] = bool((m.split == m.split_w).all())
    ck["window_label_equals_max_sample_label"] = bool((m.groupby(["hostname", "window_start_epoch"]).label.max() == m.groupby(["hostname", "window_start_epoch"]).label_w.first()).all())
    pos = m[m.label == 1].pivot_table(index="scenario", columns="split", values="label", aggfunc="count", fill_value=0)[["train", "val", "test"]]
    ck["positive_samples_by_scenario_split"] = pos.to_dict("index")
    ck["each_scenario_in_all_splits"] = bool((pos > 0).all().all())
    # ----- giải mã ngược
    rng = np.random.default_rng(7)
    pick = pd.concat([m[m.label == 1].sample(min(N_POS, int((m.label == 1).sum())), random_state=7), m[m.label == 0].sample(N_NEG, random_state=7)]).reset_index(drop=True)
    con = duckdb.connect()
    con.execute("SET threads=8; SET memory_limit='12GB'")
    con.register("pk", pick[["hostname", "window_start_epoch"]].drop_duplicates())
    raw = con.execute(f"SELECT f.* FROM read_parquet('{FLOWS}') f JOIN pk ON f.hostname = pk.hostname AND f.window_start_epoch = pk.window_start_epoch ORDER BY f.hostname, f.window_start_epoch, f.ts, f.uid").df()
    raw = raw.astype(object).where(raw.notna(), None)
    groups = {k: g for k, g in raw.groupby(["hostname", "window_start_epoch"], sort=False)}
    cats = spec["model_input_layout"]["x_cat_columns"]
    nums = spec["model_input_layout"]["x_num_columns"]
    rows, shard_cache = [], {}
    for _, r in pick.iterrows():
        z = shard_cache.get(r.shard_file)
        if z is None:
            if len(shard_cache) > 3:
                shard_cache.clear()
            z = shard_cache[r.shard_file] = dict(np.load(V2 / "S4_shards" / r.shard_file))
        i = int(r.shard_sample_index)
        a0, a1 = int(z["sample_offsets"][i]), int(z["sample_offsets"][i + 1])
        g = groups[(r.hostname, r.window_start_epoch)].iloc[int(r.chunk_index) * 512:(int(r.chunk_index) + 1) * 512]
        n_same = bool(len(g) == a1 - a0)
        d_cat = d_num = d_miss = d_bin = d_dt = d_lab = 0
        if n_same:
            prev = None
            for k, (_, fr) in enumerate(g.iterrows()):
                e = C.encode_flow(fr.to_dict(), spec)
                d_cat += int(any(e["x_cat"][f]["id"] != z["x_cat"][a0 + k][j] for j, f in enumerate(cats)))
                d_num = max(d_num, max(abs(e["x_num"][f]["z"] - float(z["x_num"][a0 + k][j])) for j, f in enumerate(nums)))
                d_miss += int(any(e["x_num"][f]["missing"] != z["x_num_missing"][a0 + k][j] for j, f in enumerate(nums)))
                d_bin += int(e["x_bin"]["has_missed_bytes"]["value"] != z["x_bin"][a0 + k][0])
                dt = 0.0 if prev is None else float(np.log1p(max(0.0, float(fr["ts"]) - prev)))
                d_dt = max(d_dt, abs(dt - float(z["delta_t_log1p"][a0 + k])))
                prev = float(fr["ts"])
            d_lab = int(int(g["label"].max()) != int(z["sample_labels"][i]))
        rows.append({"sample_id": r.sample_id, "split": r.split, "label": r.label, "n_flows_shard": a1 - a0, "n_flows_raw": len(g), "same_length": n_same, "bad_x_cat_flows": d_cat,
                     "max_abs_diff_x_num": d_num, "bad_missing_flows": d_miss, "bad_bin_flows": d_bin, "max_abs_diff_delta_t": d_dt, "bad_label": d_lab})
    v = pd.DataFrame(rows)
    v.to_csv(OUT / "sample_verification.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    ck["decode_samples_checked"] = int(len(v))
    ck["decode_all_same_length"] = bool(v.same_length.all())
    ck["decode_bad_x_cat_flows"] = int(v.bad_x_cat_flows.sum())
    ck["decode_max_abs_diff_x_num"] = float(v.max_abs_diff_x_num.max())
    ck["decode_bad_missing_flows"] = int(v.bad_missing_flows.sum())
    ck["decode_bad_bin_flows"] = int(v.bad_bin_flows.sum())
    ck["decode_max_abs_diff_delta_t"] = float(v.max_abs_diff_delta_t.max())
    ck["decode_bad_label"] = int(v.bad_label.sum())
    ck["PASS"] = bool(all(ck[f"{s}_PASS"] for s in ("S1_join", "S2_windows_split", "S3_preprocess", "S4_shards")) and ck["fit_windows_equal_train_windows"] and ck["fit_flows_equal_train_flows"]
                      and not ck["fit_used_label_val_test"] and ck["window_unique_key"] and ck["samples_match_windows_split"] and ck["window_label_equals_max_sample_label"]
                      and ck["each_scenario_in_all_splits"] and ck["decode_all_same_length"] and ck["decode_bad_x_cat_flows"] == 0 and ck["decode_max_abs_diff_x_num"] < 1e-4
                      and ck["decode_bad_missing_flows"] == 0 and ck["decode_bad_bin_flows"] == 0 and ck["decode_max_abs_diff_delta_t"] < 1e-3 and ck["decode_bad_label"] == 0)
    json.dump(ck, open(OUT / "checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print(json.dumps(ck, ensure_ascii=False, indent=1, default=str))
    print(f"S5 xong ({time.time() - t0:.0f}s) PASS={ck['PASS']}")


if __name__ == "__main__":
    main()
