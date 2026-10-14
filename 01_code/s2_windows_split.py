#!/usr/bin/env python3
"""S2 - CỬA SỔ và SPLIT: gom flow thành cửa sổ (hostname, 15 phút) và chia 70/15/15 theo cửa sổ, phân tầng theo scenario.

Input : S1_join/data/flows_joined.parquet ; 02_artifacts/11_dataset_overview_v1/hosts_625.csv (máy nào thuộc 620 máy supervised và scenario của 29 máy bị tấn công)
Output: S2_windows_split/data/windows.csv  (1 dòng = 1 cửa sổ), split_summary.json, schema.json, preview.csv, preview_record.json, checks.json
Quy tắc: không host-disjoint (yêu cầu của người dùng 2026-10-12); mọi chunk của một cửa sổ cùng một split; tầng = scenario (cửa sổ dương) | ngày UTC (cửa sổ benign);
mỗi tầng cắt 70/15/15 theo thứ tự băm sha256 của KLTN_OPTC_WINDOW_STRATIFIED_V1|seed=1|hostname|window_start_epoch (tái lập được).
"""
import csv
import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
IN = V2 / "S1_join/data/flows_joined.parquet"
OUT = V2 / "S2_windows_split"
SEED = 1
MAX_EVENTS = 512
SCHEMA = [
    ("hostname", "string", "khóa", "Máy (sysclientNNNN)."),
    ("window_start_epoch", "int64", "khóa", "Đầu cửa sổ 15 phút, epoch UTC = floor(ts/900)*900."),
    ("window_start_utc", "string", "audit", "window_start_epoch dạng đọc được (UTC)."),
    ("date_utc", "string", "audit", "Ngày UTC của cửa sổ."),
    ("scenario", "string", "audit", "scenario_1/2/3 nếu máy thuộc 29 máy bị tấn công, ngược lại rỗng."),
    ("n_flows", "int64", "audit", "Số flow trong cửa sổ."),
    ("n_chunks", "int64", "audit", "ceil(n_flows / 512) = số sample (chunk) sinh ra ở S4."),
    ("n_positive_flows", "int64", "audit", "Số flow có label = 1."),
    ("label", "int8", "nhãn", "1 nếu cửa sổ có ít nhất một flow dương."),
    ("stratum", "string", "audit", "Tầng chia: tên scenario (cửa sổ dương) hoặc 'benign_<ngày UTC>'."),
    ("split", "string", "khóa", "train / val / test."),
]


def h(s):
    return int(hashlib.sha256(s.encode()).hexdigest(), 16)


def main():
    t0 = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "data").mkdir(exist_ok=True)
    hosts = pd.read_csv(ROOT / "02_artifacts/11_dataset_overview_v1/hosts_625.csv")
    hosts = hosts[hosts["in_network_dataset"].astype(str).str.lower() == "true"][["hostname", "scenario"]].copy()
    hosts["scenario"] = hosts["scenario"].fillna("")
    con = duckdb.connect()
    con.execute("SET threads=8; SET memory_limit='16GB'")
    con.register("hosts", hosts)
    q = f"""
      SELECT f.hostname, f.window_start_epoch,
             strftime(make_timestamp(f.window_start_epoch*1000000), '%Y-%m-%d %H:%M:%S') AS window_start_utc,
             strftime(make_timestamp(f.window_start_epoch*1000000), '%Y-%m-%d') AS date_utc,
             h.scenario, count(*)::BIGINT AS n_flows, ((count(*) + {MAX_EVENTS - 1}) // {MAX_EVENTS})::BIGINT AS n_chunks,
             sum(f.label)::BIGINT AS n_positive_flows, max(f.label)::TINYINT AS label
      FROM read_parquet('{str(IN).replace(chr(92), '/')}') f JOIN hosts h ON f.hostname = h.hostname
      GROUP BY f.hostname, f.window_start_epoch, h.scenario
    """
    w = con.execute(q).df()
    print(f"cửa sổ: {len(w):,} ({time.time() - t0:.0f}s); máy: {w.hostname.nunique()}")
    w["stratum"] = np.where(w.label == 1, np.where(w.scenario != "", w.scenario, "pos_other"), "benign_" + w.date_utc)
    w["k"] = [h(f"KLTN_OPTC_WINDOW_STRATIFIED_V1|seed={SEED}|{a}|{b}") for a, b in zip(w.hostname, w.window_start_epoch)]
    parts = []
    for s, g in w.groupby("stratum"):
        g = g.sort_values("k")
        n = len(g)
        a, b = int(round(0.70 * n)), int(round(0.85 * n))
        g = g.copy()
        g["split"] = ["train"] * a + ["val"] * (b - a) + ["test"] * (n - b)
        parts.append(g)
    w = pd.concat(parts).drop(columns=["k"]).sort_values(["hostname", "window_start_epoch"]).reset_index(drop=True)
    cols = ["hostname", "window_start_epoch", "window_start_utc", "date_utc", "scenario", "n_flows", "n_chunks", "n_positive_flows", "label", "stratum", "split"]
    w = w[cols]
    w.to_csv(OUT / "data/windows.csv", index=False, encoding="utf-8", lineterminator="\n")

    # ----- thống kê và kiểm tra
    pos = w[w.label == 1].pivot_table(index="scenario", columns="split", values="label", aggfunc="count", fill_value=0)[["train", "val", "test"]]
    tot = w.groupby("split").agg(windows=("label", "size"), positive_windows=("label", "sum"), flows=("n_flows", "sum"), positive_flows=("n_positive_flows", "sum"), samples=("n_chunks", "sum"))
    multi = w.groupby("hostname").split.nunique().value_counts().sort_index()
    summ = {
        "positive_windows_by_scenario_and_split": pos.to_dict("index"),
        "totals_by_split": tot.to_dict("index"),
        "hosts_present_in_n_splits": {int(k): int(v) for k, v in multi.items()},
        "benign_windows_by_split": w[w.label == 0].split.value_counts().to_dict(),
    }
    json.dump(summ, open(OUT / "split_summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=int)
    ck = {"hosts": int(w.hostname.nunique()), "windows": int(len(w)), "positive_windows": int(w.label.sum()), "flows_in_windows": int(w.n_flows.sum()),
          "samples_expected": int(w.n_chunks.sum())}
    flows_universe = con.execute(f"SELECT count(*) FROM read_parquet('{str(IN).replace(chr(92), '/')}') f JOIN hosts h ON f.hostname=h.hostname").fetchone()[0]
    ck["flows_conserved"] = bool(flows_universe == ck["flows_in_windows"])
    ck["each_scenario_in_all_splits"] = bool((pos > 0).all().all()) and set(pos.index) >= {"scenario_1", "scenario_2", "scenario_3"}
    ck["proportions_train_val_test_windows"] = {k: round(v / len(w), 4) for k, v in tot.windows.items()}
    ck["no_pos_other"] = bool("pos_other" not in set(w.stratum))
    # so với STEP 21A (cùng thuật toán, cửa sổ lấy từ bảng cũ): kỳ vọng giống hệt nếu S1 tái tạo đúng bảng cũ
    try:
        old = pd.read_csv(ROOT / "02_artifacts/21a_window_split_v1/window_split_seed1.csv", usecols=["hostname", "window_start_epoch", "assigned_split"])
        m = w.merge(old, on=["hostname", "window_start_epoch"], how="outer", indicator=True)
        ck["vs_21a_same_window_universe"] = bool((m["_merge"] == "both").all())
        ck["vs_21a_windows_only_new"] = int((m["_merge"] == "left_only").sum())
        ck["vs_21a_windows_only_old"] = int((m["_merge"] == "right_only").sum())
        both = m[m["_merge"] == "both"]
        ck["vs_21a_split_identical"] = bool((both["split"] == both["assigned_split"]).all())
    except Exception as e:  # noqa: BLE001
        ck["vs_21a_error"] = str(e)
    ck["PASS"] = bool(ck["hosts"] == 620 and ck["flows_conserved"] and ck["each_scenario_in_all_splits"] and ck["no_pos_other"])
    json.dump(ck, open(OUT / "checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    # ----- preview và schema
    prev = pd.concat([w[w.label == 1].groupby(["scenario", "split"]).head(5), w[w.label == 0].groupby("split").head(10)]).sort_values(["label", "scenario", "split"], ascending=[False, True, True])
    prev.to_csv(OUT / "preview.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    json.dump({"cua_so_duong": w[w.label == 1].iloc[0].to_dict(), "cua_so_benign": w[w.label == 0].iloc[0].to_dict()}, open(OUT / "preview_record.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    ex = w[w.label == 1].iloc[0].to_dict()
    json.dump({"table": "windows.csv", "grain": "1 dòng = 1 cửa sổ (hostname, 15 phút)", "fields": [
        {"field": n, "type": t, "role": r, "meaning_vi": m, "example": ex.get(n)} for n, t, r, m in SCHEMA]}, open(OUT / "schema.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    print(json.dumps(ck, ensure_ascii=False, indent=1, default=str))
    print(pos)
    print(tot)
    print(f"S2 xong ({time.time() - t0:.0f}s) PASS={ck['PASS']}")


if __name__ == "__main__":
    main()
