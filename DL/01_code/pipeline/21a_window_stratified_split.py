#!/usr/bin/env python3
"""STEP 21a - split cấp CỬA SỔ (hostname, 15 phút), phân tầng theo scenario, 70/15/15, 3 seed. KHÔNG host-disjoint (theo yêu cầu của người dùng 2026-10-12, như cách chia của nhánh Host).
Tầng: cửa sổ dương -> theo scenario của máy (scenario_1/2/3); cửa sổ benign -> theo ngày. Mỗi tầng cắt 70/15/15 theo thứ tự băm sha256 (tái lập được).
Vũ trụ cửa sổ lấy từ network_sample_manifest.csv của seed_1 (110,402 cửa sổ của 620 máy; mọi chunk của một cửa sổ cùng một split).
Ra: 02_artifacts/21a_window_split_v1/window_split_seed{k}.csv, summary_21a.json, STEP_21A_WINDOW_SPLIT.md (viết tay sau khi xem số).
Không sửa artifact cũ; chưa đụng preprocessing/shards.
"""
import hashlib
import json
import os
import sys

import numpy as np
import pandas as pd

R = "D:/UIT/KLTNv2/"
OUT = R + "02_artifacts/21a_window_split_v1"
os.makedirs(OUT, exist_ok=True)


def h(s):
    return int(hashlib.sha256(s.encode()).hexdigest(), 16)


def load_windows():
    m = pd.read_csv(R + "03_datasets/random_network_dl_v1_1_15m/seed_1/split/network_sample_manifest.csv",
                    usecols=["split", "date", "hostname", "window_start_epoch", "label", "event_count", "positive_event_count"])
    sc = pd.read_csv(R + "02_artifacts/11_dataset_overview_v1/scenario_hosts_29.csv")[["hostname", "scenario"]]
    w = (m.groupby(["hostname", "window_start_epoch"])
         .agg(label=("label", "max"), samples=("label", "size"), events=("event_count", "sum"), date=("date", "first"))
         .reset_index().merge(sc, on="hostname", how="left"))
    return m, w


def assign(w, seed):
    df = w.copy()
    df["stratum"] = np.where(df.label == 1, df.scenario.fillna("pos_other"), "benign_" + df.date.astype(str))
    df["k"] = [h(f"KLTN_OPTC_WINDOW_STRATIFIED_V1|seed={seed}|{a}|{b}") for a, b in zip(df.hostname, df.window_start_epoch)]
    parts = []
    for s, g in df.groupby("stratum"):
        g = g.sort_values("k")
        n = len(g)
        a, b = int(round(0.70 * n)), int(round(0.85 * n))
        g["assigned_split"] = ["train"] * a + ["val"] * (b - a) + ["test"] * (n - b)
        parts.append(g)
    return pd.concat(parts).drop(columns=["k"]).sort_values(["hostname", "window_start_epoch"]).reset_index(drop=True)


def neighbor(df, col):
    pos = df[df.label == 1]
    tr = {}
    for hn, e in pos[pos[col] == "train"][["hostname", "window_start_epoch"]].itertuples(index=False):
        tr.setdefault(hn, []).append(e)
    tr = {k: np.sort(v) for k, v in tr.items()}
    te = pos[pos[col] == "test"]
    c15 = c60 = anyh = 0
    for hn, e in te[["hostname", "window_start_epoch"]].itertuples(index=False):
        v = tr.get(hn)
        if v is None:
            continue
        anyh += 1
        d = int(np.abs(v - e).min())
        c15 += d <= 900
        c60 += d <= 3600
    return {"test_positive_windows": int(len(te)), "same_host_positive_in_train": int(anyh), "within_15min": int(c15), "within_60min": int(c60)}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    m, w = load_windows()
    summ = {"windows": int(len(w)), "samples": int(len(m)), "positive_windows": int(w.label.sum()), "hosts": int(w.hostname.nunique()), "seeds": {}}
    for k in (1, 2, 3):
        a = assign(w, k)
        a[["hostname", "window_start_epoch", "date", "scenario", "label", "samples", "events", "stratum", "assigned_split"]].to_csv(
            f"{OUT}/window_split_seed{k}.csv", index=False, lineterminator="\n")
        hd = pd.read_csv(R + f"03_datasets/random_network_dl_v1_1_15m/seed_{k}/split/network_sample_manifest.csv", usecols=["split", "hostname", "window_start_epoch"])
        hd = hd.groupby(["hostname", "window_start_epoch"]).split.first().rename("hostdisjoint_split").reset_index()
        b = a.merge(hd, on=["hostname", "window_start_epoch"], how="left")
        pos_new = b[b.label == 1].pivot_table(index="scenario", columns="assigned_split", values="label", aggfunc="count", fill_value=0)[["train", "val", "test"]]
        pos_old = b[b.label == 1].pivot_table(index="scenario", columns="hostdisjoint_split", values="label", aggfunc="count", fill_value=0)[["train", "val", "test"]]
        smp = b.groupby("assigned_split").agg(windows=("label", "size"), positive_windows=("label", "sum"), samples=("samples", "sum"), events=("events", "sum"))
        hosts_multi = b.groupby("hostname").assigned_split.nunique()
        summ["seeds"][k] = {
            "positive_windows_by_scenario_new": pos_new.to_dict("index"), "positive_windows_by_scenario_hostdisjoint": pos_old.to_dict("index"),
            "new_split_totals": smp.to_dict("index"), "hosts_present_in_n_splits": hosts_multi.value_counts().sort_index().to_dict(),
            "neighbor_leakage_new": neighbor(b, "assigned_split"), "neighbor_leakage_hostdisjoint": neighbor(b, "hostdisjoint_split"),
        }
        print(f"== seed {k}")
        print("positive windows theo scenario, split MỚI (cấp cửa sổ):\n", pos_new)
        print("positive windows theo scenario, split host-disjoint hiện có:\n", pos_old)
        print(smp)
        print("số split mà mỗi máy xuất hiện:", hosts_multi.value_counts().sort_index().to_dict())
        print("láng giềng:", summ["seeds"][k]["neighbor_leakage_new"], "| host-disjoint:", summ["seeds"][k]["neighbor_leakage_hostdisjoint"])
    json.dump(summ, open(f"{OUT}/summary_21a.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=int)


if __name__ == "__main__":
    main()
