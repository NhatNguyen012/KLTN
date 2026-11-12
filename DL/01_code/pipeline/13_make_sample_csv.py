#!/usr/bin/env python3
"""STEP 13 - tao CSV mau de gui thay: moi dong la 1 flow Unraveled (da lam sach), 3 flow cho moi stage doc hai
(+ vai flow benign thuoc nhieu loai ung dung khac nhau). Chon ngau nhien co seed, uu tien khac Activity."""
import datetime as dt
import glob
import os
import random

import pandas as pd

ROOT = "D:/UIT/KLTNv2/03_datasets/unraveled_v1_clean/network-flows/"
OUT = "D:/UIT/KLTNv2/02_artifacts/13_unraveled_overview_v1/"
SEED = 42
STAGES = ["Reconnaissance", "Establish Foothold", "Lateral Movement", "Data Exfiltration", "Cover up"]
VN = {
    "Reconnaissance": "Trinh sat: do quet, doan mat khau tu may tan cong",
    "Establish Foothold": "Thiet lap cho dung chan: kenh C2 ma hoa",
    "Lateral Movement": "Di chuyen ngang / duy tri truy cap trong mang",
    "Data Exfiltration": "Danh cap du lieu qua kenh C2 / gioi han dung luong",
    "Cover up": "Xoa dau vet",
    "Benign": "Binh thuong (khong tan cong)",
}
COMPACT = ["source_file", "line_in_file", "first_seen_utc", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
           "bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes", "src2dst_packets", "src2dst_bytes",
           "dst2src_packets", "dst2src_bytes", "application_name", "application_category_name", "requested_server_name",
           "user_agent", "content_type", "Activity", "Stage", "DefenderResponse", "Signature", "stage_mo_ta"]


def main():
    rng = random.Random(SEED)
    mal, ben = [], []
    for f in sorted(glob.glob(ROOT + "*/*.csv")):
        rel = f.replace("\\", "/").split("network-flows/")[1]
        d = pd.read_csv(f, dtype=str, keep_default_na=False)
        d.insert(0, "line_in_file", d.index + 2)  # dong trong file sach (dong 1 la header)
        d.insert(0, "source_file", rel)
        m = d[d["Stage"] != "Benign"]
        if len(m):
            mal.append(m)
        b = d[d["Stage"] == "Benign"]
        ben.append(b.sample(min(len(b), 300), random_state=SEED))
    mal = pd.concat(mal)
    ben = pd.concat(ben)

    picks = []
    for st in STAGES:
        g = mal[mal["Stage"] == st]
        acts = g["Activity"].value_counts()
        # hoat dong chinh (>= 100 flow) de dai dien; neu it hoat dong thi lap lai hoat dong pho bien nhat o file khac
        main_acts = [a for a, n in acts.items() if n >= 100]
        chosen = []
        for a in main_acts[:3]:
            chosen.append(g[g["Activity"] == a].sample(1, random_state=rng.randint(0, 10**6)))
        used_files = {c["source_file"].iloc[0] for c in chosen}
        top = g[g["Activity"] == main_acts[0]]
        while len(chosen) < 3:
            cand = top[~top["source_file"].isin(used_files)]
            cand = cand if len(cand) else top
            row = cand.sample(1, random_state=rng.randint(0, 10**6))
            used_files.add(row["source_file"].iloc[0])
            chosen.append(row)
        picks += chosen

    # benign: moi ung dung mot flow, chon cac ung dung pho bien khac nhau
    apps = ben["application_name"].value_counts()
    want = ["TLS.Google", "DNS", "HTTP", "SSH", "NTP", "DHCP"]
    chosen_b = []
    for w in want:
        sub = ben[ben["application_name"] == w]
        if len(sub) == 0:
            sub = ben[ben["application_name"].str.startswith(w.split(".")[0])]
        if len(sub):
            chosen_b.append(sub.sample(1, random_state=rng.randint(0, 10**6)))
    picks += chosen_b

    s = pd.concat(picks)
    s["first_seen_utc"] = s["bidirectional_first_seen_ms"].map(
        lambda x: dt.datetime.fromtimestamp(int(x) / 1000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    s["stage_mo_ta"] = s["Stage"].map(VN)
    order = {st: i for i, st in enumerate(STAGES + ["Benign"])}
    s = s.sort_values(by="Stage", key=lambda c: c.map(order), kind="stable").reset_index(drop=True)
    os.makedirs(OUT, exist_ok=True)
    s[COMPACT].to_csv(OUT + "unraveled_sample_flows.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    s.drop(columns=["stage_mo_ta", "first_seen_utc"]).to_csv(OUT + "unraveled_sample_flows_full.csv", index=False,
                                                           encoding="utf-8-sig", lineterminator="\n")
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 30)
    print(s[["source_file", "src_ip", "dst_ip", "dst_port", "protocol", "application_name", "Activity", "Stage", "Signature"]].to_string())


if __name__ == "__main__":
    main()
