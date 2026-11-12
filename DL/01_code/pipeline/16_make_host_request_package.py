#!/usr/bin/env python3
"""STEP 16 - tạo gói yêu cầu cho nhánh host (Nguyễn): file split theo hostname, danh sách cửa sổ cần chấm điểm, mẫu file kết quả.
Chỉ đọc artifact cũ; ghi vào 02_artifacts/16_host_branch_request_v1/."""
import csv
import os

import pandas as pd

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/16_host_branch_request_v1"
K_BENIGN = 2  # số cửa sổ benign lấy ngẫu nhiên mỗi (host, ngày), seed 42


def main():
    os.makedirs(OUT, exist_ok=True)
    sp = pd.read_csv(R + "/02_artifacts/14_readable_pipeline_v1/S3_split/host_split_all.csv")
    sp = sp[sp["split_random_seed1"].notna()].copy()
    sp["is_attacked_host"] = (sp["scenario"].notna()).astype(int)
    out = sp[["hostname", "split_random_seed1", "scenario", "is_attacked_host", "host_group"]].rename(
        columns={"split_random_seed1": "split"})
    out.sort_values(["split", "hostname"]).to_csv(OUT + "/host_split_seed1.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print(out.groupby("split").agg(hosts=("hostname", "count"), attacked=("is_attacked_host", "sum")))

    h = pd.read_csv(R + "/02_artifacts/14_readable_pipeline_v1/S6_host_branch/host_window_features.csv")
    h = h[h["split_seed1"].isin(["val", "test"])]
    h["start_epoch"] = ((pd.to_datetime(h["window_start_utc"]) - pd.Timestamp("1970-01-01")).dt.total_seconds()).astype("int64")
    pos = h[h["n_host_mal_events"] > 0].assign(kind="co_event_doc_hai")
    ben = h[h["n_host_mal_events"] == 0]
    ben = ben.sample(frac=1, random_state=42).groupby(["hostname", "day"]).head(K_BENIGN).assign(kind="benign_lay_mau")
    w = pd.concat([pos, ben]).sort_values(["split_seed1", "hostname", "start_epoch"])
    w = w.rename(columns={"split_seed1": "split"})[["split", "hostname", "day", "window_start_utc", "window_start_edt", "start_epoch", "kind"]]
    w = w.rename(columns={"start_epoch": "window_start_epoch_utc"})
    w.to_csv(OUT + "/eval_windows_seed1.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    ev = h.set_index(["hostname", "window_start_utc"])["n_events"]
    w["n_events_uoc_tinh"] = [ev.get((a, b), 0) for a, b in zip(w.hostname, w.window_start_utc)]
    print(w.groupby(["split", "kind"]).agg(windows=("hostname", "count"), events_M=("n_events_uoc_tinh", lambda s: round(s.sum() / 1e6, 1))))
    with open(OUT + "/output_template_event_predictions.csv", "w", encoding="utf-8-sig", newline="") as f:
        wr = csv.writer(f, lineterminator="\n")
        wr.writerow(["hostname", "timestamp", "split", "model", "prob", "pred", "label"])
        wr.writerow(["sysclient0051", "2019-09-25T10:45:12.345-04:00", "test", "lightgbm", "0.0137", "0", "1"])
        wr.writerow(["sysclient0051", "2019-09-25T10:45:13.001-04:00", "test", "lightgbm", "0.9210", "1", "1"])


if __name__ == "__main__":
    main()
