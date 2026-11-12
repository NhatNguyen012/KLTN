#!/usr/bin/env python3
"""STEP 15 (bước 2) - pilot SUY LUẬN (không train lại) cho biến thể left join.

Câu hỏi: nếu cửa sổ của sysclient0051 (SC3) chứa thêm các flow bị loại do không có eCAR-Bro (REJ tới :8080...), thì model
network ĐÃ TRAIN (bản bỏ app_family, seed_1) có cho điểm cao hơn không?
Ba biến thể mỗi cửa sổ:
  V0  flow đã ghép (đúng như dữ liệu train/test hiện tại)                      -> phải khớp test_predictions.csv
  V1  V0 + flow độc hại bị loại (nhãn A New Hope), app_family = <MISSING>      -> "nếu model thấy các flow REJ"
  V2  mọi flow Bro conn của host trong cửa sổ (left join thật)                 -> thực tế hơn; có cả flow benign không có eCAR-Bro
Chỉ đọc; model không được sửa. Cảnh báo: model chưa từng thấy loại cửa sổ V1/V2, nên kết quả chỉ là tín hiệu thăm dò.
"""
import glob
import gzip
import importlib.util
import json
import math
import sys

import numpy as np
import pandas as pd
import torch

R = "D:/UIT/KLTNv2"
NB = "C:/Users/ADMIN/AppData/Local/Temp/claude/D--UIT-KLTNv2/c3adf6d3-92a6-4afb-8508-c1cc6109dae7/scratchpad/nbcode"
DS = R + "/03_datasets/random_network_dl_v1_1_15m/seed_1"
OUT = R + "/02_artifacts/15_leftjoin_scale_v1"
HOST, HOST_IP = "sysclient0051", "142.20.56.52"
sys.path.insert(0, NB + "/mixed/step05e_code")
from mixed_type_attention_model import MixedTypeModelConfig, MixedTypeSelfAttentionClassifier  # noqa: E402

spec = importlib.util.spec_from_file_location("b14", R + "/01_code/pipeline/14b_readable_features_and_windows.py")
b14 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b14)

maps = json.load(open(DS + "/preprocessing/network_category_maps.json", encoding="utf-8"))["fields"]
stats = json.load(open(DS + "/preprocessing/network_numeric_stats.json", encoding="utf-8"))["features"]
common = json.load(open(R + "/01_code/pipeline/network_event_schema_v1.json", encoding="utf-8"))["port_class"]["common_ports"]
CAT = ["app_family", "proto", "service", "conn_state", "resp_port_class"]
NUM = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
CONN_COLS = ["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes",
             "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
             "resp_ip_bytes", "tunnel_parents", "label"]


def read_host_conn(day):
    rows = []
    for f in sorted(glob.glob(f"E:/bro/{day}/conn.*.log.gz")):
        with gzip.open(f, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if HOST_IP in line and line[0] != "#":
                    c = line.rstrip("\n").split("\t")
                    if len(c) >= 21 and c[2] == HOST_IP:
                        rows.append(c[:21] + [c[21] if len(c) > 21 else ""])
    df = pd.DataFrame(rows, columns=CONN_COLS)
    df["ts"] = df["ts"].astype(float)
    for c in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "missed_bytes"]:
        df[c] = pd.to_numeric(df[c].replace("-", np.nan), errors="coerce")
    df["resp_p"] = pd.to_numeric(df["resp_p"], errors="coerce")
    return df.sort_values(["ts", "uid"]).reset_index(drop=True)


def encode(df):
    cats, nums, miss, binv, delta = [], [], [], [], []
    prev = None
    for _, f in df.iterrows():
        row = []
        for c in CAT:
            if c == "app_family":
                row.append(0)  # bản bỏ app_family: cột này luôn = <UNK> (0)
            else:
                src = b14.port_class(f["resp_p"], common) if c == "resp_port_class" else b14.cat_norm(f[c])
                row.append(int(maps[c]["mapping"].get(src, 0)))
        cats.append(row)
        nr, mr = [], []
        for c in NUM:
            v = f[c]
            if v is None or pd.isna(v) or v < 0:
                nr.append(0.0)
                mr.append(1)
            else:
                z = (math.log1p(float(v)) - stats[c]["log1p_mean"]) / stats[c]["scale_used"]
                nr.append(max(-10.0, min(10.0, z)))
                mr.append(0)
        nums.append(nr)
        miss.append(mr)
        mb = f["missed_bytes"]
        binv.append([int(mb is not None and not pd.isna(mb) and mb > 0)])
        delta.append(0.0 if prev is None else math.log1p(max(0.0, f["ts"] - prev)))
        prev = f["ts"]
    return (np.array(cats), np.array(nums, dtype=np.float32), np.array(miss), np.array(binv), np.array(delta, dtype=np.float32))


@torch.no_grad()
def score(model, df):
    """Xác suất của cửa sổ = max qua các chunk 512 flow (giống cách gộp ở fusion)."""
    if len(df) == 0:
        return None, 0
    ps = []
    for a in range(0, len(df), 512):
        ch = df.iloc[a:a + 512]
        xc, xn, xm, xb, dt_ = encode(ch)
        T = len(ch)
        out = model(x_cat=torch.tensor(xc, dtype=torch.long)[None], x_num=torch.tensor(xn)[None],
                    x_num_missing=torch.tensor(xm, dtype=torch.float32)[None], x_bin=torch.tensor(xb, dtype=torch.float32)[None],
                    delta_t_log1p=torch.tensor(dt_)[None, :, None], attention_mask=torch.ones(1, T, dtype=torch.bool))
        logit = out[0] if isinstance(out, (tuple, list)) else out
        ps.append(float(torch.sigmoid(logit.reshape(-1)[0])))
    return max(ps), len(df)


def main():
    ck = torch.load(R + "/05_models/10_random_seed1_v1/mixed_v2_noapp_seed1/best_model.pt", map_location="cpu", weights_only=False)
    cfg = MixedTypeModelConfig(**ck["model_config"])
    model = MixedTypeSelfAttentionClassifier(cfg)
    model.load_state_dict(ck["model_state_dict"])
    model.eval()
    thr = json.load(open(R + "/05_models/10_random_seed1_v1/mixed_v2_noapp_seed1/threshold.json"))["threshold"]
    print("threshold (VAL):", thr)

    day = "2019-09-25"
    conn = read_host_conn(day)
    print("conn rows of host on", day, len(conn))
    import duckdb
    jj = duckdb.connect().execute(
        f"select uid, label from read_parquet('{R}/02_artifacts/02_network_joined_v1/joined/split=*/date={day}/*.parquet', hive_partitioning=true) "
        f"where hostname='{HOST}'").fetchdf()
    inj = set(jj.uid)
    mal = set()
    for l in open("D:/UIT/KLTN/KLTN-main/a_new_hope_for_darpa_optc/labelling/network/scenario-3/conn-sysclient-051.log", encoding="utf-8"):
        if l[0] != "#":
            mal.add(l.split("\t")[1])
    print("joined uids", len(inj), "malicious uids (A New Hope)", len(mal), "malicious not in joined", len(mal - inj))
    pred = pd.read_csv(R + "/05_models/10_random_seed1_v1/mixed_v2_noapp_seed1/test_predictions.csv")
    man = pd.read_csv(DS + "/split/network_sample_manifest.csv")
    man = man[(man.hostname == HOST)].merge(pred[["sample_id", "probability"]], on="sample_id")

    win = lambda ep: conn[(conn.ts >= ep) & (conn.ts < ep + 900)]
    attack_w = [1569420900, 1569422700, 1569423600, 1569424500, 1569431700]   # 14:15, 14:45, 15:00, 15:15, 17:15 UTC
    control_w = [1569409200 + 900 * k for k in range(0, 8)]                     # 11:00-12:45 UTC (trước tấn công)
    rows = []
    for tag, ws in (("attack", attack_w), ("control_truoc_tan_cong", control_w)):
        for ep in ws:
            w = win(ep)
            v0 = w[w.uid.isin(inj)]
            v1 = w[w.uid.isin(inj) | w.uid.isin(mal)]
            p0, n0 = score(model, v0)
            p1, n1 = score(model, v1)
            p2, n2 = score(model, w)
            ref = man[man.window_start_epoch == ep]
            rows.append({"loai": tag, "window_start_utc": pd.to_datetime(ep, unit="s").strftime("%Y-%m-%d %H:%M"),
                         "n_V0": n0, "p_V0": p0, "p_tu_test_predictions": float(ref.probability.max()) if len(ref) else None,
                         "n_V1": n1, "p_V1": p1, "n_V2": n2, "p_V2": p2, "n_mal_trong_cua_so": int(w.uid.isin(mal).sum()),
                         "n_mal_khong_co_trong_joined": int((w.uid.isin(mal) & ~w.uid.isin(inj)).sum())})
            print(rows[-1], flush=True)
    out = pd.DataFrame(rows)
    out["thr_VAL"] = thr
    out.to_csv(OUT + "/pilot_inference_sc3_mixed_noapp_seed1.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print(out.to_string())


if __name__ == "__main__":
    main()
