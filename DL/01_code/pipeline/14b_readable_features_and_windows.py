#!/usr/bin/env python3
"""STEP 14 (phần 2) - S4: bảng đặc trưng/từ điển mã hóa (đọc được) và S5: mẫu cửa sổ thô vs mã hóa, đối chiếu shard .npz.
Không sửa shard/preprocessing cũ; chỉ đọc. Chạy: python 14b_readable_features_and_windows.py --stage S4 S5
"""
import argparse
import csv
import datetime as dt
import json
import math
import os

import duckdb
import numpy as np
import pandas as pd

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/14_readable_pipeline_v1"
JOINED = R + "/02_artifacts/02_network_joined_v1/joined/split=*/date=*/*.parquet"
SCHEMA = R + "/01_code/pipeline/network_event_schema_v1.json"
DS = R + "/03_datasets/random_network_dl_v1_1_15m"


def wjson(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def wcsv(path, rows, header):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


CAT_RULES = {
    "app_family": "Họ tiến trình lấy từ image_path của eCAR-Bro (tên file thực thi, chữ thường)",
    "direction": "Hướng kết nối theo eCAR (inbound/outbound)",
    "proto": "Giao thức Bro (tcp/udp/icmp)",
    "service": "Dịch vụ Zeek nhận diện (ssl, http, dns... hoặc <MISSING>)",
    "conn_state": "Trạng thái kết thúc kết nối Bro (SF, S0, REJ, RSTO...)",
    "local_orig": "Máy khởi tạo thuộc mạng nội bộ (T/F)",
    "local_resp": "Máy nhận thuộc mạng nội bộ (T/F)",
    "orig_ip_scope": "Loại IP nguồn (nội bộ, công cộng...)",
    "resp_ip_scope": "Loại IP đích (nội bộ, công cộng...)",
    "orig_port_class": "Lớp cổng nguồn (cổng phổ biến, dải cổng)",
    "resp_port_class": "Lớp cổng đích: PORT_<cổng>_<TÊN> cho 24 cổng phổ biến; còn lại WELL_KNOWN_OTHER / REGISTERED / EPHEMERAL / OTHER",
}
NUM_RULES = {
    "duration": "Thời lượng kết nối (giây)", "orig_bytes": "Byte ứng dụng máy khởi tạo gửi", "resp_bytes": "Byte ứng dụng máy nhận gửi",
    "missed_bytes": "Byte bị mất gói (thay bằng cờ has_missed_bytes)", "orig_pkts": "Số gói máy khởi tạo gửi",
    "orig_ip_bytes": "Byte tầng IP máy khởi tạo gửi", "resp_pkts": "Số gói máy nhận gửi", "resp_ip_bytes": "Byte tầng IP máy nhận gửi",
}


def stage_S4():
    for k in (1, 2, 3):
        pre = f"{DS}/seed_{k}/preprocessing"
        spec = json.load(open(pre + "/network_preprocess_spec.json", encoding="utf-8"))
        maps = json.load(open(pre + "/network_category_maps.json", encoding="utf-8"))
        num = json.load(open(pre + "/network_numeric_stats.json", encoding="utf-8"))
        d = f"{OUT}/S4_features/seed_{k}"
        os.makedirs(d, exist_ok=True)
        def vi(r):
            if r.startswith("constant_on_fold_train"):
                return "hằng số trên TRAIN (mọi flow cùng một giá trị) nên không mang thông tin; chỉ giữ để kiểm toán"
            return r
        rows = []
        act_c, ina_c = spec["active_categorical_features"], spec["inactive_categorical_features"]
        for f in spec["profiled_categorical_features"]:
            rows.append([f, "categorical (phân loại)", "có" if f in act_c else "không", vi(ina_c.get(f, "")), CAT_RULES.get(f, ""),
                         f"{f}_id" if f in act_c else ""])
        act_n, ina_n = spec["active_numerical_features"], spec["inactive_numerical_features"]
        for f in spec["profiled_numerical_features"]:
            rows.append([f, "numeric (số)", "có" if f in act_n else "không", vi(ina_n.get(f, "")), NUM_RULES.get(f, ""),
                         f"{f}_z, {f}_missing" if f in act_n else ""])
        rows.append(["has_missed_bytes", "binary (0/1)", "có", "", "1 nếu missed_bytes > 0", "has_missed_bytes"])
        rows.append(["delta_t_log1p", "time (thời gian)", "có", "", "ln(1 + số giây từ flow liền trước trong cùng chunk); flow đầu = 0", "delta_t_log1p"])
        wcsv(d + "/feature_spec.csv", rows, ["feature", "loại", "dùng_cho_model", "lý_do_không_dùng", "ý_nghĩa", "cột_đầu_ra_sau_mã_hóa"])
        for f, v in maps["fields"].items():
            wcsv(d + f"/vocab_{f}.csv", [[i, val] for val, i in sorted(v["mapping"].items(), key=lambda kv: kv[1])], ["id", "giá_trị"])
        nrows = []
        for f, v in num["features"].items():
            nrows.append([f, v["active_for_model"], round(v["log1p_mean"], 6), round(v["scale_used"], 6), num["zscore_clip_abs"],
                          v["raw_train_min"], v["raw_train_max"], round(v["train_missing_rate"], 8)])
        wcsv(d + "/numeric_normalization.csv", nrows,
             ["feature", "dùng_cho_model", "mean_log1p_TRAIN", "std_log1p_TRAIN", "cắt_|z|_tối_đa", "min_thô_TRAIN", "max_thô_TRAIN", "tỉ_lệ_thiếu_TRAIN"])
    print("S4 ok")


def cat_norm(v):
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return "<MISSING>"
    t = str(v).strip()
    if t == "" or t.lower() in ("-", "(empty)", "null", "none", "nan"):
        return "<MISSING>"
    return t.lower()


def port_class(p, common):
    if p is None or pd.isna(p):
        return "<MISSING>"
    p = int(p)
    if str(p) in common:
        return f"PORT_{p}_{common[str(p)]}"
    if 0 <= p <= 1023:
        return "WELL_KNOWN_OTHER"
    if 1024 <= p <= 49151:
        return "REGISTERED"
    if 49152 <= p <= 65535:
        return "EPHEMERAL"
    return "OTHER"


def stage_S5():
    k = 1
    pre = f"{DS}/seed_{k}/preprocessing"
    maps = json.load(open(pre + "/network_category_maps.json", encoding="utf-8"))["fields"]
    num = json.load(open(pre + "/network_numeric_stats.json", encoding="utf-8"))
    common = json.load(open(SCHEMA, encoding="utf-8"))["port_class"]["common_ports"]
    man = pd.read_csv(f"{DS}/seed_{k}/split/network_sample_manifest.csv")
    wanted = [("beacon_SC2_bi_bat", "sysclient0618", 1569355200), ("binh_thuong", None, None),
              ("SC3_kho_bi_bo_sot", "sysclient0051", 1569422700)]
    con = duckdb.connect()
    base = f"read_parquet('{JOINED}', hive_partitioning=true)"
    out_rows, ver, samples = [], {}, {}
    for name, host, ep in wanted:
        if host is None:
            m = man[(man["label"] == 0) & (man["hostname"] == "sysclient0618") & (man["event_count"].between(20, 80)) & (man["chunk_index"] == 0)]
            m = m.sort_values("window_start_epoch").iloc[0:1]
        else:
            m = man[(man["hostname"] == host) & (man["window_start_epoch"] == ep) & (man["chunk_index"] == 0)]
        r = m.iloc[0]
        host_, ep_ = r["hostname"], int(r["window_start_epoch"])
        df = con.execute(
            f"SELECT uid, ts, hostname, label, app_family, direction, proto, service, conn_state, orig_h, orig_p, resp_h, resp_p, duration, "
            f"orig_bytes, resp_bytes, missed_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes FROM {base} "
            f"WHERE hostname='{host_}' AND ts>={ep_} AND ts<{ep_ + 900} ORDER BY ts, uid").fetchdf()
        df = df.iloc[: int(r["event_count"])].reset_index(drop=True)
        z = np.load(f"{DS}/seed_{k}/{r['shard_file']}", allow_pickle=True)
        i = int(r["shard_sample_index"])
        a, b = int(z["sample_offsets"][i]), int(z["sample_offsets"][i + 1])
        cat_names = [str(x) for x in z["categorical_feature_names"]]
        num_names = [str(x) for x in z["numerical_feature_names"]]
        enc, prev = [], None
        for _, f in df.iterrows():
            row = {}
            for c in cat_names:
                src = port_class(f["resp_p"], common) if c == "resp_port_class" else cat_norm(f[c])
                row[c + "_id"] = int(maps[c]["mapping"].get(src, 0))
            for c in num_names:
                v = f[c]
                st = num["features"][c]
                if v is None or pd.isna(v) or v < 0:
                    row[c + "_z"], row[c + "_missing"] = 0.0, 1
                else:
                    zv = (math.log1p(float(v)) - st["log1p_mean"]) / st["scale_used"]
                    row[c + "_z"], row[c + "_missing"] = max(-10.0, min(10.0, zv)), 0
            mb = f["missed_bytes"]
            row["has_missed_bytes"] = int(mb is not None and not pd.isna(mb) and mb > 0)
            row["delta_t_log1p"] = 0.0 if prev is None else math.log1p(max(0.0, f["ts"] - prev))
            prev = f["ts"]
            enc.append(row)
        E = pd.DataFrame(enc)
        okc = np.array_equal(E[[c + "_id" for c in cat_names]].to_numpy(), z["x_cat"][a:b].astype(int))
        maxd = float(np.abs(E[[c + "_z" for c in num_names]].to_numpy() - z["x_num"][a:b]).max())
        okm = np.array_equal(E[[c + "_missing" for c in num_names]].to_numpy(), z["x_num_missing"][a:b].astype(int))
        okb = np.array_equal(E[["has_missed_bytes"]].to_numpy(), z["x_bin"][a:b].astype(int))
        maxt = float(np.abs(E["delta_t_log1p"].to_numpy() - z["delta_t_log1p"][a:b]).max())
        ver[name] = {"hostname": host_, "window_start_epoch": ep_, "n_flows_tái_tạo": int(len(df)), "n_flows_trong_shard": int(b - a),
                     "x_cat_giống_hệt": bool(okc), "x_num_sai_lệch_lớn_nhất": maxd, "x_num_missing_giống_hệt": bool(okm),
                     "x_bin_giống_hệt": bool(okb), "delta_t_sai_lệch_lớn_nhất": maxt, "shard": r["shard_file"], "sample_index_trong_shard": i}
        raw = df.copy()
        raw.insert(1, "ts_utc", [dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f") for t in raw["ts"]])
        both = pd.concat([raw.reset_index(drop=True), E], axis=1)
        both.insert(0, "window", name)
        out_rows.append(both)
        samples[name] = {
            "sample_id": r["sample_id"], "split": r["split"], "hostname": host_, "window_start_utc": r["window_start_utc"],
            "label_window": int(r["label"]), "n_flows": int(len(df)),
            "flow_0": {"thô": json.loads(raw.iloc[0].to_json()), "mã_hóa": json.loads(E.iloc[0].to_json())},
            "flow_1": ({"thô": json.loads(raw.iloc[1].to_json()), "mã_hóa": json.loads(E.iloc[1].to_json())} if len(df) > 1 else None),
        }
    d = OUT + "/S5_window_samples"
    os.makedirs(d, exist_ok=True)
    pd.concat(out_rows).to_csv(d + "/window_flows_raw_vs_encoded.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    wjson(d + "/sample_windows.json", samples)
    wjson(d + "/verification_vs_npz_shard.json", ver)
    man.head(30).to_csv(d + "/sample_manifest_head.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print(json.dumps(ver, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", nargs="+", required=True)
    a = ap.parse_args()
    for s in a.stage:
        globals()["stage_" + s]()
