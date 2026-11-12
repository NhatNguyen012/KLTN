#!/usr/bin/env python3
"""S3 - PREPROCESS (fit CHỈ trên TRAIN): từ điển category, thống kê numeric, trường nào active - gói trong MỘT file preprocess_spec.json.

Input : S1_join/data/flows_joined.parquet ; S2_windows_split/data/windows.csv (chỉ dùng các cửa sổ split = train)
Output: S3_preprocess/data/preprocess_spec.json (+ vocab.csv để mở bằng Excel), schema.json, preview_record.json (ví dụ mã hóa một flow tấn công và một flow benign), checks.json
Quy tắc (giữ như bản cũ để mô hình dùng lại được): reserved <UNK>=0, <MISSING>=1; vocab xếp theo số lần xuất hiện trong TRAIN giảm dần (hòa -> theo chữ);
min_train_frequency app_family/service = 5, còn lại 1; numeric = log1p(max(x,0)) -> z-score theo TRAIN -> clip ±10; thiếu -> 0.0 kèm mask; has_missed_bytes = missed_bytes > 0.
Active: category cần >= 2 giá trị mỗi giá trị >= 5 flow TRAIN (hoặc thiếu/có giá trị đều >= 5 flow); numeric cần log1p std >= 0.01. Nhãn, VAL, TEST không tham gia fit.
"""
import csv
import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import v2_common as C  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
FLOWS = str(V2 / "S1_join/data/flows_joined.parquet").replace("\\", "/")
WINDOWS = V2 / "S2_windows_split/data/windows.csv"
OUT = V2 / "S3_preprocess"
MIN_SUPPORT = 5  # số flow TRAIN tối thiểu để một giá trị được tính khi xét feature active


def main():
    t0 = time.time()
    (OUT / "data").mkdir(parents=True, exist_ok=True)
    w = pd.read_csv(WINDOWS)
    train = w[w.split == "train"][["hostname", "window_start_epoch"]]
    con = duckdb.connect()
    con.execute("SET threads=8; SET memory_limit='16GB'")
    con.register("train_windows", train)
    con.execute(f"CREATE VIEW tr AS SELECT f.* FROM read_parquet('{FLOWS}') f JOIN train_windows t ON f.hostname = t.hostname AND f.window_start_epoch = t.window_start_epoch")
    fit_flows = con.execute("SELECT count(*) FROM tr").fetchone()[0]
    fit_windows = con.execute("SELECT count(*) FROM (SELECT DISTINCT hostname, window_start_epoch FROM tr)").fetchone()[0]
    print(f"phạm vi fit: {fit_windows:,} cửa sổ TRAIN, {fit_flows:,} flow ({time.time() - t0:.0f}s)", flush=True)

    fields = {}
    for f in C.CAT_ORDER:
        rows = con.execute(f"SELECT {C.cat_expr(f)} AS v, count(*)::BIGINT AS n FROM tr GROUP BY 1").fetchall()
        n_missing = sum(n for v, n in rows if v == "<MISSING>")
        nonmiss = sorted([(v, n) for v, n in rows if v != "<MISSING>"], key=lambda x: (-x[1], x[0]))
        minf = C.MIN_FREQ.get(f, C.DEFAULT_MIN_FREQ)
        maxv = C.MAX_VALUES.get(f, C.DEFAULT_MAX_VALUES)
        kept = [(v, n) for v, n in nonmiss if n >= minf][:maxv]
        dropped = [(v, n) for v, n in nonmiss if (v, n) not in set(kept)]
        n_nonmiss = sum(n for _, n in nonmiss)
        # Active: cần >= 2 giá trị, mỗi giá trị >= MIN_SUPPORT flow TRAIN (hoặc thiếu/có giá trị đều >= MIN_SUPPORT flow).
        # Lý do: một flow đơn lẻ (vd. direction = inbound chỉ có 1 flow RDP trong TRAIN) không được bật cả một feature.
        support = [n for _, n in nonmiss if n >= MIN_SUPPORT]
        varies = len(support) >= 2 or (n_missing >= MIN_SUPPORT and n_nonmiss >= MIN_SUPPORT)
        fields[f] = {
            "active": bool(varies),
            "reason": (f"thay đổi trên TRAIN (>= 2 giá trị, mỗi giá trị >= {MIN_SUPPORT} flow, hoặc thiếu/có giá trị đều >= {MIN_SUPPORT} flow)" if varies
                       else f"coi như hằng số trên TRAIN (chỉ {len(support)} giá trị có >= {MIN_SUPPORT} flow); chỉ giữ để audit"),
            "min_train_frequency": minf, "max_values_excluding_reserved": maxv,
            "n_train_flows": int(n_missing + n_nonmiss), "n_missing": int(n_missing), "n_distinct_non_missing": len(nonmiss),
            "n_distinct_dropped_below_min_freq": len(dropped), "flows_of_dropped_values": int(sum(n for _, n in dropped)),
            "vocab": [{"value": v, "id": i + 2, "train_count": int(n)} for i, (v, n) in enumerate(kept)],
        }
        print(f"  {f}: {len(nonmiss)} giá trị, giữ {len(kept)}, missing {n_missing:,}, active={varies}", flush=True)

    sel = ", ".join(
        f"avg(ln(1 + greatest({c}, 0))) AS m_{c}, stddev_pop(ln(1 + greatest({c}, 0))) AS s_{c}, count({c}) AS o_{c}, count(*) - count({c}) AS x_{c}, min({c}) AS lo_{c}, max({c}) AS hi_{c}"
        for c in C.NUM_ORDER)
    r = con.execute(f"SELECT {sel} FROM tr").fetchone()
    nums = {}
    for i, c in enumerate(C.NUM_ORDER):
        m, s, o, x, lo, hi = r[i * 6: i * 6 + 6]
        act = bool(s is not None and s >= 0.01)
        nums[c] = {"active": act,
                   "reason": ("log1p std >= 0.01" if act else f"log1p std = {s:.6f} < 0.01: z-score không ổn định cho giá trị khác 0 hiếm; dùng cờ nhị phân thay thế"),
                   "log1p_mean": float(m), "log1p_std": float(s), "n_observed": int(o), "n_missing": int(x), "raw_min": float(lo), "raw_max": float(hi)}
    act_cat = [f for f in C.CAT_ORDER if fields[f]["active"]]
    act_num = [c for c in C.NUM_ORDER if nums[c]["active"]]
    spec = {
        "version": "v2-preprocess-spec-1.0",
        "fit": {"split": "train", "source_flows": "S1_join/data/flows_joined.parquet", "source_windows": "S2_windows_split/data/windows.csv (split = train)",
                "n_windows": int(fit_windows), "n_flows": int(fit_flows), "label_used_for_fit": False, "val_used_for_fit": False, "test_used_for_fit": False},
        "categorical": {"reserved_ids": {"<UNK>": 0, "<MISSING>": 1},
                        "value_rule": "văn bản: chữ thường, bỏ khoảng trắng; '', '-', '(empty)', 'null', 'none' hoặc NULL -> <MISSING>; ip_scope/port_class theo quy tắc ở dưới",
                        "vocab_order": "số lần xuất hiện trong TRAIN giảm dần, hòa thì theo chữ; id bắt đầu từ 2; giá trị không có trong từ điển -> <UNK>=0 lúc mã hóa",
                        "fields": fields},
        "numeric": {"transform": "log1p(max(x, 0)) -> (x - log1p_mean) / log1p_std -> clip ±zscore_clip_abs", "zscore_clip_abs": 10.0, "std": "stddev_pop",
                    "missing_policy": "giá trị thiếu -> z = 0.0 và x_num_missing = 1", "fields": nums},
        "binary": [{"name": "has_missed_bytes", "source": "missed_bytes", "rule": "1 nếu missed_bytes > 0, ngược lại 0 (thiếu -> 0)", "fit_required": False}],
        "time": {"delta_t_log1p": "ln(1 + max(0, ts - ts_flow_trước_trong_cùng_chunk)); flow đầu mỗi chunk = 0"},
        "derived_rules": {"port_class": {"common_ports": {str(k): v for k, v in C.COMMON_PORTS.items()}, "format_common": "PORT_<port>_<tên>",
                                         "ranges": {"WELL_KNOWN_OTHER": "0-1023", "REGISTERED": "1024-49151", "EPHEMERAL": "49152-65535", "OTHER": "còn lại", "<MISSING>": "NULL"}},
                          "ip_scope": ["<MISSING>", "LOOPBACK", "PRIVATE", "PRIVATE_IPV6", "LINK_LOCAL", "MULTICAST", "BROADCAST", "PUBLIC_IPV4", "PUBLIC_IPV6", "OTHER"],
                          "image_dir_class": {"source": "eCAR-Bro properties.image_path (host)", "values": {
                              "MISSING": "không có image_path", "BARE_NAME": "chỉ có tên file, không có thư mục", "TEMP_OR_APPDATA": "đường dẫn chứa thư mục Temp hoặc AppData",
                              "SYSTEM32": "thư mục Windows/System32 hoặc SysWOW64", "WINDOWS_OTHER": "thư mục Windows khác", "PROGRAM_FILES": "thư mục Program Files",
                              "USERS_OTHER": "thư mục Users (không phải Temp/AppData)", "OTHER": "còn lại"}, "order": "xét từ trên xuống theo thứ tự này"},
                          "principal_class": {"source": "eCAR-Bro principal (host)", "values": {
                              "NONE": "rỗng", "SYSTEM_ACCOUNT": "tài khoản hệ thống: NT AUTHORITY, NT SERVICE, Font Driver, Window Manager, DWM", "ADMINISTRATOR": "tài khoản miền tên Administrator",
                              "SYSADMIN": "tài khoản miền tên sysadmin", "DOMAIN_USER": "còn lại (tài khoản người dùng miền)"}, "order": "xét từ trên xuống theo thứ tự này"}},
        "model_input_layout": {"x_cat_columns": act_cat, "x_num_columns": act_num, "x_bin_columns": ["has_missed_bytes"], "extra_per_flow": ["delta_t_log1p"],
                               "host_derived_columns": [f for f in C.HOST_DERIVED if f in act_cat],
                               "host_derived_note": "app_family (tên tiến trình), image_dir_class (tiến trình chạy từ thư mục nào) và principal_class (loại tài khoản chạy tiến trình) lấy từ eCAR-Bro, tức telemetry phía host; mọi cột khác là Bro conn",
                               "not_model_input": ["uid", "hostname", "label", "ts", "actor_id", "pid", "ppid", "principal (chỉ dùng qua principal_class)", "image_path (chỉ dùng qua app_family, image_dir_class)", "orig_h", "orig_p", "resp_h (chỉ dùng tạo remote_local_id)"]},
    }
    fp = hashlib.sha256(json.dumps(spec, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    spec["fingerprint_sha256"] = fp
    json.dump(spec, open(OUT / "data/preprocess_spec.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    with open(OUT / "data/vocab.csv", "w", encoding="utf-8-sig", newline="") as fh:
        wr = csv.writer(fh, lineterminator="\n")
        wr.writerow(["field", "active", "value", "id", "train_count"])
        for f in C.CAT_ORDER:
            wr.writerow([f, fields[f]["active"], "<UNK>", 0, ""])
            wr.writerow([f, fields[f]["active"], "<MISSING>", 1, fields[f]["n_missing"]])
            for e in fields[f]["vocab"]:
                wr.writerow([f, fields[f]["active"], e["value"], e["id"], e["train_count"]])
    # ví dụ mã hóa
    s1 = json.load(open(V2 / "S1_join/preview_record.json", encoding="utf-8"))
    ex = {k: (C.encode_flow(v, spec) if v else None) for k, v in s1.items()}
    ex["raw_flows"] = s1
    json.dump(ex, open(OUT / "preview_record.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    pd.DataFrame([{"field": c, "active": nums[c]["active"], **{k: v for k, v in nums[c].items() if k not in ("active", "reason")}, "reason": nums[c]["reason"]} for c in C.NUM_ORDER]).to_csv(
        OUT / "preview.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    json.dump({"file": "preprocess_spec.json", "sections": {
        "fit": "phạm vi dữ liệu dùng để fit (chỉ TRAIN) và cam kết không dùng nhãn/VAL/TEST",
        "categorical": "reserved ids, quy tắc giá trị, và từng trường: active/lý do, đếm, vocab [{value, id, train_count}]",
        "numeric": "biến đổi, clip, và từng trường: active/lý do, log1p_mean, log1p_std, số quan sát/thiếu, min/max thô",
        "binary": "cờ nhị phân dẫn xuất", "time": "cách tính delta_t_log1p", "derived_rules": "quy tắc port_class và ip_scope",
        "model_input_layout": "thứ tự cột x_cat / x_num / x_bin mà mô hình nhận", "fingerprint_sha256": "sha256 của toàn bộ spec (trừ chính nó)"},
        "companion": {"vocab.csv": "từ điển dạng bảng (field, value, id, train_count)", "preview.csv": "thống kê numeric dạng bảng", "preview_record.json": "ví dụ mã hóa từng bước một flow thật"}},
        open(OUT / "schema.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    ck = {"fit_windows": int(fit_windows), "expected_train_windows": int(len(train)), "fit_flows": int(fit_flows), "fit_scope_equals_train_windows": bool(fit_windows == len(train)),
          "active_categorical": act_cat, "active_numeric": act_num,
          "old_pipeline_features_all_active": bool(all(f in act_cat for f in ["app_family", "proto", "service", "conn_state", "resp_port_class"]) and
                                                   act_num == ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]),
          "host_derived_active": [f for f in C.HOST_DERIVED if f in act_cat],
          "vocab_sizes": {f: len(fields[f]["vocab"]) + 2 for f in C.CAT_ORDER}, "fingerprint_sha256": fp}
    ck["PASS"] = bool(ck["fit_scope_equals_train_windows"] and all(len(fields[f]["vocab"]) > 0 for f in act_cat) and len(act_num) > 0)
    json.dump(ck, open(OUT / "checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(ck, ensure_ascii=False, indent=1))
    print(f"S3 xong ({time.time() - t0:.0f}s) PASS={ck['PASS']}")


if __name__ == "__main__":
    main()
