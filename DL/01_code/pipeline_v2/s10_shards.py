#!/usr/bin/env python3
"""S10c - Mã hóa bảng flow của dataset mới bằng ĐÚNG preprocess_spec.json của OpTC v2 (không fit lại gì) và đóng gói shards .npz cùng định dạng S4.

Input : flows parquet từ s10_skrghosh_flows.py hoặc s10_ait_flows.py (cột uid, hostname, ts, window_start_epoch, label, app_family, image_path, proto, resp_h, resp_p)
Output: <out>/data/flows_norm.parquet, <out>/data/samples.csv, <out>/shards/test/test_NNNN.npz, <out>/split/network_sample_manifest.csv, <out>/checks.json, <out>/decoded_preview.json
        (toàn bộ sample xếp vào split 'test' để dùng lại bộ nạp dữ liệu của notebook 06e/07e; đây là bộ ĐÁNH GIÁ, không phải bộ train)
Cột Bro và cột tiến trình mà dataset không có: category = <MISSING> (id 1), numeric = 0 kèm cờ thiếu = 1 (mô hình B đã bỏ chúng nên không ảnh hưởng).
Sample = (hostname, cửa sổ 15 phút) sắp theo (ts, uid), cắt chunk 512 flow; nhãn sample = có >= 1 flow dương.
Chạy: python s10_shards.py --flows <parquet> --out <dir> --name <tên>"""
import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import s4_shards as S4  # noqa: E402
import v2_common as C  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
SPEC = Path("D:/UIT/KLTNv2/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json")
import os as _os
MAX_EVENTS = int(_os.environ.get("S10_MAX_EVENTS", "512"))
SHARD_EVENTS = 1_000_000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--spec", default=str(SPEC), help="preprocess_spec.json (mặc định: spec OpTC; dùng spec mở rộng cho fine-tune)")
    a = ap.parse_args()
    t0 = time.time()
    out = Path(a.out)
    for d in ("data", "shards/test", "split"):
        (out / d).mkdir(parents=True, exist_ok=True)
    spec = json.load(open(a.spec, encoding="utf-8"))
    cats = spec["model_input_layout"]["x_cat_columns"]
    nums = spec["model_input_layout"]["x_num_columns"]
    con = duckdb.connect()
    con.execute("SET memory_limit='10GB'; SET threads=8")
    norm = (out / "data/flows_norm.parquet").as_posix()
    have = set(con.execute(f"DESCRIBE SELECT * FROM read_parquet('{Path(a.flows).as_posix()}')").df().column_name)
    app_sel = "app_family" if "app_family" in have else "NULL::VARCHAR AS app_family"
    img_sel = "image_path" if "image_path" in have else "NULL::VARCHAR AS image_path"
    num_null = ", ".join(f"NULL::DOUBLE AS {c}" for c in nums)
    con.execute(f"""COPY (SELECT uid, hostname, ts, window_start_epoch, label::TINYINT AS label, {app_sel}, {img_sel}, proto, resp_h, resp_p::BIGINT AS resp_p,
                      NULL::VARCHAR AS service, NULL::VARCHAR AS conn_state, NULL::VARCHAR AS principal, NULL::BIGINT AS missed_bytes, {num_null}
                      FROM read_parquet('{Path(a.flows).as_posix()}')) TO '{norm}' (FORMAT PARQUET)""")
    w = con.execute(f"""SELECT hostname, window_start_epoch, 'test' AS split, count(*) AS n_flows, sum(label)::BIGINT AS n_positive_flows
                        FROM read_parquet('{norm}') GROUP BY 1, 2 ORDER BY 1, 2""").df()
    w["n_chunks"] = (w.n_flows + MAX_EVENTS - 1) // MAX_EVENTS
    con.register("win", w[["hostname", "window_start_epoch", "split"]])
    S4.FLOWS = norm
    hosts = sorted(w.hostname.unique())
    X = {k: [] for k in ("x_cat", "x_num", "x_miss", "x_bin", "delta", "app", "rem")}
    meta = []
    for i in range(0, len(hosts), 20):
        t = con.execute(S4.build_query(spec, hosts[i:i + 20])).fetch_arrow_table()
        host = np.asarray(t.column("hostname").to_pylist())
        win = t.column("window_start_epoch").to_numpy()
        chk = t.column("chunk_index").to_numpy()
        lab = t.column("label").to_numpy()
        X["x_cat"].append(np.stack([t.column(f"c_{f}").to_numpy() for f in cats], axis=1).astype(np.uint16))
        X["x_num"].append(np.stack([t.column(f"z_{c}").to_numpy() for c in nums], axis=1).astype(np.float32))
        X["x_miss"].append(np.stack([t.column(f"m_{c}").to_numpy() for c in nums], axis=1).astype(np.uint8))
        X["x_bin"].append(t.column("b_has_missed_bytes").to_numpy().astype(np.uint8)[:, None])
        X["delta"].append(t.column("delta_t_log1p").to_numpy().astype(np.float32))
        X["app"].append(t.column("app_local_id").to_numpy().astype(np.uint16))
        X["rem"].append(t.column("remote_local_id").to_numpy().astype(np.uint16))
        hcode = pd.factorize(host)[0]
        change = np.r_[True, (hcode[1:] != hcode[:-1]) | (win[1:] != win[:-1]) | (chk[1:] != chk[:-1])]
        st = np.flatnonzero(change)
        cnt = np.diff(np.r_[st, len(host)])
        meta.append(pd.DataFrame({"hostname": host[st], "window_start_epoch": win[st], "chunk_index": chk[st], "event_count": cnt,
                                  "positive_event_count": np.add.reduceat(lab.astype(np.int64), st), "label": (np.maximum.reduceat(lab, st) > 0).astype(np.uint8),
                                  "app_node_count": np.maximum.reduceat(X["app"][-1], st).astype(np.int64) + 1, "remote_node_count": np.maximum.reduceat(X["rem"][-1], st).astype(np.int64) + 1}))
    X = {k: np.concatenate(v) for k, v in X.items()}
    md = pd.concat(meta, ignore_index=True)
    offs = np.r_[0, np.cumsum(md.event_count.to_numpy())]
    order = np.arange(len(md))  # giữ thứ tự thời gian (không xáo trộn): đây là bộ đánh giá
    rows, k, i = [], 0, 0
    while i < len(order):
        j, tot = i, 0
        while j < len(order) and (tot < SHARD_EVENTS or j == i):
            tot += int(md.event_count.iat[order[j]])
            j += 1
        idx = order[i:j]
        ev = np.concatenate([np.arange(offs[x], offs[x + 1]) for x in idx])
        ec = md.event_count.to_numpy()[idx]
        so = np.r_[0, np.cumsum(ec)].astype(np.int64)
        fn = f"shards/test/test_{k:04d}.npz"
        np.savez(out / fn, x_cat=X["x_cat"][ev], x_num=X["x_num"][ev], x_num_missing=X["x_miss"][ev], x_bin=X["x_bin"][ev], delta_t_log1p=X["delta"][ev],
                 edge_app_local=X["app"][ev], edge_remote_local=X["rem"][ev], sample_offsets=so, sample_labels=md.label.to_numpy()[idx].astype(np.uint8),
                 sample_event_counts=ec.astype(np.uint16), sample_positive_event_counts=md.positive_event_count.to_numpy()[idx].astype(np.uint16),
                 sample_app_node_counts=md.app_node_count.to_numpy()[idx].astype(np.uint16), sample_remote_node_counts=md.remote_node_count.to_numpy()[idx].astype(np.uint16),
                 sample_window_start=md.window_start_epoch.to_numpy()[idx].astype(np.int64), sample_chunk_index=md.chunk_index.to_numpy()[idx].astype(np.uint16),
                 categorical_feature_names=np.array(cats), numerical_feature_names=np.array(nums), binary_feature_names=np.array(["has_missed_bytes"]))
        for pos, x in enumerate(idx):
            r = md.iloc[x]
            dt = datetime.fromtimestamp(int(r.window_start_epoch), tz=timezone.utc)
            rows.append({"sample_id": hashlib.sha256(f"{a.name}|{r.hostname}|{int(r.window_start_epoch)}|{int(r.chunk_index)}".encode()).hexdigest()[:24], "split": "test",
                         "date": dt.strftime("%Y-%m-%d"), "hostname": r.hostname, "window_start_epoch": int(r.window_start_epoch), "window_start_utc": dt.isoformat(),
                         "chunk_index": int(r.chunk_index), "label": int(r.label), "event_count": int(r.event_count), "positive_event_count": int(r.positive_event_count),
                         "shard_file": fn, "shard_sample_index": pos})
        k += 1
        i = j
    sm = pd.DataFrame(rows)
    sm.to_csv(out / "data/samples.csv", index=False, encoding="utf-8", lineterminator="\n")
    sm.to_csv(out / "split/network_sample_manifest.csv", index=False, encoding="utf-8", lineterminator="\n")
    # ---------- kiểm tra
    ws = w.agg({"n_flows": "sum", "n_positive_flows": "sum", "n_chunks": "sum"})
    ck = {"name": a.name, "flows_parquet": int(ws.n_flows), "events_in_shards": int(md.event_count.sum()), "positive_flows_parquet": int(ws.n_positive_flows),
          "positive_events_in_shards": int(md.positive_event_count.sum()), "samples_expected": int(ws.n_chunks), "samples": int(len(md)), "positive_samples": int(md.label.sum()),
          "windows": int(len(w)), "positive_windows": int((w.n_positive_flows > 0).sum()), "hosts": int(len(hosts)), "max_event_count": int(md.event_count.max()), "unique_sample_id": bool(sm.sample_id.is_unique)}
    # mã hóa lại 300 flow bằng Python thuần từ spec và so với shard
    chosen = con.execute(f"SELECT * FROM read_parquet('{norm}') ORDER BY hash(uid) LIMIT 300").df()
    bad, checked = 0, 0
    for r in chosen.itertuples():
        row = {c: (None if pd.isna(getattr(r, c)) else getattr(r, c)) for c in ("app_family", "image_path", "proto", "resp_p", "service", "conn_state", "principal")}
        py = C.encode_flow(row, spec)["x_cat"]
        # tìm flow trong shards
        wins = sm[(sm.hostname == r.hostname) & (sm.window_start_epoch == r.window_start_epoch)]
        if wins.empty:
            continue
        sub = con.execute(f"SELECT uid FROM read_parquet('{norm}') WHERE hostname = '{S4.q(r.hostname)}' AND window_start_epoch = {int(r.window_start_epoch)} ORDER BY ts, uid").df().uid.tolist()
        pos_in_win = sub.index(r.uid)
        c = wins[wins.chunk_index == pos_in_win // MAX_EVENTS].iloc[0]
        z = np.load(out / c.shard_file)
        a0 = int(z["sample_offsets"][int(c.shard_sample_index)]) + pos_in_win % MAX_EVENTS
        got = dict(zip(cats, z["x_cat"][a0].tolist()))
        checked += 1
        if any(got[f] != py[f]["id"] for f in cats):
            bad += 1
    ck["recheck_python_vs_shard"] = {"checked": checked, "mismatch": bad}
    top = con.execute(f"SELECT app_family, count(*) n, sum(label) pos FROM read_parquet('{norm}') GROUP BY 1 ORDER BY 2 DESC LIMIT 8").fetchall()
    unk = {f: float((X["x_cat"][:, cats.index(f)] == 0).mean()) for f in cats}
    miss = {f: float((X["x_cat"][:, cats.index(f)] == 1).mean()) for f in cats}
    ck["share_unk_by_field"] = {k_: round(v, 4) for k_, v in unk.items()}
    ck["share_missing_by_field"] = {k_: round(v, 4) for k_, v in miss.items()}
    ck["top_app_family"] = [list(map(lambda v: v if not isinstance(v, (np.integer,)) else int(v), t_)) for t_ in top]
    ck["PASS"] = bool(ck["events_in_shards"] == ck["flows_parquet"] and ck["positive_events_in_shards"] == ck["positive_flows_parquet"] and ck["samples"] == ck["samples_expected"]
                      and ck["unique_sample_id"] and ck["max_event_count"] <= MAX_EVENTS and bad == 0)
    ck["seconds"] = round(time.time() - t0)
    json.dump(ck, open(out / "checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print(json.dumps(ck, ensure_ascii=False, indent=1, default=str))
    sys.exit(0 if ck["PASS"] else 1)


if __name__ == "__main__":
    main()
