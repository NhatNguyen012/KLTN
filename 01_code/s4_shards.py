#!/usr/bin/env python3
"""S4 - SHARDS: mã hóa flow bằng preprocess_spec.json và đóng gói thành sample (cửa sổ 15 phút, chunk <= 512 flow) trong các file .npz.

Input : S1_join/data/flows_joined.parquet ; S2_windows_split/data/windows.csv ; S3_preprocess/data/preprocess_spec.json
Output: S4_shards/shards/{train,val,test}/<split>_NNNN.npz (~1 triệu flow mỗi file, các sample xáo trộn có seed nên mỗi file trộn nhiều máy/ngày)
        S4_shards/data/samples.csv (1 dòng = 1 sample), shard_format.json, decoded_preview.json, schema.json, preview.csv, checks.json
Sample: flow của một (hostname, cửa sổ 15 phút) sắp theo (ts, uid), cắt chunk mỗi 512 flow; nhãn sample = có ít nhất 1 flow dương.
Khóa npz giữ như bản cũ: x_cat, x_num, x_num_missing, x_bin, delta_t_log1p, edge_app_local, edge_remote_local, sample_* (để dùng lại mã mô hình).
"""
import csv
import hashlib
import json
import shutil
import sys
import time
from datetime import datetime, timezone
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
WINDOWS = V2 / "S2_windows_split/data/windows.csv"
SPEC = V2 / "S3_preprocess/data/preprocess_spec.json"
OUT = V2 / "S4_shards"
MAX_EVENTS = 512
SHARD_EVENTS = 1_000_000
HOST_BATCH = 20
SHUFFLE_SEED = 20261013


def q(s):
    return str(s).replace("'", "''")


def build_query(spec, hosts):
    cats = spec["model_input_layout"]["x_cat_columns"]
    nums = spec["model_input_layout"]["x_num_columns"]
    sel_v = ", ".join(f"{C.cat_expr(f)} AS v_{f}" for f in cats)
    id_cols = []
    for f in cats:
        voc = spec["categorical"]["fields"][f]["vocab"]
        whens = " ".join(f"WHEN '{q(e['value'])}' THEN {e['id']}" for e in voc)
        id_cols.append(f"CASE v_{f} WHEN '<MISSING>' THEN 1 {whens} ELSE 0 END::USMALLINT AS c_{f}")
    z_cols, m_cols = [], []
    clip = spec["numeric"]["zscore_clip_abs"]
    for c in nums:
        st = spec["numeric"]["fields"][c]
        z_cols.append(f"CASE WHEN {c} IS NULL THEN 0.0 ELSE greatest(-{clip}, least({clip}, (ln(1 + greatest({c}, 0)) - {st['log1p_mean']!r}) / {st['log1p_std']!r})) END::FLOAT AS z_{c}")
        m_cols.append(f"({c} IS NULL)::UTINYINT AS m_{c}")
    hl = ", ".join(f"'{q(h)}'" for h in hosts)
    return f"""
    WITH f AS (
      SELECT fl.hostname, fl.window_start_epoch, w.split, fl.ts, fl.uid, fl.label, fl.resp_h, fl.missed_bytes, {', '.join(nums)},
             {sel_v}
      FROM read_parquet('{FLOWS}') fl JOIN win w ON fl.hostname = w.hostname AND fl.window_start_epoch = w.window_start_epoch
      WHERE fl.hostname IN ({hl})
    ), numbered AS (
      SELECT *, (row_number() OVER (PARTITION BY hostname, window_start_epoch ORDER BY ts, uid) - 1) AS rn FROM f
    ), chunked AS (
      SELECT *, (rn // {MAX_EVENTS})::INTEGER AS chunk_index, (rn % {MAX_EVENTS})::INTEGER AS event_pos FROM numbered
    ), enc AS (
      SELECT hostname, window_start_epoch, split, chunk_index, event_pos, ts, label::UTINYINT AS label,
             {', '.join(id_cols)}, {', '.join(z_cols)}, {', '.join(m_cols)},
             (CASE WHEN missed_bytes IS NOT NULL AND missed_bytes > 0 THEN 1 ELSE 0 END)::UTINYINT AS b_has_missed_bytes,
             (dense_rank() OVER (PARTITION BY hostname, window_start_epoch, chunk_index ORDER BY c_{cats[0]}) - 1)::USMALLINT AS app_local_id,
             (dense_rank() OVER (PARTITION BY hostname, window_start_epoch, chunk_index ORDER BY COALESCE(resp_h, '<MISSING>')) - 1)::USMALLINT AS remote_local_id,
             lag(ts) OVER (PARTITION BY hostname, window_start_epoch, chunk_index ORDER BY event_pos) AS prev_ts
      FROM chunked
    )
    SELECT *, (CASE WHEN prev_ts IS NULL THEN 0.0 ELSE ln(1.0 + greatest(0.0, ts - prev_ts)) END)::FLOAT AS delta_t_log1p
    FROM enc ORDER BY split, hostname, window_start_epoch, chunk_index, event_pos
    """


def main():
    t0 = time.time()
    spec = json.load(open(SPEC, encoding="utf-8"))
    cats = spec["model_input_layout"]["x_cat_columns"]
    nums = spec["model_input_layout"]["x_num_columns"]
    w = pd.read_csv(WINDOWS)
    hosts_all = sorted(w.hostname.unique())
    con = duckdb.connect()
    con.execute("SET threads=8; SET memory_limit='14GB'")
    con.register("win", w[["hostname", "window_start_epoch", "split"]])
    if (OUT / "shards").exists():
        shutil.rmtree(OUT / "shards")
    (OUT / "data").mkdir(parents=True, exist_ok=True)
    acc = {s: {k: [] for k in ["x_cat", "x_num", "x_miss", "x_bin", "delta", "app", "rem"]} for s in ("train", "val", "test")}
    meta = {s: [] for s in ("train", "val", "test")}
    n_batches = (len(hosts_all) + HOST_BATCH - 1) // HOST_BATCH
    for bi in range(n_batches):
        hs = hosts_all[bi * HOST_BATCH:(bi + 1) * HOST_BATCH]
        t = con.execute(build_query(spec, hs)).fetch_arrow_table()
        df_split = np.asarray(t.column("split").to_pylist())
        host = np.asarray(t.column("hostname").to_pylist())
        win = t.column("window_start_epoch").to_numpy()
        chk = t.column("chunk_index").to_numpy()
        lab = t.column("label").to_numpy()
        xc = np.stack([t.column(f"c_{f}").to_numpy() for f in cats], axis=1).astype(np.uint16)
        xn = np.stack([t.column(f"z_{c}").to_numpy() for c in nums], axis=1).astype(np.float32)
        xm = np.stack([t.column(f"m_{c}").to_numpy() for c in nums], axis=1).astype(np.uint8)
        xb = t.column("b_has_missed_bytes").to_numpy().astype(np.uint8)[:, None]
        dl = t.column("delta_t_log1p").to_numpy().astype(np.float32)
        ap = t.column("app_local_id").to_numpy().astype(np.uint16)
        rm = t.column("remote_local_id").to_numpy().astype(np.uint16)
        for s in ("train", "val", "test"):
            m = df_split == s
            if not m.any():
                continue
            h_, w_, c_, l_ = host[m], win[m], chk[m], lab[m]
            hcode = pd.factorize(h_)[0]
            change = np.r_[True, (hcode[1:] != hcode[:-1]) | (w_[1:] != w_[:-1]) | (c_[1:] != c_[:-1])]
            st = np.flatnonzero(change)
            cnt = np.diff(np.r_[st, len(h_)])
            a = acc[s]
            a["x_cat"].append(xc[m]); a["x_num"].append(xn[m]); a["x_miss"].append(xm[m]); a["x_bin"].append(xb[m]); a["delta"].append(dl[m])
            a["app"].append(ap[m]); a["rem"].append(rm[m])
            ap_m, rm_m = ap[m], rm[m]
            meta[s].append(pd.DataFrame({
                "hostname": h_[st], "window_start_epoch": w_[st], "chunk_index": c_[st], "event_count": cnt,
                "positive_event_count": np.add.reduceat(l_.astype(np.int64), st), "label": (np.maximum.reduceat(l_, st) > 0).astype(np.uint8),
                "app_node_count": np.maximum.reduceat(ap_m, st).astype(np.int64) + 1, "remote_node_count": np.maximum.reduceat(rm_m, st).astype(np.int64) + 1}))
        print(f"  lô {bi + 1}/{n_batches}: {len(host):,} flow ({time.time() - t0:.0f}s)", flush=True)
    # ---------- ghi shards
    rng = np.random.default_rng(SHUFFLE_SEED)
    rows_all, stats = [], {}
    for s in ("train", "val", "test"):
        a = acc[s]
        X = {k: np.concatenate(v) for k, v in a.items()}
        a.clear()
        md = pd.concat(meta[s], ignore_index=True)
        offs = np.r_[0, np.cumsum(md.event_count.to_numpy())]
        perm = rng.permutation(len(md))
        (OUT / "shards" / s).mkdir(parents=True, exist_ok=True)
        k, i = 0, 0
        while i < len(perm):
            j, tot = i, 0
            while j < len(perm) and (tot < SHARD_EVENTS or j == i):
                tot += int(md.event_count.iat[perm[j]])
                j += 1
            idx = perm[i:j]
            ev = np.concatenate([np.arange(offs[x], offs[x + 1]) for x in idx])
            ec = md.event_count.to_numpy()[idx]
            so = np.r_[0, np.cumsum(ec)].astype(np.int64)
            fn = f"shards/{s}/{s}_{k:04d}.npz"
            np.savez(OUT / fn, x_cat=X["x_cat"][ev], x_num=X["x_num"][ev], x_num_missing=X["x_miss"][ev], x_bin=X["x_bin"][ev], delta_t_log1p=X["delta"][ev],
                     edge_app_local=X["app"][ev], edge_remote_local=X["rem"][ev], sample_offsets=so,
                     sample_labels=md.label.to_numpy()[idx].astype(np.uint8), sample_event_counts=ec.astype(np.uint16),
                     sample_positive_event_counts=md.positive_event_count.to_numpy()[idx].astype(np.uint16),
                     sample_app_node_counts=md.app_node_count.to_numpy()[idx].astype(np.uint16), sample_remote_node_counts=md.remote_node_count.to_numpy()[idx].astype(np.uint16),
                     sample_window_start=md.window_start_epoch.to_numpy()[idx].astype(np.int64), sample_chunk_index=md.chunk_index.to_numpy()[idx].astype(np.uint16),
                     categorical_feature_names=np.array(cats), numerical_feature_names=np.array(nums), binary_feature_names=np.array(["has_missed_bytes"]))
            for pos, x in enumerate(idx):
                r = md.iloc[x]
                dt = datetime.fromtimestamp(int(r.window_start_epoch), tz=timezone.utc)
                rows_all.append({"sample_id": hashlib.sha256(f"{s}|{r.hostname}|{int(r.window_start_epoch)}|{int(r.chunk_index)}".encode()).hexdigest()[:24], "split": s,
                                 "date": dt.strftime("%Y-%m-%d"), "hostname": r.hostname, "window_start_epoch": int(r.window_start_epoch),
                                 "window_start_utc": dt.isoformat(), "chunk_index": int(r.chunk_index), "label": int(r.label), "event_count": int(r.event_count),
                                 "positive_event_count": int(r.positive_event_count), "app_node_count": int(r.app_node_count), "remote_node_count": int(r.remote_node_count),
                                 "shard_file": fn, "shard_sample_index": pos})
            k += 1
            i = j
        stats[s] = {"samples": int(len(md)), "events": int(md.event_count.sum()), "positive_events": int(md.positive_event_count.sum()), "positive_samples": int(md.label.sum()), "shards": k}
        print(f"{s}: {stats[s]} ({time.time() - t0:.0f}s)", flush=True)
        del X, md
    cols = ["sample_id", "split", "date", "hostname", "window_start_epoch", "window_start_utc", "chunk_index", "label", "event_count", "positive_event_count", "app_node_count",
            "remote_node_count", "shard_file", "shard_sample_index"]
    sm = pd.DataFrame(rows_all)[cols]
    sm.to_csv(OUT / "data/samples.csv", index=False, encoding="utf-8", lineterminator="\n")
    sm.groupby(["split", "label"]).head(5).sort_values(["split", "label"]).to_csv(OUT / "preview.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    # ---------- kiểm tra bảo toàn
    ws = w.groupby("split").agg(flows=("n_flows", "sum"), pos_flows=("n_positive_flows", "sum"), samples=("n_chunks", "sum"))
    ck = {"by_split": {}, "unique_sample_id": bool(sm.sample_id.is_unique), "max_event_count": int(sm.event_count.max())}
    ok = True
    for s in ("train", "val", "test"):
        c = {"events_shards": stats[s]["events"], "flows_windows_csv": int(ws.loc[s, "flows"]), "positive_events_shards": stats[s]["positive_events"],
             "positive_flows_windows_csv": int(ws.loc[s, "pos_flows"]), "samples_shards": stats[s]["samples"], "samples_windows_csv": int(ws.loc[s, "samples"])}
        c["conserved"] = bool(c["events_shards"] == c["flows_windows_csv"] and c["positive_events_shards"] == c["positive_flows_windows_csv"] and c["samples_shards"] == c["samples_windows_csv"])
        ok &= c["conserved"]
        ck["by_split"][s] = c
    ck["stats"] = stats
    ck["PASS"] = bool(ok and ck["unique_sample_id"] and ck["max_event_count"] <= MAX_EVENTS)
    json.dump(ck, open(OUT / "checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"npz_keys": {
        "x_cat": f"uint16 [T, {len(cats)}] id category theo thứ tự {cats}; 0=<UNK>, 1=<MISSING>", "x_num": f"float32 [T, {len(nums)}] z-score theo thứ tự {nums}",
        "x_num_missing": f"uint8 [T, {len(nums)}] 1 nếu giá trị thiếu", "x_bin": "uint8 [T, 1] has_missed_bytes", "delta_t_log1p": "float32 [T] ln(1 + giây từ flow trước trong chunk)",
        "edge_app_local": "uint16 [T] số thứ tự cục bộ của app_family trong sample", "edge_remote_local": "uint16 [T] số thứ tự cục bộ của resp_h trong sample",
        "sample_offsets": "int64 [S+1] đầu/cuối của từng sample trong mảng T", "sample_labels": "uint8 [S]", "sample_event_counts": "uint16 [S]",
        "sample_positive_event_counts": "uint16 [S]", "sample_app_node_counts": "uint16 [S]", "sample_remote_node_counts": "uint16 [S]",
        "sample_window_start": "int64 [S]", "sample_chunk_index": "uint16 [S]", "*_feature_names": "tên cột (kiểm tra thứ tự)"},
        "T": "tổng số flow trong file", "S": "số sample trong file", "shuffle": f"sample xáo trộn có seed {SHUFFLE_SEED} trước khi chia file"},
        open(OUT / "shard_format.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"table": "samples.csv", "grain": "1 dòng = 1 sample (hostname, cửa sổ 15 phút, chunk)", "fields": {
        "sample_id": "sha256(split|hostname|window|chunk)[:24]", "split": "train/val/test (từ S2)", "date": "ngày UTC", "hostname": "máy", "window_start_epoch": "đầu cửa sổ",
        "window_start_utc": "ISO UTC", "chunk_index": "thứ tự chunk trong cửa sổ", "label": "1 nếu có >= 1 flow dương", "event_count": "số flow (<= 512)", "positive_event_count": "số flow dương",
        "app_node_count": "số app_family khác nhau", "remote_node_count": "số resp_h khác nhau", "shard_file": "file npz chứa sample", "shard_sample_index": "chỉ số sample trong file"}},
        open(OUT / "schema.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    # ---------- decoded preview: vài sample (một mỗi scenario dương) - flow raw cạnh vector đã mã hóa
    scen = w[(w.label == 1) & (w.split == "test")].groupby("scenario").head(1)
    prev = []
    for _, r in scen.iterrows():
        cand = sm[(sm.hostname == r.hostname) & (sm.window_start_epoch == r.window_start_epoch) & (sm.chunk_index == 0)]
        if cand.empty:
            continue
        c = cand.iloc[0]
        z = np.load(OUT / c.shard_file)
        i = int(c.shard_sample_index)
        a0, a1 = int(z["sample_offsets"][i]), int(z["sample_offsets"][i + 1])
        raw = con.execute(f"SELECT * FROM read_parquet('{FLOWS}') WHERE hostname = '{q(c.hostname)}' AND window_start_epoch = {int(c.window_start_epoch)} ORDER BY ts, uid LIMIT 3").df()
        flows = []
        for k_ in range(min(3, a1 - a0)):
            rowd = raw.iloc[k_].where(pd.notna(raw.iloc[k_]), None).to_dict()
            flows.append({"raw_flow": rowd, "encoded_in_shard": {"x_cat": dict(zip(cats, z["x_cat"][a0 + k_].tolist())), "x_num": dict(zip(nums, [round(float(v), 6) for v in z["x_num"][a0 + k_]])),
                                                            "x_num_missing": z["x_num_missing"][a0 + k_].tolist(), "x_bin": z["x_bin"][a0 + k_].tolist(),
                                                            "delta_t_log1p": round(float(z["delta_t_log1p"][a0 + k_]), 6)},
                          "encoded_by_python_from_spec": C.encode_flow(rowd, spec)})
        prev.append({"scenario": r.scenario, "sample": c.to_dict(), "first_flows": flows})
    json.dump(prev, open(OUT / "decoded_preview.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    size = sum(f.stat().st_size for f in (OUT / "shards").rglob("*.npz")) / 1e9
    print(json.dumps(ck, ensure_ascii=False, indent=1))
    print(f"S4 xong ({time.time() - t0:.0f}s) PASS={ck['PASS']} shards={size:.2f} GB")


if __name__ == "__main__":
    main()
