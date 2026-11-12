#!/usr/bin/env python3
"""S36a - ATLASv2: bang netconn (STEP 40, s26_atlas_rows.py) -> bang flow cung cot voi s10_shards.py + gan fold/val theo cua so.

Input : 02_artifacts/40_why_malicious_v1/atlas/atlas_netconn_rows.csv (29,744 dong netconn; nhan REAPr theo tien trinh: label_proc)
Output: <out>/flows_atlas.parquet, <out>/windows.csv (cua so + fold + vb), <out>/checks_flows.json
Quy tac:
  - bo ACTION_CONNECTION_LISTEN va dong khong co dau xa (giong STEP 40): 29,565 flow.
  - hostname = atlas_<host>_<scenario>; ts = device_timestamp (UTC); cua so 15 phut: window_start_epoch = floor(ts/900)*900.
  - app_family = basename (chu thuong) cua process_path; image_path = process_path; proto tu netconn_protocol (tcp/udp);
    dau phan hoi (resp) = dau xa neu ket noi di ra (inbound != 1), nguoc lai = cong cuc bo.
  - nhan flow = label_proc (nhan REAPr muc tien trinh, KHONG phai nhan tung flow; firefox co ca nhan 0 va 1).
  - fold: chia TRON theo cua so (khong host-disjoint, theo yeu cau cua thay), 3 fold, phan tang: cua so duong theo scenario, cua so am theo scenario va ngay;
    vb (0..4): nhom con dung de lay VAL (VAL cua fold k = cua so co fold != k va vb == 0).
Chay: python s36_atlas_flows.py"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import v2_common as C  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
SRC = ROOT / "02_artifacts/40_why_malicious_v1/atlas/atlas_netconn_rows.csv"
OUT = ROOT / "02_artifacts/48_il_atlasv2_dataset_v1/data"
SEED = 42
K = 3
NB = 5


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    d = pd.read_csv(SRC, low_memory=False)
    n0 = len(d)
    d = d[(d.action != "ACTION_CONNECTION_LISTEN") & d.remote_ip.notna() & (d.remote_ip.astype(str).str.strip() != "")].copy()
    ts = pd.to_datetime(d.device_timestamp.str.replace(r"\.(\d{6})\d* \+0000 UTC$", r".\1", regex=True).str.replace(r" \+0000 UTC$", "", regex=True), utc=True)
    d["ts"] = ts.astype("int64") / 1e9 if str(ts.dtype).endswith("[ns, UTC]") else ts.map(pd.Timestamp.timestamp)
    inbound = d.netconn_inbound.astype(str).isin(["1.0", "1", "True"])
    resp_p = np.where(inbound, d.local_port, d.remote_port)
    resp_h = np.where(inbound, d.local_ip, d.remote_ip)
    f = pd.DataFrame({
        "uid": d.process_guid.astype(str) + "@" + d.ts.map(lambda v: f"{v:.6f}"),
        "hostname": "atlas_" + d.host.astype(str) + "_" + d.scenario.astype(str),
        "ts": d.ts.astype(float),
        "window_start_epoch": (np.floor(d.ts / 900) * 900).astype("int64"),
        "label": d.label_proc.astype("int8"),
        "app_family": d.process_path.astype(str).str.lower().str.replace("/", "\\", regex=False).str.extract(r"([^\\]*)$")[0],
        "image_path": d.process_path.astype(str),
        "proto": d.netconn_protocol.map({"PROTO_TCP": "tcp", "PROTO_UDP": "udp"}),
        "resp_h": resp_h, "resp_p": pd.Series(resp_p, index=d.index).astype("Int64"),
        "scenario": d.scenario.astype(str), "kind": d.kind.astype(str), "host": d.host.astype(str),
    }).sort_values(["ts", "uid"]).reset_index(drop=True)
    f["uid"] = f.uid + "#" + f.index.astype(str).str.zfill(6)  # uid duy nhat (cung tien trinh, cung thoi diem co the co nhieu ket noi)
    f.to_parquet(OUT / "flows_atlas.parquet", index=False)
    f["date"] = pd.to_datetime(f.ts, unit="s", utc=True).dt.strftime("%Y-%m-%d")
    w = f.groupby(["hostname", "window_start_epoch"]).agg(n_flows=("uid", "size"), n_pos=("label", "sum"), scenario=("scenario", "first"), kind=("kind", "first"), date=("date", "first")).reset_index()
    w["label"] = (w.n_pos > 0).astype(int)
    rng = np.random.default_rng(SEED)
    w["fold"] = -1
    w["vb"] = -1
    w["stratum"] = np.where(w.label == 1, "pos:" + w.scenario, "neg:" + w.scenario + ":" + w.date)
    for _, g in w.groupby("stratum", sort=True):
        idx = g.index.to_numpy()[rng.permutation(len(g))]
        w.loc[idx, "fold"] = np.arange(len(idx)) % K
        w.loc[idx, "vb"] = rng.permutation(np.arange(len(idx)) % NB)
    w = w.sort_values(["hostname", "window_start_epoch"]).reset_index(drop=True)
    w.to_csv(OUT / "windows.csv", index=False, lineterminator="\n")
    chk = {"rows_in": int(n0), "flows": int(len(f)), "flows_positive": int(f.label.sum()), "windows": int(len(w)), "windows_positive": int(w.label.sum()),
           "proto_values": f.proto.value_counts(dropna=False).to_dict(), "app_family_null": int(f.app_family.isna().sum()), "resp_p_null": int(f.resp_p.isna().sum()),
           "positive_windows_by_scenario": w[w.label == 1].groupby("scenario").size().to_dict(),
           "fold_counts": w.groupby(["fold", "label"]).size().unstack(fill_value=0).to_dict(),
           "val_counts_if_fold0_is_test": w[(w.fold != 0) & (w.vb == 0)].groupby("label").size().to_dict(),
           "ts_min": float(f.ts.min()), "ts_max": float(f.ts.max()), "seed": SEED, "folds": K, "val_buckets": NB}
    json.dump(chk, open(OUT.parent / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(chk, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
