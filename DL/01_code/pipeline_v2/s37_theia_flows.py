#!/usr/bin/env python3
"""S37a - THEIA (DARPA TC E3, tep 6r): bang flow cho s10_shards.py + gan fold/val theo cua so (STEP 49).

Input : 02_artifacts/40_why_malicious_v1/theia/{net_agg.csv, subjects_all.csv, exec_by_subject.csv} (s27_theia_why.py; da doc raw THEIA 6r, nhan REAPr)
Output: <out>/flows_theia.parquet, <out>/windows.csv, <out>/checks_flows.json
Quy tac:
  - 1 flow = 1 khoa (Subject, NetFlowObject co dau xa that) = 226,692 flow; ts = thoi diem su kien mang dau tien (UTC).
  - app_family = ten chuong trinh tu EVENT_EXECUTE cuoi cung cua subject (token dau cua cmdLine, lay basename); neu subject khong co EXECUTE thi dung basename cua Subject.path (ten luc fork).
    image_path = token dau cua EXECUTE neu la duong dan tuyet doi, nguoc lai Subject.path neu bat dau bang '/', nguoc lai ten chuong trinh.
  - proto = rong (THEIA khong co ipProtocol) => <MISSING>; resp_h/resp_p tu remoteAddress:remotePort.
  - nhan flow = 1 neu khoa co canh co nhan REAPr (Event.uuid) hoac Subject co nhan REAPr (nhan muc tien trinh/canh, khong phai nhan tung flow).
  - hostname = theia_host (mot may); cua so 15 phut; fold/vb tinh theo cua so nhu s36_atlas_flows.py (3 fold, 5 nhom VAL, seed 42); cua so duong phan tang theo ngay, cua so am theo ngay.
Chay: python s37_theia_flows.py"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
SRC = ROOT / "02_artifacts/40_why_malicious_v1/theia"
OUT = ROOT / "02_artifacts/49_il_theia_dataset_v1/data"
SEED = 42
K = 3
NB = 5


def prog_token(c):
    t = str(c).strip().split(" ")[0] if str(c).strip() else ""
    return t


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    net = pd.read_csv(SRC / "net_agg.csv")
    sub = pd.read_csv(SRC / "subjects_all.csv", low_memory=False).fillna("").drop_duplicates("uuid").set_index("uuid")
    ex = pd.read_csv(SRC / "exec_by_subject.csv", low_memory=False).fillna("")
    ex["ts_ns"] = pd.to_numeric(ex.ts_ns, errors="coerce")
    last_exec = ex.sort_values("ts_ns").groupby("subject").cmdline.last()
    sub["exec_tok"] = last_exec.reindex(sub.index).fillna("").map(prog_token)
    net["exec_tok"] = net.subject.map(sub.exec_tok).fillna("")
    net["fork_path"] = net.subject.map(sub.subj_path).fillna("").astype(str)
    prog = net.exec_tok.where(net.exec_tok != "", net.fork_path).astype(str)
    app = prog.str.replace("\\", "/", regex=False).str.split("/").str[-1].str.lower()
    img = np.where(net.exec_tok.str.startswith("/"), net.exec_tok, np.where(net.fork_path.str.startswith("/"), net.fork_path, prog))
    pos = (net.n_labeled_events > 0) | net.subject.isin(sub.index[sub.label_subject != ""])
    ra = net.remote.str.rsplit(":", n=1)
    ts = net.first_ts_ns.astype("float64") / 1e9
    f = pd.DataFrame({
        "uid": net.subject.astype(str) + "|" + net.netflow.astype(str),
        "hostname": "theia_host", "ts": ts, "window_start_epoch": (np.floor(ts / 900) * 900).astype("int64"),
        "label": pos.astype("int8"), "app_family": app, "image_path": img, "proto": None,
        "resp_h": ra.str[0], "resp_p": pd.to_numeric(ra.str[1], errors="coerce").astype("Int64"),
        "n_events": net.n_events.astype(int), "exec_found": (net.exec_tok != "").astype(int),
    }).sort_values(["ts", "uid"]).reset_index(drop=True)
    f.to_parquet(OUT / "flows_theia.parquet", index=False)
    f["date"] = pd.to_datetime(f.ts, unit="s", utc=True).dt.strftime("%Y-%m-%d")
    w = f.groupby(["hostname", "window_start_epoch"]).agg(n_flows=("uid", "size"), n_pos=("label", "sum"), date=("date", "first")).reset_index()
    w["label"] = (w.n_pos > 0).astype(int)
    w["scenario"] = "theia_" + w.date
    w["kind"] = np.where(w.label == 1, "attack", "benign")
    rng = np.random.default_rng(SEED)
    w["fold"] = -1
    w["vb"] = -1
    w["stratum"] = np.where(w.label == 1, "pos:", "neg:") + w.date
    for _, g in w.groupby("stratum", sort=True):
        idx = g.index.to_numpy()[rng.permutation(len(g))]
        w.loc[idx, "fold"] = np.arange(len(idx)) % K
        w.loc[idx, "vb"] = rng.permutation(np.arange(len(idx)) % NB)
    w = w.sort_values(["hostname", "window_start_epoch"]).reset_index(drop=True)
    w.to_csv(OUT / "windows.csv", index=False, lineterminator="\n")
    chk = {"flows": int(len(f)), "flows_positive": int(f.label.sum()), "windows": int(len(w)), "windows_positive": int(w.label.sum()),
           "windows_over_512_flows": int((w.n_flows > 512).sum()), "max_flows_per_window": int(w.n_flows.max()),
           "exec_found_share_all": round(float(f.exec_found.mean()), 4), "exec_found_share_positive": round(float(f[f.label == 1].exec_found.mean()), 4),
           "positive_windows_by_day": w[w.label == 1].groupby("date").size().to_dict(), "app_family_null": int((f.app_family == "").sum()),
           "top_app_family": f.app_family.value_counts().head(10).to_dict(), "top_app_family_positive": f[f.label == 1].app_family.value_counts().head(10).to_dict(),
           "image_dir_values": {k: int(v) for k, v in pd.Series([__import__("v2_common").image_dir_class(p) for p in f.image_path.drop_duplicates()]).value_counts().items()} if False else None,
           "fold_window_counts": w.groupby(["fold", "label"]).size().unstack(fill_value=0).to_dict(),
           "val_windows_fold0_test": w[(w.fold != 0) & (w.vb == 0)].groupby("label").size().to_dict(), "seed": SEED}
    json.dump(chk, open(OUT.parent / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print(json.dumps(chk, ensure_ascii=False, indent=1, default=str))


if __name__ == "__main__":
    main()
