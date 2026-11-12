#!/usr/bin/env python3
"""Kiểm tra file dự đoán nhánh host trước khi gửi cho Lâm.

Cách chạy (đặt cạnh host_split_seed1.csv và eval_windows_seed1.csv):
    python check_submission.py --pred event_predictions.csv

Kiểm tra: đủ cột, prob nằm trong [0,1], host chỉ thuộc val/test theo đúng host_split_seed1.csv,
mỗi cửa sổ trong eval_windows_seed1.csv có bao nhiêu event được chấm điểm.
"""
import argparse
import sys

import pandas as pd

REQ = ["hostname", "timestamp", "split", "model", "prob", "pred", "label"]


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", required=True)
    ap.add_argument("--split", default="host_split_seed1.csv")
    ap.add_argument("--windows", default="eval_windows_seed1.csv")
    a = ap.parse_args()
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(("[PASS] " if cond else "[FAIL] ") + name + (f" | {detail}" if detail else ""))
        ok = ok and bool(cond)

    p = pd.read_csv(a.pred)
    check("đủ cột " + ",".join(REQ), all(c in p.columns for c in REQ), f"cột hiện có: {list(p.columns)}")
    if not all(c in p.columns for c in REQ):
        sys.exit(1)
    p["hostname"] = p["hostname"].str.lower().str.replace(".systemia.com", "", regex=False)
    check("prob trong [0,1], không rỗng", p["prob"].between(0, 1).all(), f"min={p.prob.min():.4g} max={p.prob.max():.4g}")
    check("label chỉ gồm 0/1", set(p["label"].dropna().unique()) <= {0, 1})
    sp = pd.read_csv(a.split).set_index("hostname")["split"]
    exp = p["hostname"].map(sp)
    check("mọi host nằm trong host_split_seed1.csv", exp.notna().all(), f"{(~exp.notna()).sum()} dòng có host lạ")
    check("cột split khớp host_split_seed1.csv", (exp == p["split"]).all(), f"{(exp != p['split']).sum()} dòng sai split")
    check("không có host TRAIN trong file dự đoán", (p["split"] != "train").all())
    t = pd.to_datetime(p["timestamp"], utc=True, errors="coerce")
    check("timestamp đọc được và có múi giờ", t.notna().all(), f"{t.isna().sum()} dòng lỗi")
    p["start"] = ((t.dt.floor("15min") - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()).astype("int64")
    w = pd.read_csv(a.windows)
    cnt = p.groupby(["hostname", "start"]).size().rename("n_events_cham")
    w = w.merge(cnt, left_on=["hostname", "window_start_epoch_utc"], right_index=True, how="left").fillna({"n_events_cham": 0})
    cover = (w["n_events_cham"] > 0).mean()
    check("phủ ≥ 95% cửa sổ trong eval_windows_seed1.csv", cover >= 0.95, f"phủ {cover:.1%}; cửa sổ thiếu: {(w.n_events_cham == 0).sum()}/{len(w)}")
    print(w.groupby(["split", "kind"]).agg(cua_so=("hostname", "count"), co_diem=("n_events_cham", lambda s: int((s > 0).sum())),
                                          event_cham=("n_events_cham", "sum")).to_string())
    print("\nKẾT QUẢ:", "ĐẠT" if ok else "CHƯA ĐẠT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
