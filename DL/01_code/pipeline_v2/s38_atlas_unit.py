#!/usr/bin/env python3
"""S38a - ATLASv2 voi don vi mau moi = (may, chuong trinh, cua so 15 phut) (STEP 51).
Input : 02_artifacts/48_il_atlasv2_dataset_v1/data/{flows_atlas.parquet, windows.csv}
Output: 02_artifacts/51_il_atlas_unit_v1/data/{flows_atlas.parquet, windows.csv}
Quy tac: hostname moi = hostname_cu + '|' + app_family (s10_shards gom theo hostname+cua so => 1 mau = 1 chuong trinh trong 1 cua so).
Fold/vb THUA HUONG tu cua so goc (may, cua so) de cac chuong trinh cung cua so nam cung fold (khong tach cua so cho TRAIN/TEST).
Nhan mau = co flow duong. Chay: python s38_atlas_unit.py"""
import json
import sys
from pathlib import Path

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
SRC = ROOT / "02_artifacts/48_il_atlasv2_dataset_v1/data"
OUT = ROOT / "02_artifacts/51_il_atlas_unit_v1/data"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    f = pd.read_parquet(SRC / "flows_atlas.parquet")
    w0 = pd.read_csv(SRC / "windows.csv")[["hostname", "window_start_epoch", "fold", "vb"]].rename(columns={"hostname": "host0"})
    f["host0"] = f.hostname
    f["hostname"] = f.host0 + "|" + f.app_family.astype(str)
    f.drop(columns="host0").to_parquet(OUT / "flows_atlas.parquet", index=False)
    f["date"] = pd.to_datetime(f.ts, unit="s", utc=True).dt.strftime("%Y-%m-%d")
    w = f.groupby(["hostname", "host0", "window_start_epoch"]).agg(n_flows=("uid", "size"), n_pos=("label", "sum"), scenario=("scenario", "first"), kind=("kind", "first"), date=("date", "first")).reset_index()
    w = w.merge(w0, left_on=["host0", "window_start_epoch"], right_on=["host0", "window_start_epoch"], how="left")
    assert w.fold.notna().all()
    w["label"] = (w.n_pos > 0).astype(int)
    w = w.drop(columns="host0").sort_values(["hostname", "window_start_epoch"]).reset_index(drop=True)
    w.to_csv(OUT / "windows.csv", index=False, lineterminator="\n")
    chk = {"flows": int(len(f)), "units": int(len(w)), "units_positive": int(w.label.sum()), "units_over_512_flows": int((w.n_flows > 512).sum()),
           "positive_by_app": w[w.label == 1].hostname.str.split("|").str[1].value_counts().to_dict(),
           "fold_counts": {str(k): v for k, v in w.groupby(["fold", "label"]).size().unstack(fill_value=0).to_dict().items()},
           "val_if_fold0_test": w[(w.fold != 0) & (w.vb == 0)].groupby("label").size().to_dict(),
           "mixed_label_units_note": "unit co ca flow duong va am: %d" % int(((w.n_pos > 0) & (w.n_pos < w.n_flows)).sum())}
    json.dump(chk, open(OUT.parent / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print(json.dumps(chk, ensure_ascii=False, indent=1, default=str))


if __name__ == "__main__":
    main()
