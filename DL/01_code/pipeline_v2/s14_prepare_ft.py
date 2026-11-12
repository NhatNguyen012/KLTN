#!/usr/bin/env python3
"""S14a - Dựng gói dữ liệu fine-tune cho Kaggle (STEP 30): từ điển mở rộng theo fold, shards hai miền Windows, tập replay OpTC, mô hình gốc, dự đoán zero-shot tham chiếu.

Input : STEP 25 (skrghosh) và STEP 29 (FiveDirections): flows_norm.parquet + samples.csv; fold_assignment_both_<K>fold.csv (STEP 30); preprocess_spec.json (OpTC); S4 samples.csv (OpTC);
        05_models/v2_subsetB/{bilstm,mixed}_v2_subsetB (mô hình gốc); dự đoán zero-shot STEP 26 và 29.
Output: 03_datasets/v3_ft_kaggle_upload/ (gói nhỏ, không có dataset_manifest.json để không lẫn với gói OpTC v2):
        ft_manifest.json, folds.csv, replay_R.csv, base_models/<mô hình>/{best_model.pt,config.json,threshold.json}, ref_zeroshot/predictions_<bộ>_<mô hình>.csv,
        fold<k>/spec_ext.json, fold<k>/<bộ>/{data/samples.csv, shards/test/test_0000.npz}
Quy tắc mở rộng từ điển (chỉ nối thêm, giữ id OpTC): trên các cửa sổ TRAIN của fold, giá trị chưa có trong từ điển OpTC và có >= 5 flow được thêm với id nối tiếp (xếp theo số flow giảm dần, rồi theo tên).
Không dùng cửa sổ test của fold để chọn token. Cột đầu vào, thứ tự cột và các id cũ giữ nguyên.
Chạy: python s14_prepare_ft.py --folds 3"""
import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import v2_common as C  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
A = ROOT / "02_artifacts"
V2 = A / "22_v2_pipeline"
SPEC = V2 / "S3_preprocess/data/preprocess_spec.json"
OUT = ROOT / "03_datasets/v3_ft_kaggle_upload"
PY = ROOT / ".venv-host/Scripts/python.exe"
SHARDS_SCRIPT = Path(__file__).parent / "s10_shards.py"
DOMAINS = {
    "skrghosh": {"flows": A / "25_newdataset_preprocess_v1/skrghosh/data/flows_norm.parquet", "samples": A / "25_newdataset_preprocess_v1/skrghosh/data/samples.csv",
                 "flows_src": A / "25_newdataset_preprocess_v1/skrghosh/data/flows_norm.parquet", "ref": A / "26_newdataset_eval_v1"},
    "fivedirections": {"flows": A / "29_fivedirections_analysis_v1/data/flows_fd.parquet", "samples": A / "29_fivedirections_analysis_v1/fivedirections/data/samples.csv",
                       "ref": A / "29_fivedirections_analysis_v1/eval_zeroshot"},
}
MODELS = {"bilstm": ROOT / "05_models/v2_subsetB/bilstm_v2_subsetB", "mixed": ROOT / "05_models/v2_subsetB/mixed_v2_subsetB"}
EXT_FIELDS = ("app_family", "proto", "resp_port_class", "image_dir_class")
MIN_FLOWS = 5
REPLAY_POS_ALL = True
REPLAY_NEG = 1600
REPLAY_SEED = 20261022


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def norm_text(v):
    return "<MISSING>" if v is None or (isinstance(v, float) and np.isnan(v)) or str(v).strip().lower() in C.MISSING_TOKENS else str(v).strip().lower()


def field_values(df, field):
    """Giá trị category (chưa mã hóa id) của một trường, cùng quy tắc với v2_common.cat_value."""
    if field == "app_family":
        return df["app_family"].map(norm_text)
    if field == "proto":
        return df["proto"].map(norm_text)
    if field == "resp_port_class":
        return df["resp_p"].map(lambda p: C.port_class(None if pd.isna(p) else int(p)))
    if field == "image_dir_class":
        return df["image_path"].map(C.image_dir_class)
    raise ValueError(field)


def build_ext_spec(base, train_flows, fold):
    spec = copy.deepcopy(base)
    added = {}
    for f in EXT_FIELDS:
        fld = spec["categorical"]["fields"][f]
        known = {e["value"] for e in fld["vocab"]}
        next_id = max(e["id"] for e in fld["vocab"]) + 1
        vals = field_values(train_flows, f)
        cnt = vals[~vals.isin(known) & (vals != "<MISSING>")].value_counts()
        cnt = cnt[cnt >= MIN_FLOWS]
        new = sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))
        added[f] = []
        for v, n in new:
            fld["vocab"].append({"value": v, "id": next_id, "train_count": int(n), "source": f"finetune_fold{fold}"})
            added[f].append({"value": v, "id": next_id, "train_flows": int(n)})
            next_id += 1
    spec["version"] = base["version"] + f"+ft-ext-fold{fold}"
    spec["extension"] = {"base_fingerprint_sha256": base["fingerprint_sha256"], "fold": fold, "min_flows": MIN_FLOWS, "added": added,
                         "note": "chỉ nối thêm token từ cửa sổ TRAIN của fold; id cũ không đổi; hàng embedding mới khởi tạo bằng bản sao <UNK>"}
    spec["fingerprint_sha256"] = hashlib.sha256(json.dumps(spec["categorical"], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return spec, added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds", type=int, default=3)
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    out = Path(a.out)
    K = a.folds
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    base = json.load(open(SPEC, encoding="utf-8"))
    fold_file = A / f"30_finetune_design_final_v1/fold_assignment_both_{K}fold.csv"
    folds = pd.read_csv(fold_file)
    folds[["dataset", "sample_id", "fold", "label"]].to_csv(out / "folds.csv", index=False, lineterminator="\n")
    con = duckdb.connect()
    # cửa sổ -> fold cho từng bộ
    win_fold = {}
    for ds, d in DOMAINS.items():
        sm = pd.read_csv(d["samples"])[["sample_id", "hostname", "window_start_epoch"]]
        m = sm.merge(folds[folds.dataset == ds][["sample_id", "fold"]], on="sample_id")
        assert len(m) == len(sm) == (folds.dataset == ds).sum(), ds
        win_fold[ds] = m.groupby(["hostname", "window_start_epoch"]).fold.first().reset_index()
    summary = {"folds": K, "fold_sizes": {}, "added_tokens": {}, "shards": {}}
    flows_by_ds = {ds: con.execute(f"SELECT * FROM read_parquet('{d['flows'].as_posix()}')").df() for ds, d in DOMAINS.items()}
    for k in range(K):
        fdir = out / f"fold{k}"
        fdir.mkdir()
        train_parts = []
        for ds, df in flows_by_ds.items():
            wf = win_fold[ds]
            tr = df.merge(wf[wf.fold != k][["hostname", "window_start_epoch"]], on=["hostname", "window_start_epoch"])
            train_parts.append(tr[["app_family", "proto", "resp_p", "image_path"]])
        spec, added = build_ext_spec(base, pd.concat(train_parts, ignore_index=True), k)
        spec_path = fdir / "spec_ext.json"
        json.dump(spec, open(spec_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        summary["added_tokens"][f"fold{k}"] = {f: [e["value"] for e in v] for f, v in added.items()}
        summary["fold_sizes"][f"fold{k}"] = {"train_samples": int((folds.fold != k).sum()), "train_positive": int(folds[folds.fold != k].label.sum()),
                                             "test_samples": int((folds.fold == k).sum()), "test_positive": int(folds[folds.fold == k].label.sum())}
        for ds, d in DOMAINS.items():
            dest = fdir / ds
            flows_pq = d["flows"]
            cmd = [str(PY), str(SHARDS_SCRIPT), "--flows", str(flows_pq), "--out", str(dest), "--name", ds, "--spec", str(spec_path)]
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            ck = json.load(open(dest / "checks.json", encoding="utf-8"))
            assert ck["PASS"], (k, ds, r.stdout[-800:], r.stderr[-800:])
            # chỉ giữ cái cần cho Kaggle
            for sub in ("data/flows_norm.parquet", "split", "preprocessing"):
                p = dest / sub
                if p.is_dir():
                    shutil.rmtree(p)
                elif p.exists():
                    p.unlink()
            summary["shards"][f"fold{k}/{ds}"] = {"samples": ck["samples"], "positive_samples": ck["positive_samples"], "share_unk_app_family": ck["share_unk_by_field"]["app_family"],
                                                  "share_unk_resp_port": ck["share_unk_by_field"]["resp_port_class"]}
            print(f"fold{k}/{ds}: {ck['samples']} sample, UNK app {ck['share_unk_by_field']['app_family']}", flush=True)
    # tập replay OpTC
    s4 = pd.read_csv(V2 / "S4_shards/data/samples.csv")
    tr = s4[s4.split == "train"]
    pos = tr[tr.label == 1]
    neg = tr[tr.label == 0]
    rng = np.random.default_rng(REPLAY_SEED)
    share = neg.groupby("date").size() / len(neg)
    take = (share * REPLAY_NEG).round().astype(int)
    parts = []
    for date, n in take.items():
        g = neg[neg.date == date]
        parts.append(g.iloc[rng.permutation(len(g))[:n]])
    rep = pd.concat([pos] + parts, ignore_index=True)
    rep[["sample_id", "date", "hostname", "label", "event_count", "shard_file", "shard_sample_index"]].to_csv(out / "replay_R.csv", index=False, lineterminator="\n")
    summary["replay_R"] = {"positive": int((rep.label == 1).sum()), "negative": int((rep.label == 0).sum()), "events": int(rep.event_count.sum())}
    # mô hình gốc và dự đoán zero-shot tham chiếu
    for tag, src in MODELS.items():
        d = out / "base_models" / tag
        d.mkdir(parents=True)
        for fn in ("best_model.pt", "config.json", "threshold.json", "metrics.json"):
            shutil.copy(src / fn, d / fn)
    (out / "ref_zeroshot").mkdir()
    for ds, d in DOMAINS.items():
        for tag in MODELS:
            shutil.copy(d["ref"] / f"predictions_{ds}_{tag}.csv", out / "ref_zeroshot" / f"predictions_{ds}_{tag}.csv")
    man = {"version": "v3-finetune-package-1", "folds": K, "base_spec_fingerprint": base["fingerprint_sha256"], "ext_fields": list(EXT_FIELDS), "min_flows_new_token": MIN_FLOWS,
           "replay": {"positive_all": True, "negative": REPLAY_NEG, "seed": REPLAY_SEED}, "domains": list(DOMAINS), "summary": summary,
           "base_model_sha256": {t: sha256(MODELS[t] / "best_model.pt") for t in MODELS},
           "note": "Gói này đi cùng gói OpTC v2 (v2_network_dl_kaggle_upload) khi chạy trên Kaggle: replay và đánh giá OpTC TEST đọc shards của gói v2."}
    json.dump(man, open(out / "ft_manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file()) / 1e6
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:3500])
    print(f"gói: {out} ({size:.1f} MB)")


if __name__ == "__main__":
    main()
