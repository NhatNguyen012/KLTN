#!/usr/bin/env python3
"""S36b - Dung goi Kaggle fine-tune/IL cho ATLASv2 (STEP 48): tu dien mo rong theo fold, shards, fold/val, replay OpTC that, mo hinh goc.

Input : 02_artifacts/48_il_atlasv2_dataset_v1/data/{flows_atlas.parquet, windows.csv} (s36_atlas_flows.py); preprocess_spec.json (OpTC);
        S4 samples.csv (OpTC, dung cho replay); 05_models/v2_subsetB/{bilstm,mixed}_v2_subsetB (mo hinh goc).
Output: 03_datasets/il_atlasv2_kaggle_upload/ : ft_manifest.json, folds.csv, replay_R.csv, base_models/<mo hinh>/..., fold<k>/spec_ext.json, fold<k>/atlasv2/{data/samples.csv, shards/test/test_0000.npz}
Quy tac: tu dien mo rong tren cua so TRAIN cua fold (khong gom VAL, TEST); gia tri chua co va >= 5 flow duoc them voi id noi tiep (app_family tu 61, image_dir_class tu 10).
Replay OpTC: cung quy tac STEP 30 (toan bo cua so duong TRAIN + 1600 cua so am TRAIN, phan theo ngay) lay tu shards OpTC that (khong tong hop).
Chay: python s36_prepare_il_atlas.py"""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import s14_prepare_ft as P  # noqa: E402  (dung lai build_ext_spec, sha256, hang so)

sys.stdout.reconfigure(encoding="utf-8")
ROOT = P.ROOT
DATA = ROOT / "02_artifacts/48_il_atlasv2_dataset_v1/data"
OUT = ROOT / "03_datasets/il_atlasv2_kaggle_upload"
DS = "atlasv2"
K = 3


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    base = json.load(open(P.SPEC, encoding="utf-8"))
    flows = pd.read_parquet(DATA / "flows_atlas.parquet")
    win = pd.read_csv(DATA / "windows.csv")[["hostname", "window_start_epoch", "label", "fold", "vb", "scenario", "kind"]]
    fl = flows.merge(win[["hostname", "window_start_epoch", "fold", "vb"]], on=["hostname", "window_start_epoch"], how="left")
    assert fl.fold.notna().all()
    summary = {"folds": K, "fold_sizes": {}, "added_tokens": {}, "shards": {}}
    samples_ref = None
    for k in range(K):
        fdir = OUT / f"fold{k}"
        fdir.mkdir()
        tr = fl[(fl.fold != k) & (fl.vb != 0)]  # TRAIN = khong thuoc fold test va khong thuoc VAL
        spec, added = P.build_ext_spec(base, tr[["app_family", "proto", "resp_p", "image_path"]], k)
        spec_path = fdir / "spec_ext.json"
        json.dump(spec, open(spec_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        summary["added_tokens"][f"fold{k}"] = {f: [e["value"] for e in v] for f, v in added.items()}
        dest = fdir / DS
        cmd = [str(P.PY), str(P.SHARDS_SCRIPT), "--flows", str(DATA / "flows_atlas.parquet"), "--out", str(dest), "--name", DS, "--spec", str(spec_path)]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        ck = json.load(open(dest / "checks.json", encoding="utf-8"))
        assert ck["PASS"], (k, r.stdout[-800:], r.stderr[-800:])
        sm = pd.read_csv(dest / "data/samples.csv")
        if samples_ref is None:
            samples_ref = sm[["sample_id", "hostname", "window_start_epoch", "label", "event_count"]].copy()
        else:
            assert (samples_ref.sample_id.to_numpy() == sm.sample_id.to_numpy()).all(), "sample_id khong on dinh giua cac fold"
        for sub in ("data/flows_norm.parquet", "split", "preprocessing"):
            p = dest / sub
            if p.is_dir():
                shutil.rmtree(p)
            elif p.exists():
                p.unlink()
        summary["shards"][f"fold{k}"] = {"samples": ck["samples"], "positive_samples": ck["positive_samples"], "share_unk_by_field": ck["share_unk_by_field"]}
        print(f"fold{k}: {ck['samples']} sample, UNK {ck['share_unk_by_field']}, token moi { {f: len(v) for f, v in added.items()} }", flush=True)
    folds = samples_ref.merge(win[["hostname", "window_start_epoch", "fold", "vb", "scenario", "kind"]], on=["hostname", "window_start_epoch"], how="left")
    assert folds.fold.notna().all()
    folds["fold"] = folds.fold.astype(int)
    folds["vb"] = folds.vb.astype(int)
    folds.insert(0, "dataset", DS)
    folds[["dataset", "sample_id", "label", "fold", "vb", "hostname", "window_start_epoch", "scenario", "kind", "event_count"]].to_csv(OUT / "folds.csv", index=False, lineterminator="\n")
    for k in range(K):
        te = folds[folds.fold == k]
        rest = folds[folds.fold != k]
        va = rest[rest.vb == 0]
        trn = rest[rest.vb != 0]
        summary["fold_sizes"][f"fold{k}"] = {"train_samples": int(len(trn)), "train_positive": int(trn.label.sum()), "val_samples": int(len(va)), "val_positive": int(va.label.sum()),
                                             "test_samples": int(len(te)), "test_positive": int(te.label.sum())}
    # replay OpTC (that)
    s4 = pd.read_csv(P.V2 / "S4_shards/data/samples.csv")
    trn = s4[s4.split == "train"]
    pos, neg = trn[trn.label == 1], trn[trn.label == 0]
    rng = np.random.default_rng(P.REPLAY_SEED)
    take = ((neg.groupby("date").size() / len(neg)) * P.REPLAY_NEG).round().astype(int)
    parts = []
    for date, n in take.items():
        g = neg[neg.date == date]
        parts.append(g.iloc[rng.permutation(len(g))[:n]])
    rep = pd.concat([pos] + parts, ignore_index=True)
    rep[["sample_id", "date", "hostname", "label", "event_count", "shard_file", "shard_sample_index"]].to_csv(OUT / "replay_R.csv", index=False, lineterminator="\n")
    summary["replay_R"] = {"positive": int((rep.label == 1).sum()), "negative": int((rep.label == 0).sum()), "events": int(rep.event_count.sum()), "source": "OpTC v2 TRAIN that (S4 shards)"}
    for tag, src in P.MODELS.items():
        d = OUT / "base_models" / tag
        d.mkdir(parents=True)
        for fn in ("best_model.pt", "config.json", "threshold.json", "metrics.json"):
            shutil.copy(src / fn, d / fn)
    man = {"version": "il-atlasv2-package-1", "folds": K, "base_spec_fingerprint": base["fingerprint_sha256"], "ext_fields": list(P.EXT_FIELDS), "min_flows_new_token": P.MIN_FLOWS,
           "replay": {"positive_all": True, "negative": P.REPLAY_NEG, "seed": P.REPLAY_SEED}, "domains": [DS], "seed_split": 42, "val_bucket": 0,
           "summary": summary, "base_model_sha256": {t: P.sha256(P.MODELS[t] / "best_model.pt") for t in P.MODELS},
           "note": "Di cung goi OpTC v2 (v2_network_dl_kaggle_upload) tren Kaggle: replay va danh gia OpTC TEST doc shards cua goi v2. Nhan ATLASv2 la nhan REAPr muc tien trinh."}
    json.dump(man, open(OUT / "ft_manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    size = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file()) / 1e6
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:3500])
    print(f"goi: {OUT} ({size:.1f} MB)")


if __name__ == "__main__":
    main()
