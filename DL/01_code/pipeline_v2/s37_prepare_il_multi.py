#!/usr/bin/env python3
"""S37b - Dung goi Kaggle IL OpTC -> {ATLASv2, THEIA} (STEP 49): tu dien mo rong theo fold tren TRAIN cua CA HAI mien, shards tung mien, fold/val, replay OpTC that, mo hinh goc.

Input : 02_artifacts/48_il_atlasv2_dataset_v1/data/{flows_atlas.parquet, windows.csv} (s36_atlas_flows.py) va 02_artifacts/49_il_theia_dataset_v1/data/{flows_theia.parquet, windows.csv} (s37_theia_flows.py);
        preprocess_spec.json (OpTC); S4 samples.csv (replay); 05_models/v2_subsetB.
Output: 03_datasets/il_atlas_theia_kaggle_upload/ : ft_manifest.json, folds.csv, replay_R.csv, base_models/..., fold<k>/spec_ext.json, fold<k>/<mien>/{data/samples.csv, shards/test/*.npz}
Quy tac: tu dien mo rong tren cua so TRAIN cua fold (khong gom VAL, TEST); gia tri chua co va >= 5 flow (gop hai mien) duoc them voi id noi tiep; THEIA dung lop thu muc Linux cua v2_common.image_dir_class.
Chay: python s37_prepare_il_multi.py"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
import s14_prepare_ft as P  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
ROOT = P.ROOT
A = ROOT / "02_artifacts"
DOMAINS = {
    "atlasv2": {"flows": A / "48_il_atlasv2_dataset_v1/data/flows_atlas.parquet", "windows": A / "48_il_atlasv2_dataset_v1/data/windows.csv"},
    "theia": {"flows": A / "49_il_theia_dataset_v1/data/flows_theia.parquet", "windows": A / "49_il_theia_dataset_v1/data/windows.csv"},
}
OUT = ROOT / "03_datasets/il_atlas_theia_kaggle_upload"
K = 3


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    base = json.load(open(P.SPEC, encoding="utf-8"))
    win, fl = {}, {}
    for ds, d in DOMAINS.items():
        win[ds] = pd.read_csv(d["windows"])[["hostname", "window_start_epoch", "label", "fold", "vb", "scenario", "kind"]]
        f = pd.read_parquet(d["flows"]).merge(win[ds][["hostname", "window_start_epoch", "fold", "vb"]], on=["hostname", "window_start_epoch"], how="left")
        assert f.fold.notna().all(), ds
        fl[ds] = f
    summary = {"folds": K, "fold_sizes": {}, "added_tokens": {}, "shards": {}}
    samples_ref = {}
    for k in range(K):
        fdir = OUT / f"fold{k}"
        fdir.mkdir()
        tr = pd.concat([f[(f.fold != k) & (f.vb != 0)][["app_family", "proto", "resp_p", "image_path"]] for f in fl.values()], ignore_index=True)
        spec, added = P.build_ext_spec(base, tr, k)
        spec_path = fdir / "spec_ext.json"
        json.dump(spec, open(spec_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        summary["added_tokens"][f"fold{k}"] = {f: [e["value"] for e in v] for f, v in added.items()}
        for ds, d in DOMAINS.items():
            dest = fdir / ds
            cmd = [str(P.PY), str(P.SHARDS_SCRIPT), "--flows", str(d["flows"]), "--out", str(dest), "--name", ds, "--spec", str(spec_path)]
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            ck = json.load(open(dest / "checks.json", encoding="utf-8"))
            assert ck["PASS"], (k, ds, r.stdout[-800:], r.stderr[-800:])
            sm = pd.read_csv(dest / "data/samples.csv")
            if ds not in samples_ref:
                samples_ref[ds] = sm[["sample_id", "hostname", "window_start_epoch", "label", "event_count"]].copy()
            else:
                assert (samples_ref[ds].sample_id.to_numpy() == sm.sample_id.to_numpy()).all(), "sample_id khong on dinh"
            for sub in ("data/flows_norm.parquet", "split", "preprocessing"):
                p = dest / sub
                if p.is_dir():
                    shutil.rmtree(p)
                elif p.exists():
                    p.unlink()
            summary["shards"][f"fold{k}/{ds}"] = {"samples": ck["samples"], "positive_samples": ck["positive_samples"], "share_unk_app_family": ck["share_unk_by_field"]["app_family"],
                                                  "share_unk_image_dir_class": ck["share_unk_by_field"]["image_dir_class"], "share_unk_resp_port": ck["share_unk_by_field"]["resp_port_class"]}
            print(f"fold{k}/{ds}: {ck['samples']} sample ({ck['positive_samples']} duong), UNK app {ck['share_unk_by_field']['app_family']}, UNK dir {ck['share_unk_by_field']['image_dir_class']}", flush=True)
    parts = []
    for ds in DOMAINS:
        m = samples_ref[ds].merge(win[ds][["hostname", "window_start_epoch", "fold", "vb", "scenario", "kind"]], on=["hostname", "window_start_epoch"], how="left")
        assert m.fold.notna().all()
        m["fold"] = m.fold.astype(int)
        m["vb"] = m.vb.astype(int)
        m.insert(0, "dataset", ds)
        parts.append(m)
    folds = pd.concat(parts, ignore_index=True)
    folds[["dataset", "sample_id", "label", "fold", "vb", "hostname", "window_start_epoch", "scenario", "kind", "event_count"]].to_csv(OUT / "folds.csv", index=False, lineterminator="\n")
    for k in range(K):
        fs = {}
        for ds in DOMAINS:
            g = folds[folds.dataset == ds]
            te, rest = g[g.fold == k], g[g.fold != k]
            va, trn = rest[rest.vb == 0], rest[rest.vb != 0]
            fs[ds] = {"train": [int(len(trn)), int(trn.label.sum())], "val": [int(len(va)), int(va.label.sum())], "test": [int(len(te)), int(te.label.sum())]}
        summary["fold_sizes"][f"fold{k}"] = fs
    s4 = pd.read_csv(P.V2 / "S4_shards/data/samples.csv")
    trn = s4[s4.split == "train"]
    pos, neg = trn[trn.label == 1], trn[trn.label == 0]
    rng = np.random.default_rng(P.REPLAY_SEED)
    take = ((neg.groupby("date").size() / len(neg)) * P.REPLAY_NEG).round().astype(int)
    rp = []
    for date, n in take.items():
        g = neg[neg.date == date]
        rp.append(g.iloc[rng.permutation(len(g))[:n]])
    rep = pd.concat([pos] + rp, ignore_index=True)
    rep[["sample_id", "date", "hostname", "label", "event_count", "shard_file", "shard_sample_index"]].to_csv(OUT / "replay_R.csv", index=False, lineterminator="\n")
    summary["replay_R"] = {"positive": int((rep.label == 1).sum()), "negative": int((rep.label == 0).sum()), "events": int(rep.event_count.sum()), "source": "OpTC v2 TRAIN that (S4 shards)"}
    for tag, src in P.MODELS.items():
        d = OUT / "base_models" / tag
        d.mkdir(parents=True)
        for fn in ("best_model.pt", "config.json", "threshold.json", "metrics.json"):
            shutil.copy(src / fn, d / fn)
    man = {"version": "il-atlas-theia-package-1", "folds": K, "base_spec_fingerprint": base["fingerprint_sha256"], "ext_fields": list(P.EXT_FIELDS), "min_flows_new_token": P.MIN_FLOWS,
           "replay": {"positive_all": True, "negative": P.REPLAY_NEG, "seed": P.REPLAY_SEED}, "domains": list(DOMAINS), "seed_split": 42, "val_bucket": 0, "summary": summary,
           "base_model_sha256": {t: P.sha256(P.MODELS[t] / "best_model.pt") for t in P.MODELS},
           "note": "Di cung goi OpTC v2 (v2_network_dl_kaggle_upload) tren Kaggle. Nhan la nhan REAPr muc tien trinh/canh. THEIA: proto rong (<MISSING>), ten chuong trinh chu yeu tu Subject.path."}
    json.dump(man, open(OUT / "ft_manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    size = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file()) / 1e6
    print(json.dumps(summary["fold_sizes"], ensure_ascii=False))
    print({k: v for k, v in summary["added_tokens"].items()})
    print(f"goi: {OUT} ({size:.1f} MB)")


if __name__ == "__main__":
    main()
