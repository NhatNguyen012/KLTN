#!/usr/bin/env python3
"""S6b - ĐÓNG GÓI Kaggle: dựng thư mục upload từ S1-S5 (không sửa S1-S5).

Bố cục giống bản cũ để notebook 06d/07d (giữ nguyên mã mô hình) chạy được:
  loose : dataset_manifest.json, build_config.json, README_DATASET.md
  zip   : shards.zip (shards/{train,val,test}/*.npz), split.zip (split/network_sample_manifest.csv + split/windows.csv),
          preprocessing.zip (4 file định dạng cũ do script này SINH TỪ preprocess_spec.json + bản gốc preprocess_spec.json và vocab.csv),
          integrity.zip (checks.json của S1-S5, split_summary.json)
Chỉ chạy khi S5 PASS.
"""
import hashlib
import json
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
OUT = ROOT / "03_datasets/v2_network_dl_kaggle_upload"
STAGE = V2 / "_work/package_stage"


def main():
    t0 = time.time()
    assert json.load(open(V2 / "S5_validate/checks.json", encoding="utf-8"))["PASS"], "S5 chưa PASS"
    if OUT.exists():
        raise FileExistsError(f"{OUT} đã tồn tại; không ghi đè")
    spec = json.load(open(V2 / "S3_preprocess/data/preprocess_spec.json", encoding="utf-8"))
    fp = spec["fingerprint_sha256"]
    sm = pd.read_csv(V2 / "S4_shards/data/samples.csv")
    if STAGE.exists():
        shutil.rmtree(STAGE)
    (STAGE / "preprocessing").mkdir(parents=True)
    (STAGE / "split").mkdir()
    (STAGE / "integrity").mkdir()
    # ---- định dạng cũ cho mã mô hình
    cats = spec["model_input_layout"]["x_cat_columns"]
    nums = spec["model_input_layout"]["x_num_columns"]
    fields = {}
    for f, v in spec["categorical"]["fields"].items():
        mp = {"<UNK>": 0, "<MISSING>": 1}
        mp.update({e["value"]: e["id"] for e in v["vocab"]})
        fields[f] = {"mapping": mp, "size": len(mp), "min_train_frequency": v["min_train_frequency"], "active_for_model": v["active"]}
    json.dump({"version": "v2-adapter-from-preprocess_spec", "reserved_ids": {"<UNK>": 0, "<MISSING>": 1}, "fit_split": "train", "fields": fields},
              open(STAGE / "preprocessing/network_category_maps.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"version": "v2-adapter-from-preprocess_spec", "fit_split": "train", "transform": spec["numeric"]["transform"], "zscore_clip_abs": spec["numeric"]["zscore_clip_abs"],
               "features": {c: {**{k: v for k, v in st.items() if k not in ("active", "reason")}, "scale_used": st["log1p_std"], "active_for_model": st["active"]} for c, st in spec["numeric"]["fields"].items()}},
              open(STAGE / "preprocessing/network_numeric_stats.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"version": "v2-adapter-from-preprocess_spec", "fit_split": "train", "active_categorical_features": cats, "active_numerical_features": nums,
               "inactive_categorical_features": {f: v["reason"] for f, v in spec["categorical"]["fields"].items() if not v["active"]},
               "inactive_numerical_features": {c: v["reason"] for c, v in spec["numeric"]["fields"].items() if not v["active"]},
               "derived_binary_features": spec["binary"], "categorical_reserved_ids": {"<UNK>": 0, "<MISSING>": 1}, "numeric_zscore_clip_abs": spec["numeric"]["zscore_clip_abs"],
               "note": "File này là bản định dạng cũ SINH TỪ preprocess_spec.json (nguồn sự thật); mô hình cũ đọc được."},
              open(STAGE / "preprocessing/network_preprocess_spec.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"fingerprint_sha256": fp, "source": "preprocess_spec.json (v2)"}, open(STAGE / "preprocessing/network_preprocess_fingerprint.json", "w", encoding="utf-8"), indent=1)
    shutil.copy2(V2 / "S3_preprocess/data/preprocess_spec.json", STAGE / "preprocessing/preprocess_spec.json")
    shutil.copy2(V2 / "S3_preprocess/data/vocab.csv", STAGE / "preprocessing/vocab.csv")
    shutil.copy2(V2 / "S4_shards/data/samples.csv", STAGE / "split/network_sample_manifest.csv")
    shutil.copy2(V2 / "S2_windows_split/data/windows.csv", STAGE / "split/windows.csv")
    for s in ("S1_join", "S2_windows_split", "S3_preprocess", "S4_shards", "S5_validate"):
        shutil.copy2(V2 / s / "checks.json", STAGE / "integrity" / f"{s}_checks.json")
    shutil.copy2(V2 / "S2_windows_split/split_summary.json", STAGE / "integrity/split_summary.json")
    # ---- manifest
    stats = {}
    for s in ("train", "val", "test"):
        g = sm[sm.split == s]
        stats[s] = {"samples": int(len(g)), "positive_samples": int(g.label.sum()), "negative_samples": int(len(g) - g.label.sum()), "events": int(g.event_count.sum()),
                    "positive_events": int(g.positive_event_count.sum())}
    build_config = {"dataset_version": "v2-window-stratified", "window_seconds": 900, "max_events": 512, "split_unit": "window (hostname, 15 min)",
                    "split_policy": "70/15/15 stratified by scenario (positive windows) and by UTC date (benign windows); NOT host-disjoint", "split_seed": 1}
    manifest = {"version": "v2", "created_utc": datetime.now(timezone.utc).isoformat(), "split_stats": stats, "build_config": build_config,
                "source": {"step04c_preprocess_fingerprint": fp, "step05f_c_preprocess_fingerprint": fp}, "pipeline": "02_artifacts/22_v2_pipeline (S1..S5)"}
    OUT.mkdir(parents=True)
    json.dump(manifest, open(OUT / "dataset_manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(build_config, open(OUT / "build_config.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    (OUT / "README_DATASET.md").write_text(
        "# Dataset Network DL v2 (dựng lại từ raw OpTC)\n\n- Nguồn: Bro conn INNER JOIN eCAR-Bro (bro_uid), 620 máy, 17-25/9/2019.\n- Split cấp cửa sổ (hostname, 15 phút), 70/15/15, phân tầng theo scenario; KHÔNG host-disjoint.\n"
        "- Feature host lấy từ eCAR-Bro: app_family, image_dir_class, principal_class (còn lại là Bro conn).\n- Preprocessing fit chỉ trên TRAIN (xem preprocessing/preprocess_spec.json và vocab.csv).\n- Sample = cửa sổ 15 phút, chunk <= 512 flow, nhãn = có >= 1 flow dương.\n"
        f"- Mẫu: train {stats['train']['samples']:,}, val {stats['val']['samples']:,}, test {stats['test']['samples']:,}.\n- Chi tiết từng bước: 02_artifacts/22_v2_pipeline/S1..S5.\n", encoding="utf-8")
    # ---- zip (STORED, như bản cũ)
    def zip_dir(name, files):
        target = OUT / f"{name}.zip"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
            for p, arc in files:
                zf.write(p, arcname=arc)
        with zipfile.ZipFile(target) as zf:
            assert zf.testzip() is None, f"{target} hỏng"
        print(f"[ZIP] {target.name}: {len(files)} file, {target.stat().st_size / 1e9:.2f} GB", flush=True)
    zip_dir("shards", [(p, p.relative_to(V2 / "S4_shards").as_posix()) for p in sorted((V2 / "S4_shards/shards").rglob("*.npz"))])
    for folder in ("split", "preprocessing", "integrity"):
        zip_dir(folder, [(p, p.relative_to(STAGE).as_posix()) for p in sorted((STAGE / folder).rglob("*")) if p.is_file()])
    h = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()[:16] for p in OUT.glob("*.json")}
    print(json.dumps({"stats": stats, "json_sha": h}, ensure_ascii=False, indent=1))
    print(f"S6 package xong ({time.time() - t0:.0f}s): {OUT}")


if __name__ == "__main__":
    main()
