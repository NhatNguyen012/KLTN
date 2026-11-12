"""Dong goi 1 dataset (vd. seed_1) thanh cac file zip de upload Kaggle (tranh loi UI khi upload hang tram file le).

Bo cuc giong 03_datasets/network_dl_v1_1_15m/kaggle_upload: moi thu muc con (shards, split, preprocessing,
integrity) -> <ten>.zip, ben trong co thu muc goc <ten>/...; 3 file goc de ngoai. Ghi ra thu muc MOI (khong
dong vao dataset nguon). Resolver cua notebook 06b/07b xu ly thu muc lap ten do Kaggle tu giai nen.

    python 10_pack_kaggle_upload.py --dataset-dir 03_datasets/random_network_dl_v1_1_15m/seed_1 \
        --out-dir 03_datasets/random_network_dl_v1_1_15m/seed_1_kaggle_upload
"""
from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path

FOLDERS = ("shards", "split", "preprocessing", "integrity")
LOOSE = ("dataset_manifest.json", "build_config.json", "README_DATASET.md")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    src = Path(args.dataset_dir)
    out = Path(args.out_dir)

    for f in (*LOOSE, *FOLDERS):
        if not (src / f).exists():
            raise FileNotFoundError(src / f)

    if out.exists():
        raise FileExistsError(f"{out} da ton tai; khong ghi de")

    out.mkdir(parents=True)

    for name in LOOSE:
        shutil.copy2(src / name, out / name)

    for folder in FOLDERS:
        files = sorted(p for p in (src / folder).rglob("*") if p.is_file())
        target = out / f"{folder}.zip"

        # npz khong nen san -> STORED cho nhanh va tranh tang CPU; moi file goc giu nguyen byte
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
            for p in files:
                zf.write(p, arcname=p.relative_to(src).as_posix())

        with zipfile.ZipFile(target) as zf:
            bad = zf.testzip()

        if bad is not None:
            raise RuntimeError(f"{target}: file hong {bad}")

        print(f"[ZIP] {target.name}: {len(files)} file, {target.stat().st_size / 1024 ** 3:.2f} GB")

    print(f"[DONE] {out}")


if __name__ == "__main__":
    main()
