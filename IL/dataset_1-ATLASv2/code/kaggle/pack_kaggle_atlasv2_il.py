#!/usr/bin/env python3
"""Package script to bundle all ATLASv2 L=3 shards, OpTC base checkpoint, and code for Kaggle."""

from __future__ import annotations
import os
from pathlib import Path
import shutil
import zipfile

PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
IL_DIR = PROJECT_ROOT / "IL/dataset_1-ATLASv2"
OUTPUT_ZIP = IL_DIR / "output/kaggle/kaggle_atlasv2_upload.zip"
STAGING_DIR = PROJECT_ROOT / "Temp/kaggle_atlasv2_staging"


def main():
    print(f"Creating Kaggle package at: {OUTPUT_ZIP}")
    OUTPUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy OpTC Base Checkpoint
    ckpt_src = PROJECT_ROOT / "DL/code/output/results/mixhead_attention_t4x2_full.pt"
    if ckpt_src.exists():
        print(f"  Copying OpTC Base Checkpoint ({ckpt_src.stat().st_size / (1024*1024):.1f} MB)...")
        shutil.copy2(ckpt_src, STAGING_DIR / "mixhead_attention_t4x2_full.pt")
    else:
        print(f"  WARNING: Base checkpoint missing: {ckpt_src}")

    # 2. Copy ATLASv2 Pre-Built Shards
    shards_src = IL_DIR / "output/dl_shards"
    shards_dst = STAGING_DIR / "atlasv2_dl_shards"
    if shards_src.exists() and (shards_src / "split_manifest.json").exists():
        print(f"  Copying pre-built ATLASv2 DL shards ({shards_src})...")
        shutil.copytree(shards_src, shards_dst)
    else:
        print(f"  WARNING: Missing shards in {shards_src}")

    # 3. Copy Code Module (atlasv2_pkg)
    code_dir = STAGING_DIR / "atlasv2_pkg"
    code_dir.mkdir(parents=True, exist_ok=True)

    code_files = [
        (PROJECT_ROOT / "DL/code/preprocess/model_mixhead_attention.py", code_dir / "model_mixhead_attention.py"),
        (PROJECT_ROOT / "DL/code/preprocess/causal_dataset.py", code_dir / "causal_dataset.py"),
        (IL_DIR / "code/DL/train_mixhead_atlasv2.py", code_dir / "train_mixhead_atlasv2.py"),
        (IL_DIR / "code/preprocess/common_schema.py", code_dir / "common_schema.py"),
        (IL_DIR / "code/preprocess/label_refiner.py", code_dir / "label_refiner.py"),
        (IL_DIR / "code/preprocess/cbc_adapter.py", code_dir / "cbc_adapter.py"),
        (IL_DIR / "code/preprocess/split_config.py", code_dir / "split_config.py"),
    ]

    for src, dst in code_files:
        if src.exists():
            text = src.read_text(encoding="utf-8")
            text = text.replace("from preprocess.", "from ")
            dst.write_text(text, encoding="utf-8")
        else:
            print(f"  WARNING: Missing code file: {src}")

    (code_dir / "__init__.py").write_text('"""ATLASv2 Continual Learning Mix-Head Package."""\n')

    # 4. Copy Notebook
    nb_src = IL_DIR / "code/kaggle/ATLASv2-MixHead-IL.ipynb"
    if nb_src.exists():
        shutil.copy2(nb_src, STAGING_DIR / "ATLASv2-MixHead-IL.ipynb")

    # 5. Build Final ZIP
    print(f"\nCompressing staging directory into {OUTPUT_ZIP}...")
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
        for root, _, files in os.walk(STAGING_DIR):
            for file in files:
                abs_f = Path(root) / file
                rel_f = abs_f.relative_to(STAGING_DIR)
                zipf.write(abs_f, arcname=str(rel_f))

    sz_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"\nSUCCESS: Kaggle package created: {OUTPUT_ZIP} ({sz_mb:.2f} MB)")
    shutil.rmtree(STAGING_DIR)


if __name__ == "__main__":
    main()
