#!/usr/bin/env python3
"""Package script to bundle all THEIA L=3 shards, OpTC base checkpoint, and notebook for Kaggle."""

from __future__ import annotations
import os
from pathlib import Path
import shutil
import zipfile

PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
THEIA_DIR = PROJECT_ROOT / "IL/dataset_4-THEIA"
OUTPUT_ZIP = THEIA_DIR / "output/kaggle/kaggle_theia_upload.zip"
SHARDS_ZIP = THEIA_DIR / "output/theia_dl_shards.zip"
STAGING_DIR = PROJECT_ROOT / "Temp/kaggle_theia_staging"


def main():
    print(f"Creating Kaggle THEIA packages...")
    OUTPUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Standalone Shards ZIP
    shards_src = THEIA_DIR / "output/dl_shards"
    if shards_src.exists() and (shards_src / "split_manifest.json").exists():
        print(f"\n[1/3] Creating standalone Shards ZIP: {SHARDS_ZIP}...")
        with zipfile.ZipFile(SHARDS_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
            for root, _, files in os.walk(shards_src):
                for file in files:
                    abs_f = Path(root) / file
                    rel_f = abs_f.relative_to(shards_src)
                    zipf.write(abs_f, arcname=str(Path("theia_dl_shards") / rel_f))
        sz_mb = SHARDS_ZIP.stat().st_size / (1024 * 1024)
        print(f"  --> Shards ZIP created: {SHARDS_ZIP} ({sz_mb:.2f} MB)")
    else:
        print(f"  WARNING: Missing shards in {shards_src}")

    # 2. Stage Full Kaggle Bundle
    print("\n[2/3] Staging full Kaggle upload bundle...")

    # Copy OpTC Base Checkpoint
    ckpt_src = PROJECT_ROOT / "DL/code/output/results/mixhead_attention_t4x2_full.pt"
    if ckpt_src.exists():
        print(f"  Copying OpTC Base Checkpoint ({ckpt_src.stat().st_size / (1024*1024):.1f} MB)...")
        shutil.copy2(ckpt_src, STAGING_DIR / "mixhead_attention_t4x2_full.pt")
    else:
        print(f"  WARNING: Base checkpoint missing: {ckpt_src}")

    # Copy Pre-Built THEIA Shards
    shards_dst = STAGING_DIR / "theia_dl_shards"
    if shards_src.exists():
        print(f"  Copying THEIA DL shards ({shards_src})...")
        shutil.copytree(shards_src, shards_dst)

    # Copy Notebook
    nb_src = THEIA_DIR / "code/kaggle/THEIA-MixHead-IL.ipynb"
    if nb_src.exists():
        shutil.copy2(nb_src, STAGING_DIR / "THEIA-MixHead-IL.ipynb")

    # 3. Build Final Kaggle Bundle ZIP
    print(f"\n[3/3] Compressing staging directory into {OUTPUT_ZIP}...")
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
        for root, _, files in os.walk(STAGING_DIR):
            for file in files:
                abs_f = Path(root) / file
                rel_f = abs_f.relative_to(STAGING_DIR)
                zipf.write(abs_f, arcname=str(rel_f))

    sz_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"\nSUCCESS: Full Kaggle upload bundle created: {OUTPUT_ZIP} ({sz_mb:.2f} MB)")
    shutil.rmtree(STAGING_DIR)


if __name__ == "__main__":
    main()
