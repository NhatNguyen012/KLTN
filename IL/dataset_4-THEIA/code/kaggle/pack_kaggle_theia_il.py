#!/usr/bin/env python3
"""Package THEIA L=3 shards, OpTC Replay/Val bundle, FULL 1.25M OpTC Test shards, OpTC base ckpt, and notebook."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import zipfile

PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
THEIA_DIR = PROJECT_ROOT / "IL/dataset_4-THEIA"
OPTC_TEST_DIR = PROJECT_ROOT / "DL/code/output/dl_shards/test"
OPTC_REPLAY_DIR = THEIA_DIR / "output/optc_il_eval"
OUTPUT_ZIP = THEIA_DIR / "output/kaggle/kaggle_theia_upload.zip"
SHARDS_ZIP = THEIA_DIR / "output/theia_dl_shards.zip"
STAGING_DIR = PROJECT_ROOT / "Temp/kaggle_theia_staging"


def _copy_dir_files(src: Path, dst: Path) -> int:
    dst.mkdir(parents=True, exist_ok=True)
    count = 0
    for f in sorted(src.glob("*")):
        if f.is_file():
            shutil.copy2(f, dst / f.name)
            count += 1
    return count


def main() -> None:
    print("Creating Kaggle Multi-Domain IL (OpTC + THEIA) packages...")
    OUTPUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    shards_src = THEIA_DIR / "output/dl_shards"
    if shards_src.exists() and (shards_src / "split_manifest.json").exists():
        print(f"\n[1/5] Creating standalone THEIA Shards ZIP: {SHARDS_ZIP}...")
        with zipfile.ZipFile(SHARDS_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
            for root, _, files in os.walk(shards_src):
                for file in sorted(files):
                    abs_f = Path(root) / file
                    rel_f = abs_f.relative_to(shards_src)
                    zipf.write(abs_f, arcname=str(Path("theia_dl_shards") / rel_f))
        print(f"  --> THEIA Shards ZIP created: {SHARDS_ZIP} ({SHARDS_ZIP.stat().st_size / (1024*1024):.2f} MB)")
    else:
        raise FileNotFoundError(f"Missing THEIA shards in {shards_src}")

    print("\n[2/5] Staging OpTC base checkpoint, THEIA shards, and OpTC Replay/Val bundle...")
    ckpt_src = PROJECT_ROOT / "DL/code/output/results/mixhead_attention_t4x2_full.pt"
    if not ckpt_src.is_file():
        raise FileNotFoundError(f"Base checkpoint missing: {ckpt_src}")
    shutil.copy2(ckpt_src, STAGING_DIR / "mixhead_attention_t4x2_full.pt")
    shutil.copytree(shards_src, STAGING_DIR / "theia_dl_shards")

    if not OPTC_REPLAY_DIR.exists():
        raise FileNotFoundError(f"OpTC Replay bundle missing: {OPTC_REPLAY_DIR}. Run build_optc_replay_bundle.py first.")
    n_rep = _copy_dir_files(OPTC_REPLAY_DIR, STAGING_DIR / "optc_il_eval")
    print(f"  Copied {n_rep} OpTC Replay/Val files from {OPTC_REPLAY_DIR}")

    print(f"\n[3/5] Staging FULL OpTC Test shards ({OPTC_TEST_DIR}) for end-to-end backward transfer evaluation...")
    if not OPTC_TEST_DIR.exists():
        raise FileNotFoundError(f"OpTC Test shards missing: {OPTC_TEST_DIR}")
    n_optc_test = _copy_dir_files(OPTC_TEST_DIR, STAGING_DIR / "optc_test_shards")
    print(f"  Copied {n_optc_test} OpTC test shards (1,249,689 test samples)")

    print("\n[4/5] Staging notebook...")
    nb_src = THEIA_DIR / "code/kaggle/THEIA-MixHead-IL.ipynb"
    if not nb_src.is_file():
        raise FileNotFoundError(f"Notebook missing: {nb_src}")
    shutil.copy2(nb_src, STAGING_DIR / "THEIA-MixHead-IL.ipynb")

    print(f"\n[5/5] Compressing complete Multi-Domain bundle into {OUTPUT_ZIP}...")
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
        for root, _, files in os.walk(STAGING_DIR):
            for file in sorted(files):
                abs_f = Path(root) / file
                rel_f = abs_f.relative_to(STAGING_DIR)
                zipf.write(abs_f, arcname=str(rel_f))

    sz_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"\nSUCCESS: Full Kaggle Multi-Domain IL bundle created: {OUTPUT_ZIP} ({sz_mb:.2f} MB)")
    shutil.rmtree(STAGING_DIR)


if __name__ == "__main__":
    main()
