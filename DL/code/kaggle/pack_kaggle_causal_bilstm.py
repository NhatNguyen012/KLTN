#!/usr/bin/env python3
"""Package script to bundle all inputs, pre-built shards, and code for Kaggle Dual GPU (T4x2).

Produces a single, clean uploadable zip:
  DL/code/kaggle/kaggle_upload.zip
"""

from __future__ import annotations
import os
import shutil
import zipfile
from pathlib import Path

PROJECT_ROOT = Path("/mnt/SSD_Data/optc")
OUTPUT_ZIP = PROJECT_ROOT / "DL/code/kaggle/kaggle_upload.zip"
STAGING_DIR = PROJECT_ROOT / "Temp/kaggle_causal_bilstm_t4x2_staging"


def main():
    print(f"Creating Kaggle package at: {OUTPUT_ZIP}")
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy Data Files
    data_dir = STAGING_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    files_to_copy = [
        # Sidecar label catalog
        (
            PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz",
            data_dir / "optc_multitask_labels_v1.json.gz",
        ),
        # 42k Multi-Task Cohort
        (
            PROJECT_ROOT / "DL/code/others/sample_multitask_cohort_42k.json.gz",
            data_dir / "sample_multitask_cohort_42k.json.gz",
        ),
        # Unified DL Vocabulary (Host + Bounded Network)
        (
            PROJECT_ROOT / "DL/code/output/dl_vocab.json",
            data_dir / "dl_vocab.json",
        ),
        (
            PROJECT_ROOT / "DL/code/output/dl_vocab_metadata.json",
            data_dir / "dl_vocab_metadata.json",
        ),
    ]

    for src, dst in files_to_copy:
        if src.exists():
            print(f"  Copying {src.name} ({src.stat().st_size / (1024*1024):.1f} MB)...")
            shutil.copy2(src, dst)
        else:
            print(f"  WARNING: Source file missing: {src}")

    # 1b. Copy Pre-Built DL Shards if available
    shards_src = PROJECT_ROOT / "DL/code/output/dl_shards"
    shards_dst = STAGING_DIR / "dl_shards"
    if shards_src.exists() and (shards_src / "split_manifest.json").exists():
        print(f"  Copying pre-built DL shards from {shards_src}...")
        shutil.copytree(shards_src, shards_dst)

    # 2. Copy Code Module
    code_dir = STAGING_DIR / "causal_bilstm_pkg"
    code_dir.mkdir(parents=True, exist_ok=True)

    code_files = [
        (PROJECT_ROOT / "DATASET/Preprocess/label_catalog.py", code_dir / "label_catalog.py"),
        (PROJECT_ROOT / "ML/code/preprocess/ecar_tokenizer.py", code_dir / "ecar_tokenizer.py"),
        (PROJECT_ROOT / "DL/code/preprocess/dl_ecar_tokenizer.py", code_dir / "dl_ecar_tokenizer.py"),
        (PROJECT_ROOT / "DL/code/preprocess/build_dl_vocab.py", code_dir / "build_dl_vocab.py"),
        (PROJECT_ROOT / "DL/code/preprocess/build_dl_shards.py", code_dir / "build_dl_shards.py"),
        (PROJECT_ROOT / "DL/code/preprocess/build_dl_shards_from_contextual_split.py", code_dir / "build_dl_shards_from_contextual_split.py"),
        (PROJECT_ROOT / "ML/code/preprocess/process_context_tracker.py", code_dir / "process_context_tracker.py"),
        (PROJECT_ROOT / "ML/code/preprocess/command_syntax.py", code_dir / "command_syntax.py"),
        (PROJECT_ROOT / "ML/code/preprocess/pipeline_contract.py", code_dir / "pipeline_contract.py"),
        (PROJECT_ROOT / "DL/code/preprocess/causal_dataset.py", code_dir / "causal_dataset.py"),
        (PROJECT_ROOT / "DL/code/preprocess/model_causal_bilstm.py", code_dir / "model_causal_bilstm.py"),
        (PROJECT_ROOT / "DL/code/preprocess/model_mixhead_attention.py", code_dir / "model_mixhead_attention.py"),
        (PROJECT_ROOT / "DL/code/preprocess/trainer.py", code_dir / "trainer.py"),
        (PROJECT_ROOT / "DL/code/preprocess/train_causal_bilstm.py", code_dir / "train_causal_bilstm.py"),
        (PROJECT_ROOT / "DL/code/preprocess/train_mixhead_attention.py", code_dir / "train_mixhead_attention.py"),
    ]

    for src, dst in code_files:
        if src.exists():
            text = src.read_text(encoding="utf-8")
            # Sanitize package imports for standalone execution in Kaggle causal_bilstm_pkg
            text = text.replace("from ML.code.preprocess.", "from ")
            text = text.replace("from DL.code.preprocess.", "from ")
            text = text.replace("from DATASET.Preprocess.", "from ")
            text = text.replace("from preprocess.", "from ")
            dst.write_text(text, encoding="utf-8")
        else:
            print(f"  WARNING: Missing code file: {src}")

    # Create __init__.py
    (code_dir / "__init__.py").write_text('"""Causal BiLSTM and Mix-Head Self-Attention Package for Kaggle."""\n')

    # 3. Copy Jupyter Notebooks
    notebooks = [
        "BiLSTM.ipynb",
        "Mix-Head.ipynb",
    ]
    for nb_name in notebooks:
        nb_src = PROJECT_ROOT / f"DL/code/kaggle/{nb_name}"
        if nb_src.exists():
            shutil.copy2(nb_src, STAGING_DIR / nb_name)
            print(f"  Added notebook: {nb_name}")

    # 4. Create README_KAGGLE.md
    readme_content = """# Kaggle GPU T4x2 Causal Host Multi-Task Package

Supports both:
1. **Mix-Head Self-Attention** (`Mix-Head.ipynb`) inspired by Peter Bloem.
2. **BiLSTM Causal Multi-Task** (`BiLSTM.ipynb`).

## Pre-Built Shards (`dl_shards/`):
- All events are already tokenized using `dl_vocab.json` (10,496 tokens).
- Fast training with zero JSON parsing bottleneck on Kaggle CPU.
- Split is stratified across Benign and all 3 Attack Scenarios (SC1, SC2, SC3).

## Quickstart on Kaggle:
1. In your Kaggle Notebook settings (right pane):
   - **Accelerator:** Select `GPU T4 x 2` (Dual T4).
2. Open `Mix-Head.ipynb`.
3. Run all cells: Both T4 GPUs (cuda:0 and cuda:1) will run simultaneously with PyTorch DistributedDataParallel (NCCL)!
"""
    (STAGING_DIR / "README_KAGGLE.md").write_text(readme_content)

    # 5. Zip the staging directory
    OUTPUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()

    print(f"Zipping to {OUTPUT_ZIP}...")
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(STAGING_DIR):
            for file in files:
                abs_path = Path(root) / file
                rel_path = abs_path.relative_to(STAGING_DIR)
                zf.write(abs_path, arcname=str(rel_path))

    # Clean up staging
    shutil.rmtree(STAGING_DIR)
    size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"Package successfully created: {OUTPUT_ZIP} ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()
