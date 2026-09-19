#!/usr/bin/env python3
"""Package matrix outputs + scripts into kaggle_input/ for Kaggle upload.

Copies:
  - code/output/matrix/*.npz, *.npy, *.jsonl, *.json
  - code/output/vocab.json
  - code/output/vocab_metadata.json
  - code/ecar_tokenizer.py  (for reference/inference)
  - code/kaggle/train_rf.py, train_xgb.py, train_lgbm.py, evaluate_models.py
  - README_kaggle.md

Source data is never modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from pipeline_contract import TRAIN_BENIGN_DAYS, load_vocabulary, validate_output_path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CODE_DIR = PROJECT_ROOT / "code"
OUTPUT_DIR = CODE_DIR / "output"
MATRIX_DIR = OUTPUT_DIR / "matrix"
KAGGLE_DIR = OUTPUT_DIR / "kaggle_input"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--matrix-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, default=KAGGLE_DIR)
    args = parser.parse_args(argv)
    source_dir = args.input_dir.resolve()
    matrix_dir = (args.matrix_dir or source_dir / "matrix").resolve()
    output = validate_output_path(args.output_dir, [matrix_dir])
    if output.exists():
        raise ValueError("package output already exists; choose an unused output directory")
    if not matrix_dir.exists():
        print(f"ERROR: matrix dir not found: {matrix_dir}", file=sys.stderr)
        print("Run build_matrix.py first.", file=sys.stderr)
        return 1

    # Verify key files exist
    required = [
        source_dir / "vocab.json",
        source_dir / "vocab_metadata.json",
    ]
    for path in required:
        if not path.exists():
            print(f"ERROR: required file not found: {path}", file=sys.stderr)
            return 1

    # Check matrix files
    _, vocab_meta = load_vocabulary(*required, training_days=TRAIN_BENIGN_DAYS)
    split_meta = json.loads((matrix_dir / "split_metadata.json").read_text())
    if split_meta.get("vocabulary_sha256") != vocab_meta["vocabulary_sha256"]:
        raise ValueError("matrix/vocabulary identity mismatch")
    if vocab_meta.get('fit_purpose') == 'supervised_training' and split_meta.get('split_sha256') != vocab_meta.get('split_sha256'):
        raise ValueError('matrix/vocabulary shared split mismatch')
    for split in ("train", "val", "test"):
        info = split_meta.get("splits", {}).get(split, {})
        if not info.get("label_0") or not info.get("label_1"):
            raise ValueError(f"{split} must contain both classes before training packaging")
    hashes = split_meta.get("artifact_sha256", {})
    required_matrix = {f"{prefix}_{split}.{suffix}" for split in ("train", "val", "test")
                       for prefix, suffix in (("X", "npz"), ("y", "npy"), ("row_sidecar", "jsonl"))}
    if not required_matrix <= hashes.keys():
        raise ValueError("matrix publication lacks required artifact checksums")
    for name, digest in hashes.items():
        if Path(name).name != name:
            raise ValueError("invalid matrix artifact name")
        with (matrix_dir / name).open("rb") as handle:
            if hashlib.file_digest(handle, "sha256").hexdigest() != digest:
                raise ValueError(f"matrix checksum mismatch: {name}")
    matrix_files = list(matrix_dir.glob("*"))
    if not matrix_files:
        print(f"ERROR: no files in {matrix_dir}", file=sys.stderr)
        return 1

    # Stage a new package; preserve all prior packages.
    output.parent.mkdir(parents=True, exist_ok=True)
    package_dir = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    try:
        (package_dir / "matrix").mkdir()

        # Copy matrix files
        for f in matrix_files:
            shutil.copy2(f, package_dir / "matrix" / f.name)
            print(f"  Copied matrix/{f.name}", file=sys.stderr)

        # Copy vocab files
        for name in ("vocab.json", "vocab_metadata.json"):
            shutil.copy2(source_dir / name, package_dir / name)
            print(f"  Copied {name}", file=sys.stderr)

        # Copy tokenizer for reference
        for name in ("ecar_tokenizer.py", "command_syntax.py", "pipeline_contract.py", "evaluation_metrics.py"):
            shutil.copy2(CODE_DIR / name, package_dir / name)

        # Copy Kaggle training scripts
        kaggle_scripts_dir = CODE_DIR / "kaggle"
        if kaggle_scripts_dir.exists():
            for script in sorted(kaggle_scripts_dir.glob("*.py")):
                shutil.copy2(script, package_dir / script.name)
                print(f"  Copied {script.name}", file=sys.stderr)

        # Generate README
        readme = _generate_readme(matrix_dir)
        (package_dir / "README_kaggle.md").write_text(readme, encoding="utf-8")
        if output.exists():
            raise ValueError("package output was created concurrently; preserving it")
        os.rename(package_dir, output)
    finally:
        if package_dir.exists():
            shutil.rmtree(package_dir)
    print("  Generated README_kaggle.md", file=sys.stderr)

    # Summary
    total_size = sum(f.stat().st_size for f in output.rglob("*") if f.is_file())
    file_count = sum(1 for _ in output.rglob("*") if _.is_file())
    print(f"\nPackaged {file_count} files ({total_size / (1024**2):.1f} MB) "
          f"to {output}/", file=sys.stderr)
    print("Upload this folder as a Kaggle Dataset.", file=sys.stderr)
    return 0


def _generate_readme(matrix_dir: Path = MATRIX_DIR) -> str:
    # Load split metadata if available
    meta_path = matrix_dir / "split_metadata.json"
    split_info = ""
    if meta_path.exists():
        meta = json.loads(meta_path.read_text("utf-8"))
        splits = meta.get("splits", {})
        lines = []
        for split, info in splits.items():
            lines.append(f"| {split} | {info.get('rows', '?'):,} | "
                         f"{info.get('label_0', '?'):,} | {info.get('label_1', '?'):,} | "
                         f"{info.get('pos_rate', 0):.4%} |")
        split_info = (
            "\n| Split | Rows | Label 0 | Label 1 | Pos Rate |\n"
            "|---|---|---|---|---|\n"
            + "\n".join(lines)
        )

    return f"""# OpTC Host-ML — Kaggle Input Dataset

**Created:** {datetime.now(timezone.utc).isoformat()}

## Contents

```
kaggle_input/
  vocab.json                  — frozen vocabulary; fit scope and split identity in metadata
  vocab_metadata.json         — provenance, weird-token hints
  matrix/
    X_{{train,val,test}}.npz    — sparse CSR binary features
    X_{{train,val,test}}_count.npz  — sparse CSR count features (ablation)
    y_{{train,val,test}}.npy    — int8 labels (0=benign, 1=malicious)
    row_sidecar_{{train,val,test}}.jsonl  — JOIN_ONLY fields per row
    split_metadata.json       — shapes, balance, split policy
  ecar_tokenizer.py           — tokenizer code (reference)
  train_rf.py                 — Random Forest training
  train_xgb.py                — XGBoost training
  train_lgbm.py               — LightGBM training
  evaluate_models.py          — unified evaluation + SHAP
```

## Split Summary
{split_info}

## How to Use on Kaggle

1. Upload this folder as a **Kaggle Dataset**
2. Create a new **Notebook** and attach the dataset
3. Run the training scripts:

```python
# In a Kaggle notebook cell:
%run /kaggle/input/your-dataset-name/train_rf.py
%run /kaggle/input/your-dataset-name/train_xgb.py
%run /kaggle/input/your-dataset-name/train_lgbm.py
%run /kaggle/input/your-dataset-name/evaluate_models.py
```

Or run from terminal:
```bash
cd /kaggle/input/your-dataset-name
python train_rf.py --input-dir /kaggle/input/your-dataset-name --output-dir /kaggle/working/results
python train_xgb.py --input-dir /kaggle/input/your-dataset-name --output-dir /kaggle/working/results
python train_lgbm.py --input-dir /kaggle/input/your-dataset-name --output-dir /kaggle/working/results
python evaluate_models.py --input-dir /kaggle/input/your-dataset-name --model-dir /kaggle/working/results --output-dir /kaggle/working/results
```

## Models

| Model | Accelerator | Notes |
|---|---|---|
| Random Forest | CPU (n_jobs=-1) | class_weight='balanced', max_depth grid |
| XGBoost | GPU (tree_method=hist) | early stopping on val, scale_pos_weight |
| LightGBM | GPU (device=gpu) | early stopping on val, class_weight='balanced' |
"""


if __name__ == "__main__":
    raise SystemExit(main())
