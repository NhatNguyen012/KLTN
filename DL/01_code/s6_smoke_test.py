#!/usr/bin/env python3
"""S6c - Chạy thử (CPU, vài batch) mã train của notebook 06d/07d trên gói dữ liệu v2 để bắt lỗi tích hợp TRƯỚC khi tốn thời gian Kaggle.
Dựng thư mục gốc giả như Kaggle: dataset_manifest.json, build_config.json (từ gói), split/preprocessing/integrity (giải nén từ zip), shards (junction tới S4)."""
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
PKG = ROOT / "03_datasets/v2_network_dl_kaggle_upload"
S4 = ROOT / "02_artifacts/22_v2_pipeline/S4_shards"
NB = ROOT / "04_notebooks"
PY = "D:/UIT/KLTNv2/.venv-host/Scripts/python.exe"


def code_dir(nbname, tag):
    nb = json.load(open(NB / nbname, encoding="utf-8"))
    d = Path(tempfile.mkdtemp(prefix=f"smoke_{tag}_"))
    for c in nb["cells"]:
        src = "".join(c["source"])
        if "WORK_CODE = Path(" in src and "write_text(" in src:
            import re
            m = re.search(r"WORK_CODE = Path\('([^']+)'\)", src)
            exec("import sys, os, json\nfrom pathlib import Path\n" + src.replace(m.group(0), f"WORK_CODE = Path(r'{d}')"), {})
            return d
    raise RuntimeError("không thấy cell ghi mã")


def main():
    root = Path(tempfile.mkdtemp(prefix="smoke_root_"))
    for f in ("dataset_manifest.json", "build_config.json", "README_DATASET.md"):
        (root / f).write_bytes((PKG / f).read_bytes())
    for z in ("split", "preprocessing", "integrity"):
        with zipfile.ZipFile(PKG / f"{z}.zip") as zf:
            zf.extractall(root)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "shards"), str(S4 / "shards")], check=True, capture_output=True)
    for p in ["dataset_manifest.json", "split/network_sample_manifest.csv", "preprocessing/network_preprocess_spec.json", "preprocessing/network_category_maps.json", "shards/train", "shards/val", "shards/test"]:
        assert (root / p).exists(), p
    print("gốc giả:", root, flush=True)
    results = {}
    for nbname, tag, script, extra in (("06d_BiLSTM_Kaggle_v2_final.ipynb", "bilstm", "05b_train_bilstm.py", ["--epochs", "1", "--batch-size", "16", "--max-train-batches", "30", "--max-eval-batches", "10", "--num-workers", "0"]),
                                       ("07d_Mixed_Type_Kaggle_v2_final.ipynb", "mixed", "05e_train_mixed_type_attention.py", ["--epochs", "1", "--batch-size", "8", "--grad-accum", "1", "--max-train-batches", "10", "--max-eval-batches", "5", "--num-workers", "0"])):
        d = code_dir(nbname, tag)
        out = Path(tempfile.mkdtemp(prefix=f"smoke_out_{tag}_"))
        cmd = [PY, str(d / script), "--dataset-root", str(root), "--output-dir", str(out)] + extra
        print(">>", " ".join(cmd), flush=True)
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        print(r.stdout[-1800:])
        print(r.stderr[-1800:])
        results[tag] = {"returncode": r.returncode, "outputs": sorted(p.name for p in out.iterdir())}
    print(json.dumps(results, indent=1))
    sys.exit(0 if all(v["returncode"] == 0 for v in results.values()) else 1)


if __name__ == "__main__":
    main()
