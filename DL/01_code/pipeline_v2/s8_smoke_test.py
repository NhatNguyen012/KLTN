#!/usr/bin/env python3
"""S8b - Chạy thử CPU vài batch cho notebook 06e/07e (phương án B) trên gói v2: kiểm tra hình dạng đầu vào, số tham số và việc train chạy hết.
Dựng gốc giả như Kaggle (xem s6_smoke_test.py), chạy cell cấu hình SUBSET_CELL thật rồi chạy mã train được trích từ notebook."""
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
from s8_notebooks_subset import SUBSET_CELL  # noqa: E402

ROOT = Path("D:/UIT/KLTNv2")
PKG = ROOT / "03_datasets/v2_network_dl_kaggle_upload"
S4 = ROOT / "02_artifacts/22_v2_pipeline/S4_shards"
NB = ROOT / "04_notebooks"
PY = "D:/UIT/KLTNv2/.venv-host/Scripts/python.exe"


def code_dir(nbname, tag):
    nb = json.load(open(NB / nbname, encoding="utf-8"))
    d = Path(tempfile.mkdtemp(prefix=f"smoke8_{tag}_"))
    for c in nb["cells"]:
        src = "".join(c["source"])
        if "WORK_CODE = Path(" in src and "write_text(" in src:
            m = re.search(r"WORK_CODE = Path\('([^']+)'\)", src)
            exec("import sys, os, json\nfrom pathlib import Path\n" + src.replace(m.group(0), f"WORK_CODE = Path(r'{d}')"), {})
            return d
    raise RuntimeError("không thấy cell ghi mã")


def nb_subset_cell(nbname):
    nb = json.load(open(NB / nbname, encoding="utf-8"))
    cells = ["".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"]
    hit = [s for s in cells if s.startswith("import shutil\nKEEP_CAT")]
    assert len(hit) == 1 and hit[0] == SUBSET_CELL, "cell cấu hình trong notebook khác SUBSET_CELL"
    return hit[0]


def main():
    root = Path(tempfile.mkdtemp(prefix="smoke8_root_"))
    for f in ("dataset_manifest.json", "build_config.json", "README_DATASET.md"):
        (root / f).write_bytes((PKG / f).read_bytes())
    for z in ("split", "preprocessing", "integrity"):
        with zipfile.ZipFile(PKG / f"{z}.zip") as zf:
            zf.extractall(root)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "shards"), str(S4 / "shards")], check=True, capture_output=True)
    results = {}
    for nbname, tag, script, extra in (("06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "bilstm", "05b_train_bilstm.py", ["--epochs", "1", "--batch-size", "16", "--max-train-batches", "30", "--max-eval-batches", "10", "--num-workers", "0"]),
                                       ("07e_Mixed_Type_Kaggle_v2_subsetB.ipynb", "mixed", "05e_train_mixed_type_attention.py", ["--epochs", "1", "--batch-size", "8", "--grad-accum", "1", "--max-train-batches", "10", "--max-eval-batches", "5", "--num-workers", "0"])):
        cell = nb_subset_cell(nbname)
        exec(cell, {"json": json, "DATASET_ROOT": root, "Path": Path})
        exec(cell, {"json": json, "DATASET_ROOT": root, "Path": Path})  # chạy lần hai phải vẫn đúng (idempotent)
        d = code_dir(nbname, tag)
        out = Path(tempfile.mkdtemp(prefix=f"smoke8_out_{tag}_"))
        cmd = [PY, str(d / script), "--dataset-root", str(root), "--output-dir", str(out)] + extra
        print(">>", " ".join(cmd), flush=True)
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        print(r.stdout[-1500:])
        print(r.stderr[-1500:])
        results[tag] = {"returncode": r.returncode, "outputs": sorted(p.name for p in out.iterdir())}
    print(json.dumps(results, indent=1))
    sys.exit(0 if all(v["returncode"] == 0 for v in results.values()) else 1)


if __name__ == "__main__":
    main()
