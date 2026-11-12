#!/usr/bin/env python3
"""S14c - Chạy thử CPU s14_ft_train.py trên gói fine-tune thật + shards OpTC local (một fold, ít epoch, ít mẫu OpTC TEST) để bắt lỗi tích hợp TRƯỚC khi lên Kaggle.
Kiểm tra: mô hình mở rộng chưa train khớp zero-shot (dung sai chặt trên CPU), train hai giai đoạn chạy hết, ghi đủ file kết quả."""
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
from s8_notebooks_subset import extract_files  # noqa: E402

ROOT = Path("D:/UIT/KLTNv2")
PKG = ROOT / "03_datasets/v2_network_dl_kaggle_upload"
S4 = ROOT / "02_artifacts/22_v2_pipeline/S4_shards"
FT = ROOT / "03_datasets/v3_ft_kaggle_upload"
PY = str(ROOT / ".venv-host/Scripts/python.exe")
SCRIPT = Path(__file__).parent / "s14_ft_train.py"


def main():
    root = Path(tempfile.mkdtemp(prefix="s14_optc_"))
    with zipfile.ZipFile(PKG / "split.zip") as zf:
        zf.extractall(root)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "shards"), str(S4 / "shards")], check=True, capture_output=True)
    code = Path(tempfile.mkdtemp(prefix="s14_code_"))
    for nbname in ("06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb"):
        nb = json.load(open(ROOT / "04_notebooks" / nbname, encoding="utf-8"))
        d, _ = extract_files(nb, "t")
        for p in d.iterdir():
            (code / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    ok = True
    for kind in ("bilstm", "mixed"):
        out = Path(tempfile.mkdtemp(prefix=f"s14_out_{kind}_"))
        cmd = [PY, str(SCRIPT), "--model", kind, "--ft-root", str(FT), "--optc-root", str(root), "--code-dir", str(code), "--out-dir", str(out), "--folds", "0", "--cpu",
               "--epochs-a", "1", "--epochs-b", "1", "--replay-per-epoch", "60", "--replay-pos", "15", "--max-optc-test", "150", "--equiv-tol", "0.001"]
        print(">>", " ".join(cmd), flush=True)
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        print(r.stdout[-3500:])
        print(r.stderr[-1500:])
        files = sorted(p.name for p in out.iterdir())
        print(kind, "returncode", r.returncode, files)
        ok &= r.returncode == 0 and any(f.startswith("result_") for f in files)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
