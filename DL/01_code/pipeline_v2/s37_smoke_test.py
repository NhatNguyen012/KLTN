#!/usr/bin/env python3
"""S37d - Chay thu CPU s37_il_train.py tren goi il_atlasv2 that + shards OpTC local (mot fold, moi giai doan 1 epoch, it mau OpTC TEST) de bat loi tich hop TRUOC khi len Kaggle.
Day la kiem tra mach chay, KHONG phai danh gia: khong doc so lieu F1 cua lan chay thu nay."""
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
FT = ROOT / "03_datasets/il_atlas_theia_kaggle_upload"
PY = str(ROOT / ".venv-host/Scripts/python.exe")
SCRIPT = Path(__file__).parent / "s37_il_train.py"
KINDS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["bilstm", "mixed"]


def main():
    root = Path(tempfile.mkdtemp(prefix="s37_optc_"))
    with zipfile.ZipFile(PKG / "split.zip") as zf:
        zf.extractall(root)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "shards"), str(S4 / "shards")], check=True, capture_output=True)
    code = Path(tempfile.mkdtemp(prefix="s36_code_"))
    for nbname in ("06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb"):
        nb = json.load(open(ROOT / "04_notebooks" / nbname, encoding="utf-8"))
        d, _ = extract_files(nb, "t")
        for p in d.iterdir():
            (code / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    for n in ("s14_ft_train.py", "s36_il_train.py", "s37_il_train.py"):
        (code / n).write_text((Path(__file__).parent / n).read_text(encoding="utf-8"), encoding="utf-8")
    ok = True
    for kind in KINDS:
        out = Path(tempfile.mkdtemp(prefix=f"s36_out_{kind}_"))
        cmd = [PY, str(code / "s37_il_train.py"), "--model", kind, "--ft-root", str(FT), "--optc-root", str(root), "--code-dir", str(code), "--out-dir", str(out), "--folds", "0", "--cpu",
               "--epochs-a", "1", "--epochs-b", "1", "--replay-per-epoch", "60", "--replay-pos", "15", "--max-optc-test", "150", "--equiv-tol", "0.001"]
        print(">>", " ".join(cmd), flush=True)
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        print(r.stdout[-3500:])
        print(r.stderr[-2000:])
        files = sorted(p.name for p in out.iterdir())
        print(kind, "returncode", r.returncode, files)
        ok &= r.returncode == 0 and any(f.startswith("result_") for f in files)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
