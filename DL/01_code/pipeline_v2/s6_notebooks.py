#!/usr/bin/env python3
"""S6a - Sinh notebook Kaggle v2 (06d BiLSTM, 07d Mixed-Type) từ 06b/07b: GIỮ NGUYÊN kiến trúc/siêu tham số, BỎ mọi tuỳ chọn drop/suffix/ablation.
Cách làm: chạy cell ghi mã của notebook cũ ra thư mục tạm, vá chữ (có assert), rồi viết lại cell bằng repr() của mã đã vá."""
import json
import re
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
NB = Path("D:/UIT/KLTNv2/04_notebooks")
DROP_RE = r"drop_app_family|drop-app-family"
STREAM = """import subprocess
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
for line in proc.stdout:
    print(line, end='', flush=True)
ret = proc.wait()"""



def extract_files(nb, tag):
    d = Path(tempfile.mkdtemp(prefix=f"nb_{tag}_"))
    for c in nb["cells"]:
        src = "".join(c["source"])
        if "WORK_CODE = Path(" in src and "write_text(" in src:
            m = re.search(r"WORK_CODE = Path\('([^']+)'\)", src)
            src2 = src.replace(m.group(0), f"WORK_CODE = Path(r'{d}')")
            exec("import sys, os, json\nfrom pathlib import Path\n" + src2, {})
            return d, m.group(1), src
    raise RuntimeError("không thấy cell ghi mã")


def patch_dataset_module(t):
    t = re.sub(r",\s*drop_app_family: bool = False,?(?=\s*\))", "", t)  # chữ ký một dòng
    t = re.sub(r"\n\s*drop_app_family: bool = False,", "", t)            # chữ ký nhiều dòng
    a = t.index("        self.drop_app_family = bool(drop_app_family)")
    b = t.index('        if self.split not in {"train", "val", "test"}:')
    t = t[:a] + "        self.app_family_col = None\n\n" + t[b:]
    assert not re.search(DROP_RE, t), "còn drop_app_family trong module dữ liệu"
    return t


def patch_train_script(t):
    t = re.sub(r'\n\s*(?:p|parser)\.add_argument\(\s*"--drop-app-family",.*?\n\s*\)\n', "\n", t, flags=re.S)
    t = t.replace(", drop_app_family=args.drop_app_family", "")
    t = re.sub(r'\n\s*drop_app_family=(?:args\.drop_app_family|bool\(config\.get\("drop_app_family", False\)\)),', "", t)
    t = re.sub(r"\n\s*if args\.drop_app_family:\n(?:        .*\n)+", "\n", t)
    t = re.sub(r'\n\s*"drop_app_family": bool\(args\.drop_app_family\),', "", t)
    left = [ln for ln in t.splitlines() if re.search(DROP_RE + r"|\bDROP\b", ln)]
    assert not left, f"còn dòng drop trong script: {left}"
    return t


def build(old_name, new_name, run_name, title, extra_md):
    nb = json.load(open(NB / old_name, encoding="utf-8"))
    d, kaggle_code_dir, _ = extract_files(nb, run_name)
    files = {}
    for p in sorted(d.iterdir()):
        t = p.read_text(encoding="utf-8")
        if p.name.startswith("network_dl_dataset"):
            t = patch_dataset_module(t)
        elif p.suffix == ".py" and re.search(DROP_RE, t):
            t = patch_train_script(t)
        compile(t, p.name, "exec")  # phải là Python hợp lệ sau khi vá
        files[p.name] = t
    cells = []
    for i, c in enumerate(nb["cells"]):
        src = "".join(c["source"])
        if i == 0:
            src = (f"# {title}\n\n{extra_md}\n\nDataset: pipeline v2 dựng lại từ raw (`02_artifacts/22_v2_pipeline`), split cấp cửa sổ phân tầng theo scenario. "
                   "Một lần chạy (seed 42), đủ feature, không có tuỳ chọn bỏ feature hay ablation. Model selection và threshold chỉ dùng VAL; "
                   "TEST chỉ chạy một lần sau khi checkpoint và threshold đã chốt.")
        elif i == 2:
            src = f"## Cấu hình\nTên run cố định: `{run_name}`."
        elif i == 3:
            src = f"RUN_NAME = '{run_name}'\nprint('RUN_NAME =', RUN_NAME)\n"
        elif "WORK_CODE = Path(" in src and "write_text(" in src:
            lines = [f"WORK_CODE = Path('{kaggle_code_dir}')", "WORK_CODE.mkdir(parents=True, exist_ok=True)"]
            for name, text in files.items():
                lines.append(f"(WORK_CODE/{name!r}).write_text({text!r}, encoding='utf-8')")
            lines.append("print('Wrote:', sorted(p.name for p in WORK_CODE.iterdir()))")
            lines.append("sys.path.insert(0, str(WORK_CODE))")
            src = "\n".join(lines)
        else:
            src = src.replace(", drop_app_family=DROP_APP_FAMILY", "")
            src = src.replace("ret = os.system(cmd)", STREAM)
            src = re.sub(r"\n\s*\+ \(\" --drop-app-family\" if DROP_APP_FAMILY else \"\"\)", "", src)
            assert "DROP_APP_FAMILY" not in src, f"cell {i} còn DROP_APP_FAMILY: {src[:200]}"
        cells.append({"cell_type": c["cell_type"], "metadata": {}, "source": src.splitlines(True), **({"outputs": [], "execution_count": None} if c["cell_type"] == "code" else {})})
    out = dict(nb)
    out["cells"] = cells
    json.dump(out, open(NB / new_name, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    allsrc = json.dumps(out, ensure_ascii=False)
    print(new_name, "cells:", len(cells), "files:", list(files), "| còn 'drop_app_family/DROP_APP_FAMILY':", len(re.findall(DROP_RE + r"|DROP_APP_FAMILY", allsrc)))


if __name__ == "__main__":
    build("06b_BiLSTM_Kaggle_v2.ipynb", "06d_BiLSTM_Kaggle_v2_final.ipynb", "bilstm_v2", "BiLSTM trên dataset v2 (bản cuối)", "Kiến trúc và siêu tham số giữ nguyên bản 06b.")
    build("07b_Mixed_Type_Self_Attention_Kaggle_v2.ipynb", "07d_Mixed_Type_Kaggle_v2_final.ipynb", "mixed_v2", "Mixed-Type Self-Attention trên dataset v2 (bản cuối)", "Kiến trúc và siêu tham số giữ nguyên bản 07b.")
