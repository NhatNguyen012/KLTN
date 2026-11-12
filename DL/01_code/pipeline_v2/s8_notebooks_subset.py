#!/usr/bin/env python3
"""S8a - Sinh notebook Kaggle 06e (BiLSTM) và 07e (Mixed-Type) cho phương án B của STEP 23: BỎ các field chỉ có ở Bro và principal_class.
Giữ: app_family, proto, resp_port_class, image_dir_class, delta_t_log1p. Kiến trúc và siêu tham số giữ nguyên bản 06d/07d.

Cách làm (không build lại shards, không sửa mã train):
 1. Một cell mới sau bước resolve dataset ghi preprocessing/feature_subset.json và sửa network_preprocess_spec.json
    (active_categorical_features = các field giữ, active_numerical_features = []). Mã train đọc spec nên tự dựng embedding đúng số cột.
 2. Module dữ liệu đọc feature_subset.json: cắt x_cat theo cột giữ, x_num/x_num_missing rỗng (0 cột), x_bin = 0 hằng (token hằng, không mang thông tin).
Chạy: python s8_notebooks_subset.py"""
import json
import re
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
NB = Path("D:/UIT/KLTNv2/04_notebooks")
KEEP_CAT = ["app_family", "proto", "resp_port_class", "image_dir_class"]
DROPPED = {
    "categorical": ["service", "conn_state", "principal_class"],
    "numeric": ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"],
    "binary": ["has_missed_bytes (đặt hằng 0)"],
}

# Code của cell cấu hình (dùng chung cho notebook và smoke test; cần biến DATASET_ROOT, KEEP_CAT)
SUBSET_CELL = '''import shutil
KEEP_CAT = %(keep)r   # phương án B (STEP 23): bỏ service, conn_state, principal_class, 7 numeric Bro, has_missed_bytes
pre = DATASET_ROOT / 'preprocessing'
if pre.is_symlink():  # trên Kaggle thư mục này là symlink tới /kaggle/input (chỉ đọc) nên chép ra bản ghi được
    real = pre.resolve(); pre.unlink(); shutil.copytree(real, pre)
spec_path = pre / 'network_preprocess_spec.json'
spec = json.loads(spec_path.read_text(encoding='utf-8'))
layout = json.loads((pre / 'preprocess_spec.json').read_text(encoding='utf-8'))['model_input_layout']
all_cat = list(layout['x_cat_columns'])  # thứ tự cột x_cat trong shards (chạy lại cell này vẫn an toàn)
assert all(f in all_cat for f in KEEP_CAT), KEEP_CAT
spec['active_categorical_features'] = list(KEEP_CAT)
spec['active_numerical_features'] = []
spec['feature_subset_note'] = 'STEP 23 phuong an B: chi giu ' + ', '.join(KEEP_CAT) + ' + delta_t_log1p'
spec_path.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding='utf-8')
(pre / 'feature_subset.json').write_text(json.dumps({
    'x_cat_columns_all': all_cat, 'keep_categorical': list(KEEP_CAT), 'drop_numeric': True, 'zero_binary': True,
}, indent=2), encoding='utf-8')
print('categorical giu:', KEEP_CAT)
print('numeric: bo het (0 cot); has_missed_bytes: hang 0; delta_t_log1p: giu')
''' % {"keep": KEEP_CAT}

STREAM_OLD = "ret = proc.wait()"


def extract_files(nb, tag):
    d = Path(tempfile.mkdtemp(prefix=f"nb8_{tag}_"))
    for c in nb["cells"]:
        src = "".join(c["source"])
        if "WORK_CODE = Path(" in src and "write_text(" in src:
            m = re.search(r"WORK_CODE = Path\('([^']+)'\)", src)
            exec("import sys, os, json\nfrom pathlib import Path\n" + src.replace(m.group(0), f"WORK_CODE = Path(r'{d}')"), {})
            return d, m.group(1)
    raise RuntimeError("không thấy cell ghi mã")


def patch_dataset_module(t):
    old_init = "        self.app_family_col = None\n"
    new_init = (old_init +
                "        self.cat_idx = None\n        self.drop_numeric = False\n        self.zero_binary = False\n"
                "        subset_file = self.dataset_root / \"preprocessing\" / \"feature_subset.json\"\n"
                "        if subset_file.exists():\n"
                "            cfg = json.loads(subset_file.read_text(encoding=\"utf-8\"))\n"
                "            order = cfg[\"x_cat_columns_all\"]\n"
                "            self.cat_idx = [order.index(f) for f in cfg[\"keep_categorical\"]]\n"
                "            self.drop_numeric = bool(cfg[\"drop_numeric\"])\n"
                "            self.zero_binary = bool(cfg[\"zero_binary\"])\n")
    assert t.count(old_init) == 1
    t = t.replace(old_init, new_init)
    a = t.index("    def _x_cat(self, x):")
    b = t.index("    def __getitem__(self, index: int)")
    new_fn = ("    def _x_cat(self, x):\n"
              "        if self.cat_idx is None:\n            return x\n"
              "        return x[:, self.cat_idx]  # fancy indexing tao ban sao, shard cache giu nguyen\n\n"
              "    def _x_num(self, x):\n"
              "        return x[:, :0] if self.drop_numeric else x\n\n"
              "    def _x_bin(self, x):\n"
              "        return np.zeros_like(x) if self.zero_binary else x\n\n")
    t = t[:a] + new_fn + t[b:]
    for old, new in (('"x_num": shard["x_num"][start:end],', '"x_num": self._x_num(shard["x_num"][start:end]),'),
                     ('"x_num_missing": shard["x_num_missing"][start:end],', '"x_num_missing": self._x_num(shard["x_num_missing"][start:end]),'),
                     ('"x_bin": shard["x_bin"][start:end],', '"x_bin": self._x_bin(shard["x_bin"][start:end]),')):
        assert t.count(old) == 1, old
        t = t.replace(old, new)
    return t


def build(old_name, new_name, run_name, title):
    nb = json.load(open(NB / old_name, encoding="utf-8"))
    d, kaggle_code_dir = extract_files(nb, run_name)
    files = {}
    for p in sorted(d.iterdir()):
        t = p.read_text(encoding="utf-8")
        if p.name.startswith("network_dl_dataset"):
            t = patch_dataset_module(t)
        compile(t, p.name, "exec")
        files[p.name] = t
    cells = []

    def mk(kind, src):
        c = {"cell_type": kind, "metadata": {}, "source": src.splitlines(True)}
        if kind == "code":
            c.update({"outputs": [], "execution_count": None})
        return c

    for i, c in enumerate(nb["cells"]):
        src = "".join(c["source"])
        if i == 0:
            src = (f"# {title}\n\nKiến trúc và siêu tham số giữ nguyên bản {old_name[:3]}d. **Chỉ đổi đầu vào (STEP 23, phương án B):** bỏ các field chỉ có ở Bro "
                   "(`service`, `conn_state`, 7 numeric, `has_missed_bytes`) và `principal_class`; còn `app_family`, `proto`, `resp_port_class`, `image_dir_class`, `delta_t_log1p`. "
                   "Mục đích: cùng một tập field tính được trên dataset ngoài OpTC (skrghosh, ...).\n\n"
                   "Dataset: bản v2 đã upload (`v2_network_dl_kaggle_upload`), không build lại shards; split cấp cửa sổ phân tầng theo scenario. Một lần chạy (seed 42). "
                   "Model selection và threshold chỉ dùng VAL; TEST chỉ chạy một lần sau khi checkpoint và threshold đã chốt.\n\n"
                   "Lưu ý khi đọc kết quả: các field còn lại chính là các field cho luật `powershell.exe` F1 0.994 ở bản v2 đầy đủ, nên F1 trên OpTC không chứng minh mô hình học thêm điều gì.")
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
        cells.append(mk(c["cell_type"], src))
        if i == 5:  # ngay sau cell resolve dataset
            cells.append(mk("markdown", "## Chọn field đầu vào (phương án B)\nGhi `preprocessing/feature_subset.json` và sửa spec trong bản làm việc. Không đụng dataset gốc."))
            cells.append(mk("code", SUBSET_CELL))
    out = dict(nb)
    out["cells"] = cells
    json.dump(out, open(NB / new_name, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(new_name, "cells:", len(cells), "files:", list(files))


if __name__ == "__main__":
    build("06d_BiLSTM_Kaggle_v2_final.ipynb", "06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "bilstm_v2_subsetB", "BiLSTM trên dataset v2, đầu vào rút gọn (không field Bro)")
    build("07d_Mixed_Type_Kaggle_v2_final.ipynb", "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb", "mixed_v2_subsetB", "Mixed-Type Self-Attention trên dataset v2, đầu vào rút gọn (không field Bro)")
