"""STEP 10 (Phần A) — sinh notebook 06b/07b có tuỳ chọn DROP_APP_FAMILY.

Đọc notebook 06/07 gốc (không sửa), vá code nhúng (chuỗi trong cell "Write versioned
training modules") và các cell cấu hình/chạy, rồi ghi ra notebook mới. Mỗi lần vá đều
assert số lần khớp để không vá nhầm/trượt.

    python 10_make_noapp_notebooks.py --project-root D:\\UIT\\KLTNv2
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
from pathlib import Path

SRC_06 = "06_BiLSTM_Kaggle.ipynb"
SRC_07 = "07_Mixed_Type_Self_Attention_Kaggle.ipynb"
DST_06 = "06b_BiLSTM_Kaggle_v2.ipynb"
DST_07 = "07b_Mixed_Type_Self_Attention_Kaggle_v2.ipynb"


def sub(text: str, old: str, new: str, *, count: int = 1, what: str = "") -> str:
    found = text.count(old)
    if found != count:
        raise RuntimeError(f"patch '{what or old[:60]}': expected {count} match, got {found}")
    return text.replace(old, new)


# ---------------------------------------------------------------- dataset module
DATASET_INIT_BLOCK = '''        self.drop_app_family = bool(drop_app_family)
        self.app_family_col = None
        if self.drop_app_family:
            # Ablation A1: thay cot app_family bang id <UNK>=0 (khong build lai shards).
            pre = self.dataset_root / "preprocessing"
            spec = json.loads((pre / "network_preprocess_spec.json").read_text(encoding="utf-8"))
            maps = json.loads((pre / "network_category_maps.json").read_text(encoding="utf-8"))
            cat_fields = list(spec["active_categorical_features"])
            if "app_family" not in cat_fields:
                raise RuntimeError("drop_app_family=True nhung app_family khong phai active categorical")
            self.app_family_col = cat_fields.index("app_family")
            if self.app_family_col != 0:
                raise RuntimeError(f"app_family col={self.app_family_col}, ky vong 0")
            if int(maps["fields"]["app_family"]["mapping"]["<UNK>"]) != 0:
                raise RuntimeError("<UNK> id cua app_family khac 0")
'''

DATASET_METHOD = '''    def _x_cat(self, x):
        if self.app_family_col is None:
            return x
        x = x.copy()  # shard cache giu nguyen, chi sua ban sao
        x[:, self.app_family_col] = 0
        return x

'''


def patch_dataset(text: str, *, multiline_sig: bool) -> str:
    text = sub(text, "import csv\n", "import csv\nimport json\n", what="import json")
    if multiline_sig:
        text = sub(
            text,
            "        cache_shards: int = 2,\n    ):",
            "        cache_shards: int = 2,\n        drop_app_family: bool = False,\n    ):",
            what="ctor sig 07",
        )
    else:
        text = sub(
            text,
            "*, cache_shards: int = 2):",
            "*, cache_shards: int = 2, drop_app_family: bool = False):",
            what="ctor sig 06",
        )
    text = sub(
        text,
        "        self.cache_shards = max(1, int(cache_shards))\n",
        "        self.cache_shards = max(1, int(cache_shards))\n" + DATASET_INIT_BLOCK,
        what="ctor body",
    )
    text = sub(
        text,
        "    def __getitem__(self, index: int) -> dict[str, Any]:\n",
        DATASET_METHOD + "    def __getitem__(self, index: int) -> dict[str, Any]:\n",
        what="_x_cat method",
    )
    text = sub(
        text,
        '"x_cat": shard["x_cat"][start:end],',
        '"x_cat": self._x_cat(shard["x_cat"][start:end]),',
        what="x_cat getitem",
    )
    return text


# ---------------------------------------------------------------- train scripts
PROBE = '''    if args.drop_app_family:
        _probe = train_ds[0]["x_cat"]
        if int(_probe[:, train_ds.app_family_col].max()) != 0:
            raise RuntimeError("drop_app_family: cot app_family van con id != 0")
        print("[DROP app_family] x_cat[:, app_family] -> <UNK>=0 cho train/val/test")
'''


def patch_train(text: str, *, parser_name: str, pin_line: str, three_ds_single_line: bool) -> str:
    text = sub(
        text,
        f'    {parser_name}.add_argument("--no-amp", action="store_true")\n',
        f'    {parser_name}.add_argument("--no-amp", action="store_true")\n'
        f'    {parser_name}.add_argument(\n'
        f'        "--drop-app-family",\n'
        f'        action="store_true",\n'
        f'        help="Ablation: thay x_cat[:, :, app_family] bang <UNK>=0 (train/val/test)",\n'
        f'    )\n',
        what="argparse",
    )
    if three_ds_single_line:
        text = sub(
            text,
            "cache_shards=args.cache_shards)",
            "cache_shards=args.cache_shards, drop_app_family=args.drop_app_family)",
            count=3,
            what="3 datasets 06",
        )
    else:
        text = sub(
            text,
            "        cache_shards=args.cache_shards,\n    )",
            "        cache_shards=args.cache_shards,\n        drop_app_family=args.drop_app_family,\n    )",
            count=3,
            what="3 datasets 07",
        )
    text = sub(text, pin_line, PROBE + pin_line, what="probe")
    # dataset build bang 08c (LOSO/random) ghi key step05f_c_..., dataset v1.1 goc ghi step04c_...
    text = sub(
        text,
        'manifest["source"]["step04c_preprocess_fingerprint"]',
        '(manifest["source"].get("step04c_preprocess_fingerprint") '
        'or manifest["source"]["step05f_c_preprocess_fingerprint"])',
        what="fingerprint key",
    )
    text = sub(
        text,
        '        "categorical_fields": cat_fields,\n',
        '        "drop_app_family": bool(args.drop_app_family),\n        "categorical_fields": cat_fields,\n',
        what="config drop flag",
    )
    return text


def patch_audit(text: str) -> str:
    return sub(
        text,
        "        args.split,\n        cache_shards=1,\n    )",
        "        args.split,\n        cache_shards=1,\n        drop_app_family=bool(config.get(\"drop_app_family\", False)),\n    )",
        what="audit dataset",
    )


# ---------------------------------------------------------------- notebook plumbing
def src_text(cell: dict) -> str:
    return "".join(cell["source"])


def set_src(cell: dict, text: str) -> None:
    cell["source"] = text.splitlines(keepends=True)


def rewrite_embedded(cell: dict, patches: dict[str, callable]) -> None:
    """Giải mã dòng `(WORK_CODE/'name').write_text('<literal>', encoding='utf-8')`, vá, mã hoá lại."""
    lines = src_text(cell).split("\n")
    done = set()
    for i, line in enumerate(lines):
        for name, fn in patches.items():
            prefix = f"(WORK_CODE/'{name}').write_text("
            if not line.startswith(prefix):
                continue
            call = ast.parse(line).body[0].value
            module_text = call.args[0].value
            new_text = fn(module_text)
            lines[i] = f"{prefix}{new_text!r}, encoding='utf-8')"
            done.add(name)
    missing = set(patches) - done
    if missing:
        raise RuntimeError(f"embedded module not found: {sorted(missing)}")
    set_src(cell, "\n".join(lines))


def find_cell(nb: dict, needle: str, *, kind: str = "code") -> dict:
    hits = [c for c in nb["cells"] if c["cell_type"] == kind and needle in src_text(c)]
    if len(hits) != 1:
        raise RuntimeError(f"cell '{needle}': expected 1, got {len(hits)}")
    return hits[0]


def code_cell(text: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": text.splitlines(keepends=True),
    }


def md_cell(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.splitlines(keepends=True)}


def config_cells(prefix: str) -> list[dict]:
    md = (
        "## Cấu hình retrain (STEP 10)\n"
        "- `DROP_APP_FAMILY = True`: thay toàn bộ `x_cat[:, :, app_family]` bằng `<UNK>` (id 0) cho "
        "train/val/test (ablation A1, không build lại shards).\n"
        "- `RUN_SUFFIX`: hậu tố tuỳ chọn (vd. `_seed1`) để không ghi đè khi train nhiều dataset.\n"
        "- Output: `" + prefix + "_{noapp|full}{RUN_SUFFIX}`; `drop_app_family` được ghi vào `config.json`.\n"
    )
    code = (
        "# ===== CẤU HÌNH RETRAIN (STEP 10) =====\n"
        "DROP_APP_FAMILY = False  # True -> bỏ app_family (id <UNK>=0)\n"
        "RUN_SUFFIX = ''          # vd. '_seed1'\n"
        f"RUN_NAME = f\"{prefix}_{{'noapp' if DROP_APP_FAMILY else 'full'}}{{RUN_SUFFIX}}\"\n"
        "print('DROP_APP_FAMILY =', DROP_APP_FAMILY)\n"
        "print('RUN_NAME =', RUN_NAME)\n"
    )
    return [md_cell(md), code_cell(code)]


GUARD_OLD = """    if not manifests:
        raise FileNotFoundError(
            "Cannot find dataset_manifest.json under /kaggle/input"
        )
"""
GUARD_NEW = GUARD_OLD + """
    if len(manifests) > 1:
        raise RuntimeError(
            "Nhieu dataset_manifest.json duoc tim thay (vd. dataset LOSO co 3 holdout). "
            "Chi gan MOT dataset vao notebook:\\n"
            + "\\n".join(str(m) for m in manifests)
        )
"""


def robust_resolver_text(nb07: dict) -> str:
    """Resolver cua notebook 07 (unwrap thu muc lap ten do Kaggle tu giai nen zip: split/split, shards/shards...)
    + chan truong hop gan nhieu manifest."""
    cell = find_cell(nb07, "def unwrap_same_name_folder")
    return sub(src_text(cell), GUARD_OLD, GUARD_NEW, what="resolver guard")


def build_06(nb: dict, nb07: dict) -> dict:
    nb = copy.deepcopy(nb)
    cells = nb["cells"]

    # Resolver cu cua 06 tra ve root "tho" khi thu muc split/preprocessing/shards ton tai,
    # nen loi FileNotFoundError khi Kaggle giai nen zip thanh split/split/... -> dung resolver cua 07.
    set_src(find_cell(nb, "def resolve_kaggle_dataset_root"), robust_resolver_text(nb07))

    set_src(cells[0], src_text(cells[0]).rstrip("\n") + (
        "\n\n**v2 (STEP 10):** có tuỳ chọn `DROP_APP_FAMILY` (xem cell cấu hình). Dùng cho dataset host-split cũ "
        "hoặc dataset random-split `seed_k` (10c). Notebook gốc `06_BiLSTM_Kaggle.ipynb` giữ nguyên.\n"
    ))

    emb = find_cell(nb, "(WORK_CODE/'05b_train_bilstm.py')")
    rewrite_embedded(emb, {
        "network_dl_dataset_v1_1.py": lambda t: patch_dataset(t, multiline_sig=False),
        "05b_train_bilstm.py": lambda t: patch_train(
            t, parser_name="p", pin_line='    pin = device.type == "cuda"\n', three_ds_single_line=True
        ),
    })

    sanity = find_cell(nb, "ds = PackedNetworkDataset(DATASET_ROOT, 'train', cache_shards=1)")
    t = src_text(sanity)
    t = sub(t, "'train', cache_shards=1)", "'train', cache_shards=1, drop_app_family=DROP_APP_FAMILY)", what="sanity ds")
    t = t.rstrip("\n") + "\nprint('app_family ids in batch:', sorted(set(b['x_cat'][:, :, 0].unique().tolist()))[:10])\n"
    set_src(sanity, t)

    run = find_cell(nb, "OUTPUT_DIR = Path('/kaggle/working/bilstm_baseline_v1')")
    t = src_text(run)
    t = sub(t, "Path('/kaggle/working/bilstm_baseline_v1')", "Path(f'/kaggle/working/{RUN_NAME}')", what="outdir")
    t = sub(t, '"--patience 3 --num-workers 2"\n', '"--patience 3 --num-workers 2"\n    + (" --drop-app-family" if DROP_APP_FAMILY else "")\n', what="cmd flag")
    set_src(run, t)

    zipc = find_cell(nb, "make_archive('/kaggle/working/bilstm_baseline_v1'")
    set_src(zipc, sub(src_text(zipc), "'/kaggle/working/bilstm_baseline_v1'", "f'/kaggle/working/{RUN_NAME}'", what="zip"))

    idx = cells.index(find_cell(nb, "import os, sys, json, shutil"))
    cells[idx + 1:idx + 1] = config_cells("bilstm_v2")
    return nb


def build_07(nb: dict, nb07: dict | None = None) -> dict:
    nb = copy.deepcopy(nb)
    cells = nb["cells"]

    set_src(find_cell(nb, "def unwrap_same_name_folder"), robust_resolver_text(nb07 or nb))

    set_src(cells[0], src_text(cells[0]).rstrip("\n") + (
        "\n\n**v2 (STEP 10):** có tuỳ chọn `DROP_APP_FAMILY` (xem cell cấu hình). Kiến trúc không đổi; khi bật, "
        "cột app_family chỉ nhận id `<UNK>`. Notebook gốc `07_Mixed_Type_Self_Attention_Kaggle.ipynb` giữ nguyên.\n"
    ))

    emb = find_cell(nb, "(WORK_CODE/'05e_train_mixed_type_attention.py')")
    rewrite_embedded(emb, {
        "network_dl_dataset_v1_1.py": lambda t: patch_dataset(t, multiline_sig=True),
        "05e_train_mixed_type_attention.py": lambda t: patch_train(
            t, parser_name="parser", pin_line='    pin_memory = device.type == "cuda"\n', three_ds_single_line=False
        ),
        "05e_attention_audit.py": patch_audit,
    })

    sanity = find_cell(nb, "ds = PackedNetworkDataset(DATASET_ROOT, 'train', cache_shards=1)")
    t = src_text(sanity)
    t = sub(t, "'train', cache_shards=1)", "'train', cache_shards=1, drop_app_family=DROP_APP_FAMILY)", what="sanity ds")
    t = sub(t, "batch = next(iter(loader))\n", "batch = next(iter(loader))\nprint('app_family ids in batch:', sorted(set(batch['x_cat'][:, :, 0].unique().tolist()))[:10])\n", what="sanity print")
    set_src(sanity, t)

    run = find_cell(nb, "OUTPUT_DIR = Path('/kaggle/working/mixed_type_attention_v1')")
    t = src_text(run)
    t = sub(t, "Path('/kaggle/working/mixed_type_attention_v1')", "Path(f'/kaggle/working/{RUN_NAME}')", what="outdir")
    t = sub(t, '    "--eval-progress-every 100"\n', '    "--eval-progress-every 100"\n    + (" --drop-app-family" if DROP_APP_FAMILY else "")\n', what="cmd flag")
    set_src(run, t)

    zipc = find_cell(nb, "'/kaggle/working/mixed_type_attention_v1',")
    set_src(zipc, sub(src_text(zipc), "'/kaggle/working/mixed_type_attention_v1',", "f'/kaggle/working/{RUN_NAME}',", what="zip"))

    idx = cells.index(find_cell(nb, "import os, sys, json, shutil"))
    cells[idx + 1:idx + 1] = config_cells("mixed_v2")
    return nb


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    args = ap.parse_args()
    nbdir = Path(args.project_root) / "04_notebooks"

    nb07_src = json.loads((nbdir / SRC_07).read_text(encoding="utf-8"))

    for src, dst, builder in ((SRC_06, DST_06, build_06), (SRC_07, DST_07, build_07)):
        nb = json.loads((nbdir / src).read_text(encoding="utf-8"))
        out = builder(nb, nb07_src)
        for c in out["cells"]:
            if c["cell_type"] == "code":
                ast.parse("".join(c["source"]))  # cú pháp cell hợp lệ
                for m in ast.walk(ast.parse("".join(c["source"]))):
                    if (isinstance(m, ast.Call) and isinstance(m.func, ast.Attribute)
                            and m.func.attr == "write_text" and m.args
                            and isinstance(m.args[0], ast.Constant) and isinstance(m.args[0].value, str)
                            and (m.func.value.__class__ is ast.BinOp)):
                        ast.parse(m.args[0].value)  # module nhúng hợp lệ cú pháp
        target = nbdir / dst
        if target.exists():
            raise FileExistsError(f"{target} đã tồn tại; không ghi đè")
        target.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
        print("[WROTE]", target)


if __name__ == "__main__":
    main()
