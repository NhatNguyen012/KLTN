"""STEP 10G — Sinh notebook 06c/07c cho thi nghiem "beacon chua tung thay" (dataset holdout_scenario_k, bo app_family).

Lay 06b/07b (STEP 10) lam goc, chi doi cell cau hinh + doan mo ta. Code train/dataset giu nguyen.

    python 10g_make_unseen_notebooks.py --project-root D:\\UIT\\KLTNv2
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
from pathlib import Path

SPEC = {
    "06b_BiLSTM_Kaggle_v2.ipynb": ("06c_BiLSTM_Kaggle_unseen_beacon.ipynb", "bilstm_unseen"),
    "07b_Mixed_Type_Self_Attention_Kaggle_v2.ipynb": ("07c_Mixed_Type_Self_Attention_Kaggle_unseen_beacon.ipynb", "mixed_unseen"),
}

INTRO = """

---
## STEP 10G — Beacon chưa từng thấy (leave-one-scenario-out, bỏ `app_family`)

**Mục đích:** kiểm tra điểm cao ở split ngẫu nhiên có phải do model đã *thấy đúng template beacon* trong TRAIN hay không.
Dữ liệu: 98% positive window (530/541) là beacon C2 gọi đều đặn (SC1: `132.197.158.98:80` mỗi ~5 giây; SC2: `202.6.172.98:443` mỗi ~30 giây),
chỉ 11 window không phải beacon nên không thể bỏ beacon khỏi cả train lẫn test.

**Dataset gắn vào notebook (CHỈ MỘT):**
- `holdout_scenario_2`: TRAIN/VAL không có beacon SC2 (chỉ có beacon SC1 + SC3); TEST là toàn bộ SC2 (482 positive window, 9 host). Đặt `HOLDOUT_TAG = 'sc2'`.
- `holdout_scenario_1`: TRAIN/VAL không có beacon SC1 (chỉ có beacon SC2 + SC3); TEST là toàn bộ SC1 (78 positive window, 17 host). Đặt `HOLDOUT_TAG = 'sc1'`.

**Cách đọc kết quả:** recall trên TEST là phần model bắt được beacon *chưa từng thấy*. Recall thấp so với split ngẫu nhiên (~0.95)
nghĩa là điểm cao trước đây phụ thuộc vào việc TRAIN có cùng template. Lưu ý: scenario ≈ ngày (SC1 = 23/9, SC2 = 24–25/9),
nên "template lạ" cũng là "ngày lạ". Không có threshold ổn định vì VAL chỉ có positive của scenario đã thấy.
"""


def src(cell):
    return "".join(cell["source"])


def set_src(cell, text):
    cell["source"] = text.splitlines(keepends=True)


def sub(text, old, new):
    assert text.count(old) == 1, (old[:60], text.count(old))
    return text.replace(old, new)


def build(nb, prefix):
    nb = copy.deepcopy(nb)
    cells = nb["cells"]
    set_src(cells[0], src(cells[0]).rstrip("\n") + INTRO)

    cfg_md = [c for c in cells if c["cell_type"] == "markdown" and "Cấu hình retrain (STEP 10)" in src(c)]
    cfg = [c for c in cells if c["cell_type"] == "code" and "DROP_APP_FAMILY = False" in src(c)]
    assert len(cfg_md) == 1 and len(cfg) == 1
    set_src(cfg_md[0],
            "## Cấu hình thí nghiệm beacon chưa từng thấy (STEP 10G)\n"
            "- `DROP_APP_FAMILY = True` (mặc định): bỏ `app_family`, chỉ còn timing/bytes/service/port.\n"
            "- `HOLDOUT_TAG`: `'sc2'` hoặc `'sc1'`, phải khớp dataset đã gắn (`holdout_scenario_2` hoặc `holdout_scenario_1`).\n"
            "- Output: `" + prefix + "_{HOLDOUT_TAG}_{noapp|full}{RUN_SUFFIX}`.\n")
    set_src(cfg[0],
            "# ===== CẤU HÌNH THÍ NGHIỆM BEACON CHƯA TỪNG THẤY (STEP 10G) =====\n"
            "DROP_APP_FAMILY = True   # True -> bỏ app_family (id <UNK>=0); False chỉ để so sánh\n"
            "HOLDOUT_TAG = 'sc2'      # 'sc2' = dataset holdout_scenario_2 ; 'sc1' = dataset holdout_scenario_1\n"
            "RUN_SUFFIX = ''\n"
            f"RUN_NAME = f\"{prefix}_{{HOLDOUT_TAG}}_{{'noapp' if DROP_APP_FAMILY else 'full'}}{{RUN_SUFFIX}}\"\n"
            "assert HOLDOUT_TAG in ('sc1', 'sc2'), HOLDOUT_TAG\n"
            "print('DROP_APP_FAMILY =', DROP_APP_FAMILY)\n"
            "print('HOLDOUT_TAG     =', HOLDOUT_TAG)\n"
            "print('RUN_NAME        =', RUN_NAME)\n")

    # kiem tra dataset da gan co dung holdout khong (doc dataset_manifest sau khi resolver chay)
    anchor = [c for c in cells if c["cell_type"] == "code" and "DATASET_ROOT = resolve_kaggle_dataset_root()" in src(c)]
    assert len(anchor) == 1
    set_src(anchor[0], src(anchor[0]).rstrip("\n") + (
        "\n\n# --- STEP 10G: dam bao gan dung dataset holdout ---\n"
        "_expected = {'sc1': 'scenario_1', 'sc2': 'scenario_2'}[HOLDOUT_TAG]\n"
        "_got = manifest.get('loso_contract', {}).get('heldout_scenario')\n"
        "assert _got == _expected, f'Dataset gan vao la heldout={_got!r} nhung HOLDOUT_TAG={HOLDOUT_TAG!r} can {_expected!r}'\n"
        "print('Dataset heldout scenario:', _got, '-> OK')\n"
    ))
    return nb


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    args = ap.parse_args()
    nbdir = Path(args.project_root) / "04_notebooks"
    for srcname, (dstname, prefix) in SPEC.items():
        nb = json.loads((nbdir / srcname).read_text(encoding="utf-8"))
        out = build(nb, prefix)
        for c in out["cells"]:
            if c["cell_type"] == "code":
                ast.parse(src(c))
        dst = nbdir / dstname
        if dst.exists():
            raise FileExistsError(dst)
        dst.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
        print("[WROTE]", dst)


if __name__ == "__main__":
    main()
