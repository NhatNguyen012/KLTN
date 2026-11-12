#!/usr/bin/env python3
"""S14d - Sinh notebook Kaggle fine-tune: 08a (BiLSTM) và 08b (Mixed-Type) từ mã mô hình của 06e/07e và s14_ft_train.py.
Cần gắn HAI dataset vào notebook: gói OpTC v2 (v2_network_dl_kaggle_upload, có dataset_manifest.json) và gói fine-tune (v3_ft_kaggle_upload, có ft_manifest.json).
Chạy: python s14_notebooks.py"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
from s8_notebooks_subset import extract_files  # noqa: E402

NB = Path("D:/UIT/KLTNv2/04_notebooks")
TRAIN = Path(__file__).parent / "s14_ft_train.py"


def build(kind, base_nb, out_name, title, model_files, lr_note):
    nb = json.load(open(NB / base_nb, encoding="utf-8"))
    d, _ = extract_files(nb, kind)
    files = {n: (d / n).read_text(encoding="utf-8") for n in model_files}
    files["s14_ft_train.py"] = TRAIN.read_text(encoding="utf-8")
    for n, t in files.items():
        compile(t, n, "exec")
    resolve_src = "".join(nb["cells"][5]["source"])  # cell resolve dataset OpTC v2
    assert "resolve_kaggle_dataset_root" in resolve_src

    def mk(kindc, src):
        c = {"cell_type": kindc, "metadata": {}, "source": src.splitlines(True)}
        if kindc == "code":
            c.update({"outputs": [], "execution_count": None})
        return c

    stream = ("import subprocess\nproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)\n"
              "for line in proc.stdout:\n    print(line, end='', flush=True)\nret = proc.wait()\nif ret != 0:\n    raise RuntimeError(f'exit code {ret}')\n")
    cells = [
        mk("markdown", f"# {title}\n\nFine-tune mô hình B (bỏ field Bro, đầu vào 4 category + delta_t) trên **hai miền Windows** (skrghosh, FiveDirections) với **từ điển mở rộng** và **replay OpTC**; "
                       "thiết kế ở `02_artifacts/30_finetune_design_final_v1/STEP_30_FINETUNE_DESIGN_FINAL.md`.\n\n"
                       "**Gắn đúng 2 dataset vào notebook:** (1) `v2_network_dl_kaggle_upload` (OpTC v2, dùng cho replay và đánh giá OpTC TEST); (2) `v3_ft_kaggle_upload` (gói fine-tune, ~25 MB). Bật GPU.\n\n"
                       "Mỗi fold: dựng mô hình với embedding mở rộng (hàng mới = bản sao `<UNK>`), **kiểm tra khớp zero-shot trước khi train** (không khớp thì dừng), giai đoạn A (3 epoch, chỉ embedding mới + đầu phân loại), "
                       "giai đoạn B (3 epoch, mở khóa toàn bộ, lr nhỏ), đánh giá một lần trên mẫu test của fold và OpTC TEST. Không chọn ngưỡng/epoch theo dữ liệu mới; ngưỡng cố định: ngưỡng VAL OpTC cũ và 0.5. "
                       f"{lr_note}\n\nCảnh báo khi đọc kết quả: chỉ 16 sample dương, 7 đợt tấn công; cửa sổ kề cùng đợt nằm ở fold khác nhau (rò rỉ có chủ ý do chia trộn); nhãn mức tiến trình hoặc suy ra."),
        mk("code", "import os, sys, json, shutil\nfrom pathlib import Path\nimport torch\nprint('Torch:', torch.__version__)\nprint('CUDA:', torch.cuda.is_available())\n"
                   "if torch.cuda.is_available():\n    for i in range(torch.cuda.device_count()):\n        print(i, torch.cuda.get_device_name(i))\n"),
        mk("markdown", "## Cấu hình\nMột seed (42), 3 fold theo thiết kế. Đổi `FOLDS` để chạy ít hơn (ví dụ `'0'` để thử một fold)."),
        mk("code", f"MODEL = '{kind}'\nFOLDS = '0,1,2'\nSEED = 42\nOPTC_EVAL = 'test'   # 'none' để bỏ qua đánh giá OpTC TEST (nhanh hơn)\nRUN_NAME = f'{{MODEL}}_finetune_seed{{SEED}}'\nprint(MODEL, FOLDS, SEED, RUN_NAME)\n"),
        mk("markdown", "## Tìm hai dataset\nGói OpTC v2 được giải nén/liên kết như notebook 06e/07e; gói fine-tune tìm theo `ft_manifest.json`."),
        mk("code", resolve_src),
        mk("code", "ft_manifests = list(Path('/kaggle/input').rglob('ft_manifest.json'))\nassert len(ft_manifests) == 1, ft_manifests\nFT_ROOT = ft_manifests[0].parent\n"
                   "print('FT_ROOT =', FT_ROOT)\nman = json.loads((FT_ROOT/'ft_manifest.json').read_text())\nprint(json.dumps(man['summary']['fold_sizes'], indent=1))\n"
                   "print('token mới theo fold:', json.dumps(man['summary']['added_tokens'], ensure_ascii=False)[:1500])\n"),
        mk("markdown", "## Ghi mã vào /kaggle/working"),
        mk("code", "WORK_CODE = Path('/kaggle/working/ft_code')\nWORK_CODE.mkdir(parents=True, exist_ok=True)\n"
                   + "\n".join(f"(WORK_CODE/{n!r}).write_text({t!r}, encoding='utf-8')" for n, t in files.items())
                   + "\nprint('Wrote:', sorted(p.name for p in WORK_CODE.iterdir()))\nsys.path.insert(0, str(WORK_CODE))\n"),
        mk("markdown", "## Chạy fine-tune"),
        mk("code", "OUTPUT_DIR = Path(f'/kaggle/working/{RUN_NAME}')\ncmd = (\n    f\"python {WORK_CODE/'s14_ft_train.py'} --model {MODEL} \"\n    f\"--ft-root '{FT_ROOT}' --optc-root '{DATASET_ROOT}' --code-dir '{WORK_CODE}' --out-dir '{OUTPUT_DIR}' \"\n"
                   "    f\"--folds {FOLDS} --seed {SEED} --optc-eval {OPTC_EVAL}\"\n)\nprint(cmd)\n" + stream),
        mk("markdown", "## Kết quả từng fold"),
        mk("code", "for p in sorted(OUTPUT_DIR.glob('result_*.json')):\n    r = json.loads(p.read_text())\n    print('=== fold', r['fold'], '| khớp zero-shot (chênh logit lớn nhất):', r['equivalence_max_logit_diff'])\n"
                   "    print('  zero-shot trên test fold :', json.dumps(r['zero_shot_on_test']['at'], ensure_ascii=False))\n"
                   "    print('  sau fine-tune trên test  :', json.dumps(r['after_on_test']['at'], ensure_ascii=False))\n"
                   "    print('  AUC sau fine-tune        :', r['after_on_test'].get('pr_auc'), r['after_on_test'].get('roc_auc'))\n"
                   "    if 'optc_test' in r:\n        print('  OpTC TEST                :', json.dumps(r['optc_test']['at'], ensure_ascii=False))\n"),
        mk("markdown", "## Nén kết quả để tải về"),
        mk("code", "archive = shutil.make_archive(f'/kaggle/working/{RUN_NAME}', 'zip', OUTPUT_DIR)\nprint('Created:', archive)\n"),
    ]
    out = dict(nb)
    out["cells"] = cells
    json.dump(out, open(NB / out_name, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(out_name, "cells:", len(cells), "files:", list(files))


if __name__ == "__main__":
    build("bilstm", "06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "08a_BiLSTM_finetune_Kaggle.ipynb", "BiLSTM fine-tune hai miền Windows (từ điển mở rộng + replay OpTC)",
          ["05b_train_bilstm.py", "network_dl_dataset_v1_1.py"], "BiLSTM: lr giai đoạn A 1e-3, giai đoạn B 1e-4, batch 32.")
    build("mixed", "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb", "08b_Mixed_finetune_Kaggle.ipynb", "Mixed-Type fine-tune hai miền Windows (từ điển mở rộng + replay OpTC)",
          ["mixed_type_attention_model.py"], "Mixed-Type: lr giai đoạn A 1e-3, giai đoạn B 3e-5, batch 16.")
