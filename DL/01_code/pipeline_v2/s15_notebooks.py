#!/usr/bin/env python3
"""S15b - Sinh notebook Kaggle chẩn đoán TRAIN: 09a (BiLSTM) và 09b (Mixed-Type) từ mã mô hình của 06e/07e và s14_ft_train.py + s15_train_diag.py.
Gắn HAI dataset: v2_network_dl_kaggle_upload (replay) và v3_ft_kaggle_upload. Chạy: python s15_notebooks.py"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
from s8_notebooks_subset import extract_files  # noqa: E402

NB = Path("D:/UIT/KLTNv2/04_notebooks")
HERE = Path(__file__).parent


def build(kind, base_nb, out_name, title, model_files, lrs):
    nb = json.load(open(NB / base_nb, encoding="utf-8"))
    d, _ = extract_files(nb, kind)
    files = {n: (d / n).read_text(encoding="utf-8") for n in model_files}
    for n in ("s14_ft_train.py", "s15_train_diag.py"):
        files[n] = (HERE / n).read_text(encoding="utf-8")
    for n, t in files.items():
        compile(t, n, "exec")
    resolve_src = "".join(nb["cells"][5]["source"])
    assert "resolve_kaggle_dataset_root" in resolve_src

    def mk(kindc, src):
        c = {"cell_type": kindc, "metadata": {}, "source": src.splitlines(True)}
        if kindc == "code":
            c.update({"outputs": [], "execution_count": None})
        return c

    stream = ("import subprocess\nproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)\n"
              "for line in proc.stdout:\n    print(line, end='', flush=True)\nret = proc.wait()\nif ret != 0:\n    raise RuntimeError(f'exit code {ret}')\n")
    cells = [
        mk("markdown", f"# {title}\n\n**Chẩn đoán CHỈ TRÊN TRAIN** (không phải kết quả chính). Câu hỏi: mô hình B (kiến trúc và đầu vào giữ nguyên) có fit được các mẫu dương TRAIN của một fold khi cho học lâu hơn / lr cao hơn không? "
                       "Nếu fit được → cấu hình fine-tune cũ (6 epoch, lr nhỏ) quá ngắn; nếu vẫn không fit được dù học lâu → đầu vào không đủ tách. Fit được TRAIN **không** chứng minh khái quát hóa.\n\n"
                       "Không đọc mẫu test của fold, không đánh giá OpTC TEST, không chọn gì theo chúng. Thiết kế ở `02_artifacts/34_train_diag_v1/STEP_34_TRAIN_DIAGNOSTIC.md`.\n\n"
                       "**Gắn đúng 2 dataset:** `v2_network_dl_kaggle_upload` (replay OpTC) và `v3_ft_kaggle_upload`. Bật GPU."),
        mk("code", "import os, sys, json, shutil\nfrom pathlib import Path\nimport torch\nprint('Torch:', torch.__version__)\nprint('CUDA:', torch.cuda.is_available())\n"),
        mk("markdown", "## Cấu hình\nMỗi cấu hình = (lr, replay) chạy `EPOCHS` epoch trên TRAIN của fold `FOLD`, mở khóa toàn bộ tham số ngay từ đầu (khác giai đoạn A/B cũ), đo độ khớp TRAIN mỗi `EVAL_EVERY` epoch."),
        mk("code", f"MODEL = '{kind}'\nFOLD = 0\nEPOCHS = 100\nEVAL_EVERY = 10\nCONFIGS = {json.dumps(lrs)}   # (tag, lr, replay mẫu/epoch)\nRUN_NAME = f'{{MODEL}}_traindiag_fold{{FOLD}}'\nprint(MODEL, FOLD, EPOCHS, CONFIGS)\n"),
        mk("code", resolve_src),
        mk("code", "ft_manifests = list(Path('/kaggle/input').rglob('ft_manifest.json'))\nassert len(ft_manifests) == 1, ft_manifests\nFT_ROOT = ft_manifests[0].parent\nprint('FT_ROOT =', FT_ROOT)\n"),
        mk("code", "WORK_CODE = Path('/kaggle/working/diag_code')\nWORK_CODE.mkdir(parents=True, exist_ok=True)\n"
                   + "\n".join(f"(WORK_CODE/{n!r}).write_text({t!r}, encoding='utf-8')" for n, t in files.items())
                   + "\nprint('Wrote:', sorted(p.name for p in WORK_CODE.iterdir()))\nsys.path.insert(0, str(WORK_CODE))\n"),
        mk("markdown", "## Chạy các cấu hình"),
        mk("code", "OUTPUT_DIR = Path(f'/kaggle/working/{RUN_NAME}')\nfor tag, lr, replay in CONFIGS:\n    cmd = (f\"python {WORK_CODE/'s15_train_diag.py'} --model {MODEL} --fold {FOLD} --epochs {EPOCHS} --lr {lr} --replay {replay} --eval-every {EVAL_EVERY} \"\n"
                   "           f\"--tag {tag} --ft-root '{FT_ROOT}' --optc-root '{DATASET_ROOT}' --code-dir '{WORK_CODE}' --out-dir '{OUTPUT_DIR}'\")\n    print('\\n=====', tag, '=====')\n    print(cmd)\n"
                   + "\n".join("    " + l for l in stream.splitlines()) + "\n"),
        mk("markdown", "## Tóm tắt"),
        mk("code", "for p in sorted(OUTPUT_DIR.glob('diag_*.json')):\n    r = json.loads(p.read_text())\n    print('===', p.name, '| TRAIN', r['train_samples'], 'dương', r['train_positives'], '| giây', r['total_seconds'])\n"
                   "    for c in r['curve']:\n        if 'fit' in c:\n            f = c['fit']\n            print(f\"  ep {c['epoch']:>3} loss {c['train_loss']:.4f} TP@0.5 {f['0.5']['tp']}/{r['train_positives']} FP@0.5 {f['0.5']['fp']} ROC {f['roc_auc']} PR {f['pr_auc']}\")\n"),
        mk("code", "archive = shutil.make_archive(f'/kaggle/working/{RUN_NAME}', 'zip', OUTPUT_DIR)\nprint('Created:', archive)\n"),
    ]
    out = dict(nb)
    out["cells"] = cells
    json.dump(out, open(NB / out_name, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(out_name, "cells:", len(cells), "files:", list(files))


if __name__ == "__main__":
    build("bilstm", "06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "09a_BiLSTM_traindiag_Kaggle.ipynb", "BiLSTM chẩn đoán TRAIN (fit mẫu dương của fine-tune)",
          ["05b_train_bilstm.py", "network_dl_dataset_v1_1.py"], [["lr3e-4_noreplay", 3e-4, 0], ["lr1e-3_noreplay", 1e-3, 0], ["lr1e-3_replay600", 1e-3, 600]])
    build("mixed", "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb", "09b_Mixed_traindiag_Kaggle.ipynb", "Mixed-Type chẩn đoán TRAIN (fit mẫu dương của fine-tune)",
          ["mixed_type_attention_model.py"], [["lr1e-4_noreplay", 1e-4, 0], ["lr3e-4_noreplay", 3e-4, 0], ["lr3e-4_replay600", 3e-4, 600]])
