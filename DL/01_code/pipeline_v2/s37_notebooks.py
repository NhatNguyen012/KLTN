#!/usr/bin/env python3
"""S37e - Sinh notebook Kaggle IL OpTC -> ATLASv2 + THEIA: 11a (BiLSTM) va 11b (Mixed-Type) tu ma mo hinh cua 06e/07e, s14_ft_train.py (ham dung chung) va s36_il_train.py.
Can gan HAI dataset: goi OpTC v2 (v2_network_dl_kaggle_upload) va goi IL ATLASv2 (il_atlas_theia_kaggle_upload, co ft_manifest.json).
Chay: python s37_notebooks.py"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
from s8_notebooks_subset import extract_files  # noqa: E402

NB = Path("D:/UIT/KLTNv2/04_notebooks")
HERE = Path(__file__).parent


RESULTS_SRC = """for p in sorted(OUTPUT_DIR.glob('result_*.json')):
    r = json.loads(p.read_text())
    print('=== fold', r['fold'], '| khớp khởi tạo (chênh logit):', r['equivalence_max_logit_diff'], '| tốt nhất:', r['best_stage'], 'epoch', r['best_epoch'])
    print('  ngưỡng (chọn trên VAL gộp): logit', round(r['threshold_logit'], 3), '= prob', round(r['threshold_prob'], 4))
    for role in ('train', 'val', 'test'):
        x = r[f'new_{role}']
        print(f'  GỘP {role:5s}:', x['n'], 'mẫu,', x['positives'], 'dương |', json.dumps(x['confusion']), '| PR-AUC', x.get('pr_auc'), 'ROC-AUC', x.get('roc_auc'))
        for ds, y in r[f'new_{role}_by_domain'].items():
            print(f'     {ds:8s}', y['n'], 'mẫu,', y['positives'], 'dương |', json.dumps(y['confusion']))
    print('  TEST theo kịch bản:', json.dumps(r['test_by_scenario']))
    if 'optc_test' in r:
        o = r['optc_test']
        print('  OpTC TEST (ngưỡng VAL gộp)   :', json.dumps(o['at_val_threshold']))
        print('  OpTC TEST (ngưỡng gốc OpTC)  :', json.dumps(o['at_optc_base_threshold']))
"""


def build(kind, base_nb, out_name, title, model_files, lr_note):
    nb = json.load(open(NB / base_nb, encoding="utf-8"))
    d, _ = extract_files(nb, kind)
    files = {n: (d / n).read_text(encoding="utf-8") for n in model_files}
    files["s14_ft_train.py"] = (HERE / "s14_ft_train.py").read_text(encoding="utf-8")
    files["s36_il_train.py"] = (HERE / "s36_il_train.py").read_text(encoding="utf-8")
    files["s37_il_train.py"] = (HERE / "s37_il_train.py").read_text(encoding="utf-8")
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
        mk("markdown", f"# {title}\n\nIncremental learning **OpTC -> ATLASv2 + THEIA** (hai miền gộp, VAL gộp) cho mô hình B (4 category + `delta_t`; đã bỏ field Bro và `principal_class`), "
                       "có **từ điển mở rộng**, **replay OpTC thật**, **mở dần đóng băng** (freezing/gradual unfreezing) và **VAL riêng** để chọn checkpoint/ngưỡng. "
                       "Thiết kế ở `02_artifacts/44_freezing_design_v1/STEP_44_FREEZING_DESIGN.md` và `02_artifacts/48_il_atlasv2_dataset_v1/STEP_48_IL_ATLASV2_DATASET.md` và `02_artifacts/49_il_theia_dataset_v1/STEP_49_IL_THEIA_DATASET.md`.\n\n"
                       "**Gắn đúng 2 dataset:** (1) `v2_network_dl_kaggle_upload` (OpTC v2: replay và đánh giá OpTC TEST); (2) `il_atlas_theia_kaggle_upload` (gói ATLASv2, ~7 MB). Bật GPU.\n\n"
                       "Mỗi fold (3 fold, chia trộn theo cửa sổ, seed 42): kiểm tra khởi tạo tương đương mô hình gốc; giai đoạn **A** (hàng embedding mới + đầu phân loại) -> **B1** (+ encoder sự kiện) -> **B2** (+ tầng chuỗi) -> **C** (+ embedding cũ, lr nhỏ); "
                       "mỗi giai đoạn dừng sớm theo VAL; checkpoint và ngưỡng chỉ chọn trên VAL; TEST và OpTC TEST tính **một lần**. "
                       f"{lr_note}\n\n"
                       "**Cảnh báo khi đọc kết quả:** nhãn là nhãn REAPr mức **tiến trình/cạnh** (ATLASv2: firefox có cả 0 và 1; 10 cuộc tấn công gần giống nhau). **THEIA chỉ có 11 cửa sổ dương (16 mẫu dương mỗi fold), VAL chỉ ~2 mẫu dương/fold => ngưỡng và checkpoint rất không ổn định; trường `proto` trống; nhiều token tên chương trình dương là tên do kẻ tấn công đặt (đường tắt).** chia trộn theo cửa sổ nên cửa sổ kề cùng cuộc tấn công nằm ở các phần khác nhau (rò rỉ có chủ ý) "
                       "=> điểm cao đo khả năng nhận ra mẫu đã thấy, không đo phát hiện tấn công mới. Không có so sánh trước/sau fine-tune; chỉ có ma trận nhầm lẫn TRAIN, VAL, TEST (từng miền và gộp) và OpTC TEST."),
        mk("code", "import os, sys, json, shutil\nfrom pathlib import Path\nimport torch\nprint('Torch:', torch.__version__)\nprint('CUDA:', torch.cuda.is_available())\n"
                   "if torch.cuda.is_available():\n    for i in range(torch.cuda.device_count()):\n        print(i, torch.cuda.get_device_name(i))\n"),
        mk("markdown", "## Cấu hình\nMột seed (42), 3 fold. Đổi `FOLDS` để chạy ít hơn (ví dụ `'0'`). `OPTC_EVAL='none'` bỏ đánh giá OpTC TEST (nhanh hơn)."),
        mk("code", f"MODEL = '{kind}'\nFOLDS = '0,1,2'\nSEED = 42\nOPTC_EVAL = 'test'\nRUN_NAME = f'{{MODEL}}_il_atlas_theia_seed{{SEED}}'\nprint(MODEL, FOLDS, SEED, RUN_NAME)\n"),
        mk("markdown", "## Tìm hai dataset"),
        mk("code", resolve_src),
        mk("code", "ft_manifests = list(Path('/kaggle/input').rglob('ft_manifest.json'))\nassert len(ft_manifests) == 1, ft_manifests\nFT_ROOT = ft_manifests[0].parent\n"
                   "print('FT_ROOT =', FT_ROOT)\nman = json.loads((FT_ROOT/'ft_manifest.json').read_text())\nprint(man['version'], man['domains'])\nprint(json.dumps(man['summary']['fold_sizes'], indent=1))\n"
                   "print('token mới theo fold:', json.dumps(man['summary']['added_tokens'], ensure_ascii=False)[:1500])\n"),
        mk("markdown", "## Ghi mã vào /kaggle/working"),
        mk("code", "WORK_CODE = Path('/kaggle/working/il_code')\nWORK_CODE.mkdir(parents=True, exist_ok=True)\n"
                   + "\n".join(f"(WORK_CODE/{n!r}).write_text({t!r}, encoding='utf-8')" for n, t in files.items())
                   + "\nprint('Wrote:', sorted(p.name for p in WORK_CODE.iterdir()))\nsys.path.insert(0, str(WORK_CODE))\n"),
        mk("markdown", "## Chạy IL"),
        mk("code", "OUTPUT_DIR = Path(f'/kaggle/working/{RUN_NAME}')\ncmd = (\n    f\"python {WORK_CODE/'s37_il_train.py'} --model {MODEL} \"\n    f\"--ft-root '{FT_ROOT}' --optc-root '{DATASET_ROOT}' --code-dir '{WORK_CODE}' --out-dir '{OUTPUT_DIR}' \"\n"
                   "    f\"--folds {FOLDS} --seed {SEED} --optc-eval {OPTC_EVAL}\"\n)\nprint(cmd)\n" + stream),
        mk("markdown", "## Ma trận nhầm lẫn từng fold (ngưỡng chọn trên VAL)"),
        mk("code", RESULTS_SRC),
        mk("markdown", "## Nén kết quả để tải về"),
        mk("code", "archive = shutil.make_archive(f'/kaggle/working/{RUN_NAME}', 'zip', OUTPUT_DIR)\nprint('Created:', archive)\n"),
    ]
    out = dict(nb)
    out["cells"] = cells
    json.dump(out, open(NB / out_name, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(out_name, "cells:", len(cells), "files:", list(files))


if __name__ == "__main__":
    build("bilstm", "06e_BiLSTM_Kaggle_v2_subsetB.ipynb", "11a_BiLSTM_IL_ATLASv2_THEIA_Kaggle.ipynb", "BiLSTM IL OpTC -> ATLASv2 + THEIA (từ điển mở rộng + mở dần + replay OpTC thật)",
          ["05b_train_bilstm.py", "network_dl_dataset_v1_1.py"], "BiLSTM: lr giai đoạn A 1e-3; B1/B2/C lr cơ sở 3e-4 (hệ số theo nhóm), batch 32; các giá trị này chưa được tinh chỉnh.")
    build("mixed", "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb", "11b_Mixed_IL_ATLASv2_THEIA_Kaggle.ipynb", "Mixed-Type IL OpTC -> ATLASv2 + THEIA (từ điển mở rộng + mở dần + replay OpTC thật)",
          ["mixed_type_attention_model.py"], "Mixed-Type: lr giai đoạn A 1e-3; B1/B2/C lr cơ sở 1e-4 (hệ số theo nhóm), batch 16; các giá trị này chưa được tinh chỉnh.")
