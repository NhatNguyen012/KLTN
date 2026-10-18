#!/usr/bin/env python3
"""Tạo thư mục _github_export/ (nội dung sẽ đẩy lên GitHub): mã v2, notebook, tài liệu, artifact nhỏ đọc được, kết quả. Không chứa dữ liệu lớn.
Chạy lại an toàn: xóa và tạo lại _github_export/."""
import re
import shutil
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
OUT = ROOT / "_github_export"
V2 = "02_artifacts/22_v2_pipeline"
MAX_MB = 40  # mỗi file phải nhỏ hơn giới hạn 100 MB của GitHub

FILES = [
    "CLAUDE.md",
    f"{V2}/STEP_22_PIPELINE_V2_PLAN.md",
    "02_artifacts/20_fusion_design_v1/STEP_20_FUSION_DESIGN.md",
    "04_notebooks/06b_BiLSTM_Kaggle_v2.ipynb", "04_notebooks/07b_Mixed_Type_Self_Attention_Kaggle_v2.ipynb",
    "04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb", "04_notebooks/07d_Mixed_Type_Kaggle_v2_final.ipynb",
    f"{V2}/S1_join/STEP_S1_JOIN.md", f"{V2}/S1_join/schema.json", f"{V2}/S1_join/preview.csv", f"{V2}/S1_join/preview_record.json", f"{V2}/S1_join/checks.json",
    f"{V2}/S1_join/unmatched_flows_audit.csv", f"{V2}/S1_join/unmatched_counts_by_host_date.csv",
    f"{V2}/S2_windows_split/STEP_S2_WINDOWS_SPLIT.md", f"{V2}/S2_windows_split/schema.json", f"{V2}/S2_windows_split/preview.csv", f"{V2}/S2_windows_split/preview_record.json",
    f"{V2}/S2_windows_split/checks.json", f"{V2}/S2_windows_split/split_summary.json", f"{V2}/S2_windows_split/data/windows.csv",
    f"{V2}/S4_shards/STEP_S4_SHARDS.md", f"{V2}/S4_shards/schema.json", f"{V2}/S4_shards/shard_format.json", f"{V2}/S4_shards/decoded_preview.json",
    f"{V2}/S4_shards/preview.csv", f"{V2}/S4_shards/checks.json",
]
DIRS = [  # (thư mục nguồn, mẫu glob, loại trừ)
    ("00_docs/ai_agent", "*.md"), ("01_code/pipeline_v2", "*.py"), (f"{V2}/S3_preprocess", "**/*"), (f"{V2}/S5_validate", "**/*"), (f"{V2}/S7_results", "**/*"),
    ("05_models/v2_final", "**/*"),
]


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    n = 0
    todo = [ROOT / f for f in FILES]
    for d, pat in DIRS:
        todo += [p for p in (ROOT / d).glob(pat) if p.is_file() and "__pycache__" not in p.parts]
    for src in todo:
        if not src.exists():
            print("THIẾU:", src)
            continue
        assert src.stat().st_size < MAX_MB * 1e6, f"{src} quá lớn"
        dst = OUT / src.relative_to(ROOT)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        n += 1
    shutil.copy2(ROOT / "01_code/pipeline_v2/README_GITHUB.md", OUT / "README.md")  # README gốc nằm ở 01_code/pipeline_v2/README_GITHUB.md
    (OUT / ".gitignore").write_text("__pycache__/\n*.pyc\n.venv*/\n*.parquet\n*.npz\n*.zip\n.ipynb_checkpoints/\n", encoding="utf-8")
    # quét bí mật / thông tin cá nhân cơ bản trong file văn bản
    pat = re.compile(r"(ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|api[_-]?key\s*[:=]|password\s*[:=]|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,})", re.I)
    hits = []
    for p in OUT.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".md", ".py", ".json", ".csv", ".ipynb", ".txt"}:
            t = p.read_text(encoding="utf-8", errors="ignore")
            for m in pat.finditer(t):
                hits.append((str(p.relative_to(OUT)), m.group(0)[:60]))
    size = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    print(f"{n} file, {size / 1e6:.1f} MB, file lớn nhất {max(p.stat().st_size for p in OUT.rglob('*') if p.is_file()) / 1e6:.1f} MB")
    print("khớp mẫu bí mật/email:", hits[:20] if hits else "không có")


if __name__ == "__main__":
    main()
