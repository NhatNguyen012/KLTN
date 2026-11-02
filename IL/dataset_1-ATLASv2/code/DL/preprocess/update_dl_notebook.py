#!/usr/bin/env python3
"""Update bilstm_atlasv2.ipynb with exact path support for /kaggle/input/datasets/ngkimngn/dl-il-atlas."""

import json
from pathlib import Path

DL_DIR = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL")
NB_PATH = DL_DIR / "notebook" / "bilstm_atlasv2.ipynb"
MODEL_DIR = DL_DIR / "model"

nb = json.load(open(NB_PATH, encoding="utf-8"))

# Read current module sources
bilstm_code = (MODEL_DIR / "bilstm.py").read_text(encoding="utf-8")
dataset_code = (MODEL_DIR / "dataset.py").read_text(encoding="utf-8")
train_code = (MODEL_DIR / "train_incremental.py").read_text(encoding="utf-8")

# 1. Update Cell 4: Auto-extract archive
cell_4_src = """# Auto-extract portable archive if input.tar is attached on Kaggle and not yet extracted
from pathlib import Path
import tarfile

target = Path("/kaggle/working/optc_network_dl")
already_extracted = any(Path("/kaggle/input").rglob("dataset_manifest.json")) if Path("/kaggle/input").exists() else False

if not already_extracted and not (target / "dataset_manifest.json").exists():
    archives = list(Path("/kaggle/input").rglob("*.tar")) if Path("/kaggle/input").exists() else []
    if archives:
        target.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archives[0]) as archive:
            archive.extractall(target)
        print(f"Extracted {archives[0]} to {target}")
elif (target / "dataset_manifest.json").exists():
    print(f"Dataset already extracted in {target}")
else:
    print("Dataset already extracted in /kaggle/input; skipping archive extraction.")
"""
nb["cells"][4]["source"] = [line + "\n" for line in cell_4_src.split("\n")[:-1]] + [cell_4_src.split("\n")[-1]]

# 2. Update Cell 6 (Resolve Dataset with explicit support for /kaggle/input/datasets/ngkimngn/dl-il-atlas)
cell_6_src = """from __future__ import annotations

import shutil
from pathlib import Path


def unwrap_same_name_folder(
    root: Path,
    name: str,
) -> Path:
    path = root / name

    if not path.exists():
        raise FileNotFoundError(
            f"Missing folder: {path}"
        )

    while (path / name).is_dir():
        path = path / name

    return path


def resolve_kaggle_dataset_root(
    *,
    input_root: str | Path = "/kaggle/input",
    working_root: str | Path = "/kaggle/working/optc_network_dl",
) -> Path:
    working_root = Path(working_root)
    # Check if already extracted into working_root (e.g. from input.tar)
    if (working_root / "dataset_manifest.json").exists() and (working_root / "build_config.json").exists():
        print(f"Using already extracted dataset root at: {working_root}")
        return working_root

    # Direct official dataset candidates
    official_candidates = [
        Path("/kaggle/input/datasets/ngkimngn/dl-il-atlas"),
        Path("/kaggle/input/dl-il-atlas"),
    ]
    source_root = None
    for cand in official_candidates:
        if (cand / "dataset_manifest.json").exists() and (cand / "build_config.json").exists():
            source_root = cand
            print(f"Matched official dataset path: {source_root}")
            break

    # If not in official candidates, search recursively
    if source_root is None:
        input_root = Path(input_root)
        manifests = list(input_root.rglob("dataset_manifest.json"))
        if not manifests:
            raise FileNotFoundError(
                "Cannot find dataset_manifest.json under /kaggle/input or /kaggle/working/optc_network_dl"
            )
        for manifest in manifests:
            candidate = manifest.parent
            if (candidate / "build_config.json").exists():
                source_root = candidate
                break
        if source_root is None:
            source_root = manifests[0].parent

    print(f"Selected source dataset root: {source_root}")

    if working_root.exists():
        shutil.rmtree(working_root)
    working_root.mkdir(parents=True, exist_ok=True)

    for filename in (
        "dataset_manifest.json",
        "build_config.json",
        "README_DATASET.md",
        "optc_replay_buffer.npz",
    ):
        src = source_root / filename
        if src.exists():
            (working_root / filename).symlink_to(src)

    for folder in (
        "shards",
        "split",
        "preprocessing",
        "integrity",
        "pretrained_optc_model",
        "optc_test",
    ):
        target = source_root / folder
        if target.exists():
            real_folder = unwrap_same_name_folder(source_root, folder) if target.is_dir() else target
            (working_root / folder).symlink_to(real_folder, target_is_directory=True)

    required = [
        "dataset_manifest.json",
        "build_config.json",
        "split/network_sample_manifest.csv",
        "preprocessing/network_category_maps.json",
        "preprocessing/network_numeric_stats.json",
        "preprocessing/network_preprocess_spec.json",
        "preprocessing/network_preprocess_fingerprint.json",
        "shards/train",
        "shards/val",
        "shards/test",
    ]

    for relative in required:
        path = working_root / relative
        print(f"{'PASS' if path.exists() else 'FAIL':4s}", relative)
        if not path.exists():
            raise FileNotFoundError(path)

    for optional_item in ("optc_replay_buffer.npz", "optc_test", "pretrained_optc_model"):
        p = working_root / optional_item
        print(f"{'OPT-PASS' if p.exists() else 'OPT-SKIP':8s}", optional_item)

    return working_root


DATASET_ROOT = resolve_kaggle_dataset_root()
print('\\nDATASET_ROOT =', DATASET_ROOT)
manifest = json.loads((DATASET_ROOT/'dataset_manifest.json').read_text())
print(json.dumps(manifest['split_stats'], indent=2))
"""
nb["cells"][6]["source"] = [line + "\n" for line in cell_6_src.split("\n")[:-1]] + [cell_6_src.split("\n")[-1]]

# 2.5 Update Cell 10 to write latest modules
cell_10_src = f"""WORK_CODE = Path('/kaggle/working/step05b_code')
WORK_CODE.mkdir(parents=True, exist_ok=True)

(WORK_CODE / 'bilstm.py').write_text({repr(bilstm_code)}, encoding='utf-8')
(WORK_CODE / 'dataset.py').write_text({repr(dataset_code)}, encoding='utf-8')
(WORK_CODE / 'train_incremental.py').write_text({repr(train_code)}, encoding='utf-8')

print('Wrote training modules to:', sorted(p.name for p in WORK_CODE.iterdir()))
sys.path.insert(0, str(WORK_CODE))
"""
nb["cells"][10]["source"] = [line + "\n" for line in cell_10_src.split("\n")[:-1]] + [cell_10_src.split("\n")[-1]]

# 3. Update Cell 14 (Execution command with direct path fallbacks)
cell_14_src = """# Locate OpTC Pretrained Checkpoint & Experience Replay Buffer
INIT_MODEL = None
candidates = [
    DATASET_ROOT / 'pretrained_optc_model/best_model.pt',
    Path('/kaggle/input/datasets/ngkimngn/dl-il-atlas/pretrained_optc_model/best_model.pt'),
    Path('/kaggle/input/dl-il-atlas/pretrained_optc_model/best_model.pt'),
    Path('/kaggle/input/pretrained_optc_model/best_model.pt'),
    Path('/kaggle/input/optc_network_dl/pretrained_optc_model/best_model.pt'),
]
for cand in candidates:
    if cand.exists():
        INIT_MODEL = cand
        break

REPLAY_BUFFER = DATASET_ROOT / 'optc_replay_buffer.npz'
if not REPLAY_BUFFER.exists():
    fallback_replay = Path('/kaggle/input/datasets/ngkimngn/dl-il-atlas/optc_replay_buffer.npz')
    if fallback_replay.exists():
        REPLAY_BUFFER = fallback_replay

OPTC_TEST_DIR = DATASET_ROOT / 'optc_test'
if not OPTC_TEST_DIR.exists():
    fallback_test = Path('/kaggle/input/datasets/ngkimngn/dl-il-atlas/optc_test')
    if fallback_test.exists():
        OPTC_TEST_DIR = fallback_test

OUTPUT_DIR = Path(f'/kaggle/working/{RUN_NAME}')

cmd_parts = [
    'python',
    str(WORK_CODE / 'train_incremental.py'),
    '--dataset-root', f"'{DATASET_ROOT}'",
    '--output-dir', f"'{OUTPUT_DIR}'",
    '--epochs', '10',
    '--batch-size', '32',
    '--lr', '0.0002',
    '--weight-decay', '0.0001',
    '--patience', '3',
    '--seed', '42',
    '--run-benchmark',
]

if INIT_MODEL is not None and INIT_MODEL.exists():
    cmd_parts.extend(['--init-model', f"'{INIT_MODEL}'"])
    print(f'[PRETRAINED CHECKPOINT] Using OpTC base weights: {INIT_MODEL}')

if REPLAY_BUFFER.exists():
    cmd_parts.extend(['--replay-buffer', f"'{REPLAY_BUFFER}'", '--replay-ratio', '0.20'])
    print(f'[EXPERIENCE REPLAY] Using OpTC buffer: {REPLAY_BUFFER} (ratio: 20%)')

if OPTC_TEST_DIR.exists():
    cmd_parts.extend(['--optc-test-root', f"'{OPTC_TEST_DIR}'"])
    print(f'[BACKWARD TRANSFER] Evaluating on OpTC benchmark test set: {OPTC_TEST_DIR}')

cmd = ' '.join(cmd_parts)
print('\\nRunning Command:\\n', cmd)

import subprocess
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
for line in proc.stdout:
    print(line, end='', flush=True)
ret = proc.wait()
if ret != 0:
    raise RuntimeError(f'Training failed with exit code {ret}')
"""
nb["cells"][14]["source"] = [line + "\n" for line in cell_14_src.split("\n")[:-1]] + [cell_14_src.split("\n")[-1]]

with open(NB_PATH, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f"Successfully updated {NB_PATH}")
