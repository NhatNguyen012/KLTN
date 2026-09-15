#!/usr/bin/env python3
"""Generate standalone notebooks with the reviewed runtime embedded.

Run with --profile kaggle on Nguyen, --profile ec2-100m on main. No dataset
artifacts are rebuilt. Runtime code is embedded so existing Kaggle input
packages remain usable without attaching a second helper-code dataset.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline_contract import validate_output_path


def cell(kind, source):
    result = dict(cell_type=kind, id=hashlib.sha256(source.encode()).hexdigest()[:12],
                  metadata={}, source=source.splitlines(keepends=True))
    if kind == 'code':
        result.update(execution_count=None, outputs=[])
    return result


def notebook(model, profile, runtime):
    main = profile == 'ec2-100m'
    title = f'# OpTC Host ML — {model.upper()}, ' + ('shared 100,000,000-row TRAIN sample' if main else 'Kaggle CPU-aware sampled training')
    intro = title + '''

All positive TRAIN events are retained. The persisted 75/10/15 split, vocabulary,
and full validation/test are unchanged. Run each model separately.
The setup cell contains generated shared runtime code so the notebook also works
with the existing full-input Kaggle package; no helper upload is required.

Configure MANIFEST, OUTPUT_ROOT and SAMPLE_DIR for EC2. Share the **completed**
sample directory (including plan/manifest/parts) across models or reproduce it
with identical input, runtime and NumPy/SciPy versions. RAM limits are explicit;
an incompatible sample/checkpoint raises an error instead of silently changing it.

The final metric evaluation retains every validation/test event. It checkpoints
by shard and scores identical binary feature rows only once within each batch.
Kaggle's session limit still applies; persist /kaggle/working to reuse checkpoints
in another session. Model checkpoints alone do not preserve a terminated VM disk.
'''
    if main:
        intro += '\nTRAIN uses exactly 100,000,000 rows, seed 01. This is sampled training, not full TRAIN.\n'
    else:
        intro += '\nTRAIN retains the previous seed-01 Bernoulli negative sampling (30:1 in expectation).\n'
    setup = f'''# EDIT THESE SETTINGS. Keep the runtime section below generated.
from pathlib import Path
import os, sys, json, subprocess
MODEL_NAME = {model!r}
PROFILE = {profile!r}
MANIFEST = Path(os.environ['OPTC_MANIFEST']) if os.environ.get('OPTC_MANIFEST') else None
OUTPUT_ROOT = Path('/kaggle/working') if Path('/kaggle/input').exists() else Path.cwd() / 'output/host_ml_training'
OUTPUT_ROOT = Path(os.environ.get('OPTC_OUTPUT', str(OUTPUT_ROOT)))
TRAIN_TARGET_ROWS = {'100_000_000' if main else 'None'}
NEG_PER_POS = 30
SEED = 1
CPU_THREADS = None  # None = CPUs actually granted by affinity/cgroup quota
DEVICE = os.environ.get('OPTC_DEVICE', 'auto')  # xgb only: auto/cpu/cuda
MAX_MATRIX_GIB = {64 if main else 4}
MAX_SAMPLE_NNZ = 1_800_000_000  # safety margin below RF's int32 nnz limit
BOOST_ROUNDS = 300
RF_TREES = 500
BALANCE_CLASSES = {not main!r}  # preserve main XGB/LGBM loss; RF remains balanced
DEDUPE_PREDICTION = True  # exact binary rows, unchanged event weights/coverage
DEDUPE_BUDGET_MIB = 128 if PROFILE == 'ec2-100m' else 64
RANKING_BINS = 100_000
SAMPLE_DIR = Path(os.environ.get('OPTC_SAMPLE_DIR', str(OUTPUT_ROOT / ('train-100m-seed01' if TRAIN_TARGET_ROWS else 'train-neg30-seed01'))))

if MANIFEST is None:
    candidates = []
    roots = [Path('/kaggle/input')] if Path('/kaggle/input').exists() else [Path.cwd() / 'code/output/host_ml/model_input']
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob('manifest.json'):
            try:
                candidate = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if isinstance(candidate, dict) and candidate.get('format') == 'host_binary_delta_npz':
                candidates.append(path)
    if len(candidates) != 1:
        raise RuntimeError(f'Set MANIFEST or OPTC_MANIFEST explicitly; found {{candidates}}')
    MANIFEST = candidates[0]
MANIFEST = Path(MANIFEST).resolve()
sys.path.insert(0, str(MANIFEST.parent))
# BEGIN EMBEDDED RUNTIME (regenerate with refresh_host_notebooks.py)
RUNTIME_SHA256 = {hashlib.sha256(runtime.encode()).hexdigest()!r}
'''
    setup += runtime
    setup += '''
# END EMBEDDED RUNTIME
meta = json.loads(MANIFEST.read_text())
used_volumes = {p['volume'] for p in meta['shards']}
packaged = all((MANIFEST.parent / 'volumes' / key).is_dir() for key in used_volumes)
VOLUME_ROOTS = {key: MANIFEST.parent / 'volumes' / key for key in meta['volumes']} if packaged else None
with phase('open manifest'):
    data = TrainingDataset(MANIFEST, VOLUME_ROOTS)
OUTPUT_ROOT = output_path(OUTPUT_ROOT, data.protected)
SAMPLE_DIR = output_path(SAMPLE_DIR, data.protected)
OUTPUT = output_path(OUTPUT_ROOT / (MODEL_NAME + '-' + PROFILE), [*data.protected, SAMPLE_DIR])
CPU_THREADS = cpu_budget(CPU_THREADS)
LOADER_WORKERS = min(4, max(1, CPU_THREADS // 4))
PREDICT_THREADS = max(1, CPU_THREADS - LOADER_WORKERS)
_blas_limiter = configure_threads(CPU_THREADS)
if DEVICE == 'auto':
    try:
        DEVICE = 'cuda' if subprocess.run(['nvidia-smi'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=5).returncode == 0 else 'cpu'
    except (OSError, subprocess.TimeoutExpired):
        DEVICE = 'cpu'
print(f'Manifest: {MANIFEST}; CPU train={CPU_THREADS}, predict={PREDICT_THREADS}, decode={LOADER_WORKERS}; XGB device={DEVICE}', flush=True)
print(f'Available RAM: {available_bytes()/2**30:.2f} GiB; sample={SAMPLE_DIR}; output={OUTPUT}', flush=True)
'''
    train = '''with phase('TRAIN sample preparation / resume'):
    sample = prepare_sample(data, SAMPLE_DIR, target_rows=TRAIN_TARGET_ROWS,
                            neg_per_pos=NEG_PER_POS, seed=SEED, workers=LOADER_WORKERS,
                            max_nnz=MAX_SAMPLE_NNZ)
model, raw_predict, model_receipt = fit_sample_model(
    data, SAMPLE_DIR, sample, OUTPUT / 'model', MODEL_NAME, CPU_THREADS,
    max_matrix_bytes=MAX_MATRIX_GIB * 2**30, device=DEVICE if MODEL_NAME == 'xgb' else 'cpu',
    balance_classes=BALANCE_CLASSES, rounds=BOOST_ROUNDS, rf_trees=RF_TREES,
    predict_threads=PREDICT_THREADS)
predict = ExactPredictor(raw_predict, enabled=DEDUPE_PREDICTION,
                         budget_bytes=DEDUPE_BUDGET_MIB * 2**20)
'''
    evaluation = '''# Full evaluation; a completed model resumes here without fitting again.
model_identity = {'model_sha256': model_receipt['sha256'], 'sample_id': sample['sample_id']}
with phase('full validation evaluation'):
    validation = evaluate_resumable(data, 'val', predict, OUTPUT/'validation-state.npz',
                                    model_identity, bins=RANKING_BINS, workers=LOADER_WORKERS)
atomic_json(OUTPUT/'validation_metrics.json', validation, data.protected)
print('Validation:', json.dumps(validation, indent=2), flush=True)
with phase('full test evaluation'):
    test = evaluate_resumable(data, 'test', predict, OUTPUT/'test-state.npz', model_identity,
                              threshold=validation['threshold'], bins=RANKING_BINS,
                              workers=LOADER_WORKERS)
report = dict(model=MODEL_NAME, profile=PROFILE, seed=SEED,
              split_sha256=data.meta['split_sha256'], vocabulary_sha256=data.meta['vocabulary_sha256'],
              sample_id=sample['sample_id'], train_sampling=dict(method=sample['method'],
                  rows=sample['rows'], positives=sample['positives'], nnz=sample['nnz']),
              model_checkpoint=model_receipt,
              runtime=dict(cpu_threads=CPU_THREADS, prediction_threads=PREDICT_THREADS,
                  loader_workers=LOADER_WORKERS, runtime_sha256=RUNTIME_SHA256,
                  numpy=np.__version__, scipy=scipy.__version__,
                  current_session_prediction_rows=predict.rows,
                  current_session_unique_rows_scored=predict.scored),
              validation=validation, test=test)
atomic_json(OUTPUT/(MODEL_NAME+'_metrics.json'), report, data.protected)
print(json.dumps(report, indent=2), flush=True)
'''
    return dict(cells=[cell('markdown', intro), cell('code', setup), cell('code', train), cell('code', evaluation)],
                metadata=dict(kernelspec=dict(display_name='Python 3', language='python', name='python3')),
                nbformat=4, nbformat_minor=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['kaggle', 'ec2-100m'], required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    runtime = (root/'host_training_runtime.py').read_text()
    for model in ('rf', 'xgb', 'lgbm'):
        path = validate_output_path(root/f'host_{model}_shards.ipynb')
        path.write_text(json.dumps(notebook(model, args.profile, runtime), indent=1)+'\n')
    # Extra Nguyen notebooks keep their own training policies; refresh only a
    # setup cell that already opted into the embedded runtime.
    if args.profile == 'kaggle':
        for model in ('isoforest', 'river_stream'):
            path = root/f'host_{model}_shards.ipynb'
            if not path.exists():
                continue
            value = json.loads(path.read_text())
            changed = False
            for item in value['cells']:
                if 'BEGIN EMBEDDED RUNTIME' in ''.join(item.get('source', [])):
                    item.update(notebook(model, args.profile, runtime)['cells'][1])
                    changed = True
            if changed:
                validate_output_path(path).write_text(json.dumps(value, indent=1)+'\n')


if __name__ == '__main__':
    main()
