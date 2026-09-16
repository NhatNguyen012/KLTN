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
    if model in ('xgb', 'lgbm', 'rf'):
        extra_check = ""
        if model == 'xgb':
            extra_check = """try:
    xgb_ver = version('xgboost')
    _versions['xgboost'] = xgb_ver
    if not Version('2.0') <= Version(xgb_ver) < Version('4.0'):
        raise RuntimeError(f'Unsupported notebook environment: xgboost={xgb_ver}; expected >= 2.0, < 4.0. '
                           'Run this in a separate cell with Internet enabled, then restart the kernel/session and Run All:\\n' + PACKAGE_REPAIR)
except PackageNotFoundError:
    pass
"""
        elif model == 'lgbm':
            extra_check = """try:
    lgb_ver = version('lightgbm')
    _versions['lightgbm'] = lgb_ver
    if not Version('3.0') <= Version(lgb_ver) < Version('5.0'):
        raise RuntimeError(f'Unsupported notebook environment: lightgbm={lgb_ver}; expected >= 3.0, < 5.0. '
                           'Run this in a separate cell with Internet enabled, then restart the kernel/session and Run All:\\n' + PACKAGE_REPAIR)
except PackageNotFoundError:
    pass
"""
        preflight = f"""# Check versions before importing binary scientific packages.
from importlib.metadata import version, PackageNotFoundError
from packaging.version import Version
PACKAGE_REPAIR = '%pip install numpy==1.26.4 scipy==1.15.3 scikit-learn==1.6.1 joblib==1.5.1 threadpoolctl==3.6.0 lightgbm==4.6.0 xgboost==3.0.5'
_versions = {{}}
for package, minimum, maximum in [('numpy','1.23.5','3.0'), ('scipy','1.15','3.0'),
                                  ('scikit-learn','1.3','3.0')]:
    try:
        installed = version(package)
    except PackageNotFoundError:
        installed = '0'
    _versions[package] = installed
    if not Version(minimum) <= Version(installed) < Version(maximum):
        raise RuntimeError(f'Unsupported notebook environment: {{package}}={{installed}}; expected >= {{minimum}}, < {{maximum}}. '
                           'Run this in a separate cell with Internet enabled, then restart the kernel/session and Run All:\\n' + PACKAGE_REPAIR)
{extra_check}print('Python:', sys.version.split()[0], 'Packages:', _versions, flush=True)
"""
        setup = setup.replace(f"MODEL_NAME = '{model}'", preflight + f"\nMODEL_NAME = '{model}'", 1)
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
                                          stderr=subprocess.DEVNULL).returncode == 0 else 'cpu'
    except OSError:
        DEVICE = 'cpu'
print(f'Manifest: {MANIFEST}; CPU train={CPU_THREADS}, predict={PREDICT_THREADS}, decode={LOADER_WORKERS}; XGB device={DEVICE}', flush=True)
print(f'Available RAM: {available_bytes()/2**30:.2f} GiB; sample={SAMPLE_DIR}; output={OUTPUT}', flush=True)
'''
    train = '''with phase('TRAIN sample preparation / resume'):
    sample = prepare_sample(data, SAMPLE_DIR, target_rows=TRAIN_TARGET_ROWS,
                            neg_per_pos=NEG_PER_POS, seed=SEED,
                            workers=LOADER_WORKERS, max_nnz=MAX_SAMPLE_NNZ)
with phase(f'fit {MODEL_NAME} / resume'):
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
    diagnostic_cell = []
    if model in ('xgb', 'lgbm', 'rf'):
        model_upper = model.upper()
        intro += f"""
## Diagnostics

FP/FN examples and full-test host/day counts are collected during evaluation.
Learning curves evaluate prefixes of the completed ensemble on fixed stratified
TRAIN/validation probes; they are estimates, not full-split learning curves or
early stopping. Class weights restore original split priors for probe metrics.
Rare false positives can be absent from a small probe, so use full validation
metrics for decisions. Test diagnostics are for final reporting, not tuning.

Outputs are under OUTPUT/diagnostics: learning_curve.json/csv/png (PNG requires
matplotlib), validation_threshold_curve.npz, val_errors.json, test_errors.json,
and val/test_diagnostics.json. Error examples are the highest-score negatives
and lowest-score positives, NOT a representative random error sample. Columns
map to tokens in the current input vocabulary; source_id + source_line locate
the raw event without executing any telemetry payload.

Use a new output/sample directory for this runtime revision: older checkpoints
are rejected by the runtime hash guard. Full source input packages are unchanged.
"""
        setup += f"""
# {model_upper} diagnostics: bounded state included in evaluation checkpoints.
DIAGNOSTICS_ENABLED = True
DIAGNOSTIC_NEGATIVE_ROWS = 10_000
DIAGNOSTIC_POSITIVE_ROWS = 1_000
DIAGNOSTIC_ERROR_EXAMPLES = 100  # maximum per FP/FN, each split
DIAGNOSTIC_MAX_NNZ = 1_000_000
LEARNING_CURVE_EVERY = 25
DIAGNOSTICS = OUTPUT / 'diagnostics'
def new_diagnostics():
    return ModelDiagnostics(data, probe_negative=DIAGNOSTIC_NEGATIVE_ROWS,
        probe_positive=DIAGNOSTIC_POSITIVE_ROWS, examples=DIAGNOSTIC_ERROR_EXAMPLES,
        max_probe_nnz=DIAGNOSTIC_MAX_NNZ, seed=17, model_name=MODEL_NAME) if DIAGNOSTICS_ENABLED else None
validation_diagnostics = new_diagnostics()
test_diagnostics = new_diagnostics()
"""
        evaluation = evaluation.replace('bins=RANKING_BINS, workers=LOADER_WORKERS)',
            'bins=RANKING_BINS, workers=LOADER_WORKERS, diagnostics=validation_diagnostics)')
        evaluation = evaluation.replace('workers=LOADER_WORKERS)\nreport =',
            'workers=LOADER_WORKERS, diagnostics=test_diagnostics)\nreport =')
        evaluation = evaluation.replace("with phase('full test evaluation'):", f"""if DIAGNOSTICS_ENABLED:
    validation_diagnostics.publish(DIAGNOSTICS, 'val', validation['threshold'])
    with phase('{model_upper} fixed-probe learning curves'):
        learning_curve = posthoc_learning_curve(data, SAMPLE_DIR, sample, model,
            validation_diagnostics, DIAGNOSTICS, validation['threshold'],
            model_name=MODEL_NAME, threads=PREDICT_THREADS, every=LEARNING_CURVE_EVERY)
with phase('full test evaluation'):""")
        evaluation += f"""
if DIAGNOSTICS_ENABLED:
    test_diagnostics.publish(DIAGNOSTICS, 'test', validation['threshold'])
    print('FP/FN examples and full-test day/host counts:', DIAGNOSTICS, flush=True)
"""
        diagnostic_cell = [cell('code', """# Curves are saved after validation, before the full test pass.
if DIAGNOSTICS_ENABLED and (DIAGNOSTICS/'learning_curve.png').exists():
    from IPython.display import display, Image
    display(Image(filename=str(DIAGNOSTICS/'learning_curve.png')))
""")]
    return dict(cells=[cell('markdown', intro), cell('code', setup), cell('code', train), cell('code', evaluation)] + diagnostic_cell,
                metadata=dict(kernelspec=dict(display_name='Python 3', language='python', name='python3')),
                nbformat=4, nbformat_minor=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['kaggle', 'ec2-100m'], required=True)
    parser.add_argument('--models', nargs='+', choices=['rf','xgb','lgbm'], default=['rf','xgb','lgbm'])
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    runtime = (root/'host_training_runtime.py').read_text()
    for model in args.models:
        path = validate_output_path(root/f'host_{model}_shards.ipynb')
        path.write_text(json.dumps(notebook(model, args.profile, runtime), indent=1)+'\n')
    # Extra Nguyen notebooks keep their own training policies; refresh only a
    # setup cell that already opted into the embedded runtime.
    if args.profile == 'kaggle' and set(args.models) == {'rf','xgb','lgbm'}:
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
