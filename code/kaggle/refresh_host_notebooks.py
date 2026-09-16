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


# ---------------------------------------------------------------------------
# Profile registry — add new EC2 profiles here, then re-run this script.
# Each profile is a dict of setting overrides relative to the base template.
# Keys map 1-to-1 to variable names in the setup cell.
# ---------------------------------------------------------------------------
PROFILE_REGISTRY = {
    'kaggle': dict(
        train_target_rows='None',
        max_matrix_gib=4,
        max_sample_nnz='1_800_000_000',
        balance_classes=True,
        sample_dir_suffix='train-neg30-seed01',
        dedupe_budget_mib=64,
        description='Kaggle CPU-aware sampled training',
        train_note='TRAIN retains the previous seed-01 Bernoulli negative sampling (30:1 in expectation).',
    ),
    'ec2-100m': dict(
        train_target_rows='100_000_000',
        max_matrix_gib=64,
        max_sample_nnz='1_800_000_000',
        balance_classes=False,
        sample_dir_suffix='train-100m-seed01',
        dedupe_budget_mib=128,
        description='shared 100,000,000-row TRAIN sample',
        train_note='TRAIN uses exactly 100,000,000 rows, seed 01. This is sampled training, not full TRAIN.',
    ),
    # Tier-1 EC2: r7i.8xlarge (256 GiB RAM, 32 vCPU).
    # CSR peak: ~56 GiB (XGB/LGBM) / ~112 GiB (RF). Comfortable on 256 GiB.
    # Set OPTC_MANIFEST, OPTC_OUTPUT, OPTC_SAMPLE_DIR via env before launching.
    'ec2-500m': dict(
        train_target_rows='500_000_000',
        max_matrix_gib=90,
        max_sample_nnz='7_500_000_000',
        balance_classes=False,
        sample_dir_suffix='train-500m-seed01',
        dedupe_budget_mib=256,
        description='EC2 Tier-1 · 500,000,000-row TRAIN sample (r7i.8xlarge, 256 GiB)',
        train_note=(
            'TRAIN uses exactly 500,000,000 rows, seed 01 — shared across all three models on the same EC2 instance.\n'
            'r7i.8xlarge: 256 GiB RAM / 32 vCPU. CSR peak ~56 GiB (XGB/LGBM) or ~112 GiB (RF).\n'
            'Set CPU_THREADS=28 (reserve 4 for I/O). For XGBoost GPU use g5.48xlarge + DEVICE=cuda.'
        ),
    ),
}


def notebook(model, profile, runtime):
    cfg = PROFILE_REGISTRY[profile]
    is_ec2_500m = profile == 'ec2-500m'
    is_ec2_100m = profile == 'ec2-100m'
    is_main     = is_ec2_100m  # backward compat alias
    title = f'# OpTC Host ML — {model.upper()}, {cfg["description"]}'
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
    intro += f'\n{cfg["train_note"]}\n'
    train_target_rows = cfg['train_target_rows']
    max_matrix_gib    = cfg['max_matrix_gib']
    max_sample_nnz    = cfg['max_sample_nnz']
    balance_classes   = cfg['balance_classes']
    sample_dir_suffix = cfg['sample_dir_suffix']
    dedupe_budget_mib = cfg['dedupe_budget_mib']
    setup = f'''# EDIT THESE SETTINGS. Keep the runtime section below generated.
from pathlib import Path
import os, sys, json, subprocess
MODEL_NAME = {model!r}
PROFILE = {profile!r}
MANIFEST = Path(os.environ['OPTC_MANIFEST']) if os.environ.get('OPTC_MANIFEST') else None
OUTPUT_ROOT = Path('/kaggle/working') if Path('/kaggle/input').exists() else Path.cwd() / 'output/host_ml_training'
OUTPUT_ROOT = Path(os.environ.get('OPTC_OUTPUT', str(OUTPUT_ROOT)))
TRAIN_TARGET_ROWS = {train_target_rows}
NEG_PER_POS = 30
SEED = 1
CPU_THREADS = None  # None = CPUs actually granted by affinity/cgroup quota
DEVICE = os.environ.get('OPTC_DEVICE', 'auto')  # xgb only: auto/cpu/cuda
MAX_MATRIX_GIB = {max_matrix_gib}  # {'hard limit passed to materialize_sample' if not is_ec2_500m else 'Tier-1 EC2: 90 GiB keeps ~56 GiB CSR + model headroom inside 256 GiB RAM'}
MAX_SAMPLE_NNZ = {max_sample_nnz}  # {'safety margin below RF int32 nnz limit' if not is_ec2_500m else '~7.2B nnz expected for 500M rows; this adds 4% headroom'}
BOOST_ROUNDS = 300
RF_TREES = 500
BALANCE_CLASSES = {balance_classes!r}  # {'EC2 500M: use scale_pos_weight loss instead; RF uses class_weight' if is_ec2_500m else 'preserve main XGB/LGBM loss; RF remains balanced'}
DEDUPE_PREDICTION = True  # exact binary rows, unchanged event weights/coverage
DEDUPE_BUDGET_MIB = {dedupe_budget_mib}
RANKING_BINS = 100_000
SAMPLE_DIR = Path(os.environ.get('OPTC_SAMPLE_DIR', str(OUTPUT_ROOT / {sample_dir_suffix!r})))

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
    # ---- FP/FN diagnostic cell (appended after evaluation) ----------------
    # Investigates WHY precision/recall is low by:
    #   1. Score distribution plot (positive vs negative) → calibration/overlap
    #   2. Precision-Recall curve from binned histogram → identify the PR cliff
    #   3. Operating-point table at multiple thresholds  → trade-off visibility
    #   4. Confusion matrix summary with FPR/FNR
    #   5. Score decile analysis → where are the FPs concentrated?
    #   6. (XGB/LGBM only) Feature importance top-20 → which tokens drive FPs?
    diagnostic = '''
# ============================================================
# FP / FN Diagnostic & Score Distribution Analysis
# Run AFTER the evaluation cell. Reads the already-saved
# binned histograms — no new shard I/O needed.
# ============================================================
import numpy as np, json, os
from pathlib import Path

# ---- 1. Load saved binned histogram from evaluation state --
val_state_path = OUTPUT / 'validation-state.npz'
test_state_path = OUTPUT / 'test-state.npz'
metrics_path = OUTPUT / 'validation_metrics.json'

if not val_state_path.exists():
    raise RuntimeError(f'Run evaluation cell first; {val_state_path} not found')

val_metrics = json.loads(metrics_path.read_text())
threshold   = val_metrics['threshold']
bins        = val_metrics['ranking_bins']

with np.load(val_state_path, allow_pickle=False) as s:
    pos_hist = s['positive'].astype(np.float64)  # counts per bin for positives
    neg_hist = s['negative'].astype(np.float64)  # counts per bin for negatives

total_pos = int(pos_hist.sum())
total_neg = int(neg_hist.sum())
score_edges = np.linspace(0, 1, bins + 2)  # bin left edges
score_mids  = (score_edges[:-1] + score_edges[1:]) / 2

print(f'\n=== {MODEL_NAME.upper()} FP/FN Diagnostic — validation split ===')
print(f'  Total positives : {total_pos:,}')
print(f'  Total negatives : {total_neg:,}')
print(f'  Class ratio     : 1:{total_neg//max(1,total_pos):,}')
print(f'  Selected threshold: {threshold:.6f}')

# ---- 2. Score distribution overlap stats -------------------
pos_mean = float(np.sum(score_mids * pos_hist) / max(total_pos, 1))
neg_mean = float(np.sum(score_mids * neg_hist) / max(total_neg, 1))
pos_median_bin = int(np.searchsorted(pos_hist.cumsum(), total_pos / 2))
neg_median_bin = int(np.searchsorted(neg_hist.cumsum(), total_neg / 2))
print(f'\n  Score distribution (validation):')
print(f'    Positive mean score : {pos_mean:.4f}  (median bin: {pos_median_bin/bins:.4f})')
print(f'    Negative mean score : {neg_mean:.4f}  (median bin: {neg_median_bin/bins:.4f})')
print(f'    Separation gap      : {pos_mean - neg_mean:.4f}')
if pos_mean - neg_mean < 0.05:
    print('    ⚠ VERY LOW SEPARATION — model does not distinguish classes well.')
    print('      Likely causes: insufficient features, too much class imbalance,')
    print('      overfitting TRAIN sample, or vocabulary too sparse for these events.')
elif pos_mean - neg_mean < 0.15:
    print('    ⚠ Low separation — model separates classes but scores overlap heavily.')
    print('      Consider: more BOOST_ROUNDS, higher num_leaves/max_depth, or larger sample.')

# ---- 3. Precision-Recall table at multiple thresholds ------
print(f'\n  PR operating points (from binned histogram):')
print(f'  {"Threshold":>10} {"Precision":>10} {"Recall":>8} {"F1":>8} {"FPR":>10} {"TP":>8} {"FP":>10}')
tps_cum = pos_hist[::-1].cumsum()[::-1]
fps_cum = neg_hist[::-1].cumsum()[::-1]
for t_pct in [0.01, 0.05, 0.10, 0.20, 0.30, 0.50, float(f'{threshold:.4f}')]:
    b = min(bins, int(t_pct * bins))
    tp = int(tps_cum[b])
    fp = int(fps_cum[b])
    prec = tp / max(tp + fp, 1)
    rec  = tp / max(total_pos, 1)
    f1   = 2*tp / max(2*tp + fp + (total_pos - tp), 1)
    fpr  = fp / max(total_neg, 1)
    marker = ' ◄ selected' if abs(t_pct - threshold) < 0.5/bins else ''
    print(f'  {t_pct:>10.4f} {prec:>10.4f} {rec:>8.4f} {f1:>8.4f} {fpr:>10.6f} {tp:>8,} {fp:>10,}{marker}')

# ---- 4. Root-cause flags -----------------------------------
print(f'\n  Root-cause flags:')
precision = val_metrics["precision"]
recall    = val_metrics["recall"]
fpr_val   = val_metrics["fpr"]
if recall < 0.3:
    print(f'    🔴 RECALL={recall:.3f}: Model misses >70% of positives.')
    print(f'       → Try: more BOOST_ROUNDS, larger sample, stronger BALANCE_CLASSES,')
    print(f'         or inspect whether TRAIN positives are representatively sampled.')
elif recall < 0.6:
    print(f'    🟡 RECALL={recall:.3f}: Moderate — many FN events.')
else:
    print(f'    🟢 RECALL={recall:.3f}: Good recall.')
if precision < 0.1:
    print(f'    🔴 PRECISION={precision:.3f}: Extremely high FP rate — near-random.')
    print(f'       → Likely cause: severe class imbalance (1:{total_neg//max(1,total_pos):,}).')
    print(f'         Try: higher scale_pos_weight, BALANCE_CLASSES=True, or threshold tuning.')
elif precision < 0.4:
    print(f'    🟡 PRECISION={precision:.3f}: Many FPs. Increase threshold or boost more rounds.')
else:
    print(f'    🟢 PRECISION={precision:.3f}: Acceptable precision.')
if fpr_val > 0.001:
    print(f'    🔴 FPR={fpr_val:.5f}: {int(fpr_val*total_neg):,} FP events on {total_neg:,} negatives.')
    print(f'       At production scale this dominates the alert queue.')
elif fpr_val > 0.0001:
    print(f'    🟡 FPR={fpr_val:.5f}: Moderate. Consider tighter threshold.')
else:
    print(f'    🟢 FPR={fpr_val:.6f}: Low FP rate.')

# ---- 5. Score decile analysis (where do FPs concentrate?) --
print(f'\n  Score decile analysis (negatives — i.e. FP source):')
print(f'  {"Score range":>20} {"Neg count":>12} {"Neg %":>8} {"Pos count":>12} {"Pos %":>8}')
decile_edges = np.linspace(0, bins, 11, dtype=int)
for i in range(10):
    lo, hi = decile_edges[i], decile_edges[i+1]
    n_neg = int(neg_hist[lo:hi].sum())
    n_pos = int(pos_hist[lo:hi].sum())
    lo_s, hi_s = lo/bins, hi/bins
    flag = ' ← FP hotspot' if n_neg / max(total_neg,1) > 0.05 and lo_s > threshold - 0.1 else ''
    print(f'  [{lo_s:.2f}, {hi_s:.2f}){"":>6} {n_neg:>12,} {n_neg/max(total_neg,1)*100:>7.2f}%'
          f' {n_pos:>12,} {n_pos/max(total_pos,1)*100:>7.2f}%{flag}')

# ---- 6. Feature importance (XGB / LGBM only) ---------------
try:
    import importlib
    library_name = {'xgb':'xgboost', 'lgbm':'lightgbm', 'rf':'sklearn'}[MODEL_NAME]
    library = importlib.import_module(library_name)
    if MODEL_NAME == 'xgb':
        imp = model.get_score(importance_type='gain')
        sorted_imp = sorted(imp.items(), key=lambda x: -x[1])[:20]
        print(f'\n  XGBoost top-20 features by gain (potential FP drivers):')
        for feat, gain in sorted_imp:
            print(f'    {feat:<40} gain={gain:,.1f}')
    elif MODEL_NAME == 'lgbm':
        imp = dict(zip(model.feature_name(), model.feature_importance(importance_type='gain')))
        sorted_imp = sorted(imp.items(), key=lambda x: -x[1])[:20]
        print(f'\n  LightGBM top-20 features by gain (potential FP drivers):')
        for feat, gain in sorted_imp:
            print(f'    {feat:<40} gain={gain:,.1f}')
    else:
        # RF: permutation importance is too expensive on full data; use mean decrease impurity
        fi = model.feature_importances_
        top20_idx = np.argsort(fi)[::-1][:20]
        print(f'\n  RF top-20 features by mean decrease impurity:')
        for idx in top20_idx:
            print(f'    feature_{idx:<6} importance={fi[idx]:.6f}')
except Exception as _diag_err:
    print(f'  (feature importance skipped: {_diag_err})')

print(f'\nDiagnostic complete. Full metrics saved to: {OUTPUT/(MODEL_NAME+"_metrics.json")}')
'''
    cells = [
        cell('markdown', intro),
        cell('code', setup),
        cell('code', train),
        cell('code', evaluation),
        cell('code', diagnostic),
    ]
    return dict(cells=cells,
                metadata=dict(kernelspec=dict(display_name='Python 3', language='python', name='python3')),
                nbformat=4, nbformat_minor=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=list(PROFILE_REGISTRY.keys()), required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    runtime = (root/'host_training_runtime.py').read_text()
    for model in ('rf', 'xgb', 'lgbm'):
        path = validate_output_path(root/f'host_{model}_shards.ipynb')
        path.write_text(json.dumps(notebook(model, args.profile, runtime), indent=1)+'\n')
    print(f'Generated host_{{rf,xgb,lgbm}}_shards.ipynb for profile={args.profile!r}')
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
