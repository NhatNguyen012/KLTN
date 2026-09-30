"""Frozen-model cascade: measured validation selection, resumable scoring, test audit."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import sqlite3
import zipfile
import numpy as np

LOW = (0.1, 0.2, 0.3, 0.5, 0.7, 0.9)
HIGH = (0.96, 0.98, 0.99, 0.995)
GRAPH = (0.7, 0.85, 0.9, 0.95, 0.9666, 0.98, 0.99)

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''): h.update(b)
    return h.hexdigest()

def safe(path):
    p = Path(path).resolve()
    if set(p.parts) & {'host-begnin', 'host-malicious', 'bro', 'ecar-bro'}:
        raise ValueError('Output inside read-only dataset root')
    return p

def atomic_json(path, value):
    path = safe(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w') as f:
        json.dump(value, f, indent=2); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def counts(y, pred):
    return np.array([np.sum((y == 1) & pred), np.sum((y == 0) & pred),
                     np.sum((y == 1) & ~pred), np.sum((y == 0) & ~pred)], dtype=np.int64)

def metrics(c):
    tp, fp, fn, tn = map(int, c)
    return dict(confusion=dict(tp=tp, fp=fp, fn=fn, tn=tn),
        precision=tp / max(1, tp + fp), recall=tp / max(1, tp + fn),
        f1=2 * tp / max(1, 2 * tp + fp + fn), fpr=fp / max(1, fp + tn), rows=tp+fp+fn+tn)

def predictions(ml, graph, policy):
    if policy['mode'] == 'baseline': return ml >= policy['threshold']
    band = (ml >= policy['low']) & (ml < policy['high'])
    pred = ml >= policy['high']
    # Missing lookup falls back to the frozen ML threshold, consistently in val/test.
    pred[band] = np.where(np.isfinite(graph[band]), graph[band] >= policy['graph'],
                          ml[band] >= policy['baseline_threshold'])
    return pred

def policies(threshold):
    return [dict(mode='baseline', threshold=threshold)] + [
        dict(mode='cascade', low=l, high=h, graph=g, baseline_threshold=threshold)
        for l, h, g in itertools.product(LOW, HIGH, GRAPH) if l < h]

def choose(options, totals):
    # Baseline wins ties; select strictly on measured validation F1.
    return options[max(range(len(options)), key=lambda i: metrics(totals[i])['f1'])]

def verify_bundle(bundle):
    data = json.loads((bundle / 'bundle_manifest.json').read_text())
    for rel, item in data['files'].items():
        path = (bundle / rel).resolve()
        if not path.is_relative_to(bundle.resolve()) or sha(path) != item['sha256']:
            raise ValueError('Bundle integrity mismatch: ' + rel)
    return data

def run(manifest_path, bundle, output):
    import lightgbm as lgb
    from host_shards import decode_shard
    from ego import EgoGraphs
    from relational_sage import RelationalSAGE
    manifest_path, bundle = Path(manifest_path).resolve(), Path(bundle).resolve()
    output = safe(output)
    if output.is_relative_to(bundle) or output.is_relative_to(manifest_path.parent):
        raise ValueError('Output overlaps input')
    output.mkdir(parents=True, exist_ok=True)
    bm = verify_bundle(bundle)
    meta = json.loads(manifest_path.read_text())
    expected = json.loads((bundle / 'models/baseline_metrics.json').read_text())
    # Match the immutable vocabulary and split assets, rather than relocated manifest paths.
    for name, key in [('vocab.json', 'vocabulary_sha256'), ('split_manifest.json', 'split_sha256')]:
        if sha(manifest_path.parent / 'assets' / name) != expected[key]:
            raise ValueError('Frozen baseline asset mismatch: ' + name)
    identity = dict(manifest_sha256=sha(manifest_path), bundle_sha256=sha(bundle / 'bundle_manifest.json'),
                    runtime_sha256=sha(__file__), baseline_threshold=expected['validation']['threshold'],
                    low=LOW, high=HIGH, graph=GRAPH, missing_policy='frozen ML fallback',
                    lightgbm_version=lgb.__version__, numpy_version=np.__version__)
    identity = json.loads(json.dumps(identity))
    config = output / 'config.json'
    if config.exists() and json.loads(config.read_text()) != identity:
        raise ValueError('Resume identity mismatch; use a fresh output directory')
    atomic_json(config, identity)
    booster = lgb.Booster(model_file=str(bundle / 'models/lgbm_model.txt'))
    model = RelationalSAGE.load(bundle / 'provenance/model_numpy.npz')
    db = sqlite3.connect((bundle / 'provenance/graph.sqlite').as_uri() + '?mode=ro', uri=True)
    db.execute('PRAGMA cache_size=-262144')
    ego = EgoGraphs(db)
    def score(s, index):
        cache = output / f'scores-{index:04d}.npz'
        receipt = cache.with_suffix('.json')
        if cache.exists() and receipt.exists() and sha(cache) == json.loads(receipt.read_text())['sha256']:
            with np.load(cache, allow_pickle=False) as d: return {k: d[k] for k in d.files}
        candidates = [manifest_path.parent / 'volumes' / s['volume'] / s['path'], manifest_path.parent / s['path']]
        path = next((p for p in candidates if p.exists()), None)
        if path is None: raise FileNotFoundError(s['path'])
        if sha(path) != s['sha256']: raise ValueError('Shard hash mismatch')
        decoded = decode_shard(path, int(meta['vocab_size']))
        X, y, lines = decoded
        ml = booster.predict(X)
        graph = np.full(len(y), np.nan, dtype=np.float64)
        found = np.zeros(len(y), dtype=bool)
        missing_identity = np.zeros(len(y), dtype=bool)
        routed = np.flatnonzero((ml >= min(LOW)) & (ml < max(HIGH)))
        for j, idx in enumerate(routed):
            row = db.execute('SELECT host,proc,t FROM target WHERE source=? AND line=?',
                             (str(s['source_id']), int(lines[idx]))).fetchone()
            if row:
                found[idx] = True
                missing_identity[idx] = not row[0] or not row[1] or row[2] is None
                graph[idx] = model.predict(ego.build(*row))['probability']
            if (j + 1) % 2000 == 0: print(f"shard {index}: graph {j+1}/{len(routed)}", flush=True)
        data = dict(y=y, ml=ml, graph=graph, found=found, missing_identity=missing_identity)
        tmp = cache.with_suffix('.tmp')
        with tmp.open('wb') as f:
            np.savez_compressed(f, **data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, cache)
        atomic_json(receipt, dict(sha256=sha(cache), source_id=s['source_id'], shard_sha256=s['sha256']))
        return data
    threshold = expected['validation']['threshold']
    options = policies(threshold)
    totals = np.zeros((len(options), 4), dtype=np.int64)
    for i, s in enumerate(meta['shards']):
        if s['split'] != 'val': continue
        d = score(s, i)
        for j, p in enumerate(options): totals[j] += counts(d['y'], predictions(d['ml'], d['graph'], p))
        print(f'Validation shard {i} complete', flush=True)
    if int(totals[0].sum()) != expected['validation']['rows']: raise ValueError('Validation scope mismatch')
    if metrics(totals[0])['confusion'] != expected['validation']['confusion']:
        raise ValueError('Frozen LightGBM validation confusion does not reproduce baseline')
    selected = choose(options, totals)
    calibration = dict(selection_split='val', selection='measured F1; baseline wins ties',
        selected=selected, identity=identity,
        grid=[dict(policy=p, **metrics(c)) for p, c in zip(options, totals)])
    atomic_json(output / 'validation_calibration.json', calibration)
    print('Frozen policy:', selected, flush=True)
    base = np.zeros(4, dtype=np.int64); unified = base.copy(); direct = base.copy(); arbiter = base.copy()
    routed_n = missing_n = missing_id_n = 0
    for i, s in enumerate(meta['shards']):
        if s['split'] != 'test': continue
        d = score(s, i); y, ml, graph = d['y'], d['ml'], d['graph']
        pred = predictions(ml, graph, selected)
        band = np.zeros(len(y), dtype=bool) if selected['mode'] == 'baseline' else (ml >= selected['low']) & (ml < selected['high'])
        base += counts(y, ml >= threshold); unified += counts(y, pred)
        direct += counts(y[~band], pred[~band]); arbiter += counts(y[band], pred[band])
        routed_n += int(band.sum()); missing_n += int((band & ~d['found']).sum())
        missing_id_n += int((band & d['missing_identity']).sum())
        print(f'Test shard {i} complete; F1={metrics(unified)["f1"]:.6f}', flush=True)
    if metrics(base)['rows'] != expected['test']['rows'] or metrics(base)['confusion'] != expected['test']['confusion']:
        raise ValueError('Frozen LightGBM test baseline mismatch')
    results = dict(identity=identity, selected_policy=selected, baseline=metrics(base), cascade=metrics(unified),
                   direct_branch=metrics(direct), graph_branch=metrics(arbiter), routed=routed_n,
                   missing_lookup=missing_n, missing_identity=missing_id_n,
                   scope='full frozen seed02 validation and test; random event generalization only')
    atomic_json(output / 'two_stage_cascade_metrics.json', results)
    archive = output / 'optc-two-stage-cascade-results.zip'
    tmp = archive.with_suffix('.tmp')
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in ('config.json', 'validation_calibration.json', 'two_stage_cascade_metrics.json'):
            z.write(output / name, arcname=name)
    os.replace(tmp, archive)
    db.close()
    print(json.dumps(results, indent=2)); print('Download:', archive)
    return results
