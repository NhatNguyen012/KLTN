"""Frozen v4 LightGBM/GraphSAGE collision-aware routing experiment.

The exact binary CSR row is the key. Labels are consulted only while building
the full-TRAIN and fit-sample diagnostic registries, never in routing.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import sqlite3

import numpy as np

from cascade_runtime import counts, metrics, sha, safe, verify_bundle, load_host_model
from ego import EgoGraphs
from relational_sage import RelationalSAGE

LOW, HIGH, GRAPH, BASELINE = .30, .96, .95, .94016
REFERENCE_TEST = dict(tp=39732, fp=630, fn=578, tn=1208749)
REFERENCE_VAL = dict(tp=26490, fp=412, fn=383, tn=805840)
REFERENCE_MANIFEST_SHA = '421d1855c2ae46f01b531f242aaa265a3a23b992d2969b24d534b1b088367fc5'


def atomic_json(path, value):
    path = safe(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)


def key_for_row(x, row):
    """Exact, sorted uint32 feature columns; no lossy hash or identity fields."""
    start, stop = int(x.indptr[row]), int(x.indptr[row + 1])
    cols = x.indices[start:stop]
    if len(cols) > 1 and np.any(cols[:-1] >= cols[1:]):
        raise ValueError('Host columns are not strictly increasing')
    return cols.astype('<u4', copy=False).tobytes()


def get_shard(data, shard):
    from host_shards import decode_shard
    return decode_shard(data.path_for(shard), data.width, shard)


def build_registry(data, sampling_seed=1, neg_per_pos=30,
                   expected_fit_counts=(6046559, 201551)):
    """Full TRAIN primary registry and exact frozen undersample diagnostic."""
    full, fit = {}, {}
    full_occurrences, fit_occurrences = {}, {}
    full_rows = Counter(); fit_rows = Counter()
    rng = np.random.default_rng(sampling_seed)
    train = data.meta['splits']['train']
    keep_p = min(1., neg_per_pos * train['label_1'] / train['label_0'])
    for shard in data.meta['shards']:
        if shard['split'] != 'train':
            continue
        x, y, _ = get_shard(data, shard)
        neg = np.flatnonzero(y == 0)
        selected_neg = np.zeros(len(y), dtype=bool)
        selected_neg[neg] = rng.random(len(neg)) < keep_p
        for row, label in enumerate(y):
            label = int(label)
            key = key_for_row(x, row)
            full[key] = full.get(key, 0) | (1 << label)
            if key not in full_occurrences:
                full_occurrences[key] = [0, 0]
            full_occurrences[key][label] += 1
            full_rows[label] += 1
            if label or selected_neg[row]:
                fit[key] = fit.get(key, 0) | (1 << label)
                if key not in fit_occurrences:
                    fit_occurrences[key] = [0, 0]
                fit_occurrences[key][label] += 1
                fit_rows[label] += 1
    if [full_rows[0], full_rows[1]] != [train['label_0'], train['label_1']]:
        raise ValueError('Full TRAIN does not match manifest')
    if expected_fit_counts is not None and [fit_rows[0], fit_rows[1]] != list(expected_fit_counts):
        raise ValueError('Fit subset does not match frozen LightGBM sampling')
    return full, fit, full_rows, fit_rows, full_occurrences, fit_occurrences


def registry_summary(reg, row_counts, occurrences):
    labels = Counter(reg.values())
    collision_rows = [sum(occurrences[key][label] for key, mask in reg.items() if mask == 3)
                      for label in (0, 1)]
    return dict(rows={'benign': row_counts[0], 'malicious': row_counts[1],
                      'total': row_counts[0] + row_counts[1]},
                unique_vectors=len(reg), benign_only_vectors=labels[1],
                malicious_only_vectors=labels[2], conflicting_vectors=labels[3],
                conflicting_vector_rows={'benign': collision_rows[0],
                                         'malicious': collision_rows[1]})


def publish_registry(path, reg, occurrences):
    """Auditable TRAIN-only key/label-set registry, with no event identities."""
    path = safe(path)
    tmp = path.with_suffix('.jsonl.tmp')
    with tmp.open('w') as stream:
        for key in sorted(reg):
            labels = reg[key]
            stream.write(json.dumps(dict(vector_key=key.hex(),
                                         labels=[label for label in (0, 1)
                                                 if labels & (1 << label)],
                                         train_label_counts=occurrences[key])) + '\n')
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)


def score_map_from_audit(path, expected_model_sha):
    """Optional local scorer when LightGBM wheel is absent; never reads labels."""
    document = json.loads(Path(path).read_text())
    if document['model_sha256'] != expected_model_sha:
        raise ValueError('Local score-map checkpoint identity mismatch')
    return {bytes.fromhex(k): float(v) for k, v in document['scores'].items()}


def local_score_map(census_path, model_path, output):
    """Strip audited checkpoint scores from a pre-existing vector census."""
    groups = json.loads(Path(census_path).read_text())
    scores = {}
    for group in groups:
        key = np.asarray(group['columns'], dtype='<u4').tobytes().hex()
        value = float(group['scores']['lgbm'])
        if key in scores and scores[key] != value:
            raise ValueError('Census score collision')
        scores[key] = value
    atomic_json(output, dict(model_sha256=sha(model_path), scores=scores,
                             provenance=str(census_path),
                             policy='Score-only projection; no census labels used'))


def route_predictions(ml, graph, collision):
    """Collision override precedes both legacy direct branches."""
    band = (ml >= LOW) & (ml < HIGH)
    routed = collision | band
    if not np.all(np.isfinite(graph[routed])):
        raise ValueError('Required GraphSAGE score missing')
    legacy = np.where(band, graph >= GRAPH, ml >= HIGH)
    aware = np.where(routed, graph >= GRAPH, ml >= HIGH)
    return legacy, aware, band, routed


def score_distribution(values):
    if not len(values):
        return dict(count=0)
    return dict(count=int(len(values)), min=float(np.min(values)),
                p10=float(np.quantile(values, .1)), p50=float(np.median(values)),
                p90=float(np.quantile(values, .9)), max=float(np.max(values)))


def run(manifest_path, bundle, output, *, score_map=None, legacy_result=None,
        volume_root_ssd=None):
    from host_shards import HostShardDataset
    manifest_path, bundle, output = map(lambda p: Path(p).resolve(),
                                         (manifest_path, bundle, output))
    safe(output)
    if output.is_relative_to(bundle) or output.is_relative_to(manifest_path.parent):
        raise ValueError('Experiment output overlaps an input')
    output.mkdir(parents=True, exist_ok=True)
    bundle_meta = verify_bundle(bundle)
    if bundle_meta.get('schema') != 4 or bundle_meta.get('context_policy', {}).get('timestamp_quantum_us') != 1:
        raise ValueError('Exact-time v4 bundle required')
    volume_roots = {'ssd': volume_root_ssd} if volume_root_ssd is not None else None
    data = HostShardDataset(manifest_path, volume_roots=volume_roots)
    atomic_json(output / 'source_index.json',
                {str(source['source_id']): source['source']['path']
                 for source in data.meta['sources']})
    baseline_meta = json.loads((bundle / 'models/lgbm_metrics.json').read_text())
    if baseline_meta['validation']['threshold'] != BASELINE:
        raise ValueError('Frozen LightGBM threshold changed')
    for filename, field in [('vocab.json', 'vocabulary_sha256'),
                            ('split_manifest.json', 'split_sha256')]:
        if sha(manifest_path.parent / 'assets' / filename) != baseline_meta[field]:
            raise ValueError('Frozen feature/split asset mismatch: ' + filename)
    identity = dict(manifest_sha256=sha(manifest_path), bundle_sha256=sha(bundle / 'bundle_manifest.json'),
                    graph_sha256=bundle_meta['files']['provenance/graph.sqlite']['sha256'],
                    graph_model_sha256=bundle_meta['files']['provenance/model_numpy.npz']['sha256'],
                    host_model_sha256=bundle_meta['files']['models/lgbm_model.txt']['sha256'],
                    schema_sha256=sha(manifest_path.parent / 'assets/vocab.json'),
                    feature_width=data.width, key_method='exact sorted uint32 column bytes, little-endian',
                    low=LOW, high=HIGH, graph_threshold=GRAPH, baseline_threshold=BASELINE)
    if identity['manifest_sha256'] != REFERENCE_MANIFEST_SHA:
        raise ValueError('Host TEST manifest SHA-256 differs from measured v4 run')
    config = output / 'config.json'
    if config.exists() and json.loads(config.read_text()) != identity:
        raise ValueError('Resume identity mismatch; use a fresh output directory')
    atomic_json(config, identity)
    if legacy_result is not None:
        legacy = json.loads(Path(legacy_result).read_text())
        if legacy['identity']['manifest_sha256'] != identity['manifest_sha256']:
            raise ValueError('Legacy v4 TEST manifest differs')
        if legacy['cascade']['confusion'] != REFERENCE_TEST:
            raise ValueError('Legacy v4 reference confusion differs')
        calibration = json.loads((Path(legacy_result).parent / 'validation_calibration.json').read_text())
        if calibration['selected'] != dict(mode='cascade', low=LOW, high=HIGH,
                                           graph=GRAPH, baseline_threshold=BASELINE):
            raise ValueError('Legacy validation policy differs from fixed policy')
        legacy_validation = next(row['confusion'] for row in calibration['grid']
                                 if row['policy'] == calibration['selected'])
    else:
        legacy_validation = REFERENCE_VAL
    full, fit, full_rows, fit_rows, full_occ, fit_occ = build_registry(data)
    if any(key not in full or fit_labels & ~full[key] for key, fit_labels in fit.items()):
        raise ValueError('Fit-only labels are not a subset of full TRAIN labels')
    collisions = {key for key, labels in full.items() if labels == 3}
    reg_summary = dict(primary=registry_summary(full, full_rows, full_occ),
                       fit_only_diagnostic=registry_summary(fit, fit_rows, fit_occ),
                       identity=identity, sampling=dict(seed=1, neg_per_pos=30,
                                                        method='frozen random_negative_undersampling',
                                                        numpy_version=np.__version__,
                                                        fit_subset_status='reconstructed from published seed and sampling code; row-identity receipt was not exported'),
                       fit_only_conflicts_not_in_primary=sum(labels == 3 and full[key] != 3
                                                             for key, labels in fit.items()),
                       full_conflicts_absent_from_fit=sum(key not in fit or fit[key] != 3
                                                          for key in collisions))
    atomic_json(output / 'collision_registry_summary.json', reg_summary)
    publish_registry(output / 'collision_registry.jsonl', full, full_occ)
    if score_map is None:
        predict_host, version = load_host_model(bundle, 'lgbm')
        trained_version = bundle_meta['model_identities']['lgbm']['library_version']
        if version != trained_version:
            raise RuntimeError(f'Frozen LightGBM requires {trained_version}; found {version}')
        def host_scores(x):
            return np.asarray(predict_host(x), dtype=np.float64)
    else:
        mapping = score_map_from_audit(score_map, identity['host_model_sha256'])
        version = 'audited frozen score lookup; model checkpoint hash verified'
        def host_scores(x):
            return np.asarray([mapping[key_for_row(x, i)] for i in range(x.shape[0])], dtype=np.float64)
    model = RelationalSAGE.load(bundle / 'provenance/model_numpy.npz')
    graph_path = bundle / 'provenance/graph.sqlite'
    db = sqlite3.connect(graph_path.as_uri() + '?mode=ro', uri=True)
    db.execute('PRAGMA cache_size=-262144')
    ego = EgoGraphs(db)
    validation_reference = json.loads((output / 'validation_metrics.json').read_text()) if (output / 'validation_metrics.json').exists() else None
    results = {}
    try:
        for split in ('val', 'test'):
            if split == 'test' and validation_reference is None:
                validation_reference = results['val']
                atomic_json(output / 'validation_metrics.json', validation_reference)
            if split == 'test':
                # Fixed routing and threshold; TEST never changes the policy.
                assert validation_reference['policy']['graph_threshold'] == GRAPH
            totals = defaultdict(lambda: np.zeros(4, dtype=np.int64))
            routing = Counter(); transitions = Counter(); scores_by_label = {0: [], 1: []}
            errors_file = output / 'test_errors_full_scores.jsonl'
            changes_file = output / 'event_transition_audit.jsonl'
            if split == 'test':
                errors_tmp = errors_file.with_suffix('.jsonl.tmp')
                changes_tmp = changes_file.with_suffix('.jsonl.tmp')
                errors_out = errors_tmp.open('w')
                changes_out = changes_tmp.open('w')
            try:
                for index, shard in enumerate(data.meta['shards']):
                    if shard['split'] != split:
                        continue
                    x, y, lines = get_shard(data, shard)
                    ml = host_scores(x)
                    collision = np.fromiter((key_for_row(x, i) in collisions for i in range(len(y))),
                                            dtype=bool, count=len(y))
                    band = (ml >= LOW) & (ml < HIGH)
                    routed = collision | band
                    extra = collision & ~band
                    cache = output / f'{split}-graph-{index:04d}.npz'
                    receipt = cache.with_suffix('.json')
                    cached_receipt = json.loads(receipt.read_text()) if receipt.exists() else None
                    if (cache.exists() and cached_receipt is not None
                            and cached_receipt.get('identity') == identity
                            and cached_receipt.get('source_id') == shard['source_id']
                            and cached_receipt.get('shard_sha256') == shard['sha256']
                            and sha(cache) == cached_receipt['sha256']):
                        with np.load(cache, allow_pickle=False) as f:
                            graph = f['graph']
                        if graph.shape != ml.shape or not np.all(np.isfinite(graph[routed])):
                            raise ValueError('Invalid graph score cache')
                    else:
                        graph = np.full(len(y), np.nan, dtype=np.float64)
                        missing = []
                        for row in np.flatnonzero(routed):
                            target = db.execute('SELECT host,proc,t FROM target WHERE source=? AND line=?',
                                                (shard['source_id'], int(lines[row]))).fetchone()
                            if target is None or not target[0] or not target[1] or target[2] is None:
                                missing.append(dict(source_id=shard['source_id'], source_line=int(lines[row]),
                                                    reason='missing_target_or_identity'))
                                continue
                            graph[row] = model.predict(ego.build(*target))['probability']
                        if missing:
                            atomic_json(output / f'{split}-missing-{index:04d}.json', missing)
                            raise ValueError(f'{len(missing)} required graph scores missing in shard {index}')
                        tmp = cache.with_suffix('.npz.tmp')
                        with tmp.open('wb') as f:
                            np.savez_compressed(f, graph=graph)
                            f.flush(); os.fsync(f.fileno())
                        os.replace(tmp, cache)
                        atomic_json(receipt, dict(sha256=sha(cache), source_id=shard['source_id'],
                                                  shard_sha256=shard['sha256'], identity=identity))
                    old, new, checked_band, checked_routed = route_predictions(ml, graph, collision)
                    if not np.array_equal(band, checked_band) or not np.array_equal(routed, checked_routed):
                        raise ValueError('Routing mask disagreement')
                    route_reason = np.where(collision, 'collision', np.where(band, 'legacy_graph', 'legacy_direct'))
                    totals['legacy'] += counts(y, old)
                    totals['collision_aware'] += counts(y, new)
                    for tag, mask in [('collision', collision), ('noncollision', ~collision)]:
                        totals['legacy_' + tag] += counts(y[mask], old[mask])
                        totals['new_' + tag] += counts(y[mask], new[mask])
                    routing['rows'] += len(y)
                    routing['collision'] += int(collision.sum())
                    routing['collision_low'] += int((collision & (ml < LOW)).sum())
                    routing['collision_middle'] += int((collision & band).sum())
                    routing['collision_high'] += int((collision & (ml >= HIGH)).sum())
                    routing['newly_routed'] += int(extra.sum())
                    routing['legacy_graph'] += int(band.sum())
                    routing['new_graph'] += int(routed.sum())
                    routing['collision_corrected'] += int((collision & (old != y) & (new == y)).sum())
                    routing['collision_new_errors'] += int((collision & (old == y) & (new != y)).sum())
                    for label in (0, 1):
                        scores_by_label[label].extend(graph[collision & (y == label)].tolist())
                    changed = np.flatnonzero(old != new)
                    if len(changed) and not np.all(collision[changed] & ~band[changed]):
                        raise ValueError('Non-collision or legacy-band prediction changed')
                    transitions.update(f'{"FP" if y[i] == 0 else "FN"}_' +
                                       ('corrected' if new[i] == y[i] else 'introduced') for i in changed)
                    if split == 'test':
                        for row in np.flatnonzero(new != y):
                            item = dict(source_id=shard['source_id'], source_line=int(lines[row]),
                                        shard=shard['path'], label=int(y[row]),
                                        ml_score=float(ml[row]),
                                        graph_score=float(graph[row]) if np.isfinite(graph[row]) else None,
                                        route='graph' if routed[row] else 'direct',
                                        route_reason=str(route_reason[row]), collision=bool(collision[row]),
                                        threshold=(GRAPH if routed[row] else
                                                   LOW if ml[row] < LOW else HIGH),
                                        prediction=int(new[row]), legacy_prediction=int(old[row]),
                                        baseline_prediction=int(ml[row] >= BASELINE),
                                        graph_score_used_for_decision=bool(routed[row]),
                                        error='FP' if y[row] == 0 else 'FN')
                            errors_out.write(json.dumps(item) + '\n')
                        for row in changed:
                            item = dict(source_id=shard['source_id'], source_line=int(lines[row]),
                                        label=int(y[row]), ml_score=float(ml[row]),
                                        graph_score=float(graph[row]), collision=bool(collision[row]),
                                        old_prediction=int(old[row]), new_prediction=int(new[row]),
                                        old_route='direct', new_route='graph',
                                        reason='collision_override_' + ('low' if ml[row] < LOW else 'high'),
                                        old_error=bool(old[row] != y[row]), new_error=bool(new[row] != y[row]))
                            changes_out.write(json.dumps(item) + '\n')
                    print(f'{split} shard {index}: rows={len(y)} collision={int(collision.sum())} '
                          f'extra={int(extra.sum())} transitions={len(changed)}', flush=True)
            finally:
                if split == 'test':
                    errors_out.close(); changes_out.close()
            if split == 'test':
                os.replace(errors_tmp, errors_file)
                os.replace(changes_tmp, changes_file)
            routing['collision_percent'] = 100 * routing['collision'] / max(1, routing['rows'])
            routing['newly_routed_percent_of_rows'] = 100 * routing['newly_routed'] / max(1, routing['rows'])
            result = dict(identity=identity, policy=dict(collision_override=True, low=LOW, high=HIGH,
                                                         graph_threshold=GRAPH, selection='fixed a priori'),
                          scorer=version, routing=dict(routing), transition_counts=dict(transitions),
                          legacy=metrics(totals['legacy']), collision_aware=metrics(totals['collision_aware']),
                          groups={tag: dict(legacy=metrics(totals['legacy_' + tag]),
                                            collision_aware=metrics(totals['new_' + tag]))
                                  for tag in ('collision', 'noncollision')},
                          collision_graph_score_by_true_label={str(k): score_distribution(np.asarray(v))
                                                                for k, v in scores_by_label.items()})
            if result['groups']['noncollision']['legacy'] != result['groups']['noncollision']['collision_aware']:
                raise ValueError('Non-collision group changed')
            old_c = result['legacy']['confusion']
            new_c = result['collision_aware']['confusion']
            expected_new = dict(
                tp=old_c['tp'] + transitions['FN_corrected'] - transitions['FN_introduced'],
                fp=old_c['fp'] - transitions['FP_corrected'] + transitions['FP_introduced'],
                fn=old_c['fn'] - transitions['FN_corrected'] + transitions['FN_introduced'],
                tn=old_c['tn'] + transitions['FP_corrected'] - transitions['FP_introduced'])
            if new_c != expected_new:
                raise ValueError('Event transitions do not reconcile with confusion matrices')
            if split == 'test':
                if result['legacy']['confusion'] != REFERENCE_TEST:
                    raise ValueError('Legacy v4 TEST result did not reproduce reference')
                result['validation_selection'] = validation_reference['validation_selection']
            else:
                if result['legacy']['rows'] != data.meta['splits']['val']['rows']:
                    raise ValueError('Validation row count mismatch')
                if legacy_validation is not None and result['legacy']['confusion'] != legacy_validation:
                    raise ValueError('Legacy v4 validation result did not reproduce reference')
                result['validation_selection'] = dict(
                    preferred_policy=('collision_aware' if result['collision_aware']['f1'] > result['legacy']['f1']
                                      else 'legacy'),
                    criterion='higher validation F1; legacy wins ties',
                    test_evaluated_policy='predeclared fixed collision-aware candidate')
            results[split] = result
            atomic_json(output / ('validation_metrics.json' if split == 'val' else 'test_metrics.json'), result)
            if split == 'val':
                validation_reference = result
        summary = output / 'summary.md'
        v, t = results['val'], results['test']
        def metric_line(name, value):
            old, new = value['legacy'], value['collision_aware']
            old_c, new_c = old['confusion'], new['confusion']
            return (f"| {name} | {old_c['tp']:,}/{old_c['fp']:,}/{old_c['fn']:,}/{old_c['tn']:,} | "
                    f"{new_c['tp']:,}/{new_c['fp']:,}/{new_c['fn']:,}/{new_c['tn']:,} | "
                    f"{old['precision']:.6f}→{new['precision']:.6f} | "
                    f"{old['recall']:.6f}→{new['recall']:.6f} | "
                    f"{old['f1']:.6f}→{new['f1']:.6f} | "
                    f"{old['fpr']:.6f}→{new['fpr']:.6f} |")
        lines = [
            '# LightGBM v4 collision-aware routing', '',
            'The only policy change is routing every exact full-TRAIN label-conflicting '
            'Host vector to the frozen GraphSAGE at threshold 0.95. Non-collision '
            'events retain the v4 legacy 0.30/0.96 gates. Models, graph SQLite, '
            'feature schema, split, and thresholds are unchanged.', '',
            f"Manifest SHA-256: `{identity['manifest_sha256']}` (matches downloaded v4). "
            f"LightGBM: `{identity['host_model_sha256']}`; GraphSAGE: "
            f"`{identity['graph_model_sha256']}`. The full TRAIN partition has "
            f"{reg_summary['primary']['rows']['total']:,} rows and "
            f"{reg_summary['primary']['unique_vectors']:,} exact vectors; "
            f"{reg_summary['primary']['conflicting_vectors']:,} conflict. "
            f"The fit-only diagnostic excludes 333 benign rows but still has "
            f"{reg_summary['fit_only_diagnostic']['conflicting_vectors']:,} conflicting vectors.", '',
            '| Split | Legacy TP/FP/FN/TN | Collision-aware TP/FP/FN/TN | Precision | Recall | F1 | FPR |',
            '| --- | --- | --- | --- | --- | --- | --- |',
            metric_line('Validation', v), metric_line('TEST', t), '',
        ]
        for name, value in [('Validation', v), ('TEST', t)]:
            r, tr = value['routing'], value['transition_counts']
            lines += [
                f"## {name}", '',
                f"Collision events: {r['collision']:,}/{r['rows']:,} "
                f"({100*r['collision']/r['rows']:.2f}%); ML bands <0.30 / 0.30–0.96 / ≥0.96: "
                f"{r['collision_low']:,} / {r['collision_middle']:,} / {r['collision_high']:,}. "
                f"GraphSAGE calls: {r['legacy_graph']:,}→{r['new_graph']:,}; "
                f"+{r['newly_routed']:,} ({100*r['newly_routed']/max(1,r['legacy_graph']):.1f}% "
                'over legacy workload).', '',
                f"Collision-group errors corrected: {r['collision_corrected']:,}; "
                f"new errors introduced: {r['collision_new_errors']:,}. "
                f"Transitions FP corrected/new: {tr.get('FP_corrected',0):,}/"
                f"{tr.get('FP_introduced',0):,}; FN corrected/new: "
                f"{tr.get('FN_corrected',0):,}/{tr.get('FN_introduced',0):,}.", '',
                f"Low-ML collision override rescues {tr.get('FN_corrected',0):,} FN but "
                f"introduces {tr.get('FP_introduced',0):,} FP. High-ML collision "
                f"override vetoes {tr.get('FP_corrected',0):,} FP but introduces "
                f"{tr.get('FN_introduced',0):,} FN.", '',
                f"Collision-group F1: {value['groups']['collision']['legacy']['f1']:.6f}→"
                f"{value['groups']['collision']['collision_aware']['f1']:.6f}; "
                f"non-collision F1: {value['groups']['noncollision']['legacy']['f1']:.6f} "
                '(identical by invariant).', '',
            ]
        recommendation = ('The fixed routing rule improved validation F1; retain it as an '
                          'experimental candidate, with TEST used only for frozen evaluation.'
                          if v['collision_aware']['f1'] > v['legacy']['f1'] else
                          'The fixed routing rule did not improve validation F1; do not '
                          'promote it as the default cascade policy.')
        lines += ['## Interpretation', '', recommendation,
                  'The full TEST baseline was independently reproduced before comparison. '
                  'Every changed prediction is keyed by `(source_id, source_line)` in '
                  '`event_transition_audit.jsonl`, and every final FP/FN is in '
                  '`test_errors_full_scores.jsonl`. Confusion deltas reconcile exactly '
                  'with the transition counts. TEST labels were never used for registry '
                  'construction, routing, or threshold selection.', '',
                  f"The conflicting TRAIN vectors contain "
                  f"{reg_summary['primary']['conflicting_vector_rows']['benign']:,} benign "
                  f"and {reg_summary['primary']['conflicting_vector_rows']['malicious']:,} "
                  'malicious rows. Collision membership is therefore common among '
                  'benign events; unconditional routing exposes its high-score tail '
                  'to GraphSAGE false positives.', '',
                  'Collision membership proves only that the Host vector is ambiguous '
                  'within TRAIN. GraphSAGE can still make new errors; its existing '
                  'Process/Host graph lacks FILE/MODULE nodes and was trained with '
                  'one-second snapshots. The local score-only cache was stripped '
                  'from a frozen-checkpoint census because the LightGBM wheel is '
                  'unavailable locally; the Kaggle notebook uses the native frozen '
                  'LightGBM checkpoint. Both runs verify the same model hash. '
                  'The fit-only registry is reconstructed from the published '
                  'sampling algorithm and seed; the downloaded model result did '
                  'not include row-identity receipts for those 333 excluded benign '
                  'TRAIN rows.', '']
        summary_tmp = summary.with_suffix('.md.tmp')
        with summary_tmp.open('w') as stream:
            stream.write('\n'.join(lines))
            stream.flush(); os.fsync(stream.fileno())
        os.replace(summary_tmp, summary)
        return results
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--score-map')
    parser.add_argument('--legacy-result')
    parser.add_argument('--volume-root-ssd')
    args = parser.parse_args()
    run(args.manifest, args.bundle, args.output,
        score_map=args.score_map, legacy_result=args.legacy_result,
        volume_root_ssd=args.volume_root_ssd)


if __name__ == '__main__':
    main()
