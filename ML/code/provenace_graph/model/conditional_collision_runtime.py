"""Validation-selected conditional collision routing over frozen v4 models.

Low-band extra FP and high-band extra FN budgets are fixed before TEST.
The middle band and every non-collision decision reproduce legacy v4.
"""
from collections import Counter, defaultdict
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'preprocess'))

from ML.code.provenace_graph.model.collision_aware_runtime import (BASELINE, GRAPH, HIGH, LOW, REFERENCE_MANIFEST_SHA,
    REFERENCE_TEST, REFERENCE_VAL, atomic_json, build_registry, get_shard, key_for_row,
    publish_registry, registry_summary, score_distribution, score_map_from_audit)
from ML.code.provenace_graph.model.cascade_runtime import counts, metrics, safe, sha, verify_bundle, load_host_model
from ML.code.provenace_graph.model.ego import EgoGraphs
from ML.code.provenace_graph.model.relational_sage import RelationalSAGE

LOW_FP_BUDGET = 10
HIGH_FN_BUDGET = 10
MIN_F1_GAIN = 0.0001


def threshold_options(labels, scores, *, band):
    """Pareto points under the fixed error budget; inclusive graph threshold."""
    labels = np.asarray(labels, dtype=np.uint8)
    scores = np.asarray(scores, dtype=np.float64)
    if not np.all(np.isfinite(scores)):
        raise ValueError('Non-finite collision graph score')
    # At 1.0, all finite model probabilities are below threshold.
    values = np.unique(np.concatenate(([1.0], scores)))
    order = np.argsort(scores, kind='stable')[::-1]
    ranked = scores[order]
    positive = np.cumsum(labels[order] == 1)
    negative = np.cumsum(labels[order] == 0)
    best = {}
    for threshold in values:
        selected = int(np.searchsorted(-ranked, -threshold, side='right'))
        tp = int(positive[selected-1]) if selected else 0
        fp = int(negative[selected-1]) if selected else 0
        if band == 'low':
            if fp > LOW_FP_BUDGET:
                continue
            budget_used, benefit = fp, tp
        else:
            fn = int(np.sum(labels == 1)) - tp
            corrected_fp = int(np.sum(labels == 0)) - fp
            if fn > HIGH_FN_BUDGET:
                continue
            budget_used, benefit = fn, corrected_fp
        incumbent = best.get(budget_used)
        if incumbent is None or benefit > incumbent['benefit'] or (
                benefit == incumbent['benefit'] and threshold > incumbent['threshold']):
            best[budget_used] = dict(threshold=float(threshold), budget_used=budget_used,
                                     benefit=benefit, tp=tp, fp=fp,
                                     fn=int(np.sum(labels == 1))-tp,
                                     tn=int(np.sum(labels == 0))-fp)
    return list(best.values())


def select_policy(legacy_counts, low, high):
    """Pick validation-only constrained F1 optimum; legacy wins unclear gains."""
    old = metrics(np.asarray(legacy_counts, dtype=np.int64))
    candidates = []
    for left in threshold_options(*low, band='low'):
        for right in threshold_options(*high, band='high'):
            delta = np.array([left['tp']-right['fn'], left['fp']-right['tn'],
                              -left['tp']+right['fn'], -left['fp']+right['tn']], dtype=np.int64)
            candidate = metrics(np.asarray(legacy_counts, dtype=np.int64)+delta)
            candidates.append((candidate['f1'], left, right, candidate))
    if not candidates:
        raise ValueError('No budget-compliant candidates')
    candidates.sort(key=lambda item: (item[0], -item[3]['confusion']['fp'],
                                      -item[3]['confusion']['fn']), reverse=True)
    f1, left, right, measured = candidates[0]
    accepted = f1 >= old['f1'] + MIN_F1_GAIN
    return dict(accepted=accepted, selected='conditional' if accepted else 'legacy',
                low_threshold=left['threshold'], high_threshold=right['threshold'],
                low_extra_fp=left['fp'], low_rescued_fn=left['tp'],
                high_vetoed_fp=right['tn'], high_extra_fn=right['fn'],
                validation_candidate=measured, validation_legacy=old,
                fp_budget_low=LOW_FP_BUDGET, fn_budget_high=HIGH_FN_BUDGET,
                minimum_f1_gain=MIN_F1_GAIN, candidates_evaluated=len(candidates),
                selection_basis='validation labels only; fixed budgets; middle and noncollision unchanged')


def predict(ml, graph, collision, policy):
    middle = (ml >= LOW) & (ml < HIGH)
    old = np.where(middle, graph >= GRAPH, ml >= HIGH)
    if not policy['accepted']:
        return old, old.copy(), np.full(len(ml), 'legacy_frozen', dtype=object)
    low = collision & (ml < LOW)
    high = collision & (ml >= HIGH)
    required = middle | low | high
    if not np.all(np.isfinite(graph[required])):
        raise ValueError('Required GraphSAGE score missing')
    new = old.copy()
    new[low] = graph[low] >= policy['low_threshold']
    new[high] = graph[high] >= policy['high_threshold']
    reason = np.where(low, 'collision_low', np.where(high, 'collision_high_veto',
                      np.where(middle, 'legacy_middle', 'legacy_direct')))
    return old, new, reason


def per_vector_audit(registry, val_rows, policy, output):
    groups = defaultdict(lambda: [[], []])
    for row in val_rows:
        groups[row['key']][row['label']].append(row)
    identical = defaultdict(list)
    candidate_pairs = []
    for key, (benign, malignant) in groups.items():
        by_score = defaultdict(lambda: [[], []])
        for row in benign+malignant:
            by_score[row['graph']][row['label']].append(row)
        for score, (b, m) in by_score.items():
            if b and m:
                candidate_pairs.append((key, score, b[0], m[0]))
    # Equal scores alone do not prove equal graph input. Verify encoded tensors.
    db_path = output['bundle'] / 'provenance/graph.sqlite'
    db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    ego = EgoGraphs(db)
    checked = 0
    try:
        for key, score, benign, malignant in candidate_pairs:
            if checked >= 2000:
                break
            digests = []
            for row in (benign, malignant):
                target = db.execute('SELECT host,proc,t,split FROM target WHERE source=? AND line=?',
                                    (row['source_id'], row['source_line'])).fetchone()
                if target is None or target[3] != 2:
                    raise ValueError('Validation graph target missing')
                graph = ego.build(*target[:3])
                content = graph['x'].tobytes() + repr(graph['edges']).encode()
                digests.append(hashlib.sha256(content).hexdigest())
            checked += 1
            if digests[0] == digests[1]:
                identical[key].append(dict(graph_score=score, graph_encoding_sha256=digests[0],
                                           benign_event=[benign['source_id'], benign['source_line']],
                                           malicious_event=[malignant['source_id'], malignant['source_line']],
                                           interpretation='representation_limitation'))
    finally:
        db.close()
    audit_path = output['path'] / 'validation_per_vector_audit.jsonl'
    with audit_path.open('w') as stream:
        for key in sorted(registry):
            item = registry[key]
            if item['labels'] != [0, 1]:
                continue
            benign, malignant = groups[key]
            conf = Counter()
            for row in benign+malignant:
                old = row['legacy_prediction']
                new = row['candidate_prediction'] if policy['accepted'] else old
                if new != row['label']:
                    conf['fp' if row['label'] == 0 else 'fn'] += 1
                if old != row['label']:
                    conf['legacy_fp' if row['label'] == 0 else 'legacy_fn'] += 1
            example = (benign or malignant)
            ml_score = example[0]['ml'] if example else None
            ml_band = ('low' if ml_score < LOW else 'middle' if ml_score < HIGH else 'high') if ml_score is not None else None
            stream.write(json.dumps(dict(vector_key=key.hex(),
                train_label_counts=item['train_label_counts'],
                validation_ml_score=ml_score, validation_ml_band=ml_band,
                validation_counts=dict(benign=len(benign), malicious=len(malignant)),
                validation_scores=dict(benign=score_distribution(np.array([r['graph'] for r in benign])),
                                       malicious=score_distribution(np.array([r['graph'] for r in malignant]))),
                validation_errors={name:int(conf[name]) for name in ('legacy_fp','legacy_fn','fp','fn')},
                verified_identical_graph_input_examples=identical[key][:5],
                representation_limitation_verified=bool(identical[key]))) + '\n')
    atomic_json(output['path'] / 'representation_limitations.json', dict(
        equal_score_opposite_label_groups=len(candidate_pairs), groups_checked=checked,
        check_cap=2000, verified_pairs=sum(len(v) for v in identical.values()),
        vectors_with_verified_limitations=sum(bool(v) for v in identical.values()),
        scope='one representative opposite-label pair per vector and identical score; not exhaustive'))


def run(manifest_path, bundle, output, *, score_map=None, cache_source=None,
        registry_source=None, volume_root_ssd=None):
    from host_shards import HostShardDataset
    manifest_path, bundle, output = map(lambda p: Path(p).resolve(),
                                         (manifest_path, bundle, output))
    safe(output)
    if output.is_relative_to(bundle) or output.is_relative_to(manifest_path.parent):
        raise ValueError('Output overlaps input')
    output.mkdir(parents=True, exist_ok=True)
    bundle_meta = verify_bundle(bundle)
    if bundle_meta.get('schema') != 4 or bundle_meta.get('context_policy', {}).get('timestamp_quantum_us') != 1:
        raise ValueError('Exact-time v4 bundle required')
    data = HostShardDataset(manifest_path,
        volume_roots={'ssd': volume_root_ssd} if volume_root_ssd else None)
    identity = dict(manifest_sha256=sha(manifest_path), bundle_sha256=sha(bundle / 'bundle_manifest.json'),
                    graph_sha256=bundle_meta['files']['provenance/graph.sqlite']['sha256'],
                    graph_model_sha256=bundle_meta['files']['provenance/model_numpy.npz']['sha256'],
                    host_model_sha256=bundle_meta['files']['models/lgbm_model.txt']['sha256'],
                    schema_sha256=sha(manifest_path.parent / 'assets/vocab.json'),
                    feature_width=data.width, key_method='exact sorted uint32 column bytes, little-endian',
                    low=LOW, high=HIGH, graph_threshold=GRAPH, baseline_threshold=BASELINE)
    if identity['manifest_sha256'] != REFERENCE_MANIFEST_SHA:
        raise ValueError('Frozen Host manifest mismatch')
    baseline_meta = json.loads((bundle / 'models/lgbm_metrics.json').read_text())
    if baseline_meta['validation']['threshold'] != BASELINE:
        raise ValueError('Frozen LightGBM threshold mismatch')
    for filename, field in (('vocab.json','vocabulary_sha256'),
                            ('split_manifest.json','split_sha256')):
        if sha(manifest_path.parent / 'assets' / filename) != baseline_meta[field]:
            raise ValueError('Frozen split/feature asset mismatch')
    atomic_json(output / 'config.json', identity)
    atomic_json(output / 'source_index.json',
        {str(s['source_id']): s['source']['path'] for s in data.meta['sources']})
    if registry_source:
        source = Path(registry_source).resolve()
        prior = json.loads((source / 'config.json').read_text())
        if prior != identity:
            raise ValueError('TRAIN registry identity mismatch')
        registry = {bytes.fromhex(d['vector_key']): dict(labels=d['labels'],
                    train_label_counts=d['train_label_counts'])
                    for line in (source / 'collision_registry.jsonl').open()
                    if (d := json.loads(line))['labels'] == [0, 1]}
        summary = json.loads((source / 'collision_registry_summary.json').read_text())
    else:
        full, fit, full_rows, fit_rows, full_occ, fit_occ = build_registry(data)
        registry = {k: dict(labels=[0,1], train_label_counts=full_occ[k])
                    for k,v in full.items() if v == 3}
        summary = dict(primary=registry_summary(full, full_rows, full_occ),
                       fit_only_diagnostic=registry_summary(fit, fit_rows, fit_occ),
                       identity=identity)
    atomic_json(output / 'collision_registry_summary.json', summary)
    with (output / 'collision_registry.jsonl').open('w') as stream:
        for key,item in sorted(registry.items()):
            stream.write(json.dumps(dict(vector_key=key.hex(), **item))+'\n')
    if score_map:
        mapping = score_map_from_audit(score_map, identity['host_model_sha256'])
        def host_scores(x):
            return np.array([mapping[key_for_row(x,i)] for i in range(x.shape[0])])
        scorer = 'audited frozen score-only map'
    else:
        scorer_fn, version = load_host_model(bundle, 'lgbm')
        if version != bundle_meta['model_identities']['lgbm']['library_version']:
            raise ValueError('LightGBM library version mismatch')
        def host_scores(x):
            return np.asarray(scorer_fn(x), dtype=np.float64)
        scorer = version
    model = None
    db = None
    ego = None
    def graph_scores(split, index, shard, lines, routed):
        nonlocal model, db, ego
        if cache_source:
            path = Path(cache_source) / f'{split}-graph-{index:04d}.npz'
            receipt = json.loads(path.with_suffix('.json').read_text())
            if (receipt['identity'] != identity or receipt['source_id'] != shard['source_id']
                    or receipt['shard_sha256'] != shard['sha256'] or sha(path) != receipt['sha256']):
                raise ValueError('Graph cache receipt mismatch')
            with np.load(path, allow_pickle=False) as file:
                graph = file['graph']
            if len(graph) != len(lines) or not np.all(np.isfinite(graph[routed])):
                raise ValueError('Missing required frozen graph score')
            return graph
        if model is None:
            model = RelationalSAGE.load(bundle / 'provenance/model_numpy.npz')
            db_path = bundle / 'provenance/graph.sqlite'
            db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
            db.execute('PRAGMA cache_size=-262144')
            ego = EgoGraphs(db)
        graph = np.full(len(lines), np.nan)
        missing = []
        for row in np.flatnonzero(routed):
            target = db.execute('SELECT host,proc,t FROM target WHERE source=? AND line=?',
                                (shard['source_id'], int(lines[row]))).fetchone()
            if target is None or not target[0] or not target[1] or target[2] is None:
                missing.append([shard['source_id'],int(lines[row])])
                continue
            graph[row] = model.predict(ego.build(*target))['probability']
        if missing:
            atomic_json(output / f'{split}-missing-{index:04d}.json', missing)
            raise ValueError('Missing required graph targets')
        return graph
    try:
        val_rows = []
        val_total = np.zeros(4,dtype=np.int64)
        val_count = 0
        for index, shard in enumerate(data.meta['shards']):
            if shard['split'] != 'val':
                continue
            x,y,lines = get_shard(data,shard)
            ml = host_scores(x)
            collision = np.fromiter((key_for_row(x,i) in registry for i in range(len(y))),
                                    dtype=bool,count=len(y))
            middle = (ml >= LOW) & (ml < HIGH)
            graph = graph_scores('val',index,shard,lines,collision|middle)
            old = np.where(middle, graph >= GRAPH, ml >= HIGH)
            val_total += counts(y,old)
            val_count += len(y)
            for row in np.flatnonzero(collision):
                val_rows.append(dict(key=key_for_row(x,int(row)), label=int(y[row]),
                    ml=float(ml[row]), graph=float(graph[row]),
                    source_id=shard['source_id'], source_line=int(lines[row]),
                    legacy_prediction=int(old[row])))
            print(f'validation shard {index}: {len(y)} rows, {int(collision.sum())} collisions',flush=True)
        if val_count != data.meta['splits']['val']['rows'] or metrics(val_total)['confusion'] != REFERENCE_VAL:
            raise ValueError('Legacy validation baseline not reproduced')
        low = [r for r in val_rows if r['ml'] < LOW]
        high = [r for r in val_rows if r['ml'] >= HIGH]
        policy = select_policy(val_total, ([r['label'] for r in low],[r['graph'] for r in low]),
                              ([r['label'] for r in high],[r['graph'] for r in high]))
        for row in val_rows:
            if row['ml'] < LOW:
                row['candidate_prediction'] = int(row['graph'] >= policy['low_threshold'])
            elif row['ml'] >= HIGH:
                row['candidate_prediction'] = int(row['graph'] >= policy['high_threshold'])
            else:
                row['candidate_prediction'] = row['legacy_prediction']
        val_transitions = Counter()
        for row in val_rows:
            new = row['candidate_prediction'] if policy['accepted'] else row['legacy_prediction']
            if new != row['legacy_prediction']:
                val_transitions[('FP' if row['label']==0 else 'FN')+
                    ('_corrected' if new==row['label'] else '_introduced')] += 1
        atomic_json(output / 'frozen_policy.json',dict(identity=identity,policy=policy))
        atomic_json(output / 'validation_metrics.json',dict(identity=identity,scorer=scorer,
            policy=policy,legacy=metrics(val_total),selected=(policy['validation_candidate'] if policy['accepted']
            else metrics(val_total)),transition_counts=dict(val_transitions),
            collision_events=len(val_rows),low_collision_events=len(low),high_collision_events=len(high)))
        per_vector_audit(registry,val_rows,policy,dict(bundle=bundle,path=output))
        # TEST is opened only after the validation policy has been frozen on disk.
        frozen = json.loads((output / 'frozen_policy.json').read_text())
        if frozen['identity'] != identity or frozen['policy'] != policy:
            raise ValueError('Frozen validation policy changed')
        test_old=np.zeros(4,dtype=np.int64);test_new=np.zeros(4,dtype=np.int64)
        transitions=Counter(); routing=Counter(); test_count=0
        errors_tmp=output/'test_errors_full_scores.jsonl.tmp'
        changes_tmp=output/'event_transition_audit.jsonl.tmp'
        with errors_tmp.open('w') as errors, changes_tmp.open('w') as changes:
            for index,shard in enumerate(data.meta['shards']):
                if shard['split'] != 'test':
                    continue
                x,y,lines=get_shard(data,shard)
                ml=host_scores(x)
                collision=np.fromiter((key_for_row(x,i) in registry for i in range(len(y))),
                                      dtype=bool,count=len(y))
                middle=(ml>=LOW)&(ml<HIGH)
                routed=middle | (collision if policy['accepted'] else np.zeros(len(y),dtype=bool))
                graph=graph_scores('test',index,shard,lines,routed)
                old,new,reason=predict(ml,graph,collision,policy)
                if np.any((old!=new)&~collision) or np.any((old!=new)&middle):
                    raise ValueError('Middle/noncollision prediction changed')
                test_old+=counts(y,old);test_new+=counts(y,new)
                test_count+=len(y)
                routing['legacy_graph']+=int(middle.sum())
                routing['selected_graph']+=int(routed.sum())
                routing['newly_routed']+=int((routed&~middle).sum())
                for row in np.flatnonzero(new!=y):
                    errors.write(json.dumps(dict(source_id=shard['source_id'],source_line=int(lines[row]),
                        label=int(y[row]),ml_score=float(ml[row]),graph_score=float(graph[row])
                        if np.isfinite(graph[row]) else None,collision=bool(collision[row]),
                        route_reason=str(reason[row]),prediction=int(new[row]),
                        legacy_prediction=int(old[row]),error='FP' if y[row]==0 else 'FN'))+'\n')
                for row in np.flatnonzero(old!=new):
                    kind=('FP' if y[row]==0 else 'FN')+('_corrected' if new[row]==y[row] else '_introduced')
                    transitions[kind]+=1
                    changes.write(json.dumps(dict(source_id=shard['source_id'],source_line=int(lines[row]),
                        label=int(y[row]),ml_score=float(ml[row]),graph_score=float(graph[row]),
                        collision=True,old_prediction=int(old[row]),new_prediction=int(new[row]),
                        reason=str(reason[row]),transition=kind))+'\n')
                print(f'TEST shard {index}: {len(y)} rows, {int(np.sum(old!=new))} changes',flush=True)
        os.replace(errors_tmp,output/'test_errors_full_scores.jsonl')
        os.replace(changes_tmp,output/'event_transition_audit.jsonl')
        if test_count!=data.meta['splits']['test']['rows'] or metrics(test_old)['confusion']!=REFERENCE_TEST:
            raise ValueError('Legacy TEST baseline not reproduced')
        old_c=metrics(test_old)['confusion'];new_c=metrics(test_new)['confusion']
        reconciled=dict(tp=old_c['tp']+transitions['FN_corrected']-transitions['FN_introduced'],
            fp=old_c['fp']-transitions['FP_corrected']+transitions['FP_introduced'],
            fn=old_c['fn']-transitions['FN_corrected']+transitions['FN_introduced'],
            tn=old_c['tn']+transitions['FP_corrected']-transitions['FP_introduced'])
        if new_c!=reconciled:
            raise ValueError('TEST transitions do not reconcile')
        atomic_json(output/'test_metrics.json',dict(identity=identity,policy=policy,
            legacy=metrics(test_old),selected=metrics(test_new),routing=dict(routing),
            transition_counts=dict(transitions)))
        lines=['# Conditional collision-aware LightGBM v4', '',
            'Policy selection used validation labels only. Low extra-FP budget: 10; '
            'high extra-FN budget: 10; minimum validation F1 gain: 0.0001. '
            'Middle band and non-collision decisions remained legacy. Model weights, '
            'Host preprocessing and exact-time graph were unchanged.', '',
            f"Selected: **{policy['selected']}**. Best validation candidate: low graph "
            f"threshold {policy['low_threshold']:.9g}, high veto threshold "
            f"{policy['high_threshold']:.9g}; low extra FP {policy['low_extra_fp']}, "
            f"FN rescued {policy['low_rescued_fn']}; high FP vetoed "
            f"{policy['high_vetoed_fp']}, FN introduced {policy['high_extra_fn']}.", '',
            '| Split | Policy | TP | FP | FN | TN | Precision | Recall | F1 | FPR |',
            '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
        for name,old,new in [('Validation',metrics(val_total),policy['validation_candidate'] if policy['accepted'] else metrics(val_total)),
                             ('TEST',metrics(test_old),metrics(test_new))]:
            for tag,value in [('legacy',old),('selected',new)]:
                c=value['confusion']
                lines.append(f"| {name} | {tag} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | "
                    f"{value['precision']:.6f} | {value['recall']:.6f} | {value['f1']:.6f} | {value['fpr']:.6f} |")
        lines+=['',f"Validation transitions: {dict(val_transitions)}; TEST transitions: {dict(transitions)}.",
            f"TEST GraphSAGE calls: {routing['legacy_graph']}→{routing['selected_graph']} "
            f"(+{routing['newly_routed']}).",'',
            'The validation-approved policy reduces FP and improves F1, but requires '
            'substantially more GraphSAGE inference. Treat it as an experimental '
            'candidate rather than an unqualified deployment recommendation.', '',
            'Per-vector TRAIN counts, validation score distributions and errors are in '
            '`validation_per_vector_audit.jsonl`. Verified opposite-label identical '
            'graph encodings are marked as representation limitations; the check samples '
            'one pair per vector and identical score, so it is not an exhaustive census. '
            'All final TEST FP/FN and prediction transitions are exported separately. '
            'The local run uses a label-free audited LightGBM score map whose model '
            'hash matches the frozen checkpoint; the Kaggle notebook loads that '
            'checkpoint natively and verifies the same identity.']
        (output/'summary.md').write_text('\n'.join(lines)+'\n')
        return dict(validation=metrics(val_total),test=metrics(test_new),policy=policy)
    finally:
        if db is not None:
            db.close()


def main():
    parser=argparse.ArgumentParser()
    for name in ('manifest','bundle','output'):
        parser.add_argument('--'+name,required=True)
    for name in ('score-map','cache-source','registry-source','volume-root-ssd'):
        parser.add_argument('--'+name)
    args=parser.parse_args()
    run(args.manifest,args.bundle,args.output,score_map=args.score_map,
        cache_source=args.cache_source,registry_source=args.registry_source,
        volume_root_ssd=args.volume_root_ssd)


if __name__=='__main__':
    main()
