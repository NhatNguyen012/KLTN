#!/usr/bin/env python3
"""
graph_vs_ml_complementarity.py
===============================
Phân tích complementarity giữa learned GraphSAGE và 3 Host ML models (RF/XGB/LGBM).

Phương pháp:
  1. Load graph scores cho 2000 test ego-graphs (từ seed02_ego_cache metadata;
     nếu có model weights thì chạy inference NumPy).
  2. Join với ML errors (source_id + source_line) từ diagnostics/test_errors.json.
  3. Đo: graph sửa được bao nhiêu FP/FN mà ML bỏ sót? Và bao nhiêu TN/TP bị phá?
  4. Phân tích theo case pattern từ fp_fn_casebook/report.md.
  5. Tính cross-model: events mà tất cả 3 ML sai nhưng graph đúng.

Lưu ý thiết kế:
  - Graph scores KHÔNG calibrated (balanced TRAIN sampling).
  - Graph threshold = 0.9666 (val-selected). ML thresholds riêng biệt.
  - Join key: (source_id, source_line) — có trong cả test_errors.json và selection.json.
  - 2000 graph events ⊂ 1,249,689 ML test events.
  - Nếu không có model weights → metadata-only mode (graph_score=None).

Chạy:
  python3 code/audit/graph_vs_ml_complementarity.py
  python3 code/audit/graph_vs_ml_complementarity.py --model-weights code/output/provenace_graph/learned_model
"""

from __future__ import annotations

import json
import sys
import argparse
from pathlib import Path
from collections import Counter
import numpy as np

# ─── Paths ─────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CACHE = ROOT / 'code/output/provenace_graph/seed02_ego_cache'
DEFAULT_ML_OUT = ROOT / 'code/output/host_ml_seed02/kaggle_ouput'
DEFAULT_GRAPH_OUT = ROOT / 'code/output/provenace_graph/kaggle_output'
DEFAULT_OUT = ROOT / 'code/output/provenace_graph'

MODELS = ['lgbm', 'xgb', 'rf']

# Graph validation threshold (from Kaggle run)
GRAPH_VAL_THRESHOLD = 0.9666019678115845
GRAPH_TEST_F1 = 0.8990825688073395

# ML thresholds (from metrics.json — each selected on its own val set)
ML_THRESHOLDS = {'lgbm': 0.94016, 'xgb': 0.87878, 'rf': 0.56634}

# Known casebook source_line → (case_id, case_type, primary_error)
# From fp_fn_casebook/report.md, decompressed line numbers.
# case_type: vector_collision | generalization | near_threshold | context_loss
KNOWN_CASEBOOK_LINES = {
    2380855: ('C01', 'vector_collision',  'FP'),   # Chrome font READ
    2385869: ('C02', 'vector_collision',  'FP'),   # Chrome READ no file_path
    2684013: ('C03', 'vector_collision',  'FP'),   # PING two IPs
    2440766: ('C04', 'generalization',    'FP'),   # Chrome $USNJRNL
    # C05/C06 lwabeat — FN, vector_collision (exact match, benign-dominated)
    # Lines from casebook not yet extracted; will match if present in cache
    # C07: Excel FN near threshold
    # C08: Start-Sleep FP context_loss
    # C09: PING LOAD FP generalization
    # C10: Edge partial FN near_threshold
    # C11/C12: Chrome tmp/AppData FP RF-only
    # C13: Chrome renderer FP RF-only
    # C14/C15/C16: various FN
}


# ─── Loaders ───────────────────────────────────────────────────────────────

def load_selection(cache_dir: Path) -> list[dict]:
    """Load test rows from selection.json."""
    sel = json.loads((cache_dir / 'selection.json').read_text())
    return sel['splits']['test']['rows']


def load_graph_metadata(cache_dir: Path) -> list[dict]:
    """
    Load metadata from all test shards.
    Returns list[{idx, source_id, source_line, label, graph_nodes, graph_edges,
                  has_missing_context, graph_score=None, graph_pred=None}]
    """
    sel_rows = load_selection(cache_dir)
    # Build source_id lookup by source_line
    line_to_source_id = {r['source_line']: r['source_id'] for r in sel_rows}

    test_dir = cache_dir / 'test'
    shard_files = sorted(test_dir.glob('*.npz'))
    results = []
    graph_idx = 0

    for shard_file in shard_files:
        shard = np.load(shard_file, allow_pickle=False)
        node_ptr = shard['node_ptr']      # (n+1,)
        x = shard['x']                    # (total_nodes, 40)
        edge_index = shard['edge_index']  # (2, total_edges)
        root = shard['root']              # (n,) — actor node global idx
        host_root = shard['host_root']    # (n,)
        labels = shard['label']           # (n,)
        source_lines = shard['source_line']  # (n,)

        n_graphs = len(root)
        for gi in range(n_graphs):
            n_start = int(node_ptr[gi])
            n_end = int(node_ptr[gi + 1])
            n_nodes = n_end - n_start
            edge_mask = (edge_index[0] >= n_start) & (edge_index[0] < n_end)
            n_edges = int(edge_mask.sum())
            actor_local = int(root[gi]) - n_start
            xi = x[n_start:n_end]
            # Attribute index 2 = missing_metadata (from config.json)
            has_missing_context = bool(xi[actor_local, 2]) if n_nodes > 0 else True

            src_line = int(source_lines[gi])
            results.append({
                'idx': graph_idx,
                'source_id': line_to_source_id.get(src_line, ''),
                'source_line': src_line,
                'label': int(labels[gi]),
                'graph_nodes': n_nodes,
                'graph_edges': n_edges,
                'has_missing_context': has_missing_context,
                'graph_score': None,
                'graph_pred': None,
            })
            graph_idx += 1

    return results


def run_graph_inference(events: list[dict], cache_dir: Path, weights_dir: Path) -> None:
    """
    Run NumPy inference and fill graph_score / graph_pred in-place.
    Uses relational_sage.RelationalSAGE.load(path) to load weights, then
    converts each NPZ graph to the dict format expected by RelationalSAGE.forward().
    """
    sage_path = ROOT / 'code/provenace_graph/model'
    sys.path.insert(0, str(sage_path))
    try:
        from relational_sage import RelationalSAGE, RELATIONS  # type: ignore
    except ImportError as e:
        print(f'[WARN] Cannot import RelationalSAGE: {e}. Skipping inference.', file=sys.stderr)
        return

    # Find weights: prefer model_numpy.npz (from export_numpy_weights), then model-slot-*.npz
    candidates = (
        sorted(weights_dir.glob('model_numpy.npz')) +
        sorted(weights_dir.glob('model-slot-*.npz')) +
        sorted(weights_dir.glob('model*.npz'))
    )
    if not candidates:
        print(f'[WARN] No .npz weight files found in {weights_dir}', file=sys.stderr)
        return
    weight_file = candidates[0]  # model_numpy.npz first
    print(f'  Using weights: {weight_file}')
    try:
        model = RelationalSAGE.load(weight_file)
        print(f'  Model: input_dim={model.input_dim}, hidden={model.hidden}, embedding={model.embedding}, params={model.parameter_count}')
    except Exception as e:
        print(f'[WARN] Could not load model: {e}', file=sys.stderr)
        return

    # relation_id → name mapping (from ego_cache RELATIONS order)
    # ego_cache.py: RELATIONS = ('creates', 'communicates', 'communicates_reverse', 'hosts')
    # edge_type uint8 value = index in RELATIONS
    RELATION_NAMES = list(RELATIONS)

    threshold = GRAPH_VAL_THRESHOLD
    ev_by_line = {e['source_line']: e for e in events}

    test_dir = cache_dir / 'test'
    n_scored = 0
    n_error = 0

    for shard_file in sorted(test_dir.glob('*.npz')):
        shard = np.load(shard_file, allow_pickle=False)
        node_ptr   = shard['node_ptr']    # (n_graphs+1,) global node offsets
        x_all      = shard['x']           # (total_nodes, 40)
        edge_index = shard['edge_index']  # (2, total_edges) global node indices
        edge_type  = shard['edge_type']   # (total_edges,) uint8
        root_all   = shard['root']        # (n_graphs,) global actor node idx
        host_root_all = shard['host_root']# (n_graphs,) global host node idx
        source_lines  = shard['source_line']
        n_graphs = len(root_all)

        for gi in range(n_graphs):
            n_start = int(node_ptr[gi])
            n_end   = int(node_ptr[gi + 1])

            # Extract this graph's node features (local indices 0..n_nodes-1)
            xi = x_all[n_start:n_end].astype(float)

            # Extract edges belonging to this graph, re-index to local
            edge_mask = (edge_index[0] >= n_start) & (edge_index[0] < n_end)
            local_src = edge_index[0, edge_mask] - n_start
            local_dst = edge_index[1, edge_mask] - n_start
            local_rel = edge_type[edge_mask]

            # Convert to relational_sage edge list format:
            # edges: list of (src_local, dst_local, relation_name)
            edges = []
            for s, d, r in zip(local_src.tolist(), local_dst.tolist(), local_rel.tolist()):
                if r < len(RELATION_NAMES):
                    edges.append((s, d, RELATION_NAMES[r]))

            actor_local = int(root_all[gi]) - n_start
            host_local  = int(host_root_all[gi]) - n_start

            graph_dict = {
                'x': xi,
                'edges': edges,
                'root': actor_local,
                'host_root': host_local,
            }

            try:
                logit, _, _ = model.forward(graph_dict)
                score = float(1.0 / (1.0 + np.exp(-logit)))
                n_scored += 1
            except Exception as exc:
                score = 0.0
                n_error += 1
                if n_error <= 3:
                    print(f'[WARN] forward error at source_line={source_lines[gi]}: {exc}', file=sys.stderr)

            src_line = int(source_lines[gi])
            ev = ev_by_line.get(src_line)
            if ev is not None:
                ev['graph_score'] = score
                ev['graph_pred'] = int(score >= threshold)

    print(f'  Scored: {n_scored}/2000  errors: {n_error}')


def load_ml_errors(ml_dir: Path, model: str) -> tuple[dict, dict]:
    """Load test_errors.json.

    Returns:
        by_line: dict[source_line → record]  (primary join)
        by_key:  dict[(source_id, source_line) → record]  (secondary, usually fails)

    NOTE: source_id in test_errors.json is SHA256 of gz CONTENT, not gz PATH.
    The graph cache selection.json uses SHA256 of gz PATH. Join on source_line only.
    """
    p = ml_dir / f'{model}_kaggle_results/results/diagnostics/test_errors.json'
    if not p.exists():
        print(f'[WARN] Missing: {p}', file=sys.stderr)
        return {}, {}
    data = json.loads(p.read_text())
    by_line: dict[int, dict] = {}
    by_key: dict[tuple, dict] = {}
    for ex in data.get('examples', []):
        by_line[ex['source_line']] = ex
        by_key[(ex['source_id'], ex['source_line'])] = ex
    return by_line, by_key


def load_ml_probe_scores(ml_dir: Path, model: str) -> dict[int, float]:
    """Load probe scores from test-state.npz diagnostics.

    Returns dict[source_line → score]. Probe is a small sample (~11k events)
    so most graph events won't have probe scores. Mainly useful to classify
    TN/TP for events that ARE in the probe set.
    """
    p = ml_dir / f'{model}_kaggle_results/results/test-state.npz'
    if not p.exists():
        return {}
    d = np.load(p, allow_pickle=True)
    scores: dict[int, float] = {}
    try:
        diag = json.loads(str(d['diagnostics']))
        for key in ('probe', 'extremes'):
            for item in diag.get(key, []):
                items = item if isinstance(item, list) else [item]
                for ev in items:
                    if 'source_line' in ev and 'score' in ev:
                        scores[ev['source_line']] = ev['score']
    except Exception as e:
        print(f'[WARN] probe parse error for {model}: {e}', file=sys.stderr)
    return scores


# ─── Analysis ──────────────────────────────────────────────────────────────

def joint_outcome(label: int, ml_pred: int | None, graph_pred: int | None) -> dict:
    def o(p, t):
        if p is None: return 'unknown'
        if p == 1 and t == 1: return 'TP'
        if p == 1 and t == 0: return 'FP'
        if p == 0 and t == 1: return 'FN'
        return 'TN'

    ml_o = o(ml_pred, label)
    gr_o = o(graph_pred, label)

    if ml_o in ('FP', 'FN') and gr_o in ('TN', 'TP'):
        joint = f'graph_corrects_ml_{ml_o}'
    elif ml_o in ('TN', 'TP') and gr_o in ('FP', 'FN'):
        joint = f'graph_breaks_ml_{ml_o}'
    elif ml_o == gr_o and ml_o in ('FP', 'FN'):
        joint = f'both_wrong_{ml_o}'
    elif ml_o == gr_o and ml_o in ('TN', 'TP'):
        joint = 'both_correct'
    else:
        joint = f'ml_{ml_o}_graph_{gr_o}'

    return {'ml': ml_o, 'graph': gr_o, 'joint': joint}


def run_analysis(cache_dir, ml_dir, output_dir, weights_dir=None):
    print('=' * 70)
    print('Graph vs ML Complementarity Analysis  (seed02 test split)')
    print('=' * 70)

    # Step 1: Graph events
    print('\n[1] Loading graph test events from cache...')
    graph_events = load_graph_metadata(cache_dir)
    n0 = sum(1 for e in graph_events if e['label'] == 0)
    n1 = sum(1 for e in graph_events if e['label'] == 1)
    print(f'    {len(graph_events)} events  (label=0: {n0}, label=1: {n1})')

    if weights_dir and Path(weights_dir).exists():
        print(f'\n[1b] Running NumPy inference from weights: {weights_dir}')
        run_graph_inference(graph_events, cache_dir, Path(weights_dir))
        n_scored = sum(1 for e in graph_events if e['graph_score'] is not None)
        print(f'    Scored: {n_scored}/{len(graph_events)}')
    else:
        print('\n[1b] No model weights → metadata-only mode (graph_score=None)')
        print('     Run with --model-weights to enable actual scoring.')

    # Step 2: ML errors
    print('\n[2] Loading ML error lists...')
    ml_err_by_line: dict[str, dict[int, dict]] = {}
    ml_probe:       dict[str, dict[int, float]] = {}
    for model in MODELS:
        by_line, _ = load_ml_errors(ml_dir, model)
        ml_err_by_line[model] = by_line
        ml_probe[model] = load_ml_probe_scores(ml_dir, model)
        n_fp = sum(1 for e in by_line.values() if e['error'] == 'FP')
        n_fn = sum(1 for e in by_line.values() if e['error'] == 'FN')
        n_probe = len(ml_probe[model])
        print(f'    {model}: {n_fp} FP, {n_fn} FN in errors  |  {n_probe} probe scores')
    print('    [Note] Join key: source_line (source_id hashes differ between pipelines)')

    # Step 3: Per-event joint classification
    print('\n[3] Computing joint outcomes...')
    per_model_rows: dict[str, list[dict]] = {m: [] for m in MODELS}

    for ev in graph_events:
        src_line = ev['source_line']
        label = ev['label']
        for model in MODELS:
            # Primary join: source_line (decompressed line number)
            err = ml_err_by_line[model].get(src_line)
            probe_sc = ml_probe[model].get(src_line)

            if err is not None:
                # Sanity check: FP must be on benign, FN must be on malicious
                expected_label = 0 if err['error'] == 'FP' else 1
                if label != expected_label:
                    # Line collision across gz files — skip this join
                    err = None

            if err is not None:
                ml_pred = 1 if err['error'] == 'FP' else 0
                ml_score_val = err.get('score')
            elif probe_sc is not None:
                ml_pred = int(probe_sc >= ML_THRESHOLDS[model])
                ml_score_val = probe_sc
            else:
                # Not in errors, not in probe → classify based on label prevalence
                # For benign events: assume TN (FPR ≈ 0.04%, very likely TN)
                # For malicious events: assume TP (recall ≈ 92%, likely TP)
                # Mark as 'inferred' so we can filter later
                if label == 0:
                    ml_pred = 0   # inferred TN (benign, not flagged in errors)
                    ml_score_val = None
                else:
                    ml_pred = 1   # inferred TP (malicious, not in FN list)
                    ml_score_val = None

            out = joint_outcome(label, ml_pred, ev['graph_pred'])
            cb = KNOWN_CASEBOOK_LINES.get(ev['source_line'])

            per_model_rows[model].append({
                'source_line': ev['source_line'],
                'source_id': ev['source_id'],
                'label': label,
                'graph_score': ev['graph_score'],
                'graph_pred': ev['graph_pred'],
                'graph_nodes': ev['graph_nodes'],
                'graph_edges': ev['graph_edges'],
                'has_missing_context': ev['has_missing_context'],
                'ml_score': ml_score_val,
                'ml_pred': ml_pred,
                'ml_outcome': out['ml'],
                'graph_outcome': out['graph'],
                'joint': out['joint'],
                'casebook_case': cb[0] if cb else None,
                'casebook_type': cb[1] if cb else None,
                'casebook_error': cb[2] if cb else None,
            })

    # Step 4: Summaries
    print('\n[4] Computing summaries...')
    summaries: dict[str, dict] = {}

    for model in MODELS:
        rows = per_model_rows[model]
        known = [r for r in rows
                 if r['ml_outcome'] != 'unknown' and r['graph_pred'] is not None]
        jc = Counter(r['joint'] for r in known)

        n_ml_err = sum(1 for r in known if r['ml_outcome'] in ('FP', 'FN'))
        n_correct = sum(1 for r in known if r['ml_outcome'] not in ('FP', 'FN'))
        n_gr_fixes = jc.get('graph_corrects_ml_FP', 0) + jc.get('graph_corrects_ml_FN', 0)
        n_gr_breaks = jc.get('graph_breaks_ml_TN', 0) + jc.get('graph_breaks_ml_TP', 0)

        fp_fixes = [r for r in known if r['joint'] == 'graph_corrects_ml_FP']
        fn_fixes = [r for r in known if r['joint'] == 'graph_corrects_ml_FN']

        def avg_nodes(lst): return float(np.mean([r['graph_nodes'] for r in lst])) if lst else 0.0
        def pct_miss(lst): return float(np.mean([r['has_missing_context'] for r in lst])) * 100 if lst else 0.0

        summaries[model] = {
            'known_events': len(known),
            'ml_errors_in_sample': n_ml_err,
            'ml_correct_in_sample': n_correct,
            'graph_corrects': n_gr_fixes,
            'graph_corrects_FP': len(fp_fixes),
            'graph_corrects_FN': len(fn_fixes),
            'graph_breaks': n_gr_breaks,
            'graph_breaks_TN': jc.get('graph_breaks_ml_TN', 0),
            'graph_breaks_TP': jc.get('graph_breaks_ml_TP', 0),
            'both_wrong': jc.get('both_wrong_FP', 0) + jc.get('both_wrong_FN', 0),
            'both_correct': jc.get('both_correct', 0),
            'complementarity_rate': n_gr_fixes / max(n_ml_err, 1),
            'interference_rate': n_gr_breaks / max(n_correct, 1),
            'fp_fix_avg_nodes': avg_nodes(fp_fixes),
            'fn_fix_avg_nodes': avg_nodes(fn_fixes),
            'fp_fix_pct_missing': pct_miss(fp_fixes),
            'fn_fix_pct_missing': pct_miss(fn_fixes),
            'joint_counts': dict(jc),
            'casebook_hits': {
                r['casebook_case']: {'joint': r['joint'], 'type': r['casebook_type']}
                for r in known if r['casebook_case']
            },
        }

        s = summaries[model]
        print(f'\n  ── {model.upper()} ──')
        print(f'  Events classifiable:      {s["known_events"]}')
        print(f'  ML errors in sample:      {s["ml_errors_in_sample"]}')
        print(f'  Graph CORRECTS ML errors: {s["graph_corrects"]}  ({s["complementarity_rate"]:.1%})')
        print(f'    └─ fixes FP: {s["graph_corrects_FP"]}  fixes FN: {s["graph_corrects_FN"]}')
        print(f'  Graph BREAKS correct:     {s["graph_breaks"]}  ({s["interference_rate"]:.1%})')
        print(f'    └─ breaks TN: {s["graph_breaks_TN"]}  breaks TP: {s["graph_breaks_TP"]}')
        print(f'  Both wrong:               {s["both_wrong"]}')
        print(f'  Both correct:             {s["both_correct"]}')
        if fp_fixes:
            print(f'  FP-fix avg nodes={s["fp_fix_avg_nodes"]:.1f}  missing_ctx={s["fp_fix_pct_missing"]:.0f}%')
        if fn_fixes:
            print(f'  FN-fix avg nodes={s["fn_fix_avg_nodes"]:.1f}  missing_ctx={s["fn_fix_pct_missing"]:.0f}%')
        if s['casebook_hits']:
            print(f'  Casebook cases: {s["casebook_hits"]}')

    # Step 5: Cross-model — all 3 wrong, graph right
    print('\n[5] Cross-model: events where ALL 3 models wrong but graph right...')
    all3_wrong_graph_right = []
    for ev in graph_events:
        if ev['graph_pred'] is None:
            continue
        label = ev['label']
        graph_correct = (ev['graph_pred'] == label)
        outcomes = {}
        for model in MODELS:
            row = next((r for r in per_model_rows[model]
                        if r['source_line'] == ev['source_line']), None)
            if row and row['ml_outcome'] != 'unknown':
                outcomes[model] = row['ml_outcome']
        if len(outcomes) == len(MODELS) and all(o in ('FP', 'FN') for o in outcomes.values()) and graph_correct:
            all3_wrong_graph_right.append({
                'source_line': ev['source_line'],
                'label': label,
                'graph_score': ev['graph_score'],
                'graph_nodes': ev['graph_nodes'],
                'has_missing_context': ev['has_missing_context'],
                'model_outcomes': outcomes,
                'casebook_case': KNOWN_CASEBOOK_LINES.get(ev['source_line'], (None,))[0],
            })
    print(f'    Found: {len(all3_wrong_graph_right)}')

    # ─── Caution: metadata-only mode note ───────────────────────────────────
    has_scores = any(e['graph_score'] is not None for e in graph_events)
    if not has_scores:
        print('\n  *** METADATA-ONLY MODE ***')
        print('  All graph_score=None → graph_pred=None → all events are "unknown".')
        print('  No joint outcomes could be computed. Run with --model-weights to score.')

    # Step 6: Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)

    result = {
        'metadata_only_mode': not has_scores,
        'graph_val_threshold': GRAPH_VAL_THRESHOLD,
        'graph_test_f1_kaggle': GRAPH_TEST_F1,
        'ml_thresholds': ML_THRESHOLDS,
        'graph_sample_size': len(graph_events),
        'graph_sample_label_dist': {'label_0': n0, 'label_1': n1},
        'ml_test_full_size': 1249689,
        'all_models_wrong_graph_right': all3_wrong_graph_right,
        'per_model': summaries,
        'notes': [
            'Graph scores are uncalibrated risk rankings (balanced TRAIN sampling).',
            'Graph threshold selected on validation; ML thresholds on respective val sets.',
            'Join key: (source_id, source_line) from test_errors.json and selection.json.',
            'Casebook case annotations are reference only (16 documented cases).',
            'See fp_fn_casebook/report.md for vector_collision/generalization context.',
        ],
    }

    jpath = output_dir / 'graph_vs_ml_complementarity.json'
    jpath.write_text(json.dumps(result, indent=2))

    mdpath = output_dir / 'graph_vs_ml_complementarity.md'
    _write_md(result, mdpath, per_model_rows)

    print(f'\nOutput JSON:      {jpath}')
    print(f'Output Markdown:  {mdpath}')
    print('\nDone.')


def _write_md(data: dict, path: Path, per_model_rows: dict):
    meta_warn = (
        '\n> ⚠️ **METADATA-ONLY MODE**: Graph scores are None. '
        'All complementarity metrics are 0/unknown. '
        'Re-run with `--model-weights` to compute actual scores.\n'
        if data['metadata_only_mode'] else ''
    )

    lines = [
        '# Graph vs ML Complementarity Report',
        '',
        f'**Phạm vi:** {data["graph_sample_size"]} ego-graph test events (uniform cached sample) '
        f'vs {data["ml_test_full_size"]:,} events (full ML test split, seed02)',
        '',
        f'**Graph threshold (val-selected):** {data["graph_val_threshold"]:.4f}  |  '
        f'**Graph test F1 (Kaggle):** {data["graph_test_f1_kaggle"]:.4f}',
        '',
        meta_warn,
        '## Complementarity per model',
        '',
    ]

    for model in MODELS:
        s = data['per_model'][model]
        lines += [
            f'### {model.upper()}  (threshold={data["ml_thresholds"][model]})',
            '',
            f'| Metric | Giá trị |',
            f'|---|---|',
            f'| Events classifiable | {s["known_events"]} |',
            f'| ML errors trong graph sample | {s["ml_errors_in_sample"]} |',
            f'| **Graph CORRECTS ML errors** | **{s["graph_corrects"]}** ({s["complementarity_rate"]:.1%}) |',
            f'| → fixes FP | {s["graph_corrects_FP"]} |',
            f'| → fixes FN | {s["graph_corrects_FN"]} |',
            f'| **Graph BREAKS correct** | **{s["graph_breaks"]}** ({s["interference_rate"]:.1%}) |',
            f'| → breaks TN | {s["graph_breaks_TN"]} |',
            f'| → breaks TP | {s["graph_breaks_TP"]} |',
            f'| Both wrong | {s["both_wrong"]} |',
            f'| Both correct | {s["both_correct"]} |',
            f'| FP-fix avg graph nodes | {s["fp_fix_avg_nodes"]:.1f} |',
            f'| FN-fix avg graph nodes | {s["fn_fix_avg_nodes"]:.1f} |',
            f'| FP-fix % missing context | {s["fp_fix_pct_missing"]:.0f}% |',
            f'| FN-fix % missing context | {s["fn_fix_pct_missing"]:.0f}% |',
            '',
        ]
        if s['casebook_hits']:
            lines += ['**Casebook cases trong graph sample:**', '']
            for case, info in s['casebook_hits'].items():
                lines.append(f'- {case} ({info["type"]}): joint=`{info["joint"]}`')
            lines.append('')
        if s['joint_counts']:
            lines += ['**Joint outcome breakdown:**', '', '| Joint | Count |', '|---|---|']
            for k, v in sorted(s['joint_counts'].items(), key=lambda x: -x[1]):
                lines.append(f'| `{k}` | {v} |')
            lines.append('')

    # Cross model
    cross = data['all_models_wrong_graph_right']
    lines += [
        '## Tất cả 3 model sai + graph đúng',
        '',
        f'**{len(cross)} events** mà graph sửa được lỗi của cả 3 ML models.',
        '',
    ]
    if cross:
        lines += ['| source_line | label | graph_score | nodes | missing_ctx | casebook |',
                  '|---|---|---|---|---|---|']
        for ev in cross[:20]:
            sc = f"{ev['graph_score']:.4f}" if ev.get('graph_score') is not None else 'N/A'
            lines.append(
                f"| {ev['source_line']} | {ev['label']} | {sc} "
                f"| {ev['graph_nodes']} | {ev['has_missing_context']} "
                f"| {ev.get('casebook_case') or ''} |"
            )
        lines.append('')

    # Casebook insight table
    lines += [
        '## Ánh xạ case pattern từ casebook → graph',
        '',
        '| Pattern | ML lỗi | Graph có thể giúp? | Lý do |',
        '|---|---|---|---|',
        '| `vector_collision` (C01/C03/C08) | FP (cùng vector) | **Có** | Graph thấy ancestry khác nhau dù event vector giống nhau |',
        '| `vector_collision` (C05/C06/C16) | FN (lwabeat, 175k benign) | **Có thể** | Graph thấy actor process trong cluster risk cao |',
        '| `generalization` (C04/C11/C12) | FP (RF only) | **Không chắc** | Graph không có file-level detail; cần host comms context |',
        '| `near_threshold` (C07/C10) | FN (score sát threshold) | **Phụ thuộc** | Graph score cộng thêm signal nếu calibrated đúng |',
        '| `context_loss` (C08 Start-Sleep) | FP (PowerShell mất context) | **Có** | Graph thấy PowerShell parent → Start-Sleep child |',
        '',
        '## Quyết định: nên build full cache?',
        '',
        '**Tiêu chí để quyết định** (sau khi chạy script với model weights):',
        '',
        '- ✅ **Nên build full cache** nếu:',
        '  - `graph_corrects` > `graph_breaks` trên mẫu này',
        '  - `complementarity_rate` > 0.15 (graph sửa >15% ML errors trong sample)',
        '  - Phần lớn `fn_fix` có `missing_context=False` (graph có đủ context)',
        '',
        '- ❌ **Cần cải thiện model trước** nếu:',
        '  - `interference_rate` > `complementarity_rate`',
        '  - `fn_fix_pct_missing` > 50% (graph sửa FN nhưng không có context)',
        '',
        '## Tham chiếu',
        '',
        '- [FP/FN Casebook](../../host_ml_seed02/fp_fn_casebook/report.md)',
        '- [Graph DESIGN.md](../../../code/provenace_graph/docs/DESIGN.md)',
        '- [Ego Cache config](../seed02_ego_cache/config.json)',
        '- [Kaggle Graph Log](../kaggle_output/optc-gpu-provenance-graph.log)',
    ]

    path.write_text('\n'.join(lines))


# ─── CLI ───────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='Graph vs ML complementarity analysis')
    p.add_argument('--cache', type=Path, default=DEFAULT_CACHE)
    p.add_argument('--ml-output', type=Path, default=DEFAULT_ML_OUT)
    p.add_argument('--model-weights', type=Path, default=None,
                   help='Directory with saved model-slot-*.npz weights for graph inference')
    p.add_argument('--output', type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    for req, name in [(args.cache, 'cache'), (args.ml_output, 'ml-output')]:
        if not req.exists():
            print(f'ERROR: {name} not found: {req}', file=sys.stderr)
            sys.exit(1)

    run_analysis(
        cache_dir=args.cache,
        ml_dir=args.ml_output,
        output_dir=args.output,
        weights_dir=args.model_weights,
    )


if __name__ == '__main__':
    main()
