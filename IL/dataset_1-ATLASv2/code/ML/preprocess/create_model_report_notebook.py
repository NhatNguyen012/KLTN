#!/usr/bin/env python3
"""Create a Kaggle Host ML notebook with teacher-facing LightGBM reports."""

from __future__ import annotations

import json
from pathlib import Path


ML_DIR = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML")
SOURCE_NOTEBOOK = ML_DIR / "notebook" / "lgbm_atlasv2.ipynb"
OUTPUT_NOTEBOOK = ML_DIR / "notebook" / "lgbm_atlasv2_model_report.ipynb"


def cell_source(text: str) -> list[str]:
    """Convert ordinary source text to the line representation used by ipynb."""
    lines = text.split("\n")
    return [line + "\n" for line in lines[:-1]] + [lines[-1]]


notebook = json.loads(SOURCE_NOTEBOOK.read_text(encoding="utf-8"))

title = """# LightGBM Continual Learning on ATLASv2 - Model/Tree Report

This notebook preserves the existing Host ML training and evaluation pipeline.
After evaluation, it prints and exports a teacher-readable audit of the Scratch,
OpTC base, and ATLASv2 incremental-residual LightGBM boosters. LightGBM has
trees, split nodes, and leaves rather than neural-network layers.
"""
notebook["cells"][0]["source"] = cell_source(title)

report_markdown = """## Inspect the LightGBM trees and active checkpoints

The following cell reports the active checkpoint selected by each `latest.json`,
maps feature indices back to semantic vocabulary tokens, summarizes every tree,
prints one decorated example tree, and exports the full model dumps. The final
incremental predictor is a composition of the OpTC base and ATLASv2 residual
boosters; it is not represented by either checkpoint alone.
"""

report_code = r'''# Teacher-facing LightGBM model/tree inspection.
from pathlib import Path
import csv
import json
import math

import lightgbm as lgb
import numpy as np


TEACHER_REPORT_DIR = output_path(OUTPUT / 'teacher_report', data.protected)
TEACHER_REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_semantic_feature_names(width):
    assets = data.manifest_path.parent / 'assets'
    candidates = [assets / 'vocab_extended.json', assets / 'vocab.json']
    for candidate in candidates:
        if not candidate.exists():
            continue
        vocabulary = json.loads(candidate.read_text(encoding='utf-8'))
        if len(vocabulary) < width:
            continue
        inverse = {int(index): token for token, index in vocabulary.items()}
        if all(index in inverse for index in range(width)):
            return [inverse[index] for index in range(width)], candidate
    return [f'feature_{index}' for index in range(width)], None


def inspect_tree(node, feature_names, depth=0):
    if 'leaf_index' in node:
        value = float(node['leaf_value'])
        return {
            'leaves': 1,
            'splits': 0,
            'max_depth': depth,
            'finite': math.isfinite(value),
            'split_features': [],
        }

    feature_index = int(node['split_feature'])
    threshold = node.get('threshold')
    threshold_finite = not isinstance(threshold, (int, float)) or math.isfinite(float(threshold))
    left = inspect_tree(node['left_child'], feature_names, depth + 1)
    right = inspect_tree(node['right_child'], feature_names, depth + 1)
    return {
        'leaves': left['leaves'] + right['leaves'],
        'splits': 1 + left['splits'] + right['splits'],
        'max_depth': max(left['max_depth'], right['max_depth']),
        'finite': threshold_finite and left['finite'] and right['finite'],
        'split_features': [feature_index, *left['split_features'], *right['split_features']],
    }


def decorate_tree(node, feature_names):
    decorated = dict(node)
    if 'split_feature' in decorated:
        index = int(decorated['split_feature'])
        decorated['split_feature_token'] = (
            feature_names[index] if 0 <= index < len(feature_names) else '<OUT_OF_RANGE>'
        )
        decorated['left_child'] = decorate_tree(decorated['left_child'], feature_names)
        decorated['right_child'] = decorate_tree(decorated['right_child'], feature_names)
    return decorated


def write_csv_atomic(rows, path):
    if not rows:
        raise ValueError(f'Cannot write an empty report table: {path}')

    def writer(temporary):
        with temporary.open('w', newline='', encoding='utf-8') as handle:
            csv_writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            csv_writer.writeheader()
            csv_writer.writerows(rows)

    atomic_write(path, writer, data.protected)


def format_table(rows, columns, limit=None):
    selected = rows if limit is None else rows[:limit]
    string_rows = [[str(row[column]) for column in columns] for row in selected]
    widths = [
        max(len(column), *(len(row[index]) for row in string_rows))
        for index, column in enumerate(columns)
    ]
    header = ' | '.join(column.ljust(widths[index]) for index, column in enumerate(columns))
    separator = '-+-'.join('-' * width for width in widths)
    body = [
        ' | '.join(value.ljust(widths[index]) for index, value in enumerate(row))
        for row in string_rows
    ]
    return '\n'.join([header, separator, *body])


def lightgbm_teacher_report(label, booster, checkpoint_path, report_name, role):
    checkpoint_path = Path(checkpoint_path).resolve()
    report_dir = output_path(TEACHER_REPORT_DIR / report_name, data.protected)
    report_dir.mkdir(parents=True, exist_ok=True)

    model_dump = booster.dump_model()
    width = booster.num_feature()
    feature_names, vocabulary_path = load_semantic_feature_names(width)
    gains = booster.feature_importance(importance_type='gain').astype(np.float64)
    split_counts = booster.feature_importance(importance_type='split').astype(np.int64)
    gain_total = max(float(gains.sum()), np.finfo(np.float64).tiny)
    importance = [
        {
            'feature_index': int(index),
            'feature': feature_names[index],
            'gain': float(gains[index]),
            'gain_fraction': float(gains[index] / gain_total),
            'split_count': int(split_counts[index]),
        }
        for index in range(width)
    ]
    importance.sort(key=lambda row: (-row['gain'], -row['split_count'], row['feature_index']))

    tree_rows = []
    all_split_features = []
    all_tree_values_finite = True
    for tree in model_dump['tree_info']:
        facts = inspect_tree(tree['tree_structure'], feature_names)
        all_tree_values_finite = all_tree_values_finite and facts['finite']
        all_split_features.extend(facts['split_features'])
        tree_rows.append({
            'tree_index': int(tree['tree_index']),
            'num_leaves': int(facts['leaves']),
            'num_split_nodes': int(facts['splits']),
            'max_depth': int(facts['max_depth']),
            'shrinkage': float(tree.get('shrinkage', 1.0)),
            'tree_values_finite': bool(facts['finite']),
        })
    split_features_in_range = all(0 <= index < width for index in all_split_features)
    tree_count_matches = len(tree_rows) == booster.num_trees()
    first_tree = decorate_tree(model_dump['tree_info'][0]['tree_structure'], feature_names)

    summary = {
        'label': label,
        'role': role,
        'checkpoint': str(checkpoint_path),
        'checkpoint_sha256': sha256(checkpoint_path),
        'lightgbm_version': lgb.__version__,
        'num_trees': int(booster.num_trees()),
        'num_features': int(width),
        'current_iteration': int(booster.current_iteration()),
        'trees_per_iteration': int(booster.num_model_per_iteration()),
        'objective': model_dump.get('objective'),
        'average_output': bool(model_dump.get('average_output', False)),
        'booster_params': booster.params,
        'vocabulary': str(vocabulary_path) if vocabulary_path is not None else None,
        'tree_count_matches_dump': bool(tree_count_matches),
        'split_features_in_range': bool(split_features_in_range),
        'all_tree_values_finite': bool(all_tree_values_finite),
        'total_split_nodes': int(sum(row['num_split_nodes'] for row in tree_rows)),
        'maximum_tree_depth': int(max(row['max_depth'] for row in tree_rows)),
        'maximum_leaves_in_tree': int(max(row['num_leaves'] for row in tree_rows)),
        'model_structure_valid': bool(
            tree_count_matches and split_features_in_range and all_tree_values_finite
        ),
        'interpretation': (
            'At each split node, binary feature absence normally follows the <= threshold '
            'branch and presence follows the > threshold branch. Each reached leaf_value '
            'contributes to the raw score.'
        ),
    }

    atomic_json(report_dir / 'summary.json', summary, data.protected)
    atomic_json(report_dir / 'full_model_dump.json', model_dump, data.protected)
    atomic_json(report_dir / 'first_tree_decorated.json', first_tree, data.protected)
    write_csv_atomic(importance, report_dir / 'feature_importance.csv')
    write_csv_atomic(tree_rows, report_dir / 'tree_summary.csv')

    text_lines = [
        '=' * 100,
        f'{label} - LightGBM teacher report',
        '=' * 100,
        f'Role:                         {role}',
        f'Checkpoint:                   {checkpoint_path}',
        f'Checkpoint SHA256:            {summary["checkpoint_sha256"]}',
        f'LightGBM version:             {summary["lightgbm_version"]}',
        f'Number of trees:              {summary["num_trees"]:,}',
        f'Number of features:           {summary["num_features"]:,}',
        f'Objective:                    {summary["objective"]}',
        f'Total split nodes:            {summary["total_split_nodes"]:,}',
        f'Maximum tree depth:           {summary["maximum_tree_depth"]}',
        f'Maximum leaves in one tree:   {summary["maximum_leaves_in_tree"]}',
        f'Tree count matches dump:      {summary["tree_count_matches_dump"]}',
        f'Split features in range:      {summary["split_features_in_range"]}',
        f'All tree values finite:       {summary["all_tree_values_finite"]}',
        f'Model structure valid:        {summary["model_structure_valid"]}',
        '',
        'BOOSTER PARAMETERS',
        json.dumps(booster.params, indent=2, default=str),
        '',
        'TOP 30 FEATURES BY GAIN',
        format_table(
            importance,
            ['feature_index', 'feature', 'gain', 'gain_fraction', 'split_count'],
            limit=30,
        ),
        '',
        'FIRST TREE (DECORATED WITH SEMANTIC FEATURE TOKENS)',
        json.dumps(first_tree, indent=2),
        '',
        'HOW TO READ THIS MODEL',
        summary['interpretation'],
    ]
    text_report = '\n'.join(text_lines) + '\n'
    atomic_write(
        report_dir / 'teacher_report.txt',
        lambda temporary: temporary.write_text(text_report, encoding='utf-8'),
        data.protected,
    )

    print('\n' + text_report)
    print('First 20 tree summaries:')
    print(format_table(
        tree_rows,
        ['tree_index', 'num_leaves', 'num_split_nodes', 'max_depth', 'shrinkage', 'tree_values_finite'],
        limit=20,
    ))
    print('Saved report directory:', report_dir)
    return summary


teacher_reports = {}

scratch_checkpoint = scratch_dir / 'model' / receipt_scratch['path']
teacher_reports['scratch'] = lightgbm_teacher_report(
    'ATLASv2 Scratch', model_scratch, scratch_checkpoint, 'scratch',
    'Standalone ATLASv2 baseline booster; probability = sigmoid(raw tree-score sum).',
)

if model_il is not None and receipt_il is not None:
    incremental_checkpoint = incremental_dir / 'model' / receipt_il['path']
    teacher_reports['incremental_residual'] = lightgbm_teacher_report(
        'ATLASv2 Incremental Residual', model_il, incremental_checkpoint,
        'incremental_residual',
        'Residual booster only; this file is not the complete deployed incremental predictor.',
    )

if OPTC_PRETRAINED_MODEL and Path(OPTC_PRETRAINED_MODEL).exists():
    if 'optc_booster' not in globals():
        optc_booster = lgb.Booster(model_file=str(OPTC_PRETRAINED_MODEL))
    teacher_reports['optc_base'] = lightgbm_teacher_report(
        'OpTC Base', optc_booster, OPTC_PRETRAINED_MODEL, 'optc_base',
        'Frozen source-domain booster contributing a raw-score margin to incremental inference.',
    )

combined_predictor = {
    'name': 'OpTC to ATLASv2 continual predictor',
    'type': 'composed_raw_score_ensemble',
    'formula': 'sigmoid(0.8 * optc_base_raw_score + atlas_incremental_residual_raw_score)',
    'base_margin_alpha': 0.8,
    'components': {
        'optc_base': teacher_reports.get('optc_base'),
        'atlas_incremental_residual': teacher_reports.get('incremental_residual'),
    },
    'effective_tree_count': (
        teacher_reports.get('optc_base', {}).get('num_trees', 0)
        + teacher_reports.get('incremental_residual', {}).get('num_trees', 0)
    ),
    'warning': (
        'model-slot-0 and model-slot-1 are alternating checkpoint filenames, not layers. '
        'The active residual slot is identified by latest.json.'
    ),
}
atomic_json(TEACHER_REPORT_DIR / 'combined_predictor.json', combined_predictor, data.protected)
atomic_json(TEACHER_REPORT_DIR / 'all_model_summaries.json', teacher_reports, data.protected)

print('\n' + '=' * 100)
print('COMBINED INCREMENTAL PREDICTOR')
print('=' * 100)
print('Formula:', combined_predictor['formula'])
print('Effective tree count:', combined_predictor['effective_tree_count'])
print('Checkpoint note:', combined_predictor['warning'])
print('All teacher reports:', TEACHER_REPORT_DIR)
'''

insert_at = 5
notebook["cells"][insert_at:insert_at] = [
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": cell_source(report_markdown),
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": cell_source(report_code),
    },
]

OUTPUT_NOTEBOOK.write_text(
    json.dumps(notebook, indent=1, ensure_ascii=False),
    encoding="utf-8",
)
print(f"Created {OUTPUT_NOTEBOOK} from {SOURCE_NOTEBOOK}")
