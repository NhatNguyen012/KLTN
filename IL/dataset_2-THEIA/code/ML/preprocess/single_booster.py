"""Export a weighted sum of binary GBDT raw margins as one LightGBM booster.

No retraining/distillation, routing, logit clipping or extra learned model.
Requires compatible feature prefixes, constant leaves and sigmoid=1.
"""
import re
import numpy as np


def combine_boosters(components):
    import lightgbm as lgb
    if not components:
        raise ValueError('No components')
    widest = max((model for model, _ in components), key=lambda m: m.num_feature())
    names = widest.feature_name()
    header = widest.model_to_string().split('Tree=0', 1)[0]
    blocks = []
    for model, weight in components:
        if not np.isfinite(weight) or weight < 0:
            raise ValueError('Component weights must be finite and nonnegative')
        if model.feature_name() != names[:model.num_feature()]:
            raise ValueError('Feature columns are not a compatible frozen prefix')
        text = model.model_to_string()
        if 'objective=binary sigmoid:1\n' not in text or 'num_tree_per_iteration=1\n' not in text or 'average_output' in text:
            raise ValueError('Only binary additive GBDT with sigmoid=1 is supported')
        if weight == 0:
            continue
        body = text.split('end of trees', 1)[0]
        for match in re.finditer(r'^Tree=\d+\n.*?(?=^Tree=\d+\n|\Z)', body, re.M | re.S):
            block = match.group(0).rstrip() + '\n\n'
            if 'is_linear=1' in block:
                raise ValueError('Linear leaves are not supported')
            block = re.sub(r'^Tree=\d+', f'Tree={len(blocks)}', block, count=1)
            for key in ('leaf_value', 'internal_value'):
                block = re.sub(r'^' + key + r'=(.*)$',
                               lambda m: key + '=' + ' '.join(format(float(v) * weight, '.17g') for v in m[1].split()),
                               block, flags=re.M)
            blocks.append(block)
    if not blocks:
        raise ValueError('At least one positive component weight required')
    header = re.sub(r'^tree_sizes=.*$', 'tree_sizes=' + ' '.join(str(len(b.encode())) for b in blocks), header, flags=re.M)
    result = lgb.Booster(model_str=header + ''.join(blocks) + 'end of trees\n\npandas_categorical:null\n')
    if result.num_trees() != len(blocks) or result.num_feature() != len(names):
        raise ValueError('Combined model shape differs')
    return result


def assert_prediction_parity(combined, components, X, threads=1):
    expected = sum(weight * model.predict(X[:, :model.num_feature()], raw_score=True, num_threads=threads)
                   for model, weight in components)
    actual = combined.predict(X, raw_score=True, num_threads=threads)
    np.testing.assert_allclose(actual, expected, rtol=1e-12, atol=1e-12)
    return float(np.max(np.abs(actual - expected))) if len(actual) else 0.0
