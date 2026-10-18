#!/usr/bin/env python3
"""Train a cached two-hop relational GraphSAGE model on Kaggle GPU.

The input is a verified static ego-graph cache built locally.  This script never
opens graph.sqlite or raw telemetry.  It uses only PyTorch, rather than requiring
PyTorch Geometric binary wheels, and batches relation-specific mean aggregation
across many small Host/Process graphs on CUDA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import time

import numpy as np

from ML.code.provenace_graph.model.ego_cache import RELATIONS, examples, load_manifest, require_exact_time


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w') as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def load_split(root, meta, split):
    result = []
    for part in meta['parts']:
        if part['split'] == split:
            result.extend(examples(root, part, len(meta['attributes'])))
    expected = meta['splits'][split]['graphs']
    if len(result) != expected:
        raise ValueError(f'{split} cache graph count mismatch')
    return result


def make_batch(items, torch, device):
    node_offset = 0
    features = []
    source = []
    target = []
    relation = []
    roots = []
    host_roots = []
    labels = []
    for item in items:
        x = item['x']
        features.append(x)
        edges = item['edge_index']
        if edges.shape[1]:
            source.append(edges[0] + node_offset)
            target.append(edges[1] + node_offset)
            relation.append(item['edge_type'])
        roots.append(item['root'] + node_offset)
        host_roots.append(item['host_root'] + node_offset)
        labels.append(item['label'])
        node_offset += len(x)
    edge_source = np.concatenate(source) if source else np.empty(0, dtype=np.int64)
    edge_target = np.concatenate(target) if target else np.empty(0, dtype=np.int64)
    edge_relation = np.concatenate(relation) if relation else np.empty(0, dtype=np.int64)
    return dict(
        x=torch.as_tensor(np.concatenate(features), dtype=torch.float32, device=device),
        source=torch.as_tensor(edge_source, dtype=torch.long, device=device),
        target=torch.as_tensor(edge_target, dtype=torch.long, device=device),
        relation=torch.as_tensor(edge_relation, dtype=torch.long, device=device),
        root=torch.as_tensor(roots, dtype=torch.long, device=device),
        host_root=torch.as_tensor(host_roots, dtype=torch.long, device=device),
        y=torch.as_tensor(labels, dtype=torch.float32, device=device),
    )


def choose_threshold(y, score):
    order = np.argsort(-score, kind='stable')
    yy, scores = y[order], score[order]
    ends = np.r_[np.flatnonzero(scores[:-1] != scores[1:]), len(scores) - 1]
    tp = np.cumsum(yy)[ends]
    fp = ends + 1 - tp
    fn = yy.sum() - tp
    f1 = 2 * tp / np.maximum(2 * tp + fp + fn, 1)
    return float(scores[ends[int(np.argmax(f1))]])


def metrics(y, score, threshold):
    prediction = score >= threshold
    tp = int(np.sum((y == 1) & prediction)); fp = int(np.sum((y == 0) & prediction))
    fn = int(np.sum((y == 1) & ~prediction)); tn = int(np.sum((y == 0) & ~prediction))
    precision = tp / max(tp + fp, 1); recall = tp / max(tp + fn, 1)
    order = np.argsort(-score, kind='stable'); yy, scores = y[order], score[order]
    ends = np.r_[np.flatnonzero(scores[:-1] != scores[1:]), len(scores) - 1]
    positives = np.cumsum(yy)[ends]
    increments = np.diff(np.r_[0, positives])
    average_precision = float(np.sum(increments * positives / (ends + 1)) / max(int(y.sum()), 1))
    return dict(rows=len(y), threshold=float(threshold), precision=float(precision), recall=float(recall),
                f1=float(2 * precision * recall / max(precision + recall, 1e-15)),
                fpr=float(fp / max(fp + tn, 1)), average_precision=average_precision,
                confusion=dict(tp=tp, fp=fp, fn=fn, tn=tn))


def build_model(torch, attributes, hidden, embedding):
    nn = torch.nn
    functional = torch.nn.functional

    class RelationalGraphSAGE(nn.Module):
        def __init__(self):
            super().__init__()
            widths = (attributes, hidden, embedding)
            self.self_layers = nn.ModuleList([nn.Linear(widths[index], widths[index + 1]) for index in range(2)])
            self.relation_layers = nn.ModuleList([
                nn.ModuleList([nn.Linear(widths[index], widths[index + 1], bias=False) for _ in RELATIONS])
                for index in range(2)
            ])
            self.head = nn.Linear(embedding * 2, 1)

        def forward(self, batch):
            h = batch['x']
            for layer in range(2):
                z = self.self_layers[layer](h)
                for relation_id in range(len(RELATIONS)):
                    selected = batch['relation'] == relation_id
                    if not bool(selected.any()):
                        continue
                    source = batch['source'][selected]
                    target = batch['target'][selected]
                    message = self.relation_layers[layer][relation_id](h[source])
                    aggregate = torch.zeros((len(h), message.shape[1]), dtype=h.dtype, device=h.device)
                    aggregate.index_add_(0, target, message)
                    degree = torch.zeros(len(h), dtype=h.dtype, device=h.device)
                    degree.index_add_(0, target, torch.ones(len(target), dtype=h.dtype, device=h.device))
                    z = z + aggregate / degree.clamp_min(1).unsqueeze(1)
                h = functional.relu(z)
            readout = torch.cat([h[batch['root']], h[batch['host_root']]], dim=1)
            return self.head(readout).squeeze(1)

    return RelationalGraphSAGE()


def scores(model, items, batch_size, torch, device):
    model.eval()
    values = []
    labels = []
    with torch.no_grad():
        for start in range(0, len(items), batch_size):
            batch = make_batch(items[start:start + batch_size], torch, device)
            values.append(torch.sigmoid(model(batch)).detach().cpu().numpy())
            labels.append(batch['y'].detach().cpu().numpy().astype(np.uint8))
    return np.concatenate(labels), np.concatenate(values)


def train(args):
    try:
        import torch
    except ModuleNotFoundError as exc:
        raise RuntimeError('PyTorch is required; enable a Kaggle GPU accelerator image with PyTorch installed') from exc
    root, meta = load_manifest(args.cache)
    require_exact_time(meta)
    if args.device == 'auto':
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    else:
        device = torch.device(args.device)
    if device.type == 'cuda' and not torch.cuda.is_available():
        raise RuntimeError('CUDA was requested but is unavailable; enable GPU in Kaggle settings')
    torch.manual_seed(args.seed)
    if device.type == 'cuda':
        torch.cuda.manual_seed_all(args.seed)
    train_items = load_split(root, meta, 'train')
    val_items = load_split(root, meta, 'val')
    test_items = load_split(root, meta, 'test') if args.evaluate_test else []
    if len({item['label'] for item in train_items}) != 2:
        raise ValueError('TRAIN cache must contain both classes')
    output = Path(args.output).resolve()
    config = dict(cache_manifest_sha256=meta['manifest_sha256'],
        time_policy=meta['time_policy'], args={
        name: str(value) if isinstance(value, Path) else value for name, value in vars(args).items()
    }, device=str(device), torch=torch.__version__, relations=list(RELATIONS), attributes=len(meta['attributes']))
    if output.exists():
        if not args.resume or not (output / 'config.json').is_file() or json.loads((output / 'config.json').read_text()) != config:
            raise ValueError('existing GPU output differs; choose a new directory or matching --resume')
    else:
        output.mkdir(parents=True)
        atomic_json(output / 'config.json', config)
    model = build_model(torch, len(meta['attributes']), args.hidden, args.embedding).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay)
    start_epoch = 0
    best = None
    rng = np.random.default_rng(args.seed)
    if args.resume and (output / 'checkpoint.pt').is_file():
        checkpoint = torch.load(output / 'checkpoint.pt', map_location=device, weights_only=False)
        if checkpoint['cache_manifest_sha256'] != meta['manifest_sha256']:
            raise ValueError('checkpoint belongs to another cache')
        model.load_state_dict(checkpoint['model']); optimizer.load_state_dict(checkpoint['optimizer'])
        start_epoch = checkpoint['epoch']; best = checkpoint['best']
        rng.bit_generator.state = checkpoint['rng_state']
    loss_function = torch.nn.BCEWithLogitsLoss()
    started = time.monotonic()
    for epoch in range(start_epoch, args.epochs):
        model.train(); order = rng.permutation(len(train_items)); total_loss = 0.; batches = 0
        for start in range(0, len(order), args.batch_size):
            batch = make_batch([train_items[index] for index in order[start:start + args.batch_size]], torch, device)
            optimizer.zero_grad(set_to_none=True)
            loss = loss_function(model(batch), batch['y'])
            loss.backward(); optimizer.step()
            total_loss += float(loss.detach().cpu()); batches += 1
        y, value = scores(model, val_items, args.batch_size, torch, device)
        threshold = choose_threshold(y, value); validation = metrics(y, value, threshold)
        candidate = validation['average_precision']
        if best is None or candidate > best['average_precision']:
            best = dict(epoch=epoch + 1, average_precision=candidate, threshold=threshold, validation=validation)
            temporary = output / 'checkpoint.tmp'
            torch.save(dict(epoch=epoch + 1, model=model.state_dict(), optimizer=optimizer.state_dict(), best=best,
                            cache_manifest_sha256=meta['manifest_sha256'], rng_state=rng.bit_generator.state), temporary)
            os.replace(temporary, output / 'checkpoint.pt')
        atomic_json(output / 'progress.json', dict(epoch=epoch + 1, loss=total_loss / max(batches, 1), best=best))
        print(f'epoch={epoch + 1} loss={total_loss / max(batches, 1):.6f} val_ap={validation["average_precision"]:.6f}', flush=True)
    checkpoint = torch.load(output / 'checkpoint.pt', map_location=device, weights_only=False)
    model.load_state_dict(checkpoint['model'])
    y, value = scores(model, val_items, args.batch_size, torch, device)
    threshold = checkpoint['best']['threshold']
    report = dict(model='Two-layer relational mean GraphSAGE (PyTorch GPU)', device=str(device),
                  parameters=sum(value.numel() for value in model.parameters()), cache_manifest_sha256=meta['manifest_sha256'],
                  time_policy=meta['time_policy'],
                  train_graphs=len(train_items), validation=metrics(y, value, threshold),
                  validation_scope='cached uniform sample', test=None,
                  calibration='Balanced TRAIN sampling makes scores risk rankings, not calibrated event probabilities.',
                  elapsed_seconds=time.monotonic() - started)
    if test_items:
        yy, vv = scores(model, test_items, args.batch_size, torch, device)
        report['test'] = metrics(yy, vv, threshold)
        report['test_scope'] = 'cached uniform sample'
    atomic_json(output / 'metrics.json', report)
    print(json.dumps(report, indent=2), flush=True)

    # Export NumPy weights compatible with relational_sage.RelationalSAGE.load()
    numpy_path = export_numpy_weights(model, output, config, report['parameters'])
    print(f'NumPy weights exported: {numpy_path}', flush=True)


def export_numpy_weights(model, output_dir: Path, config: dict, n_params: int) -> Path:
    """Convert a trained PyTorch RelationalGraphSAGE to NumPy .npz for relational_sage.py.

    The NumPy model (relational_sage.RelationalSAGE) stores weight matrices as
    shape (in_features, out_features), while PyTorch nn.Linear stores them as
    (out_features, in_features).  This function transposes accordingly.

    Adam moment state is zero-initialised (PyTorch AdamW state is not exported)
    and ``steps`` is set to 0 so that a reloaded RelationalSAGE will re-warm its
    Adam moments on the first training call if fine-tuning is needed.  The exported
    file is read-only inference-compatible; no additional training is required.

    Output: ``<output_dir>/model_numpy.npz``
    """
    import os

    attributes = config['attributes']
    args_cfg = config.get('args', {})
    hidden = int(args_cfg.get('hidden', 32))
    embedding = int(args_cfg.get('embedding', 16))
    relations = config.get('relations', ['creates', 'communicates', 'communicates_reverse', 'hosts'])

    sd = model.state_dict()

    # ── Weight mapping: PyTorch (out, in) → NumPy (in, out) ─────────────────
    params = {}

    # Layer 1: input_dim → hidden
    params['W1_self'] = sd['self_layers.0.weight'].cpu().numpy().T   # (attributes, hidden)
    params['b1']      = sd['self_layers.0.bias'].cpu().numpy()        # (hidden,)
    for rel_id, rel_name in enumerate(relations):
        params[f'W1_{rel_name}'] = sd[f'relation_layers.0.{rel_id}.weight'].cpu().numpy().T  # (attributes, hidden)

    # Layer 2: hidden → embedding
    params['W2_self'] = sd['self_layers.1.weight'].cpu().numpy().T   # (hidden, embedding)
    params['b2']      = sd['self_layers.1.bias'].cpu().numpy()        # (embedding,)
    for rel_id, rel_name in enumerate(relations):
        params[f'W2_{rel_name}'] = sd[f'relation_layers.1.{rel_id}.weight'].cpu().numpy().T  # (hidden, embedding)

    # Head: (1, embedding*2) → flatten to (embedding*2,)
    params['head'] = sd['head.weight'].cpu().numpy().flatten()  # (embedding*2,)
    params['bias'] = sd['head.bias'].cpu().numpy()              # (1,)

    # Adam moment state: zero-initialised (not available from PyTorch AdamW export)
    zero_m = {f'adam_m_{k}': np.zeros_like(v) for k, v in params.items()}
    zero_v = {f'adam_v_{k}': np.zeros_like(v) for k, v in params.items()}

    # Validate total parameter count matches the PyTorch model
    np_count = sum(v.size for v in params.values())
    if np_count != n_params:
        raise ValueError(
            f'NumPy parameter count {np_count} != PyTorch parameter count {n_params}. '
            'Check weight key mapping in export_numpy_weights().'
        )

    out_path = output_dir / 'model_numpy.npz'
    tmp_path = output_dir / 'model_numpy.npz.tmp'
    with open(tmp_path, 'wb') as f:
        np.savez_compressed(
            f,
            dimensions=np.array([attributes, hidden, embedding], dtype=np.int64),
            steps=np.int64(0),
            **params,
            **zero_m,
            **zero_v,
        )
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, out_path)
    return out_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('/kaggle/working/provenance-gpu-model'))
    parser.add_argument('--epochs', type=int, default=30)
    parser.add_argument('--batch-size', type=int, default=128)
    parser.add_argument('--hidden', type=int, default=32)
    parser.add_argument('--embedding', type=int, default=16)
    parser.add_argument('--learning-rate', type=float, default=1e-3)
    parser.add_argument('--weight-decay', type=float, default=1e-5)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--device', default='auto')
    parser.add_argument('--evaluate-test', action='store_true')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--export-only', action='store_true',
                        help='Load an existing checkpoint.pt and export model_numpy.npz without training.')
    args = parser.parse_args()

    if args.export_only:
        _export_only(args)
        return

    if min(args.epochs, args.batch_size, args.hidden, args.embedding) < 1 or args.learning_rate <= 0 or args.weight_decay < 0:
        raise ValueError('invalid GPU training configuration')
    train(args)


def _export_only(args):
    """Load an existing checkpoint.pt and write model_numpy.npz without retraining."""
    try:
        import torch
    except ModuleNotFoundError as exc:
        raise RuntimeError('PyTorch is required to load checkpoint.pt') from exc

    output = Path(args.output).resolve()
    ckpt_path = output / 'checkpoint.pt'
    cfg_path  = output / 'config.json'
    if not ckpt_path.is_file():
        raise FileNotFoundError(f'checkpoint.pt not found in {output}')
    if not cfg_path.is_file():
        raise FileNotFoundError(f'config.json not found in {output}')

    config = json.loads(cfg_path.read_text())
    args_cfg = config.get('args', {})
    hidden    = int(args_cfg.get('hidden', 32))
    embedding = int(args_cfg.get('embedding', 16))
    attributes = config['attributes']

    device = torch.device('cpu')
    checkpoint = torch.load(ckpt_path, map_location=device, weights_only=False)
    model = build_model(torch, attributes, hidden, embedding).to(device)
    model.load_state_dict(checkpoint['model'])
    model.eval()

    n_params = sum(p.numel() for p in model.parameters())
    numpy_path = export_numpy_weights(model, output, config, n_params)
    print(f'Exported: {numpy_path}')


if __name__ == '__main__':
    main()

