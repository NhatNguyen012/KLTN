#!/usr/bin/env python3
"""Add exactly one target Event to each frozen seed02 GraphSAGE cache graph.

Action/object are read from the matching approved binary Host shard. The
Process/Host backbone, labels, source identities, sample and strict-past graph
facts are copied unchanged from the frozen cache. No source telemetry is edited.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import numpy as np

HERE = Path(__file__).resolve().parents[1]
CODE = HERE.parent
sys.path[:0] = [str(HERE / 'model'), str(CODE / 'preprocess')]

from common import DEFAULT_OUTPUT, safe, sha, atomic_json
from ego_cache import load_manifest as load_base_manifest, examples as base_examples
from event_ego import EventSchema, RELATIONS
from event_ego_cache import (FORMAT, SCHEMA, RELATION_ID, decode_part,
                             manifest_digest, sha256)
from host_shards import HostShardDataset, decode_shard
from train import resolve_volume_roots


def selected_events(base_root, base_meta):
    selected = defaultdict(dict)
    for part in base_meta['parts']:
        for row in base_examples(base_root, part, len(base_meta['attributes'])):
            source = base_meta['source_ids'][row['source_index']]
            key = (source, row['source_line'])
            if row['source_line'] in selected[source]:
                raise ValueError(f'Duplicate selected event: {key}')
            selected[source][row['source_line']] = (row['label'], part['split'])
    return selected


def event_types(data, selected, schema):
    result = {}
    for shard in data.meta['shards']:
        source = shard['source_id']
        lookup = selected.get(source)
        if not lookup:
            continue
        lines_needed = [line for line, (_, split) in lookup.items()
                        if split == shard['split'] and shard['source_line_first'] <= line <= shard['source_line_last']]
        if not lines_needed:
            continue
        x, y, lines = decode_shard(data.path_for(shard), data.width, shard)
        for line in lines_needed:
            row = int(np.searchsorted(lines, line))
            if row >= len(lines) or int(lines[row]) != line:
                raise ValueError(f'Selected event missing from Host shard: {source}:{line}')
            label, _ = lookup[line]
            if int(y[row]) != label:
                raise ValueError(f'Selected label differs from frozen Host shard: {source}:{line}')
            cols = x.indices[x.indptr[row]:x.indptr[row + 1]]
            key = (source, line)
            if key in result:
                raise ValueError(f'Duplicate selected Host event: {source}:{line}')
            result[key] = schema.from_columns(cols)
    if len(result) != sum(map(len, selected.values())):
        raise ValueError('Not every frozen graph event has exactly one Host action/object')
    return result


def encode_part(destination, rows, base_meta, schema, types):
    node_arrays = []
    node_ptr = [0]
    edges = []
    edge_types = []
    roots = []; host_roots = []; labels = []; sources = []; lines = []; cutoffs = []
    offset = 0
    for row in rows:
        key = (base_meta['source_ids'][row['source_index']], row['source_line'])
        old_edges = row['edge_index']
        base = dict(x=row['x'], edges=tuple((int(a), int(b),
            base_meta['relations'][int(kind)]) for (a, b), kind in
            zip(old_edges.T, row['edge_type'])), root=row['root'],
            host_root=row['host_root'], cutoff_us=row['cutoff_us'])
        action, object_type = types[key]
        graph = schema.augment(base, action, object_type)
        x = graph['x']
        node_arrays.append(x)
        for a, b, relation in graph['edges']:
            edges.append((offset + int(a), offset + int(b)))
            edge_types.append(RELATION_ID[relation])
        roots.append(offset + int(graph['root']))
        host_roots.append(offset + int(graph['host_root']))
        labels.append(row['label']); sources.append(row['source_index'])
        lines.append(row['source_line']); cutoffs.append(row['cutoff_us'])
        offset += len(x); node_ptr.append(offset)
    if not rows:
        raise ValueError('Empty frozen graph cache part')
    arrays = dict(x=np.concatenate(node_arrays).astype('<f4', copy=False),
        node_ptr=np.asarray(node_ptr, dtype='<i8'),
        edge_index=np.asarray(edges, dtype='<i4').T,
        edge_type=np.asarray(edge_types, dtype='u1'),
        root=np.asarray(roots, dtype='<i4'), host_root=np.asarray(host_roots, dtype='<i4'),
        label=np.asarray(labels, dtype='u1'), source_index=np.asarray(sources, dtype='<u2'),
        source_line=np.asarray(lines, dtype='<u8'), cutoff_us=np.asarray(cutoffs, dtype='<i8'))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as handle:
        np.savez_compressed(handle, **arrays)
        handle.flush(); os.fsync(handle.fileno())
    return dict(graphs=len(rows), nodes=len(arrays['x']), edges=len(edge_types),
                bytes=destination.stat().st_size, sha256=sha256(destination))


def build(base_cache, baseline, output):
    base_cache, baseline, output = map(lambda p: Path(p).resolve(), (base_cache, baseline, output))
    base_root, base_meta = load_base_manifest(base_cache)
    if tuple(base_meta['relations']) != RELATIONS[:4] or len(base_meta['attributes']) != 40:
        raise ValueError('Expected frozen v4 Process/Host cache schema')
    baseline_meta = json.loads(baseline.read_text())
    volumes = resolve_volume_roots(baseline, baseline_meta)
    data = HostShardDataset(baseline, volumes)
    if base_meta['config']['split_sha256'] != data.meta['split_sha256']:
        raise ValueError('Frozen cache/Host split mismatch')
    if base_meta['source_ids'] != sorted({s['source_id'] for s in data.meta['sources']
            if any(p['source_id'] == s['source_id'] for p in data.meta['shards']) and
            s['source_id'] in base_meta['source_ids']}):
        raise ValueError('Frozen cache source ordering mismatch')
    vocab_path = baseline.parent / 'assets/vocab.json'
    schema = EventSchema(vocab_path)
    selected = selected_events(base_root, base_meta)
    types = event_types(data, selected, schema)
    output = safe(output, [base_cache, baseline.parent, *data.roots.values()])
    if output.exists():
        raise ValueError(f'Output already exists; preserving it: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
    try:
        parts = []
        for part in base_meta['parts']:
            rows = list(base_examples(base_root, part, len(base_meta['attributes'])))
            target = stage / part['path']
            record = encode_part(target, rows, base_meta, schema, types)
            record.update(path=part['path'], split=part['split'], start=part['start'], stop=part['stop'])
            decode_part(stage, record, len(schema.attributes))
            parts.append(record)
            print(f"{part['path']}: {record['graphs']} graphs, {record['nodes']} nodes", flush=True)
        config = dict(variant='event_only_v5a', base_cache_manifest_sha256=base_meta['manifest_sha256'],
            base_graph_database_sha256=base_meta['config']['graph_database_sha256'],
            baseline_split_sha256=data.meta['split_sha256'],
            vocabulary_sha256=sha(vocab_path), baseline_manifest_sha256=sha(baseline),
            event_source='frozen Host shard action/object columns; exact source_id+source_line join',
            time_policy=base_meta['config']['ego'],
            implementation={name:sha(path) for name,path in {
                'build_event_ego_cache.py':Path(__file__),
                'event_ego.py':HERE/'model/event_ego.py',
                'event_ego_cache.py':HERE/'model/event_ego_cache.py'}.items()})
        meta = dict(format=FORMAT, schema=SCHEMA, complete=True, config=config,
            selection_sha256=base_meta['selection_sha256'], attributes=list(schema.attributes),
            relations=list(RELATIONS), source_ids=base_meta['source_ids'],
            splits=base_meta['splits'], parts=parts,
            cache_bytes=sum(p['bytes'] for p in parts),
            safety='Only action/object of the target Event are appended; all other graph evidence is strict-past; labels are unchanged and never node features.')
        meta['manifest_sha256'] = manifest_digest(meta)
        atomic_json(stage/'manifest.json', meta)
        (stage/'selection.json').write_bytes((base_root/'selection.json').read_bytes())
        os.rename(stage, output)
        return meta
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-cache', type=Path, default=DEFAULT_OUTPUT/'seed02_ego_cache')
    parser.add_argument('--baseline', type=Path,
                        default=CODE/'output/host_ml_seed02/model_input/manifest.json')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT/'seed02_event_v5a_cache')
    args = parser.parse_args()
    meta = build(args.base_cache, args.baseline, args.output)
    print(json.dumps(dict(output=str(args.output), graphs=meta['splits'],
                          manifest_sha256=meta['manifest_sha256']), indent=2))


if __name__ == '__main__':
    main()
