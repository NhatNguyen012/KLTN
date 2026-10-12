#!/usr/bin/env python3
"""Build resumable static two-hop ego-graph shards from the frozen seed02 graph.

This is a local CPU/SSD preprocessing stage.  It queries the label-blind SQLite
provenance index exactly once per selected event, emits no raw commands or node
identifiers, and is safe to interrupt between compressed graph shards.  Kaggle
then only reads sequential shard files and trains the learned model on GPU.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time

import numpy as np

HERE = Path(__file__).resolve().parents[1]
CODE = HERE.parents[0]
sys.path.insert(0, str(HERE / 'model'))
sys.path.insert(0, str(CODE / 'preprocess'))

from common import BASELINE, DEFAULT_OUTPUT, atomic_json, digest, safe, sha
from ego import ATTRIBUTES, EgoGraphs, connect
from ego_cache import FORMAT, RELATIONS, RELATION_ID, decode_part, manifest_digest, sha256
from host_shards import HostShardDataset
from train import resolve_volume_roots, sampled_rows
from pipeline_contract import sync_directory
from shard_storage import exclusive_lock

SPLIT_CODE = {'train': 1, 'val': 2, 'test': 3}


def load_graph(graph: Path):
    graph = Path(graph).resolve()
    manifest_path = graph / 'manifest.json'
    database = graph / 'graph.sqlite'
    meta = json.loads(manifest_path.read_text())
    if meta.get('complete') is not True or meta.get('config', {}).get('pilot'):
        raise ValueError('a complete non-pilot graph index is required')
    if not database.is_file() or sha(database) != meta.get('database_sha256'):
        raise ValueError('graph database checksum mismatch')
    for name in ('graph.py', 'build_graph.py', 'common.py'):
        source = HERE / 'preprocess' / name
        if not source.is_file() or sha(source) != meta['config']['implementation'][name]:
            raise ValueError('graph scanner semantics changed since index publication')
    return graph, meta


def make_plan(data, db, args):
    result = dict(schema=1, selection_method='global_label_reservoir_then_selected_graph_lookup',
                  seed=args.seed, splits={})
    for offset, (split, limit, balanced) in enumerate((
            ('train', args.train_limit, True), ('val', args.val_limit, False), ('test', args.test_limit, False))):
        rows, info = sampled_rows(data, db, split, limit, args.seed + offset, balanced=balanced)
        result['splits'][split] = dict(
            selection=info,
            rows=[dict(source_id=row[4], source_line=int(row[5]), label=int(row[3])) for row in rows],
        )
    result['selection_sha256'] = digest(result['splits'])
    return result


def restore_rows(db, split, plan):
    """Recover host/process/time from the immutable graph target table."""
    expected = plan['splits'][split]['rows']
    grouped = {}
    for item in expected:
        grouped.setdefault(item['source_id'], []).append(item)
    found = {}
    code = SPLIT_CODE[split]
    for source, items in grouped.items():
        for start in range(0, len(items), 900):
            chunk = items[start:start + 900]
            placeholders = ','.join('?' for _ in chunk)
            query = f'SELECT line,host,proc,t,split FROM target WHERE source=? AND line IN ({placeholders})'
            for line, host, proc, timestamp, assigned in db.execute(query, [source, *[x['source_line'] for x in chunk]]):
                if assigned != code:
                    raise ValueError('selected row has a different frozen split')
                found[(source, int(line))] = (host, proc, timestamp)
    rows = []
    for item in expected:
        identity = found.get((item['source_id'], item['source_line']))
        if identity is None:
            raise ValueError('selected cache row missing from graph target table')
        rows.append((*identity, int(item['label']), item['source_id'], int(item['source_line'])))
    return rows


def write_part(path, examples, source_lookup):
    """Atomically publish one contiguous batch of independently bounded graphs."""
    nodes = [graph['x'] for graph, _ in examples]
    node_ptr = [0]
    edges = []
    edge_types = []
    roots = []
    host_roots = []
    labels = []
    sources = []
    lines = []
    cutoffs = []
    offset = 0
    for graph, row in examples:
        x = np.asarray(graph['x'], dtype=np.float32)
        if x.ndim != 2 or x.shape[1] != len(ATTRIBUTES) or not (1 <= len(x) <= 64):
            raise ValueError('invalid bounded ego graph')
        for source, target, relation in graph['edges']:
            if relation not in RELATION_ID:
                raise ValueError('unknown graph relation')
            edges.append((offset + int(source), offset + int(target)))
            edge_types.append(RELATION_ID[relation])
        roots.append(offset + int(graph['root']))
        host_roots.append(offset + int(graph['host_root']))
        labels.append(int(row[3]))
        sources.append(source_lookup[row[4]])
        lines.append(int(row[5]))
        cutoffs.append(-1 if graph['cutoff_us'] is None else int(graph['cutoff_us']))
        offset += len(x)
        node_ptr.append(offset)
    arrays = dict(
        x=np.concatenate(nodes, axis=0).astype(np.float32, copy=False),
        node_ptr=np.asarray(node_ptr, dtype='<i8'),
        edge_index=(np.asarray(edges, dtype='<i4').T if edges else np.empty((2, 0), dtype='<i4')),
        edge_type=np.asarray(edge_types, dtype='u1'),
        root=np.asarray(roots, dtype='<i4'),
        host_root=np.asarray(host_roots, dtype='<i4'),
        label=np.asarray(labels, dtype='u1'),
        source_index=np.asarray(sources, dtype='<u2'),
        source_line=np.asarray(lines, dtype='<u8'),
        cutoff_us=np.asarray(cutoffs, dtype='<i8'),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ValueError(f'refusing to overwrite cache part: {path}')
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('xb') as handle:
        np.savez_compressed(handle, **arrays)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)
    return dict(graphs=len(examples), nodes=len(arrays['x']), edges=len(arrays['edge_type']),
                bytes=path.stat().st_size, sha256=sha256(path))


def build(args):
    if min(args.train_limit, args.val_limit, args.test_limit, args.graphs_per_shard, args.sqlite_cache_mib) < 1:
        raise ValueError('all cache limits and SQLite cache size must be positive')
    if args.train_limit < 2:
        raise ValueError('balanced TRAIN cache requires at least two rows')
    graph, graph_meta = load_graph(args.graph)
    baseline = Path(args.baseline).resolve()
    raw = json.loads(baseline.read_text())
    volumes = resolve_volume_roots(baseline, raw)
    data = HostShardDataset(baseline, volumes)
    if graph_meta['config']['split_sha256'] != data.meta['split_sha256']:
        raise ValueError('baseline and graph split identity mismatch')
    expected_sources = {entry['source_id']: entry['source'] for entry in graph_meta['config']['sources']}
    if any(expected_sources.get(source['source_id']) != source['source'] for source in data.meta['sources']):
        raise ValueError('baseline and graph source identity mismatch')
    config = dict(
        format=FORMAT,
        schema=1,
        graph_database_sha256=graph_meta['database_sha256'],
        graph_manifest_sha256=sha(graph / 'manifest.json'),
        baseline_manifest_sha256=sha(baseline),
        split_sha256=data.meta['split_sha256'],
        limits=dict(train=args.train_limit, val=args.val_limit, test=args.test_limit),
        sampling_seed=args.seed,
        graphs_per_shard=args.graphs_per_shard,
        ego=dict(fanout=args.fanout, max_nodes=args.max_nodes, quantum_us=args.quantum_us),
        attributes=ATTRIBUTES,
        relations=list(RELATIONS),
        implementation={
            'build_ego_cache.py': sha(Path(__file__)),
            'model/ego.py': sha(HERE / 'model/ego.py'),
            'model/ego_cache.py': sha(HERE / 'model/ego_cache.py'),
            'model/train.py': sha(HERE / 'model/train.py'),
            'preprocess/graph.py': sha(HERE / 'preprocess/graph.py'),
            'preprocess/common.py': sha(HERE / 'preprocess/common.py'),
            'code/preprocess/host_shards.py': sha(CODE / 'preprocess/host_shards.py'),
        },
    )
    output = safe(args.output, [graph, baseline.parent, *data.roots.values()])
    work = safe(output.with_name('.' + output.name + '.work'), [graph, baseline.parent, *data.roots.values()])
    lock = safe(output.with_suffix('.lock'), [graph, baseline.parent, *data.roots.values()])
    if args.dry_run:
        db = connect(graph / 'graph.sqlite', readonly=True)
        try:
            plan = make_plan(data, db, args)
        finally:
            db.close()
        print(json.dumps(dict(output=str(output), config=config,
                              selections={name:value['selection'] for name, value in plan['splits'].items()}), indent=2))
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(lock, nonblocking=True):
        if output.exists():
            meta = json.loads((output / 'manifest.json').read_text())
            if meta.get('complete') is not True or meta.get('config') != config:
                raise ValueError('existing cache differs; preserving it')
            print(f'Already complete: {output}')
            return
        work.mkdir(exist_ok=True)
        config_path = work / 'config.json'
        if config_path.exists():
            if json.loads(config_path.read_text()) != config:
                raise ValueError('cache checkpoint configuration differs')
        else:
            atomic_json(config_path, config)
        db = connect(graph / 'graph.sqlite', readonly=True)
        db.execute(f'PRAGMA cache_size=-{args.sqlite_cache_mib * 1024}')
        try:
            plan_path = work / 'selection.json'
            if plan_path.exists():
                plan = json.loads(plan_path.read_text())
                if plan.get('selection_sha256') != digest(plan.get('splits')):
                    raise ValueError('cache selection checksum mismatch')
            else:
                print('selecting frozen seed02 graph rows', flush=True)
                plan = make_plan(data, db, args)
                atomic_json(plan_path, plan)
            source_ids = sorted({row['source_id'] for value in plan['splits'].values() for row in value['rows']})
            if len(source_ids) >= 2**16:
                raise ValueError('too many source IDs for cache schema')
            source_lookup = {source: index for index, source in enumerate(source_ids)}
            state_path = work / 'state.json'
            state = json.loads(state_path.read_text()) if state_path.exists() else dict(parts=[])
            part_by_path = {part['path']: part for part in state['parts']}
            if len(part_by_path) != len(state['parts']):
                raise ValueError('duplicate cache part checkpoint')
            encoder = EgoGraphs(db, fanout=args.fanout, max_nodes=args.max_nodes, quantum_us=args.quantum_us)
            final_parts = []
            started = time.monotonic()
            for split in ('train', 'val', 'test'):
                rows = restore_rows(db, split, plan)
                for start in range(0, len(rows), args.graphs_per_shard):
                    stop = min(start + args.graphs_per_shard, len(rows))
                    relative = f'{split}/graph_{start // args.graphs_per_shard:05d}.npz'
                    previous = part_by_path.get(relative)
                    if previous:
                        if previous.get('split') != split or previous.get('start') != start or previous.get('stop') != stop:
                            raise ValueError('cache checkpoint part range differs')
                        decode_part(work, previous, len(ATTRIBUTES))
                        final_parts.append(previous)
                        print(f'resumed {relative}', flush=True)
                        continue
                    print(f'building {split} graphs {start + 1:,}-{stop:,}/{len(rows):,}', flush=True)
                    examples = [(encoder.build(*row[:3]), row) for row in rows[start:stop]]
                    part = write_part(work / relative, examples, source_lookup)
                    part.update(path=relative, split=split, start=start, stop=stop)
                    state['parts'].append(part)
                    atomic_json(state_path, state)
                    final_parts.append(part)
                    print(f'published {relative}: {part["graphs"]} graphs, {part["nodes"]} nodes, {part["edges"]} edges', flush=True)
            counts = {}
            for split in ('train', 'val', 'test'):
                selected = plan['splits'][split]['rows']
                counts[split] = dict(graphs=len(selected), label_0=sum(row['label'] == 0 for row in selected),
                                     label_1=sum(row['label'] == 1 for row in selected),
                                     parts=sum(part['split'] == split for part in final_parts))
            meta = dict(format=FORMAT, schema=1, complete=True, config=config,
                        selection_sha256=plan['selection_sha256'], attributes=ATTRIBUTES,
                        relations=list(RELATIONS), source_ids=source_ids, splits=counts,
                        parts=final_parts, cache_bytes=sum(part['bytes'] for part in final_parts),
                        elapsed_seconds=time.monotonic() - started,
                        safety='Node IDs, hostnames, commands, raw telemetry and ancestor labels are absent. All graph evidence was strict-past and label-blind.',
                        evaluation='Frozen seed02 contextual random-event split; graph context is label-free transductive evidence, not an unseen-host/process evaluation.')
            meta['manifest_sha256'] = manifest_digest(meta)
            atomic_json(work / 'manifest.json', meta)
        finally:
            db.close()
        os.rename(work, output)
        sync_directory(output.parent)
        print(json.dumps(dict(output=str(output), graphs=counts, cache_bytes=meta['cache_bytes']), indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, default=BASELINE / 'model_input/manifest.json')
    parser.add_argument('--graph', type=Path, default=DEFAULT_OUTPUT / 'graph')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT / 'seed02_ego_cache')
    parser.add_argument('--train-limit', type=int, default=4000)
    parser.add_argument('--val-limit', type=int, default=2000)
    parser.add_argument('--test-limit', type=int, default=2000)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--graphs-per-shard', type=int, default=250)
    parser.add_argument('--fanout', type=int, default=8)
    parser.add_argument('--max-nodes', type=int, default=64)
    parser.add_argument('--quantum-us', type=int, default=1)
    parser.add_argument('--sqlite-cache-mib', type=int, default=256)
    parser.add_argument('--dry-run', action='store_true')
    build(parser.parse_args())


if __name__ == '__main__':
    main()
