#!/usr/bin/env python3
"""Build a corrected OpTC train/test pilot; frozen vocabulary, no validation split."""
from __future__ import annotations
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from ML.code.preprocess.build_matrix import (_assemble, _atomic_json, _digest, _file_hash, _identity,
                          _parse_file_meta, _valid_manifest, _write_chunk)
from ML.code.preprocess.ecar_tokenizer import HOST_OBJECT_FIELDS, flatten_tokens, token_layers, tokenize_record
from ML.code.preprocess.pipeline_contract import (PROJECT_ROOT, TRAIN_BENIGN_DAYS, code_hashes,
                               load_vocabulary, sync_directory, validate_output_path)


def eligible(record):
    value = record.get('object')
    return isinstance(value, str) and value.strip().casefold() in HOST_OBJECT_FIELDS


def make_plan(root, ground_truth, train_benign, test_benign):
    entries = []
    for scenario in (1, 2, 3):
        references = sorted(ground_truth.glob(f'ground_truth_corrected_sc{scenario}_evts_sysclient*.json.gz'))
        if len(references) != {1: 17, 2: 10, 3: 2}[scenario]:
            raise ValueError(f'incomplete corrected ground truth for scenario {scenario}')
        for reference in references:
            host = re.search(r'sysclient\d+', reference.name)[0]
            days = {1: ('23',), 2: ('24', '25'), 3: ('25',)}[scenario]
            for suffix in days:
                day = f'2019-09-{suffix}'
                paths = sorted(root.glob(f'{day}/*/*-{host}.json.gz'))
                if len(paths) != 1:
                    raise ValueError(f'expected exactly one source for {day}/{host}')
                entries.append(dict(path=str(paths[0].resolve()), reference=str(reference.resolve()),
                                    scenario=scenario, split='test' if scenario == 3 else 'train'))
    entries.sort(key=lambda e: e['path'])
    if len({e['path'] for e in entries}) != len(entries):
        raise ValueError('overlapping source files')
    for split, budget in [('train', train_benign), ('test', test_benign)]:
        selected = [e for e in entries if e['split'] == split]
        for i, entry in enumerate(selected):
            entry['benign_quota'] = budget // len(selected) + (i < budget % len(selected))
    return entries


def expected_ids(reference, day, host):
    ids = set()
    with gzip.open(reference, 'rt', encoding='utf-8') as handle:
        for line in handle:
            record = json.loads(line)
            if not eligible(record) or record['timestamp'][:10] != day:
                continue
            if record['hostname'].split('.')[0].casefold() != host:
                raise ValueError('ground truth hostname mismatch')
            event_id = record.get('id')
            if not isinstance(event_id, str) or not event_id or event_id in ids:
                raise ValueError('missing or duplicate ground truth event ID')
            ids.add(event_id)
    return ids


def process(entry, vocab, checkpoint, chunk_rows, seed):
    path, reference = Path(entry['path']), Path(entry['reference'])
    identity, gt_identity = _identity(path), _identity(reference)
    split = entry['split']
    directory = validate_output_path(Path(checkpoint) / _digest(entry))
    manifest_path = directory / 'manifest.json'
    if manifest_path.exists():
        try:
            saved = json.loads(manifest_path.read_text())
            if saved['gt_identity'] == gt_identity and _valid_manifest(saved, identity, split, directory):
                return {**saved, 'directory': str(directory), 'resumed': True}
        except (OSError, ValueError, KeyError, TypeError):
            pass
    directory.mkdir(parents=True, exist_ok=True)
    day, host = _parse_file_meta(path)
    expected = expected_ids(reference, day, host)
    seen = set()
    reservoir, rows, chunks = [], [], []
    stats = Counter()
    quota = entry['benign_quota']

    def emit(number, record):
        grouped, audit = tokenize_record(record)
        if not audit['eligible']:
            raise ValueError('eligibility disagreement')
        counts = Counter()
        for token in flatten_tokens(grouped):
            for layer in token_layers(token):
                stats[f'tokens_{layer}'] += 1
                if token not in vocab:
                    stats[f'oov_{layer}'] += 1
            if token in vocab:
                counts[vocab[token]] += 1
        label = record['label']
        stats['eligible_records'] += 1
        stats[f'label_{label}'] += 1
        if not counts:
            stats['no_vocab_hits'] += 1
        stats[f'selected_object_{record["object"].strip().casefold()}_label_{label}'] += 1
        sidecar = {key: record.get(key) for key in ('actorID', 'objectID', 'hostname', 'timestamp', 'object', 'action', 'pid')}
        sidecar.update(event_id=record['id'], label=label, scenario=entry['scenario'],
                       source_file=str(path), source_line=number, day=day, host=host)
        rows.append((label, counts, sidecar))
        if len(rows) >= chunk_rows:
            chunks.append(_write_chunk(directory, len(chunks), rows, len(vocab)))
            rows.clear()

    with gzip.open(path, 'rt', encoding='utf-8') as handle:
        for number, line in enumerate(handle, 1):
            stats['lines_read'] += 1
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f'{path}:{number}: event must be an object')
            if not eligible(record):
                continue
            event_id, label = record.get('id'), record.get('label')
            if not isinstance(event_id, str) or not event_id or type(label) is not int or label not in (0, 1):
                raise ValueError(f'{path}:{number}: explicit event ID and integer 0/1 label required')
            if str(record.get('hostname', '')).split('.')[0].casefold() != host:
                raise ValueError(f'{path}:{number}: hostname mismatch')
            if label != int(event_id in expected):
                raise ValueError(f'{path}:{number}: dataset label disagrees with corrected ground truth: {event_id}')
            stats[f'population_label_{label}'] += 1
            if label:
                if event_id in seen:
                    raise ValueError(f'duplicate malicious event ID: {event_id}')
                seen.add(event_id)
                emit(number, record)
            elif quota:
                # Fixed-size, deterministic uniform hash sample over the whole file.
                priority = int.from_bytes(hashlib.sha256(f'{seed}:{day}:{host}:{number}:{event_id}'.encode()).digest(), 'big')
                item = (-priority, number, line)
                if len(reservoir) < quota:
                    heapq.heappush(reservoir, item)
                elif item > reservoir[0]:
                    heapq.heapreplace(reservoir, item)
    if seen != expected:
        raise ValueError(f'{path}: {len(expected - seen)} corrected Host event IDs missing from source')
    if len(reservoir) != quota:
        raise ValueError(f'{path}: insufficient benign events for quota {quota}')
    for _, number, line in sorted(reservoir, key=lambda item: item[1]):
        emit(number, json.loads(line))
    if rows:
        chunks.append(_write_chunk(directory, len(chunks), rows, len(vocab)))
    if identity != _identity(path) or gt_identity != _identity(reference):
        raise ValueError('source or ground truth changed during scan')
    stats['eof_observed'] = 1
    result = dict(identity=identity, gt_identity=gt_identity, split=split, chunks=chunks,
                  stats=dict(stats), scenario=entry['scenario'], expected_host_positives=len(expected))
    _atomic_json(manifest_path, result)
    return {**result, 'directory': str(directory), 'resumed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--malicious-root', type=Path, default=PROJECT_ROOT / 'host-malicious')
    parser.add_argument('--ground-truth-dir', type=Path, default=PROJECT_ROOT / 'a_new_hope_for_darpa_optc/labelling/host/ground_truths')
    parser.add_argument('--vocab', type=Path, default=PROJECT_ROOT / 'code/output/vocab.json')
    parser.add_argument('--output-dir', type=Path, default=PROJECT_ROOT / 'code/output/matrix_pilot')
    parser.add_argument('--train-benign', type=int, default=400000)
    parser.add_argument('--test-benign', type=int, default=100000)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--chunk-rows', type=int, default=10000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    if min(args.workers, args.chunk_rows, args.train_benign, args.test_benign) < 1:
        raise ValueError('workers, chunk size and benign budgets must be positive')
    output = validate_output_path(args.output_dir, [args.malicious_root, args.ground_truth_dir])
    if output.exists():
        raise ValueError('output directory already exists; choose an unused directory')
    vocab, vocab_meta = load_vocabulary(args.vocab, args.vocab.with_name('vocab_metadata.json'), training_days=TRAIN_BENIGN_DAYS)
    if vocab_meta.get('fit_purpose') == 'supervised_training':
        raise ValueError('use build_matrix.py --split with a shared-split vocabulary; scenario pilot is incompatible')
    plan = make_plan(args.malicious_root, args.ground_truth_dir, args.train_benign, args.test_benign)
    config = dict(source_sha256=code_hashes(('build_host_pilot.py', 'build_matrix.py', 'ecar_tokenizer.py', 'command_syntax.py', 'pipeline_contract.py')),
                  vocabulary_sha256=vocab_meta['vocabulary_sha256'], seed=args.seed, chunk_rows=args.chunk_rows,
                  plan=plan, references={e['reference']: _file_hash(Path(e['reference'])) for e in plan},
                  sources=[_identity(Path(e['path'])) for e in plan])
    if args.dry_run:
        print(json.dumps(dict(files=len(plan), compressed_GiB=sum(s['size'] for s in config['sources']) / 2**30,
                              split_policy='train=sc1+sc2; test=sc3; no validation', plan=plan), indent=2))
        return 0
    checkpoint = validate_output_path(output.parent / f'.{output.name}.checkpoints' / _digest(config), [args.malicious_root, args.ground_truth_dir])
    checkpoint.mkdir(parents=True, exist_ok=True)
    manifests = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(process, entry, vocab, checkpoint, args.chunk_rows, args.seed) for entry in plan]
        for index, future in enumerate(futures, 1):
            result = future.result()
            manifests.append(result)
            print(f'[{index}/{len(plan)}] {Path(result["identity"]["path"]).name}: {result["stats"]["eligible_records"]:,} selected; resumed={result["resumed"]}', flush=True)
    stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
    try:
        splits = {split: _assemble(stage, split, manifests, len(vocab), 'binary') for split in ('train', 'test')}
        if any(info is None or min(info['label_0'], info['label_1']) <= 0 for info in splits.values()):
            raise ValueError('both classes required in train and test')
        if config['sources'] != [_identity(Path(e['path'])) for e in plan] or any(_file_hash(Path(p)) != h for p,h in config['references'].items()):
            raise ValueError('inputs changed before publication')
        stats = Counter()
        for manifest in manifests:
            stats.update(manifest['stats'])
        metadata = dict(created_utc=datetime.now(timezone.utc).isoformat(), **config,
                        vocab_size=len(vocab), representation='binary', splits=splits, aggregate_stats=dict(stats),
                        split_policy='train=sc1+sc2 (23–25 September); test=sc3 (25 September); no validation; scenario split, not strict temporal split',
                        sampling='All corrected Host positives; uniform hash sample of label=0 per source file. No historical benign rows in this pilot. Non-natural prevalence; report population and selected counts.',
                        evaluation='Freeze settings and threshold before test. Historical benign vocabulary may include test hosts; not an unseen-host benchmark.',
                        checkpoint=dict(resumed_files=sum(m['resumed'] for m in manifests), files=len(manifests)),
                        artifact_sha256={p.name: _file_hash(p) for p in stage.iterdir() if p.is_file()})
        _atomic_json(stage / 'split_metadata.json', metadata)
        for p in stage.iterdir():
            with p.open('rb') as handle:
                os.fsync(handle.fileno())
        sync_directory(stage)
        if output.exists():
            raise ValueError('output created concurrently')
        os.rename(stage, output)
        sync_directory(output.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    shutil.rmtree(checkpoint)
    print(json.dumps(dict(output=str(output), splits=splits), indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
