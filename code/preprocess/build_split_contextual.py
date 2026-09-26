#!/usr/bin/env python3
"""Option B contextual cohort, using the standard lossless split-mask contract.

Dry-run verifies index metadata and plans sources without scanning telemetry.
A real run revalidates every indexed label in selected files, keeps every eligible
positive, checkpoints per file, and atomically publishes a host_random_split.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import gzip
import json
import os
from pathlib import Path

from stratified_pipeline import (
    SPLITS, BLOCK, atomic_json, checked_sources, code_hashes, digest, durable,
    file_hash, file_quotas, implementation, label_of, load_manifest,
    publish_directory, relative_artifact, split_file, stamp, work_directory,
)
from pipeline_contract import PROJECT_ROOT, validate_output_path
from shard_storage import exclusive_lock

ET = timezone(timedelta(hours=-4))

BENIGN_WINDOW = (10, 0, 10, 30)   # (start_h, start_m, end_h, end_m) ET
BENIGN_DAYS   = ("2019-09-21", "2019-09-22")

# Per-host attack windows from corpus scan (September 2026).
# (host, day) -> (first_mal_ts, last_mal_ts)
ATTACK_WINDOWS: dict[tuple[str, str], tuple[str, str]] = {
    ("sysclient0104", "2019-09-23"): ("2019-09-23T14:44:53.785-04:00", "2019-09-23T15:23:10.035-04:00"),
    ("sysclient0170", "2019-09-23"): ("2019-09-23T14:44:54.115-04:00", "2019-09-23T15:23:12.753-04:00"),
    ("sysclient0201", "2019-09-23"): ("2019-09-23T11:23:54.681-04:00", "2019-09-23T14:05:10.300-04:00"),
    ("sysclient0205", "2019-09-23"): ("2019-09-23T14:44:54.877-04:00", "2019-09-23T15:23:10.825-04:00"),
    ("sysclient0255", "2019-09-23"): ("2019-09-23T14:44:55.674-04:00", "2019-09-23T15:23:11.045-04:00"),
    ("sysclient0321", "2019-09-23"): ("2019-09-23T14:44:56.365-04:00", "2019-09-23T15:23:08.749-04:00"),
    ("sysclient0355", "2019-09-23"): ("2019-09-23T14:44:55.055-04:00", "2019-09-23T15:23:07.192-04:00"),
    ("sysclient0402", "2019-09-23"): ("2019-09-23T13:23:30.780-04:00", "2019-09-23T14:05:14.119-04:00"),
    ("sysclient0419", "2019-09-23"): ("2019-09-23T14:44:57.105-04:00", "2019-09-23T15:23:10.861-04:00"),
    ("sysclient0462", "2019-09-23"): ("2019-09-23T14:44:56.834-04:00", "2019-09-23T15:23:08.625-04:00"),
    ("sysclient0503", "2019-09-23"): ("2019-09-23T14:44:59.289-04:00", "2019-09-23T15:23:08.530-04:00"),
    ("sysclient0559", "2019-09-23"): ("2019-09-23T14:44:57.763-04:00", "2019-09-23T15:23:08.182-04:00"),
    ("sysclient0609", "2019-09-23"): ("2019-09-23T14:44:59.248-04:00", "2019-09-23T15:23:08.653-04:00"),
    ("sysclient0660", "2019-09-23"): ("2019-09-23T13:34:17.240-04:00", "2019-09-23T14:05:17.394-04:00"),
    ("sysclient0771", "2019-09-23"): ("2019-09-23T14:45:00.502-04:00", "2019-09-23T15:23:08.669-04:00"),
    ("sysclient0874", "2019-09-23"): ("2019-09-23T14:45:00.035-04:00", "2019-09-23T15:23:12.190-04:00"),
    ("sysclient0955", "2019-09-23"): ("2019-09-23T14:44:59.171-04:00", "2019-09-23T15:23:11.328-04:00"),
    ("sysclient0005", "2019-09-24"): ("2019-09-24T13:58:55.992-04:00", "2019-09-24T15:23:41.470-04:00"),
    ("sysclient0010", "2019-09-24"): ("2019-09-24T15:41:16.649-04:00", "2019-09-24T23:59:43.307-04:00"),
    ("sysclient0069", "2019-09-24"): ("2019-09-24T15:41:17.073-04:00", "2019-09-24T23:59:45.531-04:00"),
    ("sysclient0203", "2019-09-24"): ("2019-09-24T15:41:17.292-04:00", "2019-09-24T23:59:48.114-04:00"),
    ("sysclient0358", "2019-09-24"): ("2019-09-24T15:41:17.523-04:00", "2019-09-24T23:59:44.813-04:00"),
    ("sysclient0501", "2019-09-24"): ("2019-09-24T10:35:52.988-04:00", "2019-09-24T23:58:58.041-04:00"),
    ("sysclient0503", "2019-09-24"): ("2019-09-24T11:09:59.933-04:00", "2019-09-24T11:09:59.997-04:00"),
    ("sysclient0504", "2019-09-24"): ("2019-09-24T11:10:39.989-04:00", "2019-09-24T11:10:40.171-04:00"),
    ("sysclient0506", "2019-09-24"): ("2019-09-24T11:10:31.529-04:00", "2019-09-24T11:10:31.717-04:00"),
    ("sysclient0510", "2019-09-24"): ("2019-09-24T11:09:35.971-04:00", "2019-09-24T11:09:36.046-04:00"),
    ("sysclient0517", "2019-09-24"): ("2019-09-24T11:09:36.308-04:00", "2019-09-24T11:09:36.612-04:00"),
    ("sysclient0524", "2019-09-24"): ("2019-09-24T11:10:48.872-04:00", "2019-09-24T11:10:49.204-04:00"),
    ("sysclient0618", "2019-09-24"): ("2019-09-24T15:41:17.567-04:00", "2019-09-24T23:59:45.071-04:00"),
    ("sysclient0811", "2019-09-24"): ("2019-09-24T10:39:40.578-04:00", "2019-09-24T13:25:49.254-04:00"),
    ("sysclient0851", "2019-09-24"): ("2019-09-24T15:41:17.917-04:00", "2019-09-24T23:59:47.169-04:00"),
    ("sysclient0974", "2019-09-24"): ("2019-09-24T13:51:20.912-04:00", "2019-09-24T15:23:55.485-04:00"),
    ("sysclient0010", "2019-09-25"): ("2019-09-25T00:00:13.153-04:00", "2019-09-25T09:17:46.465-04:00"),
    ("sysclient0051", "2019-09-25"): ("2019-09-25T10:27:51.399-04:00", "2019-09-25T14:00:46.268-04:00"),
    ("sysclient0069", "2019-09-25"): ("2019-09-25T00:00:15.351-04:00", "2019-09-25T09:17:29.093-04:00"),
    ("sysclient0203", "2019-09-25"): ("2019-09-25T00:00:17.846-04:00", "2019-09-25T09:16:26.411-04:00"),
    ("sysclient0351", "2019-09-25"): ("2019-09-25T11:17:45.827-04:00", "2019-09-25T13:56:31.232-04:00"),
    ("sysclient0358", "2019-09-25"): ("2019-09-25T00:00:14.883-04:00", "2019-09-25T09:15:41.381-04:00"),
    ("sysclient0501", "2019-09-25"): ("2019-09-25T00:00:06.263-04:00", "2019-09-25T13:54:40.870-04:00"),
    ("sysclient0618", "2019-09-25"): ("2019-09-25T00:00:15.195-04:00", "2019-09-25T09:13:55.570-04:00"),
    ("sysclient0851", "2019-09-25"): ("2019-09-25T00:00:17.266-04:00", "2019-09-25T09:12:09.498-04:00"),
}

ATTACKED_HOSTS: set[str] = {h for (h, _) in ATTACK_WINDOWS}

def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(ET)


def select_entries(index):
    by_key = {}
    for entry in index['entries']:
        key = (entry['host'], entry['day'])
        by_key.setdefault(key, []).append(entry)
        if entry['counts'].get('2', 0) and key not in ATTACK_WINDOWS:
            raise ValueError(f"positive source missing from attack windows: {key}")
    selected = []
    requested = {(h, d) for h in ATTACKED_HOSTS for d in BENIGN_DAYS} | set(ATTACK_WINDOWS)
    for key in sorted(requested):
        if key not in by_key:
            if key in ATTACK_WINDOWS:
                raise ValueError(f"required attack host/day missing from index: {key}")
            continue
        for entry in by_key[key]:
            if key in ATTACK_WINDOWS:
                if entry['benign']:
                    raise ValueError('attack window points to benign partition')
                window = ATTACK_WINDOWS[key]
                kind = 'attack'
            else:
                if not entry['benign'] or entry['counts'].get('2', 0):
                    raise ValueError('baseline must contain benign events only')
                window = (key[1]+'T10:00:00-04:00', key[1]+'T10:30:00-04:00')
                kind = 'baseline'
            selected.append(dict(entry, contextual_window=list(window), contextual_kind=kind))
    return selected


def load_index(path):
    # Label indexes precede feature-policy changes. Do not falsely relabel the old
    # index as current: preserve its hashes and verify every selected raw label
    # against its original stream using today's eligibility rules in select_file.
    path = path.resolve()
    index = json.loads(path.read_text())
    if index.get('kind') != 'host_label_index' or index.get('schema') != 1:
        raise ValueError('expected host_label_index manifest')
    if not isinstance(index.get('implementation'), dict) or not index.get('tokenizer_sha256'):
        raise ValueError('index missing code provenance')
    entries = index['entries']
    if not entries or len({e['source']['path'] for e in entries}) != len(entries):
        raise ValueError('empty or overlapping index sources')
    selected = select_entries(index)
    checked_sources(selected)
    for entry in selected:
        if file_hash(relative_artifact(path.parent, entry['artifact'])) != entry['sha256']:
            raise ValueError('index label checksum mismatch')
    return index, file_hash(path), selected


def select_file(entry, index_dir, work):
    key = digest(entry)
    artifact = work / f'{key}.labels.gz'
    receipt = work / f'{key}.selection.json'
    if receipt.exists():
        try:
            saved = json.loads(receipt.read_text())
            if saved['source'] == entry['source'] and artifact.exists() and file_hash(artifact) == saved['sha256']:
                return saved
        except (OSError, ValueError, KeyError):
            pass
    first, last = map(_parse_ts, entry['contextual_window'])
    if first > last:
        raise ValueError('inverted window')
    temporary = validate_output_path(artifact.with_suffix('.tmp'))
    counts, original = Counter(), Counter()
    with gzip.open(entry['source']['path'], 'rt', encoding='utf-8') as src, \
         gzip.open(relative_artifact(index_dir, entry['artifact']), 'rb') as labels, \
         gzip.open(temporary, 'wb') as dst:
        buffer = bytearray()
        for line in src:
            raw = labels.read(1)
            if not raw:
                raise ValueError('index shorter than source')
            record = json.loads(line) if line.strip() else None
            code = label_of(record, entry['benign'], entry['host']) if record is not None else 0
            if code != raw[0]:
                raise ValueError('indexed label/eligibility differs from current raw event')
            original[str(code)] += 1
            selected = 0
            if code:
                dt = _parse_ts(record['timestamp'])
                inside = first <= dt <= last if entry['contextual_kind'] == 'attack' else first <= dt < last
                if code == 2 and not inside:
                    raise ValueError('malicious event outside declared attack window; update windows before rebuilding')
                selected = code if inside else 0
            counts['lines'] += 1
            counts[str(selected)] += 1
            buffer.append(selected)
            if len(buffer) >= BLOCK:
                dst.write(buffer)
                buffer.clear()
        dst.write(buffer)
        if labels.read(1):
            raise ValueError('index longer than source')
    if counts['lines'] != entry['counts']['lines'] or any(original[str(c)] != entry['counts'].get(str(c), 0) for c in (0,1,2)):
        raise ValueError('index counts disagree with source')
    checked_sources([entry])
    if file_hash(relative_artifact(index_dir, entry['artifact'])) != entry['sha256']:
        raise ValueError('index changed during selection')
    durable(temporary)
    os.replace(temporary, artifact)
    result = dict(entry, counts=dict(counts), artifact=artifact.name, sha256=file_hash(artifact),
                  original_counts=entry['counts'], original_index_sha256=entry['sha256'])
    atomic_json(receipt, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, default=PROJECT_ROOT/'code/output/host_ml_seed02/index/manifest.json')
    parser.add_argument('--output-dir', type=Path, default=PROJECT_ROOT/'code/output/host_ml_seed02/split')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--require-complete-baseline', action='store_true', help='Reject missing baseline host/day files')
    args = parser.parse_args(argv)
    if args.seed < 0:
        raise ValueError('seed must be nonnegative')
    output = validate_output_path(args.output_dir, [args.index.resolve().parent])
    index, index_sha, entries = load_index(args.index)
    baseline_keys = {(e['host'], e['day']) for e in entries if e['contextual_kind'] == 'baseline'}
    missing = sorted({(h,d) for h in ATTACKED_HOSTS for d in BENIGN_DAYS} - baseline_keys)
    if missing and args.require_complete_baseline:
        raise ValueError(f'missing baseline host-days: {missing}')
    print(json.dumps(dict(missing_baseline_host_days=missing, source_files=len(entries), attacked_hosts=len(ATTACKED_HOSTS),
        attack_windows=len(ATTACK_WINDOWS), indexed_malicious=sum(e['counts'].get('2',0) for e in entries),
        output=str(output), dry_run=args.dry_run,
        note='Selected event totals measured only during real scan; no uniform-rate estimates.'), indent=2), flush=True)
    if args.dry_run:
        return 0
    config = dict(index_sha256=index_sha, seed=args.seed, implementation={**implementation(),
        **code_hashes(('build_split_contextual.py',))}, selection_sha256=digest(entries))
    if output.exists():
        saved, _ = load_manifest(output/'manifest.json', 'host_random_split')
        if all(saved.get(k) == v for k,v in config.items()):
            print(f'Already complete: {output}/manifest.json')
            return 0
        raise ValueError('completed output differs; preserving it')
    output, work = work_directory(output, config)
    # Lock outside the renamed work directory to keep concurrent builders excluded.
    with exclusive_lock(work.parent/'build.lock', nonblocking=True):
        selected = []
        for i, entry in enumerate(entries, 1):
            selected.append(select_file(entry, args.index.resolve().parent, work))
            print(f'[{i}/{len(entries)}] selected {entry["host"]}/{entry["day"]}: {selected[-1]["counts"]}', flush=True)
        allocations = file_quotas(selected)
        if any(min(sum(a[str(c)][s] for a in allocations) for s in range(3)) < 1 for c in (1,2)):
            raise ValueError('not enough examples of each class for three splits')
        results = [split_file(e,a,work,work,args.seed) for e,a in zip(selected,allocations)]
        checked_sources(entries)
        if file_hash(args.index) != index_sha:
            raise ValueError('index manifest changed during build')
        for entry in entries:
            if file_hash(relative_artifact(args.index.resolve().parent,entry['artifact'])) != entry['sha256']:
                raise ValueError('index labels changed during build')
        counts = {s:{f'label_{c-1}':sum(a[str(c)][i] for a in allocations) for c in (1,2)} for i,s in enumerate(SPLITS)}
        publish_directory(work, output, dict(schema=1, kind='host_random_split', created_utc=stamp(),
            **config, tokenizer_sha256=code_hashes(), entries=results, counts=counts, ratios=[.75,.10,.15],
            strategy='contextual_option_b', index_tokenizer_sha256=index['tokenizer_sha256'],
            missing_baseline_host_days=missing, benign_days=list(BENIGN_DAYS), benign_window_et='[10:00,10:30)',
            attacked_hosts=sorted(ATTACKED_HOSTS), attack_windows={f'{h}/{d}':v for (h,d),v in sorted(ATTACK_WINDOWS.items())},
            split_policy='random source-file/label strata; exact global class quotas; seed displayed 01 by default',
            sampling='two baseline windows plus inclusive per-file attack windows; all indexed eligible positives retained',
            source_identity_policy='path/size/mtime_ns plus index label checksums; raw content not hashed',
            checkpoint_policy='per-file; config, code, source identity and label checksum bound; invalid receipts rescanned',
            limitations='label-informed cohort; attacked file-hosts only; no temporal/process/campaign generalization; file host may differ from event host'))
    print(json.dumps(dict(manifest=str(output/'manifest.json'), counts=counts), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
