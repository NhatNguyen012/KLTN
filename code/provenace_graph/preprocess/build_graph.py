#!/usr/bin/env python3
"""Stream Host telemetry into a compact SQLite backbone; resumable, no training."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import os
import shutil
import time
import sys
import sqlite3

from common import BASELINE, DEFAULT_OUTPUT, safe, sha, digest, implementation, atomic_json, exclusive_lock
from graph import connect, observe, identity, FEATURES


def source_identity(path):
    p = Path(path).resolve(); s = p.stat()
    return dict(path=str(p), size=s.st_size, mtime_ns=s.st_mtime_ns)


def ontology_audit(db):
    result = {}
    for name, keys in [('host', 'host'), ('process', 'host,proc')]:
        result[name] = dict(db.execute(f'''SELECT partitions,count(*) FROM
            (SELECT count(DISTINCT split) partitions FROM target
             WHERE host!='' AND proc!='' GROUP BY {keys}) GROUP BY partitions''').fetchall())
    result['rows_missing_identity_or_time'] = db.execute("SELECT count(*) FROM target WHERE host='' OR proc='' OR t IS NULL").fetchone()[0]
    result['interpretation'] = 'Counts of entities appearing in 1/2/3 partitions; overlap is allowed in this random-event baseline, not evidence of unseen-process generalization.'
    return result


def check_space(work, max_bytes, reserve):
    size = sum(p.stat().st_size for p in work.glob('graph.sqlite*'))
    if size > max_bytes or shutil.disk_usage(work).free < reserve:
        raise RuntimeError('graph storage quota/free-space reserve reached; committed source progress is resumable')


def build(args):
    baseline = Path(args.baseline).resolve(); split_path = Path(args.split).resolve()
    base = json.loads(baseline.read_text()); split = json.loads(split_path.read_text())
    if sha(split_path) != base['split_sha256']:
        raise ValueError('baseline and split identity mismatch')
    entries = {e['source']['path']: e for e in split['entries']}
    sources = {s['source']['path']: dict(source_id=s['source_id'], source=s['source']) for s in base['sources']}
    if args.context_index:
        for e in json.loads(Path(args.context_index).read_text())['entries']:
            s = e['source']; sources.setdefault(s['path'], dict(source=s, source_id=digest(s)))
    sources = sorted(sources.values(), key=lambda s: s['source']['path'])
    if args.max_sources:
        sources = sources[:args.max_sources]
    for s in sources:
        if source_identity(s['source']['path']) != s['source']:
            raise ValueError(f"source identity changed: {s['source']['path']}")
    protected = [baseline.parent, split_path.parent, *(Path(s['source']['path']).parent for s in sources)]
    output = safe(args.output, protected)
    work = safe(output.with_name('.' + output.name + '.work'), protected)
    config = dict(schema=1, environment=dict(python=sys.version, sqlite=sqlite3.sqlite_version), baseline_sha256=sha(baseline), split_sha256=sha(split_path),
                  implementation=implementation(), sources=sources, max_lines=args.max_lines,
                  pilot=bool(args.max_lines or args.max_sources),
                  policy='label-blind first-observed facts; per-event hostname+UUID; CREATE-only ancestry; strict-past query')
    if args.dry_run:
        print(json.dumps(dict(config, output=str(output), estimated_bytes='not inferred from a prefix'), indent=2)); return
    for p in [output, work, output.with_suffix('.lock')]:safe(p, protected)
    output.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(output.with_suffix('.lock'), nonblocking=True):
        if output.exists():
            done = json.loads((output/'manifest.json').read_text())
            if done['config'] != config or sha(output/'graph.sqlite') != done['database_sha256']:
                raise ValueError('existing graph differs; preserving it')
            print('Already complete:', output); return
        work.mkdir(exist_ok=True)
        if (work/'config.json').exists():
            if json.loads((work/'config.json').read_text()) != config:
                raise ValueError('checkpoint configuration/code/source mismatch; use a new output')
        else:
            atomic_json(work/'config.json', config)
        db = connect(safe(work/'graph.sqlite', protected)); start = time.monotonic()
        try:
            for item in sources:
                sid = item['source_id']; source = Path(item['source']['path']); entry = entries.get(str(source))
                previous = db.execute('SELECT line,prefix_sha,complete FROM progress WHERE source=?', (sid,)).fetchone()
                skip = previous[0] if previous else 0
                mask_path = split_path.parent/entry['artifact'] if entry else None
                if mask_path and sha(mask_path) != entry['sha256']:
                    raise ValueError('split mask checksum mismatch')
                if previous and previous[2]:
                    continue
                opener = gzip.open if source.suffix == '.gz' else open
                mask = gzip.open(mask_path, 'rb') if mask_path else None
                h = hashlib.sha256(); line_no = 0; truncated = False
                try:
                    with opener(source, 'rb') as stream:
                        for line_no, raw in enumerate(stream, 1):
                            if args.max_lines and line_no > args.max_lines:
                                line_no -= 1; truncated = True; break
                            h.update(raw); assigned = mask.read(1) if mask else b'\x00'
                            if len(assigned) != 1 or assigned[0] not in (0, 1, 2, 3):
                                raise ValueError('invalid/short mask')
                            if line_no <= skip:
                                if line_no == skip and h.hexdigest() != previous[1]:
                                    raise ValueError('source prefix changed since checkpoint')
                                continue
                            record = json.loads(raw)
                            observe(db, record, sid, line_no)
                            if assigned[0]:
                                host, proc, t = identity(record)
                                db.execute('INSERT INTO target VALUES (?,?,?,?,?,?)', (sid, line_no, host, proc, t, assigned[0]))
                            if line_no % args.checkpoint_rows == 0:
                                db.execute('INSERT OR REPLACE INTO progress VALUES (?,?,?,0)', (sid, line_no, h.hexdigest()))
                                db.commit(); check_space(work, args.max_db_gib * 2**30, args.reserve_gib * 2**30)
                                print(f'{sid[:10]} lines={line_no:,}', flush=True)
                    if line_no < skip:
                        raise ValueError('source shorter than checkpoint')
                    if not truncated and mask and mask.read(1):
                        raise ValueError('source shorter than mask')
                    if source_identity(source) != item['source']:
                        raise ValueError('source changed while reading')
                    db.execute('INSERT OR REPLACE INTO progress VALUES (?,?,?,1)', (sid, line_no, h.hexdigest()))
                    db.commit(); check_space(work, args.max_db_gib * 2**30, args.reserve_gib * 2**30)
                    print(f'Completed {source.name}: {line_no:,} rows (pilot={truncated})', flush=True)
                finally:
                    if mask:mask.close()
            counts = {table: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                      for table in ['parent', 'fact', 'binding', 'flow', 'target']}
            audit = ontology_audit(db)
            source_hashes = {r[0]: dict(lines=r[1], uncompressed_prefix_sha256=r[2])
                             for r in db.execute('SELECT source,line,prefix_sha FROM progress')}
            db.commit()
        finally:
            db.close()
        atomic_json(work/'feature_schema.json', dict(features=FEATURES, count=len(FEATURES), fitted=False,
                    note='Fixed finite engineering schema; no corpus- or label-fitted vocabulary.'))
        atomic_json(work/'ontology_audit.json', audit)
        atomic_json(work/'manifest.json', dict(config=config, complete=True, database_sha256=sha(work/'graph.sqlite'),
                    counts=counts, sources=source_hashes, elapsed_seconds=time.monotonic()-start,
                    database_bytes=(work/'graph.sqlite').stat().st_size,
                    scope='All rows of listed sources, including noncandidate rows and FLOW; no Bro/eCAR-Bro or labels used. Pilot limits apply if configured.',
                    limitations='Context outside listed sources is unavailable; process/host overlap audit does not make the split inductive. First-seen host bindings are conservative; no unobserved lateral movement inferred.'))
        os.rename(work, output)
        print(json.dumps(dict(output=str(output), counts=counts), indent=2))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, default=BASELINE/'model_input/manifest.json')
    p.add_argument('--split', type=Path, default=BASELINE/'split/manifest.json')
    p.add_argument('--context-index', type=Path, help='Optional Host label-index manifest to expand label-blind context beyond baseline sources')
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT/'graph')
    p.add_argument('--max-sources', type=int, default=0)
    p.add_argument('--max-lines', type=int, default=0, help='Per-source prefix limit: makes a pilot, not production context')
    p.add_argument('--checkpoint-rows', type=int, default=100000)
    p.add_argument('--max-db-gib', type=int, default=20)
    p.add_argument('--reserve-gib', type=int, default=5)
    p.add_argument('--dry-run', action='store_true')
    return p


if __name__ == '__main__':
    a = parser().parse_args()
    if min(a.max_sources, a.max_lines, a.reserve_gib) < 0 or min(a.checkpoint_rows, a.max_db_gib) < 1:
        raise ValueError('invalid limits')
    build(a)
