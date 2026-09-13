"""Streaming corrected Host pipeline with a persisted stratified event split.

Index label streams: 0 excluded, 1 benign, 2 malicious (one byte/source line).
Split streams: 0 excluded, 1 train, 2 validation, 3 test. gzip keeps these compact.
Source identities and artifact SHA256 bind every stage; no telemetry is executed.
"""
from __future__ import annotations
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile

import numpy as np
from ecar_tokenizer import GROUPS, HOST_OBJECT_FIELDS, TOKENIZER_POLICY, flatten_tokens, token_layers, tokenize_record
from pipeline_contract import PROJECT_ROOT, code_hashes, load_vocabulary, sync_directory, validate_output_path

BASE = PROJECT_ROOT / 'code/output/host_ml'
SPLITS = ('train', 'val', 'test')
BLOCK = 1024 * 1024


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def file_hash(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def identity(path):
    path = Path(path).resolve()
    stat = path.stat()
    return dict(path=str(path), size=stat.st_size, mtime_ns=stat.st_mtime_ns)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def implementation():
    return {**code_hashes(('stratified_pipeline.py', 'build_matrix.py', 'build_vocab.py', 'pipeline_contract.py')),
            **code_hashes(), 'numpy': np.__version__, 'python': sys.version.split()[0]}


def atomic_json(path, value):
    path = validate_output_path(Path(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = validate_output_path(path.with_name(f'.{path.name}.{os.getpid()}.tmp'))
    try:
        with temporary.open('w') as handle:
            json.dump(value, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def durable(path):
    with Path(path).open('rb') as handle:
        os.fsync(handle.fileno())


def work_directory(output, config):
    output = validate_output_path(Path(output))
    if output.exists():
        raise ValueError(f'output already exists, preserving it: {output}')
    work = validate_output_path(output.parent / f'.{output.name}.checkpoints' / digest(config))
    work.mkdir(parents=True, exist_ok=True)
    return output, work


def publish_directory(work, output, manifest):
    atomic_json(work / 'manifest.json', manifest)
    if output.exists():
        raise ValueError('output was created concurrently')
    os.rename(work, output)
    sync_directory(output.parent)


def checked_sources(entries):
    for entry in entries:
        if identity(entry['source']['path']) != entry['source']:
            raise ValueError(f'source identity changed: {entry["source"]["path"]}')


def checked_manifest(path, expected_hash, manifest):
    if file_hash(path) != expected_hash:
        raise ValueError('input manifest changed during processing')
    checked_sources(manifest['entries'])
    for entry in manifest['entries']:
        if file_hash(relative_artifact(Path(path).resolve().parent, entry['artifact'])) != entry['sha256']:
            raise ValueError('input assignment artifact changed during processing')


def relative_artifact(directory, name):
    if Path(name).name != name:
        raise ValueError('unsafe artifact filename in manifest')
    return directory / name


def load_manifest(path, kind):
    path = Path(path).resolve()
    value = json.loads(path.read_text())
    if value.get('kind') != kind or value.get('schema') != 1:
        raise ValueError(f'expected {kind} manifest')
    if value.get('tokenizer_sha256') != code_hashes():
        raise ValueError('manifest tokenizer mismatch; rebuild index and split')
    if value.get('implementation') != implementation():
        raise ValueError('manifest preprocessing implementation mismatch; rebuild index and split')
    entries = value['entries']
    if not entries or len({e['source']['path'] for e in entries}) != len(entries):
        raise ValueError('empty or overlapping manifest sources')
    checked_sources(entries)
    for entry in entries:
        if file_hash(relative_artifact(path.parent, entry['artifact'])) != entry['sha256']:
            raise ValueError('manifest artifact checksum mismatch')
    return value, file_hash(path)


def bounded_map(function, tasks, workers):
    # At most workers results (including potentially large TF/DF counters) pending.
    with ProcessPoolExecutor(max_workers=workers) as pool:
        iterator = iter(tasks)
        pending = []
        for _ in range(workers):
            item = next(iterator, None)
            if item is not None:
                pending.append(pool.submit(function, *item))
        while pending:
            result = pending.pop(0).result()
            yield result
            item = next(iterator, None)
            if item is not None:
                pending.append(pool.submit(function, *item))


def label_of(record, benign, host):
    if not isinstance(record, dict):
        raise ValueError('expected an event object')
    actual_host = record.get('hostname')
    # Corrected files can contain events emitted by a different sysclient.
    # The event hostname is authoritative; the filename identifies the container.
    if not isinstance(actual_host, str) or not re.fullmatch(r'sysclient\d+', actual_host.split('.')[0], re.I):
        raise ValueError('missing or invalid event hostname')
    obj = record.get('object')
    if not isinstance(obj, str) or obj.strip().casefold() not in HOST_OBJECT_FIELDS:
        return 0
    label = record.get('label')
    if benign and label is None:
        label = 0
    if type(label) is not int or label not in (0, 1) or (benign and label != 0):
        raise ValueError('Host event requires corrected integer label 0/1; benign source must be 0')
    return label + 1


def index_file(entry, work):
    from build_matrix import _parse_file_meta
    source = entry['source']
    path = Path(source['path'])
    day, host = _parse_file_meta(path)
    key = digest(entry)
    cache = work / f'{key}.json'
    artifact = work / f'{key}.labels.gz'
    if cache.exists():
        try:
            saved = json.loads(cache.read_text())
            if saved['source'] == source and file_hash(artifact) == saved['sha256']:
                return saved
        except (OSError, ValueError, KeyError):
            pass
    temporary = validate_output_path(artifact.with_suffix('.tmp'))
    counts = Counter()
    with gzip.open(path, 'rt', encoding='utf-8') as src, gzip.open(temporary, 'wb') as target:
        buffer = bytearray()
        for line in src:
            counts['lines'] += 1
            try:
                record = json.loads(line) if line.strip() else None
                code = label_of(record, entry['benign'], host) if line.strip() else 0
            except (ValueError, TypeError) as exc:
                raise ValueError(f'{path}:{counts["lines"]}: {exc}') from exc
            if record is not None and record['hostname'].split('.')[0].casefold() != host:
                counts['hostname_differs_from_file'] += 1
            counts[str(code)] += 1
            buffer.append(code)
            if len(buffer) >= BLOCK:
                target.write(buffer)
                buffer.clear()
        target.write(buffer)
    if identity(path) != source:
        raise ValueError(f'source changed during index scan: {path}')
    durable(temporary)
    os.replace(temporary, artifact)
    result = dict(entry, day=day, host=host, counts=dict(counts), artifact=artifact.name, sha256=file_hash(artifact))
    atomic_json(cache, result)
    return result


def index_main(argv=None):
    from build_matrix import _parse_file_meta
    parser = argparse.ArgumentParser(description='Full Host label index, streaming all source lines; resumes per file.')
    parser.add_argument('--benign-root', type=Path, default=PROJECT_ROOT/'host-begnin')
    parser.add_argument('--malicious-root', type=Path, default=PROJECT_ROOT/'host-malicious')
    parser.add_argument('--output-dir', type=Path, default=BASE/'index')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    if args.workers < 1:
        raise ValueError('workers must be positive')
    roots = [args.benign_root.resolve(), args.malicious_root.resolve()]
    validate_output_path(args.output_dir, roots)
    entries = []
    for root, benign in zip(roots, (True, False)):
        if any(root.is_relative_to((PROJECT_ROOT/name).resolve()) for name in ('bro','ecar-bro')):
            raise ValueError('network inputs are excluded from Host fitting')
        if not root.is_dir():
            raise ValueError(f'missing input root: {root}')
        for path in sorted(root.rglob('*.json.gz')):
            path = path.resolve()
            if not path.is_relative_to(root):
                raise ValueError('source symlink escapes input root')
            day, host = _parse_file_meta(path)
            allowed = {f'2019-09-{d:02}' for d in (range(16,23) if benign else range(23,26))}
            if day not in allowed:
                raise ValueError(f'unexpected source partition: {path}')
            entries.append(dict(source=identity(path), benign=benign))
    if not entries or len({e['source']['path'] for e in entries}) != len(entries):
        raise ValueError('empty or overlapping source roots')
    if args.dry_run:
        print(json.dumps(dict(files=len(entries), compressed_bytes=sum(e['source']['size'] for e in entries),
                              roots=[str(p) for p in roots]), indent=2))
        return 0
    config = dict(implementation=implementation(), sources=entries)
    output, work = work_directory(args.output_dir, config)
    results = []
    for i, result in enumerate(bounded_map(index_file, [(e, work) for e in entries], args.workers), 1):
        results.append(result)
        print(f'[{i}/{len(entries)}] indexed {result["day"]}/{result["host"]}: {result["counts"]}', flush=True)
    checked_sources(results)
    population = Counter()
    for result in results:
        population.update(result['counts'])
    publish_directory(work, output, dict(schema=1, kind='host_label_index', created_utc=stamp(),
        tokenizer_sha256=code_hashes(), implementation=config['implementation'], entries=results,
        counts=dict(population), label_policy='corrected source labels; missing benign label=0; FLOW excluded',
        row_identity='source path + line; duplicate event IDs across source files are not deduplicated',
        source_identity_policy='path/size/mtime_ns; source content hashes not computed'))
    print(f'Published {output}/manifest.json', flush=True)
    return 0


def quota(total):
    # Largest remainder, stable ties in train/val/test order.
    base = [total * w // 100 for w in (75,10,15)]
    order = sorted(range(3), key=lambda i: (-(total * (75,10,15)[i] % 100), i))
    for i in order[:total-sum(base)]:
        base[i] += 1
    return base


def file_quotas(entries):
    """Allocate exact global class totals; proportional per-file strata, stable rounding."""
    allocations = [{str(c): [0,0,0] for c in (1,2)} for _ in entries]
    for c in (1,2):
        ns = [e['counts'].get(str(c),0) for e in entries]
        goals = quota(sum(ns))
        remaining = ns.copy()
        for split in range(2):
            total = sum(remaining)
            if not total:
                continue
            vals = [n*goals[split]//total for n in remaining]
            order = sorted(range(len(ns)), key=lambda i: (-(remaining[i]*goals[split]%total), i))
            for i in order[:goals[split]-sum(vals)]:
                vals[i] += 1
            for i, n in enumerate(vals):
                allocations[i][str(c)][split] = n
                remaining[i] -= n
        for i, n in enumerate(remaining):
            allocations[i][str(c)][2] = n
    return allocations


def split_file(entry, allocation, index_dir, work, seed):
    key = digest(dict(source=entry['source'], seed=seed, allocation=allocation))
    artifact, cache = work/f'{key}.split.gz', work/f'{key}.json'
    if cache.exists():
        try:
            saved = json.loads(cache.read_text())
            if file_hash(artifact) == saved['sha256']:
                return saved
        except (OSError, ValueError, KeyError):
            pass
    rng = np.random.default_rng(int(digest(dict(seed=seed, source=entry['source']))[:16],16))
    left = {int(c): np.asarray(n,dtype=np.int64) for c,n in allocation.items()}
    temporary = validate_output_path(artifact.with_suffix('.tmp'))
    with gzip.open(relative_artifact(index_dir, entry['artifact']),'rb') as src, gzip.open(temporary,'wb') as target:
        while data := src.read(BLOCK):
            labels = np.frombuffer(data,dtype=np.uint8)
            if np.any(labels>2):
                raise ValueError('invalid index label code')
            assigned = np.zeros(len(labels),dtype=np.uint8)
            for c in (1,2):
                positions = np.flatnonzero(labels == c)
                n = len(positions)
                if n:
                    chosen = rng.multivariate_hypergeometric(left[c], n, method='marginals')
                    values = np.repeat(np.array([1,2,3],dtype=np.uint8), chosen)
                    rng.shuffle(values)
                    assigned[positions] = values
                    left[c] -= chosen
            target.write(assigned.tobytes())
    if any(np.any(v) for v in left.values()):
        raise ValueError('index counts disagree with label stream')
    durable(temporary)
    os.replace(temporary,artifact)
    result = dict(entry, artifact=artifact.name, sha256=file_hash(artifact), allocation=allocation)
    atomic_json(cache,result)
    return result


def split_main(argv=None):
    parser = argparse.ArgumentParser(description='Persist a shared stratified random 75/10/15 split.')
    parser.add_argument('--index',type=Path,default=BASE/'index/manifest.json')
    parser.add_argument('--output-dir',type=Path,default=BASE/'split')
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--workers',type=int,default=4)
    args = parser.parse_args(argv)
    if args.workers < 1 or args.seed < 0:
        raise ValueError('positive workers and nonnegative seed required')
    validate_output_path(args.output_dir, [args.index.resolve().parent])
    index, index_sha = load_manifest(args.index,'host_label_index')
    allocations = file_quotas(index['entries'])
    for c in ('1','2'):
        if min(sum(a[c][s] for a in allocations) for s in range(3)) < 1:
            raise ValueError('not enough examples of each class for three splits')
    config = dict(index_sha256=index_sha, seed=args.seed, implementation=implementation())
    output, work = work_directory(args.output_dir, config)
    tasks = [(e,a,args.index.resolve().parent,work,args.seed) for e,a in zip(index['entries'],allocations)]
    results = []
    for i,result in enumerate(bounded_map(split_file,tasks,args.workers),1):
        results.append(result)
        print(f'[{i}/{len(tasks)}] split {result["day"]}/{result["host"]}',flush=True)
    checked_manifest(args.index,index_sha,index)
    counts = {s:{f'label_{c-1}':sum(a[str(c)][i] for a in allocations) for c in (1,2)} for i,s in enumerate(SPLITS)}
    publish_directory(work,output,dict(schema=1,kind='host_random_split',created_utc=stamp(),**config,
        tokenizer_sha256=code_hashes(),entries=results,counts=counts,ratios=[.75,.10,.15],
        split_policy='random events within source-file/label strata; exact global class quotas with integer rounding',
        sampling='all indexed Host events; no undersampling', limitations='not process/host/campaign/temporal isolation; event IDs not deduplicated'))
    print(json.dumps(dict(output=str(output),counts=counts),indent=2))
    return 0


def split_rows(entry, split_dir):
    from build_matrix import _parse_file_meta
    path = Path(entry['source']['path'])
    _, host = _parse_file_meta(path)
    stats = Counter()
    with gzip.open(path,'rt',encoding='utf-8') as src, gzip.open(relative_artifact(split_dir,entry['artifact']),'rb') as mask:
        number = 0
        while codes := mask.read(BLOCK):
            for code in codes:
                number += 1
                line = src.readline()
                if not line:
                    raise ValueError('source shorter than split mask')
                if code not in (0,1,2,3):
                    raise ValueError('invalid split code')
                if not code:
                    continue
                record = json.loads(line)
                label = label_of(record,entry['benign'],host)-1
                if label not in (0,1):
                    raise ValueError('split mask selects excluded event')
                stats[(label,code-1)] += 1
                record['label'] = label
                yield code, number, record
        if src.read(1) or number != entry['counts'].get('lines', 0):
            raise ValueError('split/source line count mismatch')
    for c in (1,2):
        if [stats[(c-1,s)] for s in range(3)] != entry['allocation'][str(c)]:
            raise ValueError('split class counts mismatch')
    checked_sources([entry])


def vocab_file(entry, split_dir, work):
    key = digest(entry)
    cache = work/f'{key}.json.gz'
    receipt = work/f'{key}.json'
    if receipt.exists():
        try:
            if file_hash(cache) == json.loads(receipt.read_text())['sha256']:
                with gzip.open(cache,'rt') as handle:
                    return json.load(handle)
        except (OSError, ValueError, KeyError):
            pass
    tf,df = {g:Counter() for g in GROUPS},{g:Counter() for g in GROUPS}
    counts = Counter()
    for split, _,record in split_rows(entry,split_dir):
        if split != 1:
            continue
        grouped,audit = tokenize_record(record)
        if not audit['eligible']:
            raise ValueError('tokenizer eligibility changed')
        counts[f'label_{record["label"]}'] += 1
        for g,tokens in grouped.items():
            tf[g].update(tokens)
            df[g].update(set(tokens))
    result = dict(tf=tf,df=df,counts=dict(counts))
    temporary = validate_output_path(cache.with_suffix('.tmp'))
    with gzip.open(temporary,'wt') as handle:
        json.dump(result,handle)
    durable(temporary)
    os.replace(temporary,cache)
    atomic_json(receipt,dict(sha256=file_hash(cache)))
    return result


def vocab_main(args):
    from build_vocab import _publish, select_vocabulary
    if args.workers < 1 or args.min_frequency < 1:
        raise ValueError('positive workers and min frequency required')
    manifest, split_sha = load_manifest(args.split,'host_random_split')
    output = validate_output_path(args.output)
    metadata_output = validate_output_path(args.metadata_output)
    if output == metadata_output:
        raise ValueError('vocab and metadata outputs must differ')
    if any(p.is_relative_to(args.split.resolve().parent) for p in (output,metadata_output)):
        raise ValueError('vocabulary outputs must be outside the immutable split directory')
    config = dict(split_sha256=split_sha, implementation=implementation())
    work = validate_output_path(args.checkpoint_dir or output.parent/f'.{output.name}.checkpoints') / digest(config)
    validate_output_path(work, [args.split.resolve().parent])
    if args.dry_run:
        print(json.dumps(dict(split_sha256=split_sha,train=manifest['counts']['train'],files=len(manifest['entries'])),indent=2))
        return 0
    work.mkdir(parents=True,exist_ok=True)
    tf,df = {g:Counter() for g in GROUPS},{g:Counter() for g in GROUPS}
    counts=Counter()
    for i,result in enumerate(bounded_map(vocab_file,[(e,args.split.resolve().parent,work) for e in manifest['entries']],args.workers),1):
        for g in GROUPS:
            tf[g].update(result['tf'][g]); df[g].update(result['df'][g])
        counts.update(result['counts'])
        print(f'[{i}/{len(manifest["entries"])}] TRAIN vocabulary: {dict(counts)}',flush=True)
    if dict(counts) != manifest['counts']['train']:
        raise ValueError('fit counts differ from TRAIN split')
    checked_manifest(args.split,split_sha,manifest)
    vocabulary,groups = select_vocabulary(df,tf,args.min_frequency)
    if not vocabulary:
        raise ValueError('empty vocabulary')
    metadata = dict(schema_version=6,created_utc=stamp(),source_sha256=code_hashes(),implementation=config['implementation'],
        tokenizer_policy=TOKENIZER_POLICY,fit_purpose='supervised_training',fit_classes=[0,1],
        split_sha256=split_sha,split_file=str(args.split.resolve()),split_seed=manifest['seed'],
        split_counts=manifest['counts'],fit_counts=dict(counts),vocab_size=len(vocabulary),
        scan=dict(read_to_eof=True,days=dict(Counter(e['day'] for e in manifest['entries'])),sources=[e['source'] for e in manifest['entries']]),
        frequency_policy=dict(min_term_frequency=args.min_frequency,document_unit='TRAIN Host event',max_tokens=None),
        checkpoint=dict(files=len(manifest['entries']),validation='split SHA256, implementation, source identity, counter SHA256'),
        token_statistics={t:dict(group=groups[t],layers=token_layers(t),term_frequency=tf[groups[t]][t],document_frequency=df[groups[t]][t]) for t in vocabulary})
    _publish(vocabulary,metadata,output,metadata_output)
    shutil.rmtree(work)
    print(f'wrote {len(vocabulary):,} tokens to {output}',flush=True)
    return 0


def matrix_file(entry,split_dir,vocab,work,chunk_rows):
    from build_matrix import _write_chunk, _valid_manifest
    directory = validate_output_path(work/digest(entry))
    directory.mkdir(parents=True,exist_ok=True)
    cache=directory/'manifest.json'
    if cache.exists():
        try:
            saved=json.loads(cache.read_text())
            if all(_valid_manifest(m,entry['source'],s,directory/s) for s,m in saved.items()) and set(saved)==set(SPLITS):
                return [{**saved[s],'directory':str(directory/s)} for s in SPLITS]
        except (OSError,ValueError,KeyError,TypeError):
            pass
    rows={s:[] for s in SPLITS}; chunks={s:[] for s in SPLITS}; stats={s:Counter() for s in SPLITS}
    for s in SPLITS:
        (directory/s).mkdir(exist_ok=True)
    for code,number,record in split_rows(entry,split_dir):
        s=SPLITS[code-1]
        grouped,audit=tokenize_record(record)
        if not audit['eligible']:
            raise ValueError('matrix eligibility mismatch')
        counts=Counter()
        for token in flatten_tokens(grouped):
            for layer in token_layers(token):
                stats[s][f'tokens_{layer}']+=1
                if token not in vocab:
                    stats[s][f'oov_{layer}']+=1
            if token in vocab:
                counts[vocab[token]]+=1
        label=record['label']; stats[s]['eligible_records']+=1; stats[s][f'label_{label}']+=1
        if not counts:
            stats[s]['no_vocab_hits']+=1
        sidecar={key:record.get(key) for key in ('id','hostname','timestamp','actorID','objectID','pid','object','action')}
        sidecar.update(event_id=record.get('id'),label=label,source_file=entry['source']['path'],source_line=number,day=entry['day'],
                       host=record['hostname'].split('.')[0].casefold(),file_host=entry['host'])
        rows[s].append((label,counts,sidecar))
        if len(rows[s])>=chunk_rows:
            chunks[s].append(_write_chunk(directory/s,len(chunks[s]),rows[s],len(vocab)));rows[s].clear()
    result={}
    for s in SPLITS:
        if rows[s]:
            chunks[s].append(_write_chunk(directory/s,len(chunks[s]),rows[s],len(vocab)))
        result[s]=dict(identity=entry['source'],split=s,chunks=chunks[s],stats=dict(stats[s]))
    atomic_json(cache,result)
    return [{**result[s],'directory':str(directory/s)} for s in SPLITS]


def matrix_main(args):
    from build_matrix import _assemble
    if args.workers<1 or args.chunk_rows<1:
        raise ValueError('positive workers and chunk rows required')
    validate_output_path(args.output_dir, [args.split.resolve().parent])
    manifest,split_sha=load_manifest(args.split,'host_random_split')
    vocab,meta=load_vocabulary(args.vocab,args.vocab_metadata or args.vocab.with_name('vocab_metadata.json'),split_sha256=split_sha)
    config=dict(split_sha256=split_sha,vocabulary_sha256=meta['vocabulary_sha256'],implementation=implementation(),chunk_rows=args.chunk_rows,representation=args.representation)
    output,work=work_directory(args.output_dir,config)
    parts=[]
    for i,result in enumerate(bounded_map(matrix_file,[(e,args.split.resolve().parent,vocab,work,args.chunk_rows) for e in manifest['entries']],args.workers),1):
        parts.extend(result)
        print(f'[{i}/{len(manifest["entries"])}] transformed all splits',flush=True)
    stage=Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-',dir=output.parent))
    try:
        splits={s:_assemble(stage,s,parts,len(vocab),args.representation) for s in SPLITS}
        for s,info in splits.items():
            if info is None or any(info[k]!=v for k,v in manifest['counts'][s].items()):
                raise ValueError('matrix class counts disagree with shared split')
        checked_manifest(args.split,split_sha,manifest)
        stats=Counter()
        for part in parts:stats.update(part['stats'])
        metadata=dict(created_utc=stamp(),**config,split_seed=manifest['seed'],split_policy=manifest['split_policy'],vocab_size=len(vocab),
                      splits=splits,aggregate_stats=dict(stats),artifact_sha256={p.name:file_hash(p) for p in stage.iterdir()},
                      scan=dict(sources=[e['source'] for e in manifest['entries']],read_to_eof=True))
        atomic_json(stage/'split_metadata.json',metadata)
        for p in stage.iterdir():durable(p)
        sync_directory(stage)
        if output.exists():raise ValueError('output created concurrently')
        os.rename(stage,output);sync_directory(output.parent)
    finally:
        if stage.exists():shutil.rmtree(stage)
    shutil.rmtree(work)
    print(json.dumps(dict(output=str(output),splits=splits),indent=2))
    return 0
