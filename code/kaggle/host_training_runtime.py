"""Shared notebook runtime. Embedded by refresh_host_notebooks.py for standalone use.

Only downstream TRAIN samples and model/evaluation state are written. The
published full-data readers, source shards, vocabulary and split stay unchanged.
"""
from pathlib import Path
import contextlib
import hashlib
import inspect
import json
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from collections import deque

import numpy as np
import scipy
from scipy import sparse
from scipy.stats import hypergeom
import host_shards as _host_shards
from host_shards import HostShardDataset, decode_shard


def sha256(path):
    """Streaming SHA256 compatible with Python 3.10 and existing packages."""
    result = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


if not hasattr(hashlib, 'file_digest'):
    def _file_digest(fileobj, digest, /, **kwargs):
        h = hashlib.new(digest, **kwargs) if isinstance(digest, str) else digest(**kwargs)
        for block in iter(lambda: fileobj.read(1024 * 1024), b''):
            h.update(block)
        return h
    hashlib.file_digest = _file_digest
    # The uploaded reader also hashes assets and every decoded shard internally.
    # Patch its module binding in memory, never the read-only input file.
    _host_shards.sha256 = sha256

if 'RUNTIME_SHA256' not in globals():
    RUNTIME_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
READER_SHA256 = sha256(inspect.getfile(decode_shard))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def output_path(path, protected=()):
    path = Path(path).resolve()
    # Portable guard also works when the code lives in an isolated worktree.
    if any(name in path.parts for name in ('host-begnin', 'host-malicious', 'bro', 'ecar-bro')):
        raise ValueError(f'output is inside a read-only dataset: {path}')
    for root in protected:
        if path.is_relative_to(Path(root).resolve()):
            raise ValueError(f'output overlaps input: {path}')
    return path


def atomic_write(path, writer, protected=()):
    path = output_path(path, protected)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.stem + '-', suffix=path.suffix, dir=path.parent)
    os.close(fd)
    temporary = output_path(name, protected)
    try:
        writer(temporary)
        with temporary.open('rb') as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path, value, protected=()):
    atomic_write(path, lambda p: p.write_text(json.dumps(value, indent=2)), protected)


def cpu_budget(override=None):
    from joblib import cpu_count
    available = max(1, cpu_count())  # cgroup quotas and process affinity, not host CPU count
    return available if override is None else max(1, min(available, int(override)))


def configure_threads(threads):
    for key in ('OMP_NUM_THREADS', 'NUMEXPR_NUM_THREADS'):
        os.environ[key] = str(threads)
    for key in ('OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'BLIS_NUM_THREADS'):
        os.environ[key] = '1'
    from threadpoolctl import threadpool_limits
    return threadpool_limits(limits=1, user_api='blas')


def available_bytes():
    try:
        import psutil
        available = psutil.virtual_memory().available
    except ImportError:
        fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(fields['MemAvailable'].split()[0])*1024
    for limit_name, used_name in (
        ('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current'),
        ('/sys/fs/cgroup/memory/memory.limit_in_bytes', '/sys/fs/cgroup/memory/memory.usage_in_bytes'),
    ):
        try:
            available = min(available, max(0, int(Path(limit_name).read_text()) - int(Path(used_name).read_text())))
        except (OSError, ValueError):
            pass
    return available


class TrainingDataset(HostShardDataset):
    """Cache resolved parent directories without changing published reader code."""
    def __init__(self, *args, **kwargs):
        self._parents = {}
        super().__init__(*args, **kwargs)

    def path_for(self, part):
        if part['volume'] not in self.roots:
            raise ValueError('unknown volume')
        relative = Path(part['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('shard path escapes volume')
        root = self.roots[part['volume']]
        key = (part['volume'], str(relative.parent))
        if key not in self._parents:
            parent = (root / relative.parent).resolve()
            if not parent.is_relative_to(root):
                raise ValueError('shard parent escapes volume')
            self._parents[key] = parent
        path = self._parents[key] / relative.name
        if path.is_symlink():
            raise ValueError('symlink shard is not supported by the training runtime')
        return path

    @property
    def protected(self):
        return [self.manifest_path.parent, *self.roots.values()]

    def identity(self):
        # Content identities travel with the input package. File facts additionally
        # invalidate interrupted runs when files are replaced without a new manifest.
        facts = []
        for part in self.meta['shards']:
            stat = self.path_for(part).stat()
            if stat.st_size != part['bytes']:
                raise ValueError('source shard size changed')
            facts.append((part['volume'], part['path'], stat.st_size, stat.st_mtime_ns))
        return dict(manifest_sha256=sha256(self.manifest_path), source_facts_sha256=digest(facts),
                    reader_sha256=READER_SHA256,
                    split_sha256=self.meta['split_sha256'], vocabulary_sha256=self.meta['vocabulary_sha256'])


def ordered_prefetch(items, function, workers=1):
    """Decode at most 2*workers ahead. Preserve order for deterministic sampling."""
    items = iter(items)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        pending = deque()
        for _ in range(max(1, workers) * 2):
            item = next(items, None)
            if item is not None:
                pending.append((item, pool.submit(function, item)))
        while pending:
            item, future = pending.popleft()
            result = future.result()
            following = next(items, None)
            if following is not None:
                pending.append((following, pool.submit(function, following)))
            yield item, result


def sample_plan(data, target_rows=None, neg_per_pos=30, seed=1):
    info = data.meta['splits']['train']
    if info['label_1'] < 1 or info['label_0'] < 1:
        raise ValueError('TRAIN requires both classes')
    if target_rows is not None and not info['label_1'] < target_rows <= info['rows']:
        raise ValueError('target_rows must exceed positive count and not exceed TRAIN rows')
    if neg_per_pos <= 0:
        raise ValueError('neg_per_pos must be positive')
    rng = np.random.default_rng(seed)
    remaining = info['label_0']
    needed = None if target_rows is None else target_rows - info['label_1']
    keep_p = min(1.0, neg_per_pos * info['label_1'] / info['label_0'])
    entries = []
    for index, part in enumerate(data.meta['shards']):
        if part['split'] != 'train':
            continue
        n = part['label_0']
        if target_rows is None:
            # Exactly the prior Nguyen RNG stream: one draw per negative in order.
            state = rng.bit_generator.state
            k = int(np.count_nonzero(rng.random(n) < keep_p))
        else:
            # numpy.hypergeometric rejects populations above 1e9. SciPy's inverse
            # CDF handles this corpus size without an O(population) allocation.
            if needed == 0 or n == 0:
                k = 0
            elif remaining == n:
                k = needed
            elif needed == remaining:
                k = n
            else:
                u = max(float(rng.random()), np.nextafter(0.0, 1.0))
                k = int(hypergeom.ppf(u, remaining, needed, n))
            state = None
            needed -= k
            remaining -= n
        entries.append(dict(index=index, negatives=k, rng_state=state))
    rows = sum(e['negatives'] + data.meta['shards'][e['index']]['label_1'] for e in entries)
    if target_rows is not None and (needed != 0 or rows != target_rows):
        raise ValueError('exact sample plan count mismatch')
    return dict(method='exact_stratified_train_sample' if target_rows is not None else 'random_negative_undersampling',
                seed=seed, target_rows=target_rows, neg_per_pos=neg_per_pos, keep_probability=keep_p,
                rows=rows, positives=info['label_1'], negatives=rows-info['label_1'], entries=entries)


def selected_rows(y, entry, plan):
    neg = np.flatnonzero(y == 0)
    if plan['target_rows'] is None:
        rng = np.random.default_rng()
        rng.bit_generator.state = entry['rng_state']
        kept = neg[rng.random(len(neg)) < plan['keep_probability']]
    else:
        rng = np.random.default_rng(np.random.SeedSequence([plan['seed'], entry['index']]))
        kept = neg[rng.choice(len(neg), size=entry['negatives'], replace=False)]
    if len(kept) != entry['negatives']:
        raise ValueError('sample selection differs from plan')
    return np.sort(np.concatenate((np.flatnonzero(y == 1), kept))).astype(np.int32)


def prepare_sample(data, directory, target_rows=None, neg_per_pos=30, seed=1,
                   workers=1, max_nnz=1_800_000_000, checkpoint_every=64):
    directory = output_path(directory, data.protected)
    identity = data.identity()
    config = dict(**identity, runtime_sha256=RUNTIME_SHA256, numpy=np.__version__, scipy=scipy.__version__,
                  target_rows=target_rows, neg_per_pos=neg_per_pos, seed=seed, max_nnz=max_nnz)
    directory.mkdir(parents=True, exist_ok=True)
    # Concurrent models should share a completed sample, not mutate it concurrently.
    import fcntl
    with output_path(directory/'sample.lock', data.protected).open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        plan_path = directory/'plan.json'
        if plan_path.exists():
            saved = json.loads(plan_path.read_text())
            if saved['config'] != config:
                raise ValueError('sample configuration/source/runtime changed; use a new sample directory')
            plan = saved['plan']
        else:
            print('Planning shared TRAIN sample...', flush=True)
            plan = sample_plan(data, target_rows, neg_per_pos, seed)
            atomic_json(plan_path, dict(config=config, plan=plan), data.protected)
        # File timestamps validate local resume but do not change which events
        # were selected when an identical package is relocated to another VM.
        sample_id = digest(dict(config={k:v for k,v in config.items() if k != 'source_facts_sha256'}, plan=plan))
        state_path = directory/'manifest.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else dict(
            sample_id=sample_id, complete=False, config=config, rows=0, nnz=0, positives=0, parts=[])
        if state['sample_id'] != sample_id:
            raise ValueError('sample checkpoint identity mismatch')
        for part in state['parts']:
            path = output_path(directory/part['path'], data.protected)
            if not path.is_relative_to(directory) or sha256(path) != part['sha256']:
                raise ValueError('sample shard checksum mismatch')
        completed = {p['index'] for p in state['parts']}
        todo = [e for e in plan['entries'] if e['index'] not in completed
                and e['negatives'] + data.meta['shards'][e['index']]['label_1'] > 0]

        def load(entry):
            source = data.meta['shards'][entry['index']]
            X, y, _ = decode_shard(data.path_for(source), data.width, source)
            rows = selected_rows(y, entry, plan)
            return X[rows], y[rows], rows

        started = time.monotonic()
        for i, (entry, (X, y, rows)) in enumerate(ordered_prefetch(todo, load, workers), 1):
            if state['nnz'] + X.nnz > max_nnz:
                raise MemoryError('sample exceeds nnz safety limit; choose a smaller common target, never truncate rows')
            path = output_path(directory/f'parts/{entry["index"]:06d}.npz', data.protected)
            atomic_write(path, lambda p: np.savez_compressed(p, indices=X.indices.astype(np.int32),
                         indptr=X.indptr.astype(np.int32), label=y, source_rows=rows), data.protected)
            state['parts'].append(dict(index=entry['index'], path=str(path.relative_to(directory)),
                                       rows=len(y), nnz=X.nnz, positives=int(y.sum()), sha256=sha256(path)))
            state['rows'] += len(y)
            state['nnz'] += X.nnz
            state['positives'] += int(y.sum())
            if i % checkpoint_every == 0:
                atomic_json(state_path, state, data.protected)
                print(f'Sampling {i}/{len(todo)} remaining shards; kept {state["rows"]:,} rows; '
                      f'{time.monotonic()-started:.1f}s', flush=True)
        if state['rows'] != plan['rows'] or state['positives'] != plan['positives']:
            raise ValueError('sample totals differ from the plan')
        state.update(complete=True, method=plan['method'], seed=seed, width=data.width)
        atomic_json(state_path, state, data.protected)
        print(f'Sample ready: {state["rows"]:,} rows, {state["positives"]:,} positives, '
              f'{state["nnz"]:,} nnz; identity={sample_id}', flush=True)
        return state


def materialize_sample(directory, state, max_bytes, memory_fraction=0.55):
    if not state['complete']:
        raise ValueError('sample is incomplete')
    n, nz = state['rows'], state['nnz']
    if max(n, nz, state['width']) >= 2**31:
        raise MemoryError('sample does not fit RF-compatible int32 CSR')
    required = 8*nz + 4*(n+1) + n
    if required > min(max_bytes, available_bytes()*memory_fraction):
        raise MemoryError(f'Sampled CSR needs {required/2**30:.2f} GiB before model/temporary memory')
    values = np.ones(nz, dtype=np.float32)
    indices = np.empty(nz, dtype=np.int32)
    indptr = np.empty(n+1, dtype=np.int32)
    labels = np.empty(n, dtype=np.uint8)
    indptr[0] = 0
    r = z = 0
    for part in state['parts']:
        path = Path(directory)/part['path']
        if sha256(path) != part['sha256']:
            raise ValueError('sample shard checksum mismatch')
        with np.load(path, allow_pickle=False) as chunk:
            nr, nnz = part['rows'], part['nnz']
            indices[z:z+nnz] = chunk['indices']
            indptr[r+1:r+nr+1] = chunk['indptr'][1:] + z
            labels[r:r+nr] = chunk['label']
        r += nr
        z += nnz
    if r != n or z != nz:
        raise ValueError('sample materialization count mismatch')
    return sparse.csr_matrix((values, indices, indptr), shape=(n,state['width']), copy=False), labels


def unique_binary_rows(X, budget_bytes=64*2**20):
    """Exact in-batch deduplication, no hash collisions or changed row weights.

    Group by row length, then compare exact column-index bytes. Fall back to
    unchanged input if temporary buffers exceed budget. Never densify features.
    """
    n = X.shape[0]
    if not n:
        return X, np.empty(0, dtype=np.int64)
    counts = np.diff(X.indptr)
    if counts.max(initial=0) == 0:
        return X[:1], np.zeros(n, dtype=np.int64)
    required = X.nnz*24 + n*64
    if required > budget_bytes:
        return X, None
    if not X.has_canonical_format or not np.all(X.data == 1):
        raise ValueError('deduplication requires canonical binary presence CSR')
    order = np.argsort(counts, kind='stable')
    lengths, starts, sizes = np.unique(counts[order], return_index=True, return_counts=True)
    inverse = np.empty(n, dtype=np.int64)
    first_parts = []
    offset = 0
    for width, start, size in zip(lengths, starts, sizes):
        rows = order[start:start+size]
        if width == 0:
            first, local_inverse = rows[:1], np.zeros(size, dtype=np.int64)
        elif size == 1:
            first, local_inverse = rows, np.zeros(1, dtype=np.int64)
        else:
            positions = X.indptr[rows].astype(np.int64)[:,None] + np.arange(width)
            keys = np.ascontiguousarray(X.indices[positions], dtype=np.int32)
            records = keys.view(np.dtype((np.void, 4*int(width)))).ravel()
            _, local_first, local_inverse = np.unique(records, return_index=True, return_inverse=True)
            first = rows[local_first]
        first_parts.append(first)
        inverse[rows] = local_inverse + offset
        offset += len(first)
    first = np.concatenate(first_parts)
    if len(first) == n:
        return X, None
    return X[first], inverse


class ExactPredictor:
    def __init__(self, predict, enabled=True, budget_bytes=64*2**20):
        self.predict = predict
        self.enabled = enabled
        self.budget_bytes = budget_bytes
        self.rows = self.scored = 0

    def __call__(self, X):
        unique, inverse = unique_binary_rows(X, self.budget_bytes) if self.enabled else (X, None)
        p = np.asarray(self.predict(unique)).reshape(-1)
        if len(p) != unique.shape[0]:
            raise ValueError('prediction length mismatch')
        self.rows += X.shape[0]
        self.scored += unique.shape[0]
        return p if inverse is None else p[inverse]


def evaluate_resumable(data, split, predict, state_path, model_identity, threshold=None,
                       bins=100000, workers=1, checkpoint_every=32, diagnostics=None):
    if split not in ('val', 'test') or bins < 2 or (split == 'test' and threshold is None):
        raise ValueError('test requires a frozen validation threshold')
    if threshold is not None and not 0 <= threshold <= 1:
        raise ValueError('threshold outside [0,1]')
    state_path = output_path(state_path, data.protected)
    config = dict(input=data.identity(), model=model_identity, runtime_sha256=RUNTIME_SHA256,
                  split=split, bins=bins, threshold=threshold,
                  diagnostics=diagnostics.config if diagnostics is not None else None)
    signature = digest(config)
    positive = np.zeros(bins+1, dtype=np.int64)
    negative = np.zeros(bins+1, dtype=np.int64)
    counts = np.zeros(4, dtype=np.int64)  # TP, FP, FN, TN at frozen threshold
    next_part = 0
    if state_path.exists():
        with np.load(state_path, allow_pickle=False) as saved:
            if str(saved['signature']) != signature:
                raise ValueError('evaluation checkpoint model/input/config mismatch; use a new run directory')
            positive, negative, counts = saved['positive'], saved['negative'], saved['counts']
            next_part = int(saved['next_part'])
            if diagnostics is not None:
                diagnostics.restore(json.loads(str(saved['diagnostics'])))
    parts = [p for p in data.meta['shards'] if p['split'] == split]
    started = time.monotonic()
    print(f'{split}: resume shard {next_part}/{len(parts)}; full split {data.meta["splits"][split]["rows"]:,} rows', flush=True)

    def save():
        atomic_write(state_path, lambda p: np.savez_compressed(p, signature=signature, positive=positive,
                     negative=negative, counts=counts, next_part=next_part,
                     diagnostics=json.dumps(diagnostics.state if diagnostics is not None else None)), data.protected)

    def load(part):
        return decode_shard(data.path_for(part), data.width, part)

    for part, (X,y,lines) in ordered_prefetch(parts[next_part:], load, workers):
        p = np.asarray(predict(X)).reshape(-1)
        if len(p) != len(y) or not np.all(np.isfinite(p)) or np.any((p < 0) | (p > 1)):
            raise ValueError('invalid probabilities')
        if diagnostics is not None:
            diagnostics.update(part, X, y, lines, p, threshold)
        bucket = np.minimum((p.astype(np.float64)*bins).astype(np.int64), bins)
        positive += np.bincount(bucket[y == 1], minlength=bins+1)
        negative += np.bincount(bucket[y == 0], minlength=bins+1)
        if threshold is not None:
            predicted = p.astype(np.float64) >= threshold
            counts += (np.sum(predicted & (y == 1)), np.sum(predicted & (y == 0)),
                       np.sum(~predicted & (y == 1)), np.sum(~predicted & (y == 0)))
        next_part += 1
        if next_part % checkpoint_every == 0:
            save()
            print(f'{split}: {next_part}/{len(parts)} shards; '
                  f'{int(positive.sum()+negative.sum()):,} rows; {time.monotonic()-started:.1f}s this session', flush=True)
    save()
    total_p, total_n = int(positive.sum()), int(negative.sum())
    expected = data.meta['splits'][split]
    if total_p != expected['label_1'] or total_n != expected['label_0']:
        raise ValueError('evaluation totals differ from full split')
    if not total_p or not total_n:
        raise ValueError('both classes required for evaluation')
    tps, fps = positive[::-1].cumsum()[::-1], negative[::-1].cumsum()[::-1]
    precisions = tps / np.maximum(tps+fps, 1)
    if threshold is None:
        best = int(np.argmax(2*tps/np.maximum(tps+fps+total_p, 1)))
        threshold = best/bins
        counts = (int(tps[best]), int(fps[best]), total_p-int(tps[best]), total_n-int(fps[best]))
    tp, fp, fn, tn = map(int, counts)
    precision, recall = tp/max(tp+fp, 1), tp/total_p
    return dict(split=split, rows=total_p+total_n, threshold=float(threshold), threshold_source='validation',
                precision=precision, recall=recall, f1=2*tp/max(2*tp+fp+fn, 1), fpr=fp/total_n,
                confusion=dict(tp=tp,fp=fp,fn=fn,tn=tn), ranking_bins=bins,
                pr_auc_binned=float(np.sum(precisions*positive/total_p)),
                roc_auc_binned=float(np.sum(positive.astype(np.float64)*(negative.cumsum()-negative/2))/(total_p*total_n)),
                note='Full split; validation selects a score-grid threshold; test confusion is counted directly; AUC metrics are binned.')


@contextlib.contextmanager
def phase(name):
    started = time.monotonic()
    print(f'BEGIN {name}', flush=True)
    try:
        yield
    finally:
        print(f'END {name}: {time.monotonic()-started:.1f}s', flush=True)


def fit_sample_model(data, sample_dir, sample, output, model_name, threads,
                     max_matrix_bytes, device='cpu', balance_classes=False,
                     rounds=300, rf_trees=500, checkpoint_every=25, predict_threads=None):
    """Resume boosting rounds / RF warm-start trees; publish model before metrics.

    Two alternating model files keep the last published checkpoint intact while
    saving its successor. A complete model skips matrix loading and fitting.
    """
    import importlib
    import pickle
    library_name = {'xgb':'xgboost', 'lgbm':'lightgbm', 'rf':'sklearn'}[model_name]
    library = importlib.import_module(library_name)
    output = output_path(output, data.protected)
    output.mkdir(parents=True, exist_ok=True)
    positive_weight = (sample['rows']-sample['positives'])/sample['positives'] if balance_classes else 1.0
    if model_name == 'lgbm':
        params = dict(objective='binary', metric='None', num_leaves=31, learning_rate=0.05,
                      seed=1, num_threads=threads, verbosity=1, force_col_wise=True,
                      deterministic=True, scale_pos_weight=positive_weight)
        target = rounds
        suffix = '.txt'
    elif model_name == 'xgb':
        params = dict(objective='binary:logistic', eval_metric='aucpr', tree_method='hist',
                      device=device, max_depth=8, eta=0.05, seed=1, nthread=threads,
                      max_bin=16, scale_pos_weight=positive_weight)
        target = rounds
        suffix = '.ubj'
    else:
        params = dict(max_depth=20, min_samples_leaf=5, max_features='sqrt',
                      class_weight={0:sample['rows']/(2*(sample['rows']-sample['positives'])),
                                    1:sample['rows']/(2*sample['positives'])},
                      random_state=1, warm_start=True)
        target = rf_trees
        suffix = '.pkl'
    identity = dict(sample_id=sample['sample_id'], runtime_sha256=RUNTIME_SHA256,
                    library_version=library.__version__, model=model_name, target=target,
                    params={k:v for k,v in params.items() if k not in ('nthread','num_threads')})
    signature = digest(identity)
    latest_path = output/'latest.json'
    latest = json.loads(latest_path.read_text()) if latest_path.exists() else None
    model = None
    done = 0
    generation = 0
    if latest is not None:
        if latest['signature'] != signature:
            raise ValueError('model checkpoint configuration/sample/library changed; use a new model directory')
        path = output_path(output/latest['path'], data.protected)
        if not path.is_relative_to(output) or sha256(path) != latest['sha256']:
            raise ValueError('model checkpoint checksum mismatch')
        if model_name == 'lgbm':
            model = library.Booster(model_file=str(path))
        elif model_name == 'xgb':
            model = library.Booster(model_file=str(path))
        else:
            # Only load this runtime's own, checksummed local checkpoint.
            with path.open('rb') as handle:
                model = pickle.load(handle)
        done, generation = latest['completed'], latest['generation']

    def save(current, completed, complete=False):
        nonlocal generation, latest
        generation += 1
        path = output/f'model-slot-{generation % 2}{suffix}'
        if model_name == 'rf':
            def writer(p):
                with p.open('wb') as handle:
                    pickle.dump(current, handle, protocol=5)
        else:
            writer = lambda p: current.save_model(str(p))
        atomic_write(path, writer, data.protected)
        latest = dict(signature=signature, identity=identity, path=path.name, sha256=sha256(path),
                      completed=completed, complete=complete, generation=generation, threads=threads)
        atomic_json(latest_path, latest, data.protected)
        print(f'{model_name}: checkpoint {completed}/{target}, complete={complete}', flush=True)

    if latest and done >= target and not latest['complete']:
        save(model, target, complete=True)
    if not latest or not latest['complete']:
        with phase('load sampled CSR'):
            X, y = materialize_sample(sample_dir, sample, max_matrix_bytes)
        print(f'{model_name}: training {sample["rows"]:,} rows, device={device}, CPU threads={threads}', flush=True)
        with phase(f'{model_name} training'):
            if model_name == 'lgbm':
                train = library.Dataset(X, label=y, free_raw_data=True, params=params)
                # Leave construction lazy: on resume LightGBM must install the
                # init_model predictor before it frees the raw CSR reference.
                del X, y

                def checkpoint(env):
                    completed = env.iteration+1
                    if completed % checkpoint_every == 0:
                        save(env.model, completed)
                checkpoint.order = 20
                model = library.train(params, train, num_boost_round=max(0,target-done),
                                      init_model=model, keep_training_booster=True,
                                      callbacks=[library.log_evaluation(period=checkpoint_every), checkpoint])
                del train
            elif model_name == 'xgb':
                train = library.QuantileDMatrix(X, label=y, max_bin=params['max_bin'], nthread=threads)
                del X, y

                class Checkpoint(library.callback.TrainingCallback):
                    def after_iteration(self, booster, epoch, evals_log):
                        completed = done+epoch+1
                        if completed % checkpoint_every == 0:
                            save(booster, completed)
                        return False
                model = library.train(params, train, num_boost_round=max(0,target-done),
                                      xgb_model=model, callbacks=[Checkpoint()])
                del train
            else:
                from sklearn.ensemble import RandomForestClassifier
                X_csc = X.tocsc()
                del X
                # Bootstrap and per-tree buffers grow with sample rows. Avoid
                # launching one full-size tree per CPU when RAM cannot hold them.
                per_tree = sample['rows']*32 + 256*2**20
                fit_jobs = max(1, min(threads, int(available_bytes()*0.5/per_tree)))
                print(f'RF fit workers={fit_jobs}; inference workers={threads}', flush=True)
                if model is None:
                    model = RandomForestClassifier(**params, n_estimators=0, n_jobs=fit_jobs)
                for count in range(done, target, checkpoint_every):
                    completed = min(target, count+checkpoint_every)
                    model.set_params(n_estimators=completed, n_jobs=fit_jobs)
                    model.fit(X_csc, y)
                    save(model, completed)
                del X_csc, y
        save(model, target, complete=True)
    else:
        print(f'{model_name}: using completed model, skipping TRAIN load/fit', flush=True)
    # CPU input is evaluated on CPU explicitly; avoid XGBoost's device-mismatch
    # fallback on every shard. Training can still use one CUDA GPU.
    predict_threads = threads if predict_threads is None else predict_threads
    if model_name == 'xgb':
        model.set_param({'device':'cpu', 'nthread':predict_threads})
        predict = lambda X: model.inplace_predict(X)
    elif model_name == 'lgbm':
        predict = lambda X: model.predict(X, num_threads= predict_threads)
    else:
        model.set_params(n_jobs=predict_threads)
        predict = lambda X: model.predict_proba(X)[:,1]
    return model, predict, latest


class XGBDiagnostics:
    """Bounded stratified uniform probes and extreme-score examples.

    State is published inside the evaluation checkpoint, so metrics and diagnostics
    always resume at the same shard. No extra full validation/test scan is needed.
    """
    def __init__(self, data, probe_negative=10000, probe_positive=1000,
                 examples=100, seed=17, max_probe_nnz=1000000, model_name=None):
        if min(probe_negative, probe_positive, examples, max_probe_nnz) < 1:
            raise ValueError('diagnostic limits must be positive')
        self.data = data
        self.config = dict(probe_negative=probe_negative, probe_positive=probe_positive,
                           examples=examples, seed=seed, max_probe_nnz=max_probe_nnz,
                           model_name=model_name)
        self.rng = np.random.default_rng(seed)
        self.sources = {s['source_id']:s for s in data.meta['sources']}
        self.state = dict(probe=[[], []], extremes=[[], []], rows=[0,0],
                          empty_rows=[0,0], groups={}, rng=self.rng.bit_generator.state)

    def restore(self, state):
        self.state = state
        self.rng.bit_generator.state = state['rng']

    def update(self, part, X, y, lines, scores, threshold=None):
        scores = np.asarray(scores, dtype=np.float64)
        source = self.sources.get(part['source_id'], {})
        source_meta = dict(source_id=part['source_id'], day=source.get('day','unknown'),
                           host=source.get('file_host','unknown'), shard=part.get('path',''))
        sizes = np.diff(X.indptr)
        for label in (0,1):
            rows = np.flatnonzero(y == label)
            self.state['rows'][label] += len(rows)
            self.state['empty_rows'][label] += int(np.count_nonzero(sizes[rows] == 0))
            for name, limit, keys in (
                ('probe', self.config['probe_positive' if label else 'probe_negative'], self.rng.random(len(rows))),
                ('extremes', self.config['examples'], scores[rows] if label else -scores[rows]),
            ):
                previous = self.state[name][label]
                # Keep only candidates that can enter the current bounded pool.
                candidates = np.flatnonzero(keys < previous[-1]['priority']) if len(previous) == limit else np.arange(len(rows))
                if len(candidates) > limit:
                    candidates = candidates[np.argsort(keys[candidates], kind='stable')[:limit]]
                incoming = []
                for j in candidates:
                    i = int(rows[j])
                    incoming.append(dict(**source_meta, source_line=int(lines[i]), label=label,
                        score=float(scores[i]), priority=float(keys[j]),
                        columns=X.indices[X.indptr[i]:X.indptr[i+1]].tolist()))
                self.state[name][label] = sorted(previous+incoming, key=lambda r:r['priority'])[:limit]
        if sum(len(r['columns']) for name in ('probe','extremes') for pool in self.state[name] for r in pool) > self.config['max_probe_nnz']:
            raise MemoryError('diagnostic sparse budget exceeded; reduce probe/example limits in a new run directory')
        if threshold is not None:
            predicted = scores >= threshold
            counts = [int(np.sum(predicted & (y==1))), int(np.sum(predicted & (y==0))),
                      int(np.sum(~predicted & (y==1))), int(np.sum(~predicted & (y==0)))]
            for kind, key in [('day',source_meta['day']),('host',source_meta['host'])]:
                group = self.state['groups'].setdefault(kind, {}).setdefault(key, [0,0,0,0])
                self.state['groups'][kind][key] = [a+b for a,b in zip(group, counts)]
        self.state['rng'] = self.rng.bit_generator.state

    def matrix(self):
        records = self.state['probe'][0]+self.state['probe'][1]
        ptr = np.r_[0, np.cumsum([len(r['columns']) for r in records])]
        columns = np.array([c for r in records for c in r['columns']],dtype=np.int32)
        X = sparse.csr_matrix((np.ones(len(columns),dtype=np.float32),columns,ptr),
                              shape=(len(records),self.data.width))
        return X, np.array([r['label'] for r in records],dtype=np.uint8)

    def publish(self, directory, split, threshold):
        directory = output_path(directory, self.data.protected)
        vocab_path = self.data.manifest_path.parent/'assets/vocab.json'
        reverse = {int(v):k for k,v in json.loads(vocab_path.read_text()).items()}
        errors = []
        for label,pool in enumerate(self.state['extremes']):
            for row in pool:
                if (row['score'] >= threshold) == bool(label):
                    continue
                record = {k:v for k,v in row.items() if k != 'priority'}
                record.update(error='FN' if label else 'FP', threshold=threshold,
                              tokens=[reverse[c] for c in row['columns']])
                errors.append(record)
        atomic_json(directory/f'{split}_errors.json', dict(
            split=split, selection='lowest-score positives / highest-score negatives; NOT a representative error sample',
            maximum_per_error_type=self.config['examples'], examples=errors), self.data.protected)
        atomic_json(directory/f'{split}_diagnostics.json', dict(
            split=split, threshold=threshold, rows_by_label=self.state['rows'],
            empty_rows_by_label=self.state['empty_rows'], groups=self.state['groups'],
            group_count_order=['tp','fp','fn','tn'],
            group_scope='full split at frozen threshold' if split=='test' else 'not collected: validation threshold is selected after the pass',
            probe_counts=[len(x) for x in self.state['probe']], config=self.config), self.data.protected)


def posthoc_learning_curve(data, sample_dir, sample, model, validation_probe,
                           directory, threshold, model_name=None, threads=1, every=25):
    """Evaluate prefixes of the final ensemble, not retraining or early stopping.

    Supports XGBoost, LightGBM, and Random Forest.
    TRAIN probe is drawn from the actual fitted sample. Validation probe is drawn
    during full evaluation. Both use class weights restoring original split priors.
    Negative-tail estimates on small probes are noisy; full metrics remain primary.
    """
    from sklearn.metrics import average_precision_score, log_loss, roc_auc_score
    directory = output_path(directory, data.protected)
    if every < 1:
        raise ValueError('curve interval must be positive')
    if model_name is None:
        if hasattr(model, 'num_boosted_rounds'):
            model_name = 'xgb'
        elif hasattr(model, 'num_trees'):
            model_name = 'lgbm'
        elif hasattr(model, 'estimators_'):
            model_name = 'rf'
        else:
            raise ValueError(f'unsupported model type: {type(model)}')

    train_probe = XGBDiagnostics(data, **validation_probe.config)
    train_path = directory/'train-probe.json'
    identity = dict(sample_id=sample['sample_id'], runtime=RUNTIME_SHA256,
                    config=train_probe.config, input=data.identity())
    if train_path.exists():
        saved = json.loads(train_path.read_text())
        if saved['identity'] != identity:
            raise ValueError('training probe identity mismatch; use a new diagnostics directory')
        train_probe.restore(saved['state'])
    else:
        with phase('fixed TRAIN diagnostic probe (sample parts only)'):
            for index,part in enumerate(sample['parts']):
                path = Path(sample_dir)/part['path']
                if sha256(path) != part['sha256']:
                    raise ValueError('sample checksum changed during diagnostics')
                with np.load(path,allow_pickle=False) as c:
                    X = sparse.csr_matrix((np.ones(len(c['indices']),dtype=np.float32),c['indices'],c['indptr']),
                                          shape=(len(c['label']), data.width))
                    # Train probe provenance is not exported as raw-source lines.
                    train_probe.update(data.meta['shards'][part['index']],X,c['label'],
                                       c['source_rows'],np.zeros(len(c['label'])))
                if (index+1)%256 == 0:
                    print(f'TRAIN probe: {index+1}/{len(sample["parts"])} parts',flush=True)
        atomic_json(train_path,dict(identity=identity,state=train_probe.state,
                    line_identity='source_rows are zero-based source-shard offsets, not source file lines'),data.protected)

    if model_name == 'xgb':
        import xgboost as xgb
        rounds = model.num_boosted_rounds()
    elif model_name == 'lgbm':
        rounds = model.num_trees()
    elif model_name == 'rf':
        rounds = len(model.estimators_)
    else:
        raise ValueError(f'unrecognized model_name: {model_name}')

    steps = sorted(set([1, rounds, *range(every, rounds+1, every)]))
    curves = []
    for split,probe in [('train',train_probe),('val',validation_probe)]:
        X,y = probe.matrix()
        if len(np.unique(y)) != 2:
            raise ValueError(f'{split} probe needs both classes')
        totals = data.meta['splits'][split]
        weights = np.where(y==1,totals['label_1']/np.sum(y==1),totals['label_0']/np.sum(y==0))
        
        if model_name == 'xgb':
            matrix = xgb.DMatrix(X, nthread=threads)
            preds_by_step = {trees: model.predict(matrix, iteration_range=(0, trees)).astype(np.float64) for trees in steps}
        elif model_name == 'lgbm':
            preds_by_step = {trees: model.predict(X, num_iteration=trees, num_threads=threads).astype(np.float64) for trees in steps}
        elif model_name == 'rf':
            step_set = set(steps)
            preds_by_step = {}
            accum = np.zeros(len(y), dtype=np.float64)
            for i, tree in enumerate(model.estimators_, 1):
                accum += tree.predict_proba(X)[:, 1]
                if i in step_set:
                    preds_by_step[i] = (accum / i).astype(np.float64)

        for trees in steps:
            p = preds_by_step[trees]
            pred = p >= threshold
            tp = float(weights[pred & (y==1)].sum()); fp = float(weights[pred & (y==0)].sum())
            fn = float(weights[~pred & (y==1)].sum())
            curves.append(dict(split=split,trees=trees,probe_rows=len(y),
                weighted_logloss=float(log_loss(y,p,sample_weight=weights,labels=[0,1])),
                weighted_average_precision=float(average_precision_score(y,p,sample_weight=weights)),
                weighted_roc_auc=float(roc_auc_score(y,p,sample_weight=weights)),
                weighted_f1_at_final_validation_threshold=2*tp/max(2*tp+fp+fn,1),
                threshold=threshold))
            print(f'Curve {split} trees={trees}: logloss={curves[-1]["weighted_logloss"]:.6g}, AP={curves[-1]["weighted_average_precision"]:.6g}',flush=True)

    if model_name == 'xgb':
        model_sha = hashlib.sha256(model.save_raw()).hexdigest()
        model_cfg = json.loads(model.save_config())
    elif model_name == 'lgbm':
        model_sha = hashlib.sha256(model.model_to_string().encode()).hexdigest()
        model_cfg = model.dump_model()
    else:
        import pickle
        model_sha = hashlib.sha256(pickle.dumps(model)).hexdigest()
        model_cfg = {k: str(v) for k, v in model.get_params().items()}

    report = dict(method='posthoc ensemble-prefix curve on fixed class-stratified uniform probes',
        model_name=model_name,
        identity=identity, model_sha256=model_sha,
        model_config=model_cfg, validation_probe_config=validation_probe.config,
        caveats=['Not full-split metrics; rare false positives may be absent from the probe.',
                 'TRAIN probe comes from fitted undersampled TRAIN; class weighting does not restore missing negative patterns.',
                 'F1 uses the final full-validation threshold at every prefix; logloss/AP are better for studying learning progress.',
                 'No test data, early stopping or automatic hyperparameter decisions are used.'], curve=curves)
    atomic_json(directory/'learning_curve.json',report,data.protected)
    import csv
    def write_csv(path):
        with path.open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(curves[0]));writer.writeheader();writer.writerows(curves)
    atomic_write(directory/'learning_curve.csv',write_csv,data.protected)
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print('matplotlib unavailable; learning_curve.json and .csv are ready',flush=True)
    else:
        fig,axes=plt.subplots(1,2,figsize=(11,4))
        for ax,key in zip(axes,['weighted_logloss','weighted_average_precision']):
            for split in ('train','val'):
                rows=[r for r in curves if r['split']==split]
                ax.plot([r['trees'] for r in rows],[r[key] for r in rows],label=split)
            ax.set(xlabel='Trees',ylabel=key);ax.legend();ax.grid(alpha=.3)
        fig.suptitle(f'{model_name.upper()} fixed probe estimates — not full-split performance');fig.tight_layout()
        atomic_write(directory/'learning_curve.png',lambda p:fig.savefig(p,dpi=150),data.protected)
        plt.close(fig)
    # Scores at every grid threshold from the existing full-validation histogram.
    state_path = directory.parent/'validation-state.npz'
    with np.load(state_path,allow_pickle=False) as saved:
        pos,neg=saved['positive'],saved['negative']
    tp=pos[::-1].cumsum()[::-1];fp=neg[::-1].cumsum()[::-1]
    atomic_write(directory/'validation_threshold_curve.npz',lambda p:np.savez_compressed(p,
        threshold=np.arange(len(pos))/(len(pos)-1),tp=tp,fp=fp,fn=pos.sum()-tp,
        precision=tp/np.maximum(tp+fp,1),recall=tp/max(int(pos.sum()),1),
        f1=2*tp/np.maximum(tp+fp+pos.sum(),1)),data.protected)
    return report


xgb_posthoc_learning_curve = posthoc_learning_curve
ModelDiagnostics = XGBDiagnostics
