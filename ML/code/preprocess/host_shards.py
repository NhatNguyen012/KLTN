"""Portable, lossless binary sparse shards for full Host ML events.

NPZ members: row_nnz, column_delta, label, source_line_delta. Presence is 1.
No pickle, raw commands, identifiers-as-features or global CSR assembly.
"""
from __future__ import annotations
from array import array
import hashlib
import io
import json
from pathlib import Path

import numpy as np
from scipy import sparse

FORMAT = 'host_binary_delta_npz'
SCHEMA = 1
SPLITS = ('train', 'val', 'test')


def sha256(path):
    if hasattr(hashlib, 'file_digest'):
        with Path(path).open('rb') as handle:
            return hashlib.file_digest(handle, 'sha256').hexdigest()
    result = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


class ShardBuffer:
    def __init__(self, width):
        if not 0 < width < 2**32:
            raise ValueError('feature width must fit uint32')
        self.width = width
        self.row_nnz = array('I')
        self.column_delta = array('I')
        self.labels = bytearray()
        self.line_delta = array('Q')
        self.previous_line = 0

    def __len__(self):
        return len(self.labels)

    @property
    def nbytes(self):
        return len(self.row_nnz)*4 + len(self.column_delta)*4 + len(self.labels) + len(self.line_delta)*8

    def append(self, columns, label, source_line):
        if type(label) is not int or label not in (0, 1) or source_line <= self.previous_line:
            raise ValueError('invalid label or non-increasing source line')
        columns = sorted(set(columns))
        if columns and (columns[0] < 0 or columns[-1] >= self.width):
            raise ValueError('column outside vocabulary')
        self.row_nnz.append(len(columns))
        previous = 0
        for col in columns:
            self.column_delta.append(col - previous)
            previous = col
        self.labels.append(label)
        self.line_delta.append(source_line - self.previous_line)
        self.previous_line = source_line

    def encode(self):
        # np.savez_compressed is a structured numeric container, not an outer
        # archive requiring extraction of an entire CSR matrix before use.
        stream = io.BytesIO()
        np.savez_compressed(stream,
            row_nnz=np.asarray(self.row_nnz, dtype='<u4'),
            column_delta=np.asarray(self.column_delta, dtype='<u4'),
            label=np.frombuffer(self.labels, dtype='u1'),
            source_line_delta=np.asarray(self.line_delta, dtype='<u8'))
        payload = stream.getvalue()
        positive = sum(self.labels)
        return payload, dict(rows=len(self), nnz=len(self.column_delta),
            label_0=len(self)-positive, label_1=positive, bytes=len(payload),
            source_line_first=self.line_delta[0], source_line_last=self.previous_line,
            sha256=hashlib.sha256(payload).hexdigest())


def decode_shard(path, width, expected=None):
    path = Path(path)
    if expected is not None:
        if path.stat().st_size != expected['bytes'] or sha256(path) != expected['sha256']:
            raise ValueError(f'shard checksum/size mismatch: {path}')
    with np.load(path, allow_pickle=False) as content:
        if set(content.files) != {'row_nnz','column_delta','label','source_line_delta'}:
            raise ValueError('invalid shard members')
        sizes = content['row_nnz']
        deltas = content['column_delta']
        y = content['label']
        lines_delta = content['source_line_delta']
    if (sizes.dtype != np.dtype('<u4') or deltas.dtype != np.dtype('<u4')
            or y.dtype != np.dtype('u1') or lines_delta.dtype != np.dtype('<u8')
            or any(a.ndim != 1 for a in (sizes,deltas,y,lines_delta))):
        raise ValueError('invalid shard array types')
    n = len(y)
    if (len(sizes) != n or len(lines_delta) != n or np.any(y > 1)
            or np.any(lines_delta == 0) or int(sizes.sum(dtype=np.uint64)) != len(deltas)):
        raise ValueError('invalid shard dimensions, labels or source lines')
    indptr = np.empty(n+1, dtype=np.int64)
    indptr[0] = 0
    np.cumsum(sizes, dtype=np.int64, out=indptr[1:])
    if len(deltas):
        accumulated = np.cumsum(deltas, dtype=np.uint64)
        starts = indptr[:-1]
        bases = np.zeros(n, dtype=np.uint64)
        valid = starts > 0
        bases[valid] = accumulated[starts[valid]-1]
        columns = accumulated - np.repeat(bases, sizes)
        if np.any(columns >= width):
            raise ValueError('decoded column outside vocabulary')
        # All deltas except the first column of each nonempty row must be > 0.
        zeros = np.flatnonzero(deltas == 0)
        if len(zeros) and not np.all(np.isin(zeros, starts[sizes > 0])):
            raise ValueError('duplicate column in binary shard')
        columns = columns.astype(np.int32 if width < 2**31 else np.int64)
    else:
        columns = np.empty(0, dtype=np.int32)
    lines = np.cumsum(lines_delta, dtype=np.uint64)
    if len(lines) > 1 and np.any(lines[1:] <= lines[:-1]):
        raise ValueError('source line overflow')
    if expected is not None:
        if (n != expected['rows'] or len(deltas) != expected['nnz']
                or int(y.sum()) != expected['label_1'] or n-int(y.sum()) != expected['label_0']
                or (n and (int(lines[0]) != expected['source_line_first'] or int(lines[-1]) != expected['source_line_last']))):
            raise ValueError('decoded shard disagrees with manifest')
    X = sparse.csr_matrix((np.ones(len(columns), dtype=np.float32), columns, indptr), shape=(n,width))
    return X, y, lines


class HostShardDataset:
    """One manifest for every model; optional volume relocation after upload."""
    def __init__(self, manifest_path, volume_roots=None):
        self.manifest_path = Path(manifest_path).resolve()
        self.meta = json.loads(self.manifest_path.read_text())
        if (self.meta.get('format') != FORMAT or self.meta.get('schema') != SCHEMA
                or self.meta.get('complete') is not True):
            raise ValueError('expected a complete Host binary shard manifest')
        self.width = self.meta['vocab_size']
        supplied = volume_roots or {}
        unknown = set(supplied)-set(self.meta['volumes'])
        if unknown:
            raise ValueError(f'unknown volume IDs: {unknown}')
        self.roots = {key: Path(supplied.get(key, value)).resolve() for key,value in self.meta['volumes'].items()}
        assets = self.manifest_path.parent / 'assets'
        for name in ('vocab.json','vocab_metadata.json'):
            if sha256(assets/name) != self.meta['assets_sha256'][name]:
                raise ValueError('vocabulary asset checksum mismatch')
        vm = json.loads((assets/'vocab_metadata.json').read_text())
        if vm.get('split_sha256') != self.meta['split_sha256'] or vm.get('vocabulary_sha256') != self.meta['vocabulary_sha256']:
            raise ValueError('vocabulary/split identity mismatch')
        self.sources = {entry['source_id']: entry for entry in self.meta['sources']}
        if len(self.sources) != len(self.meta['sources']):
            raise ValueError('duplicate source identity')
        counts = {s:dict(rows=0, nnz=0, label_0=0, label_1=0, bytes=0) for s in SPLITS}
        seen = set()
        for part in self.meta['shards']:
            if part['source_id'] not in self.sources or part['split'] not in SPLITS:
                raise ValueError('invalid shard source/split')
            key = (part['volume'],part['path'])
            if key in seen:
                raise ValueError('duplicate shard reference')
            seen.add(key)
            self.path_for(part)
            for k in counts[part['split']]:
                counts[part['split']][k] += part[k]
        if counts != self.meta['splits']:
            raise ValueError('shard totals disagree with manifest')

    def path_for(self, part):
        if part['volume'] not in self.roots:
            raise ValueError('unknown storage volume')
        root = self.roots[part['volume']]
        path = (root/part['path']).resolve()
        if not path.is_relative_to(root):
            raise ValueError('shard path escapes volume')
        return path

    def iter_batches(self, split, verify=True, with_provenance=False):
        if split not in SPLITS:
            raise ValueError('unknown split')
        for part in self.meta['shards']:
            if part['split'] != split:
                continue
            X,y,lines = decode_shard(self.path_for(part),self.width,part if verify else None)
            if with_provenance:
                yield X,y,dict(source=self.sources[part['source_id']],source_lines=lines)
            else:
                yield X,y

    def csr_bytes(self, split):
        # Large consolidated CSR uses int64 indices/indptr and float32 data.
        info = self.meta['splits'][split]
        return 12*info['nnz'] + 8*(info['rows']+1) + info['rows']

    def materialize(self, split, max_bytes):
        """Explicit in-memory path for estimators that require a full matrix.

        This is not automatic sampling or incremental forest training. Refuse
        before allocating when sparse array storage alone exceeds the budget.
        Estimator working memory remains additional to this budget.
        """
        needed = self.csr_bytes(split)
        if needed > max_bytes:
            raise MemoryError(f'{split}: CSR+labels needs at least {needed/2**30:.1f} GiB; '
                              'model memory is additional. Use a suitably provisioned runtime; no rows were sampled.')
        info = self.meta['splits'][split]
        data = np.ones(info['nnz'], dtype=np.float32)
        indices = np.empty(info['nnz'], dtype=np.int64)
        indptr = np.empty(info['rows']+1, dtype=np.int64)
        y = np.empty(info['rows'], dtype=np.uint8)
        indptr[0] = 0
        row_offset = nz_offset = 0
        for chunk, labels in self.iter_batches(split):
            r,nz = chunk.shape[0],chunk.nnz
            indices[nz_offset:nz_offset+nz] = chunk.indices
            indptr[row_offset+1:row_offset+r+1] = chunk.indptr[1:]+nz_offset
            y[row_offset:row_offset+r] = labels
            row_offset += r
            nz_offset += nz
        if row_offset != info['rows'] or nz_offset != info['nnz']:
            raise ValueError('materialized shape mismatch')
        return sparse.csr_matrix((data,indices,indptr),shape=(info['rows'],self.width),copy=False), y


def xgboost_iterator(dataset, split, cache_prefix):
    """CPU external-memory iterator. XGBoost >= 3.0 is needed by notebook templates."""
    import xgboost as xgb
    class Iterator(xgb.DataIter):
        def __init__(self):
            self.iterator = dataset.iter_batches(split)
            super().__init__(cache_prefix=str(cache_prefix))
        def reset(self):
            self.iterator = dataset.iter_batches(split)
        def next(self, input_data):
            item = next(self.iterator, None)
            if item is None:
                return False
            self.current_X,self.current_y = item
            input_data(data=self.current_X,label=self.current_y)
            return True
    return Iterator()
