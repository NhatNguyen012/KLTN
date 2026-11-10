"""Stable event-time replay cache and frozen retained-row cohort; never model features."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import numpy as np


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''): h.update(b)
    return h.hexdigest()


def ordered_csv(source, cache):
    source, cache = Path(source).resolve(), Path(cache).resolve()
    if source.parent == cache or source.parent in cache.parents:
        raise ValueError('Replay cache cannot be inside source directory')
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / 'events.csv'
    meta = cache / 'manifest.json'
    identity = dict(source=str(source), source_sha256=sha(source), policy='stable_numeric_timestamp_column7_v1')
    if target.exists() and meta.exists():
        old = json.loads(meta.read_text())
        if all(old.get(k) == v for k,v in identity.items()) and old.get('sha256') == sha(target):
            return target
    with tempfile.TemporaryDirectory(prefix='.sort-', dir=cache) as temp:
        temp = Path(temp)
        body = temp / 'body.csv'
        env = dict(os.environ, LC_ALL='C')
        with body.open('wb') as out, source.open('rb') as src:
            header = src.readline().rstrip(b'\r\n')
            with subprocess.Popen(['sort','--stable','-t,','-k7,7n','-S','512M','--parallel=4','-T',str(temp)],
                                  stdin=subprocess.PIPE, stdout=out, env=env) as proc:
                for line_no, line in enumerate(src, 2):
                    row = line.rstrip(b'\r\n')
                    if len(row.split(b',')) != 7 or not row.split(b',')[6].isdigit():
                        raise ValueError(f'Invalid numeric event timestamp/CSV at source line {line_no}')
                    proc.stdin.write(row + b',' + str(line_no).encode() + b'\n')
                proc.stdin.close()
                if proc.wait(): raise RuntimeError('Event sort failed')
        final = temp / 'events.csv'
        with final.open('wb') as out, body.open('rb') as src:
            out.write(header + b',source_line\n')
            import shutil
            shutil.copyfileobj(src, out, 8 << 20)
            out.flush(); os.fsync(out.fileno())
        identity.update(sha256=sha(final), rows=line_no-1)
        final.replace(target)
        pending = cache / 'manifest.json.partial'
        pending.write_text(json.dumps(identity, indent=2)+'\n'); pending.replace(meta)
    return target


def freeze_cohort(output, decode):
    """Capture the published cohort before reordering; identity/labels only for verification."""
    output = Path(output)
    target = output / 'retained_cohort.npz'
    if target.exists():
        with np.load(target, allow_pickle=False) as z: return {int(x) for x in z['source_line']}
    manifest = json.loads((output / 'manifest.json').read_text())
    lines, labels, splits = [], [], []
    for part in manifest['shards']:
        _, y, row = decode(output / part['path'], manifest['vocab_size'], part)
        lines.extend(row); labels.extend(y); splits.extend([part['split']]*len(y))
    order = np.argsort(lines)
    lines = np.asarray(lines,dtype=np.int64)[order]
    if len(np.unique(lines)) != len(lines): raise ValueError('Duplicate retained source identity')
    pending = target.with_suffix('.partial.npz')
    np.savez_compressed(pending, source_line=lines, label=np.asarray(labels,dtype=np.uint8)[order],
                        split=np.asarray(splits)[order])
    pending.replace(target)
    return set(map(int, lines))
