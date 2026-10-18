"""Quota-aware atomic shard placement across explicitly configured output volumes."""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil

from ML.code.preprocess.pipeline_contract import sync_directory, validate_output_path
from ML.code.preprocess.stratified_pipeline import atomic_json, file_hash


@contextmanager
def exclusive_lock(path, nonblocking=False):
    path = validate_output_path(Path(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as handle:
        try:
            fcntl.flock(handle,fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError as exc:
            raise RuntimeError('another builder is using this output directory') from exc
        try:
            yield
        finally:
            fcntl.flock(handle,fcntl.LOCK_UN)


def load_volumes(path, protected=(), create=False):
    raw = json.loads(Path(path).read_text())
    entries = raw.get('volumes')
    if not isinstance(entries,list) or not entries:
        raise ValueError('storage config needs a nonempty volumes list')
    result=[]
    for entry in entries:
        if (not isinstance(entry.get('id'),str) or not entry['id'].replace('_','').isalnum()
                or type(entry.get('max_bytes')) is not int or entry['max_bytes']<=0
                or type(entry.get('reserve_free_bytes')) is not int or entry['reserve_free_bytes']<0):
            raise ValueError('invalid storage volume ID/quota/reserve')
        root=validate_output_path(Path(entry['path']),protected)
        for old in result:
            other=Path(old['path'])
            if entry['id']==old['id'] or root.is_relative_to(other) or other.is_relative_to(root):
                raise ValueError('storage volumes overlap or have duplicate IDs')
        if create:root.mkdir(parents=True,exist_ok=True)
        result.append(dict(entry,path=str(root)))
    return result


def directory_bytes(root):
    total=0
    for path in Path(root).rglob('*'):
        if path.is_symlink():
            raise ValueError(f'symlink inside managed shard volume: {path}')
        if path.is_file():total+=path.stat().st_size
    return total


def initialize_ledger(control, volumes):
    """Recount on startup, including partial files and other runs in these roots."""
    ledger=control/'storage_ledger.json'
    atomic_json(ledger,dict(volumes=volumes,used={v['id']:directory_bytes(v['path']) for v in volumes}))
    return ledger


def _safe_path(root,relative):
    p=validate_output_path(Path(root)/relative)
    if not p.is_relative_to(Path(root).resolve()) or p==Path(root).resolve():
        raise ValueError('shard path escapes storage root')
    return p


def write_shard(control, relative, payload):
    """Serialize placement only; compression/tokenization happen outside the lock.

    Existing partial-file shards can be reused byte-for-byte during a rescan.
    Actual writes are counted inside the lock, preventing quota oversubscription.
    """
    if Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('unsafe shard relative path')
    checksum=hashlib.sha256(payload).hexdigest()
    with exclusive_lock(control/'storage.lock'):
        ledger_path=control/'storage_ledger.json'
        state=json.loads(ledger_path.read_text())
        for volume in state['volumes']:
            p=_safe_path(volume['path'],relative)
            if p.exists() and p.stat().st_size==len(payload) and file_hash(p)==checksum:
                return dict(volume=volume['id'],path=relative)
        for volume in state['volumes']:
            p=_safe_path(volume['path'],relative)
            temporary=_safe_path(volume['path'],relative+f'.{os.getpid()}.tmp')
            # Discard only this worker's stale, private temporary file.
            if temporary.exists():
                state['used'][volume['id']]-=temporary.stat().st_size
                temporary.unlink()
            free=shutil.disk_usage(volume['path']).free
            used=state['used'][volume['id']]
            # Allow enough space for a complete atomic replacement, including
            # old bytes until rename. Quota remains strict even transiently.
            if used+len(payload)>volume['max_bytes'] or free-len(payload)<volume['reserve_free_bytes']:
                continue
            p.parent.mkdir(parents=True,exist_ok=True)
            old_size=p.stat().st_size if p.exists() else 0
            try:
                with temporary.open('xb') as handle:
                    handle.write(payload);handle.flush();os.fsync(handle.fileno())
                os.replace(temporary,p)
                sync_directory(p.parent)
                state['used'][volume['id']]+=len(payload)-old_size
                atomic_json(ledger_path,state)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
            return dict(volume=volume['id'],path=relative)
    raise OSError('No output volume has quota/free space for the next shard. Completed file checkpoints are preserved; free space or extend approved volumes and rerun.')
