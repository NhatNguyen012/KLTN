"""Durable endpoint inbox and checksum-gated LightGBM shadow inference.

Raw collection is independent from inference. With no eligible model bundle the
agent behaves as a bounded durable inbox and emits no score. Linux collection
remains supported while Linux inference stays explicitly unsupported until a
THEIA-compatible adapter and validated bundle exist.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
from typing import Any
import urllib.error
import urllib.request

from fastapi import FastAPI, HTTPException, Request

SOURCES = {'audit', 'journal', 'sysmon', 'security', 'powershell', 'smoke'}
MAX_BODY = 4 * 1024 * 1024
READY_STATES = {'ready_shadow', 'ready_active'}


class CapacityError(Exception):
    pass


class BundleError(Exception):
    pass


def event_id(host_id, source, raw):
    identity = {k: v for k, v in raw.items() if k != 'date'}
    data = json.dumps([host_id, source, identity], sort_keys=True,
                      separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = root / 'manifest.json'
    if not manifest_path.is_file():
        raise BundleError('manifest_missing')
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError) as exc:
        raise BundleError('manifest_invalid') from exc
    if manifest.get('schema_version') != 'bundle.v1' or manifest.get('branch') != 'host_ml':
        raise BundleError('manifest_schema_or_branch_incompatible')
    if manifest.get('algorithm') != 'lightgbm':
        raise BundleError('algorithm_unsupported')
    if not manifest.get('activation', {}).get('eligible', False):
        raise BundleError('bundle_not_activation_eligible')
    if manifest.get('domain_validation') != 'validated':
        raise BundleError('bundle_domain_not_validated')
    if manifest.get('parity', {}).get('passed') is not True:
        raise BundleError('bundle_parity_not_passed')
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > 100:
        raise BundleError('artifact_manifest_invalid')
    for relative, metadata in artifacts.items():
        if not isinstance(relative, str) or not isinstance(metadata, dict):
            raise BundleError('artifact_manifest_invalid')
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise BundleError('artifact_path_escape') from exc
        if not path.is_file() or path.is_symlink():
            raise BundleError('artifact_missing_or_symlink')
        expected = metadata.get('sha256')
        if not isinstance(expected, str) or not hmac.compare_digest(sha256_file(path), expected):
            raise BundleError('artifact_checksum_mismatch')
    return manifest


class Inbox:
    def __init__(self, path, host_id, max_rows=50000, max_bytes=128*1024*1024,
                 min_free_bytes=256*1024*1024):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.host_id, self.max_rows = host_id, max_rows
        self.max_bytes, self.min_free_bytes = max_bytes, min_free_bytes
        with closing(self.connect()) as db, db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''CREATE TABLE IF NOT EXISTS inbox (
              event_id TEXT PRIMARY KEY, source TEXT NOT NULL, raw TEXT NOT NULL,
              raw_bytes INTEGER NOT NULL,
              received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
              state TEXT NOT NULL DEFAULT 'waiting_for_model');
              CREATE TABLE IF NOT EXISTS identity (host_id TEXT PRIMARY KEY);
              CREATE TABLE IF NOT EXISTS score_outbox (
                score_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                sent_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
            ''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(inbox)')}
            for name, declaration in (
                ('normalized', 'TEXT'), ('score_id', 'TEXT'), ('error', 'TEXT'),
                ('attempts', 'INTEGER NOT NULL DEFAULT 0'),
                ('updated_at', "TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in columns:
                    db.execute(f'ALTER TABLE inbox ADD COLUMN {name} {declaration}')
            identity = db.execute('SELECT host_id FROM identity').fetchone()
            if identity and identity[0] != host_id:
                raise ValueError('Inbox belongs to a different host; use separate state directory')
            db.execute('INSERT OR IGNORE INTO identity VALUES (?)', (host_id,))

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def put(self, source, records):
        encoded = [(event_id(self.host_id, source, r),
                    json.dumps(r, ensure_ascii=False, allow_nan=False)) for r in records]
        with closing(self.connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            rows, size = db.execute('SELECT count(*), coalesce(sum(raw_bytes),0) FROM inbox').fetchone()
            inserted = 0
            for identity, raw in encoded:
                if db.execute('SELECT 1 FROM inbox WHERE event_id=?', (identity,)).fetchone():
                    continue
                length = len(raw.encode())
                if (rows + 1 > self.max_rows or size + length > self.max_bytes or
                        shutil.disk_usage(self.path.parent).free < self.min_free_bytes):
                    raise CapacityError('Inbox capacity reached; raw archive continues independently')
                db.execute('INSERT INTO inbox(event_id,source,raw,raw_bytes) VALUES (?,?,?,?)',
                           (identity, source, raw, length))
                inserted += 1
                rows += 1
                size += length
            return inserted

    def next_waiting(self, supported_sources: set[str]) -> tuple[str, str, dict] | None:
        if not supported_sources:
            return None
        placeholders = ','.join('?' for _ in supported_sources)
        with closing(self.connect()) as db:
            row = db.execute(f'''SELECT event_id,source,raw FROM inbox
              WHERE state IN ('waiting_for_model','retry') AND source IN ({placeholders})
              ORDER BY received_at,event_id LIMIT 1''', tuple(sorted(supported_sources))).fetchone()
        if not row:
            return None
        return row[0], row[1], json.loads(row[2])

    def store_score(self, identity: str, normalized: dict, score: dict):
        payload = json.dumps(score, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        with closing(self.connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''UPDATE inbox SET state='scored_shadow',normalized=?,score_id=?,
              error=NULL,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE event_id=?''',
              (json.dumps(normalized, ensure_ascii=False), score['score_id'], identity))
            db.execute('INSERT OR IGNORE INTO score_outbox(score_id,payload) VALUES (?,?)',
                       (score['score_id'], payload))

    def mark_ignored(self, identity: str, state: str, normalized: dict | None = None):
        with closing(self.connect()) as db, db:
            db.execute('''UPDATE inbox SET state=?,normalized=?,updated_at=strftime(
              '%Y-%m-%dT%H:%M:%fZ','now') WHERE event_id=?''',
              (state, json.dumps(normalized, ensure_ascii=False) if normalized else None, identity))

    def mark_error(self, identity: str, error: str):
        with closing(self.connect()) as db, db:
            db.execute('''UPDATE inbox SET state=CASE WHEN attempts>=2 THEN 'error' ELSE 'retry' END,
              attempts=attempts+1,error=?,
              updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE event_id=?''',
              (error[:256], identity))

    def outbox_batch(self, limit=100):
        with closing(self.connect()) as db:
            return db.execute('''SELECT score_id,payload FROM score_outbox
              WHERE sent_at IS NULL AND next_attempt_at<=strftime('%Y-%m-%dT%H:%M:%fZ','now')
              ORDER BY created_at LIMIT ?''', (limit,)).fetchall()

    def outbox_sent(self, score_ids):
        if not score_ids:
            return
        with closing(self.connect()) as db, db:
            db.executemany("UPDATE score_outbox SET sent_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE score_id=?",
                           ((item,) for item in score_ids))

    def outbox_failed(self, score_ids):
        if not score_ids:
            return
        with closing(self.connect()) as db, db:
            db.executemany('''UPDATE score_outbox SET attempts=attempts+1,
              next_attempt_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+30 seconds')
              WHERE score_id=?''', ((item,) for item in score_ids))

    def status(self):
        with closing(self.connect()) as db:
            rows = db.execute('SELECT source,count(*),max(received_at) FROM inbox GROUP BY source').fetchall()
            count, size = db.execute('SELECT count(*),coalesce(sum(raw_bytes),0) FROM inbox').fetchone()
            states = db.execute('SELECT state,count(*) FROM inbox GROUP BY state').fetchall()
            outbox = db.execute('SELECT count(*) FROM score_outbox WHERE sent_at IS NULL').fetchone()[0]
        return {'host_id': self.host_id, 'pending_events': count, 'raw_bytes': size,
                'max_rows': self.max_rows, 'max_raw_bytes': self.max_bytes,
                'capacity_reached': count >= self.max_rows or size >= self.max_bytes,
                'pending_score_delivery': outbox,
                'states': {state: number for state, number in states},
                'sources': [{'source': s, 'count': n, 'last_received': t} for s,n,t in rows]}


class HostModel:
    def __init__(self, root: Path, domain: str):
        self.root = root
        self.manifest = verify_manifest(root)
        if domain not in self.manifest.get('supported_domains', []):
            raise BundleError('unsupported_domain')
        runtime_root = Path(__file__).resolve().parent
        runtime_hashes = self.manifest.get('runtime_code_sha256', {})
        for relative in ('ML/code/preprocess/ecar_tokenizer.py',
                         'ML/code/preprocess/command_syntax.py'):
            expected = runtime_hashes.get(relative)
            deployed = runtime_root / relative
            if (not isinstance(expected, str) or not deployed.is_file() or
                    not hmac.compare_digest(sha256_file(deployed), expected)):
                raise BundleError('tokenizer_runtime_hash_mismatch')
        from ML.code.preprocess.ecar_tokenizer import flatten_tokens, tokenize_record
        import lightgbm
        import numpy as np
        from scipy.sparse import csr_matrix
        self.flatten_tokens = flatten_tokens
        self.tokenize_record = tokenize_record
        self.np = np
        self.csr_matrix = csr_matrix
        self.vocab = json.loads((root / 'preprocess/vocab.json').read_text(encoding='utf-8'))
        self.booster = lightgbm.Booster(model_file=str(root / 'model/model.txt'))
        if self.booster.num_feature() != len(self.vocab):
            raise BundleError('model_vocabulary_width_mismatch')
        self.threshold = float(self.manifest['policy']['threshold'])
        if not 0 <= self.threshold <= 1:
            raise BundleError('threshold_invalid')
        self.bundle_id = self.manifest['bundle_id']
        self.domain = domain
        self.supported_sources = {'sysmon', 'security', 'powershell'}

    @staticmethod
    def _basename(path: str | None) -> str:
        if not path:
            return ''
        return path.replace('/', '\\').rstrip('\\').split('\\')[-1].lower()

    def canonical_record(self, event: dict[str, Any]) -> dict[str, Any] | None:
        kind = event['event_type']
        props: dict[str, Any]
        if kind == 'PROCESS_START':
            obj, action = 'process', 'start'
            props = {'image_path': event.get('process_path'),
                     'parent_image_path': event.get('parent_path'),
                     'command_line': event.get('command_line')}
        elif kind == 'PROCESS_END':
            obj, action, props = 'process', 'terminate', {'image_path': event.get('process_path')}
        elif kind == 'FILE_CREATE':
            obj, action = 'file', 'create'
            props = {'image_path': event.get('process_path'), 'file_path': event.get('object_path')}
        elif kind == 'FILE_DELETE':
            obj, action = 'file', 'delete'
            props = {'image_path': event.get('process_path'), 'file_path': event.get('object_path')}
        elif kind == 'REGISTRY_WRITE':
            obj, action = 'registry', 'modify'
            props = {'image_path': event.get('process_path'), 'key': event.get('object_path')}
        elif kind == 'MODULE_LOAD':
            obj, action = 'module', 'load'
            props = {'image_path': event.get('process_path'), 'module_path': event.get('object_path')}
        elif kind == 'CROSS_PROCESS':
            obj, action, props = 'process', 'open', {'image_path': event.get('process_path')}
        elif kind == 'SCRIPT_BLOCK':
            obj, action = 'shell', 'command'
            props = {'image_path': 'powershell.exe', 'payload': event.get('command_line')}
        else:
            return None
        return {'object': obj, 'action': action, 'principal': event.get('principal'),
                'properties': {key: value for key, value in props.items() if value}}

    def score(self, event: dict[str, Any]) -> tuple[float, list[int]] | None:
        record = self.canonical_record(event)
        if record is None:
            return None
        grouped, _audit = self.tokenize_record(record)
        tokens = self.flatten_tokens(grouped)
        parent = self._basename(event.get('parent_path'))
        if parent:
            tokens.append(f'parent_image::basename={parent}')
        columns = sorted({self.vocab[token] for token in tokens if token in self.vocab})
        data = self.np.ones(len(columns), dtype=self.np.float32)
        indptr = self.np.array([0, len(columns)], dtype=self.np.int32)
        indices = self.np.asarray(columns, dtype=self.np.int32)
        matrix = self.csr_matrix((data, indices, indptr), shape=(1, len(self.vocab)))
        value = float(self.booster.predict(matrix, num_threads=1)[0])
        if not 0 <= value <= 1:
            raise BundleError('model_emitted_invalid_probability')
        return value, columns


def build_score(config: dict, model: HostModel, identity: str, value: float,
                columns: list[int]) -> dict[str, Any]:
    processed = datetime.now(timezone.utc).isoformat()
    payload = {
        'schema_version': 'score.v1', 'host_id': config['host_id'],
        'branch': 'host_ml', 'bundle_id': model.bundle_id,
        'event_refs': [identity], 'window': None, 'status': 'ready_shadow',
        'score': value, 'threshold': model.threshold,
        'prediction': int(value >= model.threshold), 'domain': model.domain,
        'domain_validation': model.manifest.get('domain_validation', 'shadow_unvalidated'),
        'processed_at': processed,
        'evidence': {'nonzero_features': len(columns),
                     'feature_indices_sample': columns[:32],
                     'adapter_version': 'kltn-live-windows-v1'},
    }
    payload['score_id'] = canonical_hash([
        'score.v1', payload['host_id'], payload['branch'], payload['bundle_id'],
        payload['event_refs'], payload['window'], processed,
    ])
    return payload


async def inference_loop(app):
    while True:
        model = app.state.model
        if model is None:
            await asyncio.sleep(5)
            continue
        row = await asyncio.to_thread(app.state.inbox.next_waiting, model.supported_sources)
        if row is None:
            await asyncio.sleep(1)
            continue
        identity, source, raw = row
        try:
            from endpoint_normalization import normalize_endpoint_event
            event = normalize_endpoint_event(app.state.config['host_id'], identity, source, raw)
            result = await asyncio.to_thread(model.score, event)
            if result is None:
                await asyncio.to_thread(app.state.inbox.mark_ignored, identity,
                                        'not_scored_event_type', event)
                continue
            value, columns = result
            score = build_score(app.state.config, model, identity, value, columns)
            await asyncio.to_thread(app.state.inbox.store_score, identity, event, score)
        except Exception as exc:
            await asyncio.to_thread(app.state.inbox.mark_error, identity, type(exc).__name__)
            await asyncio.sleep(1)


def deliver(config: dict, batch: list[tuple[str, str]]) -> None:
    payload = '[' + ','.join(item[1] for item in batch) + ']'
    request = urllib.request.Request(config['central_score_url'], data=payload.encode(),
        headers={'Authorization': 'Bearer ' + config['central_token'],
                 'Content-Type': 'application/json'}, method='POST')
    context = ssl.create_default_context(cafile=config.get('tls_ca'))
    with urllib.request.urlopen(request, timeout=15, context=context) as response:
        if response.status // 100 != 2:
            raise OSError('central score receiver rejected batch')


async def outbox_loop(app):
    while True:
        batch = await asyncio.to_thread(app.state.inbox.outbox_batch)
        if not batch or not app.state.config.get('central_score_url'):
            await asyncio.sleep(5)
            continue
        ids = [row[0] for row in batch]
        try:
            await asyncio.to_thread(deliver, app.state.config, batch)
            await asyncio.to_thread(app.state.inbox.outbox_sent, ids)
        except (OSError, urllib.error.URLError, ssl.SSLError):
            await asyncio.to_thread(app.state.inbox.outbox_failed, ids)
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app):
    config = json.loads(Path(os.environ['KLTN_AGENT_CONFIG']).read_text())
    import lightgbm, numpy, scipy
    app.state.versions = {m.__name__: m.__version__ for m in (lightgbm, numpy, scipy)}
    app.state.config = config
    app.state.inbox = Inbox(config['database'], config['host_id'],
                            config.get('max_rows', 50000), config.get('max_bytes', 128*1024*1024))
    app.state.model = None
    app.state.inference = 'waiting_for_model'
    app.state.bundle_error = None
    if config.get('mode') in READY_STATES and config.get('bundle_path'):
        try:
            app.state.model = HostModel(Path(config['bundle_path']), config['platform_domain'])
            app.state.inference = config['mode']
        except BundleError as exc:
            app.state.bundle_error = str(exc)
            app.state.inference = 'unsupported_domain' if str(exc) == 'unsupported_domain' else 'incompatible_schema'
    tasks = [asyncio.create_task(inference_loop(app)), asyncio.create_task(outbox_loop(app))]
    yield
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(lifespan=lifespan)


@app.get('/healthz')
async def health():
    status = await asyncio.to_thread(app.state.inbox.status)
    model = app.state.model
    return dict(status, status='ok', inference=app.state.inference,
                score=None, bundle_id=model.bundle_id if model else None,
                bundle_error=app.state.bundle_error,
                domain=app.state.config.get('platform_domain'), runtime=app.state.versions)


@app.get('/readyz')
async def ready():
    if app.state.inference not in READY_STATES or app.state.model is None:
        raise HTTPException(503, app.state.bundle_error or 'waiting_for_eligible_model_and_compatible_adapter')
    return {'status': 'ready', 'inference': app.state.inference,
            'bundle_id': app.state.model.bundle_id, 'domain': app.state.model.domain}


@app.post('/v1/raw/{source}')
async def ingest(source: str, request: Request):
    expected = 'Bearer ' + app.state.config['local_token']
    if not hmac.compare_digest(request.headers.get('authorization', ''), expected):
        raise HTTPException(401, 'unauthorized')
    if source not in SOURCES:
        raise HTTPException(422, 'unknown source')
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise HTTPException(413, 'batch too large')
    def invalid_constant(value):
        raise ValueError(value)
    try:
        records = json.loads(body, parse_constant=invalid_constant)
        if isinstance(records, dict):
            records = [records]
        if (not isinstance(records, list) or not 1 <= len(records) <= 2000 or
                any(not isinstance(r, dict) for r in records)):
            raise ValueError('Expected event objects')
        inserted = await asyncio.to_thread(app.state.inbox.put, source, records)
    except (ValueError, UnicodeError):
        raise HTTPException(422, 'expected 1..2000 valid JSON objects')
    except (sqlite3.Error, CapacityError, OSError):
        raise HTTPException(503, 'inbox unavailable or full; retry batch')
    return {'accepted': len(records), 'inserted': inserted, 'inference': app.state.inference}
