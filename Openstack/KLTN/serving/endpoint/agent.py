"""Loopback-only, durable model-free inbox. Never produces detection scores."""
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
from contextlib import asynccontextmanager, closing

from fastapi import FastAPI, HTTPException, Request

SOURCES = {'audit', 'journal', 'sysmon', 'security', 'powershell', 'smoke'}
MAX_BODY = 4 * 1024 * 1024


class CapacityError(Exception):
    pass


def event_id(host_id, source, raw):
    identity = {k: v for k, v in raw.items() if k != 'date'}
    data = json.dumps([host_id, source, identity], sort_keys=True,
                      separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


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
            ''')
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
                if rows + 1 > self.max_rows or size + length > self.max_bytes or shutil.disk_usage(self.path.parent).free < self.min_free_bytes:
                    raise CapacityError('Inbox capacity reached; raw archive continues independently')
                db.execute('INSERT INTO inbox(event_id,source,raw,raw_bytes) VALUES (?,?,?,?)', (identity, source, raw, length))
                inserted += 1
                rows += 1
                size += length
            return inserted

    def status(self):
        with closing(self.connect()) as db:
            rows = db.execute('SELECT source,count(*),max(received_at) FROM inbox GROUP BY source').fetchall()
            count, size = db.execute('SELECT count(*),coalesce(sum(raw_bytes),0) FROM inbox').fetchone()
        return {'host_id': self.host_id, 'pending_events': count, 'raw_bytes': size,
                'max_rows': self.max_rows, 'max_raw_bytes': self.max_bytes,
                'capacity_reached': count >= self.max_rows or size >= self.max_bytes,
                'sources': [{'source': s, 'count': n, 'last_received': t} for s,n,t in rows]}


@asynccontextmanager
async def lifespan(app):
    config = json.loads(Path(os.environ['KLTN_AGENT_CONFIG']).read_text())
    # Import now: health must not claim runtime readiness if native libraries fail.
    import lightgbm, numpy, scipy
    app.state.versions = {m.__name__: m.__version__ for m in (lightgbm, numpy, scipy)}
    app.state.config = config
    app.state.inbox = Inbox(config['database'], config['host_id'],
                            config.get('max_rows', 50000), config.get('max_bytes', 128*1024*1024))
    yield


app = FastAPI(lifespan=lifespan)


@app.get('/healthz')
async def health():
    status = await asyncio.to_thread(app.state.inbox.status)
    return dict(status, status='ok', inference='waiting_for_model', score=None,
                adapters='pending_training_contract', runtime=app.state.versions)


@app.get('/readyz')
async def ready():
    raise HTTPException(503, 'waiting_for_model_and_compatible_adapter')


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
        if not isinstance(records, list) or not 1 <= len(records) <= 2000 or any(not isinstance(r, dict) for r in records):
            raise ValueError('Expected event objects')
        inserted = await asyncio.to_thread(app.state.inbox.put, source, records)
    except (ValueError, UnicodeError):
        raise HTTPException(422, 'expected 1..2000 valid JSON objects')
    except (sqlite3.Error, CapacityError, OSError):
        raise HTTPException(503, 'inbox unavailable or full; retry batch')
    return {'accepted': len(records), 'inserted': inserted, 'inference': 'waiting_for_model'}
