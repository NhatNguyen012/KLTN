import asyncio
import hmac
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from nats.js.api import StreamConfig, StorageType, RetentionPolicy, DiscardPolicy
from common import connect_nats, db_connect, event_record, secrets

MAX_BODY = 4 * 1024 * 1024
SOURCES = {'audit', 'journal', 'sysmon', 'security', 'powershell', 'smoke'}


@asynccontextmanager
async def lifespan(app):
    nc = await connect_nats()
    js = nc.jetstream()
    await js.add_stream(config=StreamConfig(name='KLTN_EVENTS', subjects=['kltn.events'],
        storage=StorageType.FILE, retention=RetentionPolicy.WORK_QUEUE,
        max_bytes=1024**3, max_msg_size=1024**2, discard=DiscardPolicy.NEW))
    app.state.js = js
    yield
    await nc.drain()


app = FastAPI(lifespan=lifespan)


def authorized(request, expected):
    return bool(expected) and hmac.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + expected)


@app.get('/healthz')
async def health():
    try:
        await app.state.js.stream_info('KLTN_EVENTS')
    except Exception:
        raise HTTPException(503, 'queue unavailable')
    return {'status': 'ok', 'inference': 'disabled_schema_pending'}


@app.post('/v1/events/{host_id}/{source}')
async def ingest(host_id: str, source: str, request: Request):
    host = secrets()['hosts'].get(host_id)
    if not host or not authorized(request, host['token']):
        raise HTTPException(401, 'unauthorized')
    if source not in SOURCES:
        raise HTTPException(422, 'unknown source')
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise HTTPException(413, 'batch too large')
    try:
        records = json.loads(body)
    except (ValueError, UnicodeError):
        raise HTTPException(400, 'invalid JSON')
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list) or not 1 <= len(records) <= 2000 or any(not isinstance(r, dict) for r in records):
        raise HTTPException(422, 'expected 1..2000 event objects')
    encoded = [json.dumps(event_record(host_id, source, r), ensure_ascii=False).encode() for r in records]
    if any(len(r) > 900000 for r in encoded):
        raise HTTPException(413, 'record too large')
    # Publish ACK precedes HTTP success. Partial retry is safe: DB primary key
    # deduplicates re-delivery even after broker's duplicate detection window.
    try:
        for data in encoded:
            await app.state.js.publish('kltn.events', data)
    except Exception:
        raise HTTPException(503, 'queue unavailable; retry batch')
    return {'accepted': len(records)}


def status_query():
    with db_connect() as conn:
        rows = conn.execute('SELECT host_id, source, count(*), max(received_at) FROM events GROUP BY host_id, source ORDER BY host_id, source').fetchall()
    return [{'host_id': r[0], 'source': r[1], 'count': r[2], 'last_received': r[3].isoformat()} for r in rows]


@app.get('/v1/status')
async def status(request: Request):
    if not authorized(request, secrets()['admin_token']):
        raise HTTPException(401, 'unauthorized')
    try:
        rows = await asyncio.to_thread(status_query)
    except Exception:
        raise HTTPException(503, 'storage unavailable')
    info = await app.state.js.stream_info('KLTN_EVENTS')
    return {'inference': 'disabled_schema_pending', 'queue_pending': info.state.messages, 'sources': rows}
