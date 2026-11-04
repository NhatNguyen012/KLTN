import asyncio
import hmac
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from nats.js.api import StreamConfig, StorageType, RetentionPolicy, DiscardPolicy
from psycopg.types.json import Jsonb
from common import connect_nats, db_connect, event_record, secrets
from framework import (ContractError, RESPONSE_ACTIONS, REVIEW_DECISIONS,
                       canonical_hash, validate_score)

MAX_BODY = 4 * 1024 * 1024
SOURCES = {'audit', 'journal', 'sysmon', 'security', 'powershell', 'smoke'}


@asynccontextmanager
async def lifespan(app):
    nc = await connect_nats()
    js = nc.jetstream()
    try:
        await js.stream_info('KLTN_EVENTS')
    except Exception:
        try:
            await js.add_stream(config=StreamConfig(name='KLTN_EVENTS', subjects=['kltn.events'],
                storage=StorageType.FILE, retention=RetentionPolicy.WORK_QUEUE,
                max_bytes=512 * 1024 * 1024, max_msg_size=1024**2, discard=DiscardPolicy.NEW))
        except Exception:
            pass
    app.state.js = js
    yield
    await nc.drain()


app = FastAPI(lifespan=lifespan)


def authorized(request, expected):
    return bool(expected) and hmac.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + expected)


def require_admin(request):
    if not authorized(request, secrets()['admin_token']):
        raise HTTPException(401, 'unauthorized')


async def json_body(request, maximum=MAX_BODY):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise HTTPException(413, 'body too large')
    try:
        return json.loads(body)
    except (ValueError, UnicodeError):
        raise HTTPException(400, 'invalid JSON')


def authenticated_score_host(request):
    if authorized(request, secrets()['admin_token']):
        return None
    for host_id, host in secrets()['hosts'].items():
        if authorized(request, host['token']):
            return host_id
    raise HTTPException(401, 'unauthorized')


@app.get('/healthz')
async def health():
    try:
        await app.state.js.stream_info('KLTN_EVENTS')
    except Exception:
        raise HTTPException(503, 'queue unavailable')
    return {'status': 'ok', 'framework': 'model_gated', 'inference': 'bundle_dependent'}


@app.post('/v1/events/{host_id}/{source}')
async def ingest(host_id: str, source: str, request: Request):
    host = secrets()['hosts'].get(host_id)
    if not host or not authorized(request, host['token']):
        raise HTTPException(401, 'unauthorized')
    if source not in SOURCES:
        raise HTTPException(422, 'unknown source')
    records = await json_body(request)
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


def store_scores(records):
    inserted = 0
    with db_connect() as conn:
        for score in records:
            row = conn.execute('''INSERT INTO scores(
              score_id,schema_version,host_id,branch,bundle_id,status,score,threshold,
              prediction,domain,domain_validation,event_refs,score_window,evidence,processed_at)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
              ON CONFLICT(score_id) DO NOTHING RETURNING score_id''',
              (score['score_id'], score['schema_version'], score['host_id'], score['branch'],
               score['bundle_id'], score['status'], score['score'], score['threshold'],
               score['prediction'], score['domain'], score['domain_validation'],
               Jsonb(score['event_refs']), Jsonb(score['window']) if score['window'] else None,
               Jsonb(score['evidence']), score['processed_at'])).fetchone()
            inserted += int(row is not None)
    return inserted


@app.post('/v1/scores')
async def ingest_scores(request: Request):
    host_id = authenticated_score_host(request)
    payload = await json_body(request)
    records = payload if isinstance(payload, list) else [payload]
    if not 1 <= len(records) <= 500:
        raise HTTPException(422, 'expected 1..500 score objects')
    try:
        validated = [validate_score(item, host_id) for item in records]
    except ContractError as exc:
        raise HTTPException(422, str(exc))
    try:
        inserted = await asyncio.to_thread(store_scores, validated)
    except Exception:
        raise HTTPException(503, 'score storage unavailable; retry batch')
    return {'accepted': len(validated), 'inserted': inserted}


def status_query():
    with db_connect() as conn:
        rows = conn.execute('SELECT host_id, source, count(*), max(received_at) FROM events GROUP BY host_id, source ORDER BY host_id, source').fetchall()
    return [{'host_id': r[0], 'source': r[1], 'count': r[2], 'last_received': r[3].isoformat()} for r in rows]


@app.get('/v1/status')
async def status(request: Request):
    require_admin(request)
    try:
        rows = await asyncio.to_thread(status_query)
    except Exception:
        raise HTTPException(503, 'storage unavailable')
    info = await app.state.js.stream_info('KLTN_EVENTS')
    return {'framework': 'model_gated', 'queue_pending': info.state.messages, 'sources': rows}


def framework_status_query():
    with db_connect() as conn:
        tables = {}
        for name in ('events', 'normalized_events', 'scores', 'fusion_results', 'alerts',
                     'model_registry', 'training_requests', 'response_requests'):
            tables[name] = conn.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
        services = conn.execute('SELECT service,updated_at,state,pending,runtime FROM serving_status ORDER BY service').fetchall()
        models = conn.execute('SELECT bundle_id,branch,algorithm,stage,domain_validation,created_at,activated_at FROM model_registry ORDER BY created_at DESC').fetchall()
    return {
        'counts': tables,
        'services': [{'service': r[0], 'updated_at': r[1].isoformat(), 'state': r[2],
                      'pending': r[3], 'runtime': r[4]} for r in services],
        'models': [{'bundle_id': r[0], 'branch': r[1], 'algorithm': r[2], 'stage': r[3],
                    'domain_validation': r[4], 'created_at': r[5].isoformat(),
                    'activated_at': r[6].isoformat() if r[6] else None} for r in models],
    }


@app.get('/v1/framework/status')
async def framework_status(request: Request):
    require_admin(request)
    try:
        return await asyncio.to_thread(framework_status_query)
    except Exception:
        raise HTTPException(503, 'framework storage unavailable')


def list_alerts_query(limit, state):
    query = 'SELECT alert_id,host_id,risk_score,state,severity,evidence,created_at,updated_at FROM alerts'
    params = []
    if state:
        query += ' WHERE state=%s'
        params.append(state)
    query += ' ORDER BY created_at DESC LIMIT %s'
    params.append(limit)
    with db_connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{'alert_id': r[0], 'host_id': r[1], 'risk_score': r[2], 'state': r[3],
             'severity': r[4], 'evidence': r[5], 'created_at': r[6].isoformat(),
             'updated_at': r[7].isoformat()} for r in rows]


@app.get('/v1/alerts')
async def list_alerts(request: Request, limit: int = 100, state: str | None = None):
    require_admin(request)
    if not 1 <= limit <= 1000:
        raise HTTPException(422, 'limit must be 1..1000')
    return {'alerts': await asyncio.to_thread(list_alerts_query, limit, state)}


def alert_detail_query(alert_id: str):
    with db_connect() as conn:
        alert_row = conn.execute(
            '''SELECT alert_id, fusion_id, host_id, risk_score, state, severity,
                      evidence, created_at, updated_at
               FROM alerts WHERE alert_id = %s''', (alert_id,)
        ).fetchone()
        if not alert_row:
            return None

        rev_rows = conn.execute(
            '''SELECT review_id, decision, reviewer, notes, created_at
               FROM alert_reviews WHERE alert_id = %s ORDER BY created_at ASC''', (alert_id,)
        ).fetchall()
        reviews = [{
            'review_id': r[0], 'decision': r[1], 'reviewer': r[2], 'notes': r[3],
            'created_at': r[4].isoformat()
        } for r in rev_rows]

        evidence = alert_row[6] or {}
        event_refs = []
        branches = evidence.get('branches', {})
        for branch_name, branch_data in branches.items():
            if isinstance(branch_data, dict):
                refs = branch_data.get('event_refs', [])
                if isinstance(refs, list):
                    event_refs.extend(refs)
        event_refs = sorted(set(event_refs))

        events = []
        if event_refs:
            ev_rows = conn.execute(
                '''SELECT event_id, source, event_type, event_time, received_at,
                          process_path, parent_path, command_line, principal,
                          object_path, network
                   FROM normalized_events WHERE event_id = ANY(%s)
                   ORDER BY COALESCE(event_time, received_at) ASC''', (event_refs,)
            ).fetchall()
            events = [{
                'event_id': er[0], 'source': er[1], 'event_type': er[2],
                'event_time': er[3].isoformat() if er[3] else None,
                'received_at': er[4].isoformat(),
                'process_path': er[5], 'parent_path': er[6], 'command_line': er[7],
                'principal': er[8], 'object_path': er[9], 'network': er[10]
            } for er in ev_rows]

        return {
            'alert_id': alert_row[0],
            'fusion_id': alert_row[1],
            'host_id': alert_row[2],
            'risk_score': alert_row[3],
            'state': alert_row[4],
            'severity': alert_row[5],
            'evidence': evidence,
            'created_at': alert_row[7].isoformat(),
            'updated_at': alert_row[8].isoformat(),
            'reviews': reviews,
            'events': events,
        }


@app.get('/v1/alerts/{alert_id}')
async def alert_detail(alert_id: str, request: Request):
    require_admin(request)
    detail = await asyncio.to_thread(alert_detail_query, alert_id)
    if detail is None:
        raise HTTPException(404, 'alert not found')
    return detail


def verified_dataset_query():
    with db_connect() as conn:
        rows = conn.execute(
            '''SELECT a.alert_id, a.host_id, a.state, a.risk_score, a.evidence,
                      r.decision, r.reviewer, r.notes, r.created_at
               FROM alerts a
               JOIN LATERAL (
                   SELECT decision, reviewer, notes, created_at
                   FROM alert_reviews
                   WHERE alert_id = a.alert_id
                   ORDER BY created_at DESC LIMIT 1
               ) r ON true
               WHERE a.state IN ('confirmed', 'false_positive')
               ORDER BY r.created_at DESC LIMIT 1000'''
        ).fetchall()
        dataset = []
        for row in rows:
            alert_id = row[0]
            label = 1 if row[2] == 'confirmed' else 0
            evidence = row[4] or {}
            dataset.append({
                'alert_id': alert_id,
                'host_id': row[1],
                'decision': row[2],
                'label': label,
                'risk_score': row[3],
                'reviewer': row[6],
                'notes': row[7],
                'reviewed_at': row[8].isoformat(),
                'branches': evidence.get('branches', {}),
                'source_mask': evidence.get('source_mask', {}),
            })
        return dataset


@app.get('/v1/soc/verified-dataset')
async def soc_verified_dataset(request: Request):
    require_admin(request)
    return {'dataset': await asyncio.to_thread(verified_dataset_query)}


def review_alert(alert_id, decision, reviewer, notes):
    review_id = canonical_hash(['review.v1', alert_id, decision, reviewer, notes])
    with db_connect() as conn:
        if not conn.execute('SELECT 1 FROM alerts WHERE alert_id=%s', (alert_id,)).fetchone():
            return None
        conn.execute('''INSERT INTO alert_reviews(review_id,alert_id,decision,reviewer,notes)
          VALUES (%s,%s,%s,%s,%s) ON CONFLICT(review_id) DO NOTHING''',
          (review_id, alert_id, decision, reviewer, notes))
        conn.execute('UPDATE alerts SET state=%s,updated_at=now() WHERE alert_id=%s',
                     (decision, alert_id))
    return review_id


@app.post('/v1/alerts/{alert_id}/reviews')
async def create_review(alert_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    decision = payload.get('decision') if isinstance(payload, dict) else None
    reviewer = payload.get('reviewer') if isinstance(payload, dict) else None
    notes = payload.get('notes', '') if isinstance(payload, dict) else ''
    if decision not in REVIEW_DECISIONS or not isinstance(reviewer, str) or not reviewer.strip():
        raise HTTPException(422, 'invalid decision or reviewer')
    if not isinstance(notes, str) or len(notes) > 10000:
        raise HTTPException(422, 'invalid notes')
    review_id = await asyncio.to_thread(review_alert, alert_id, decision, reviewer[:256], notes)
    if review_id is None:
        raise HTTPException(404, 'alert not found')
    return {'review_id': review_id, 'state': decision}


def register_model(manifest):
    required = ('bundle_id', 'branch', 'algorithm', 'domain_validation', 'artifacts')
    if any(key not in manifest for key in required):
        raise ContractError('incomplete bundle manifest')
    if manifest['branch'] not in {'host_ml', 'network_dl', 'fusion'}:
        raise ContractError('unsupported model branch')
    if manifest['domain_validation'] not in {'validated', 'shadow_unvalidated', 'unsupported'}:
        raise ContractError('invalid domain validation')
    digest = canonical_hash(manifest)
    with db_connect() as conn:
        existing = conn.execute('SELECT manifest_sha256 FROM model_registry WHERE bundle_id=%s',
                                (manifest['bundle_id'],)).fetchone()
        if existing and not hmac.compare_digest(existing[0], digest):
            raise ContractError('bundle_id is immutable; publish a new bundle ID')
        conn.execute('''INSERT INTO model_registry(bundle_id,branch,algorithm,manifest_sha256,
          manifest,stage,domain_validation) VALUES (%s,%s,%s,%s,%s,'candidate',%s)
          ON CONFLICT(bundle_id) DO NOTHING''',
          (manifest['bundle_id'], manifest['branch'], manifest['algorithm'], digest,
           Jsonb(manifest), manifest['domain_validation']))
    return digest


@app.post('/v1/models')
async def model_register(request: Request):
    require_admin(request)
    manifest = await json_body(request)
    if not isinstance(manifest, dict):
        raise HTTPException(422, 'manifest must be an object')
    try:
        digest = await asyncio.to_thread(register_model, manifest)
    except ContractError as exc:
        raise HTTPException(422, str(exc))
    return {'bundle_id': manifest['bundle_id'], 'manifest_sha256': digest, 'stage': 'candidate'}


def activate_model(bundle_id):
    with db_connect() as conn:
        row = conn.execute('SELECT branch, manifest, domain_validation FROM model_registry WHERE bundle_id=%s',
                           (bundle_id,)).fetchone()
        if not row:
            return 'missing', None
        branch, manifest, validation = row
        eligible = bool(manifest.get('activation', {}).get('eligible'))
        parity = manifest.get('parity', {})
        if not eligible or validation != 'validated' or parity.get('passed') is not True:
            return 'blocked', None

        # Find previous active bundle for this branch and retire it
        prev = conn.execute(
            "SELECT bundle_id FROM model_registry WHERE branch=%s AND stage='active' AND bundle_id <> %s",
            (branch, bundle_id)
        ).fetchone()
        previous_bundle_id = prev[0] if prev else None
        if previous_bundle_id:
            conn.execute("UPDATE model_registry SET stage='retired' WHERE bundle_id=%s", (previous_bundle_id,))

        manifest['previous_bundle_id'] = previous_bundle_id
        conn.execute("UPDATE model_registry SET stage='active', manifest=%s, activated_at=now() WHERE bundle_id=%s",
                     (Jsonb(manifest), bundle_id))

        # Record rollout
        rollout_id = canonical_hash(['rollout.v1', bundle_id, 'promote_active', datetime.now(timezone.utc).isoformat()])
        conn.execute(
            '''INSERT INTO deployment_rollouts(rollout_id, bundle_id, target, mode, state, details)
               VALUES (%s, %s, %s, %s, %s, %s)''',
            (rollout_id, bundle_id, 'cluster', 'active', 'healthy',
             Jsonb({'previous_bundle_id': previous_bundle_id}))
        )
    return 'active', previous_bundle_id


@app.post('/v1/models/{bundle_id}/activate')
async def model_activate(bundle_id: str, request: Request):
    require_admin(request)
    state, prev_id = await asyncio.to_thread(activate_model, bundle_id)
    if state == 'missing':
        raise HTTPException(404, 'bundle not found')
    if state == 'blocked':
        raise HTTPException(409, 'bundle activation blocked by eligibility, parity, or domain validation')
    return {'bundle_id': bundle_id, 'stage': state, 'previous_bundle_id': prev_id}


def rollback_model(bundle_id: str, reason: str):
    with db_connect() as conn:
        row = conn.execute('SELECT branch, manifest, stage FROM model_registry WHERE bundle_id=%s',
                           (bundle_id,)).fetchone()
        if not row:
            return 'missing', None
        branch, manifest, current_stage = row
        prev_id = manifest.get('previous_bundle_id')
        if not prev_id:
            return 'no_previous_bundle', None

        conn.execute("UPDATE model_registry SET stage='rolled_back' WHERE bundle_id=%s", (bundle_id,))
        conn.execute("UPDATE model_registry SET stage='active', activated_at=now() WHERE bundle_id=%s", (prev_id,))

        rollout_id = canonical_hash(['rollout.v1', bundle_id, 'rollback', datetime.now(timezone.utc).isoformat()])
        conn.execute(
            '''INSERT INTO deployment_rollouts(rollout_id, bundle_id, target, mode, state, details)
               VALUES (%s, %s, %s, %s, %s, %s)''',
            (rollout_id, bundle_id, 'cluster', 'rollback', 'rolled_back',
             Jsonb({'reason': reason, 'restored_bundle_id': prev_id}))
        )
    return 'rolled_back', prev_id


@app.post('/v1/models/{bundle_id}/rollback')
async def model_rollback(bundle_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    reason = payload.get('reason', 'manual rollback') if isinstance(payload, dict) else 'manual rollback'
    state, restored_id = await asyncio.to_thread(rollback_model, bundle_id, str(reason)[:500])
    if state == 'missing':
        raise HTTPException(404, 'bundle not found')
    if state == 'no_previous_bundle':
        raise HTTPException(409, 'no previous active bundle exists to rollback to')
    return {'bundle_id': bundle_id, 'stage': state, 'restored_bundle_id': restored_id}


def record_rollout(bundle_id: str, target: str, mode: str, state: str, details: dict):
    rollout_id = canonical_hash(['rollout.v1', bundle_id, target, mode, datetime.now(timezone.utc).isoformat()])
    with db_connect() as conn:
        conn.execute(
            '''INSERT INTO deployment_rollouts(rollout_id, bundle_id, target, mode, state, details)
               VALUES (%s, %s, %s, %s, %s, %s)''',
            (rollout_id, bundle_id, target, mode, state, Jsonb(details))
        )
    return rollout_id


@app.post('/v1/models/{bundle_id}/rollouts')
async def model_rollout(bundle_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    if not isinstance(payload, dict):
        raise HTTPException(422, 'expected JSON object')
    target = payload.get('target', 'canary')
    mode = payload.get('mode', 'canary')
    state = payload.get('state', 'in_progress')
    details = payload.get('details', {})
    rollout_id = await asyncio.to_thread(record_rollout, bundle_id, str(target), str(mode), str(state), details)
    return {'rollout_id': rollout_id, 'bundle_id': bundle_id, 'target': target, 'state': state}


def create_response(alert_id, action, requested_by):
    with db_connect() as conn:
        row = conn.execute('SELECT host_id,state FROM alerts WHERE alert_id=%s', (alert_id,)).fetchone()
        if not row:
            return None
        if row[1] != 'confirmed':
            raise ContractError('response requires a confirmed SOC review')
        request_id = canonical_hash(['response.v1', alert_id, row[0], action])
        conn.execute('''INSERT INTO response_requests(request_id,alert_id,host_id,action,requested_by)
          VALUES (%s,%s,%s,%s,%s) ON CONFLICT(request_id) DO NOTHING''',
          (request_id, alert_id, row[0], action, requested_by))
    return request_id


@app.post('/v1/alerts/{alert_id}/responses')
async def response_request(alert_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    action = payload.get('action') if isinstance(payload, dict) else None
    requested_by = payload.get('requested_by') if isinstance(payload, dict) else None
    if action not in RESPONSE_ACTIONS or not isinstance(requested_by, str) or not requested_by.strip():
        raise HTTPException(422, 'invalid response action or requester')
    try:
        request_id = await asyncio.to_thread(create_response, alert_id, action, requested_by[:256])
    except ContractError as exc:
        raise HTTPException(409, str(exc))
    if request_id is None:
        raise HTTPException(404, 'alert not found')
    return {'request_id': request_id, 'state': 'pending_approval',
            'note': 'OpenStack execution is a separate explicit controller step'}


def list_responses_query(state):
    query = '''SELECT request_id,alert_id,host_id,action,state,requested_by,
      approved_by,execution,created_at,updated_at FROM response_requests'''
    params = []
    if state:
        query += ' WHERE state=%s'
        params.append(state)
    query += ' ORDER BY created_at DESC LIMIT 500'
    with db_connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{'request_id': r[0], 'alert_id': r[1], 'host_id': r[2], 'action': r[3],
             'state': r[4], 'requested_by': r[5], 'approved_by': r[6],
             'execution': r[7], 'created_at': r[8].isoformat(),
             'updated_at': r[9].isoformat()} for r in rows]


@app.get('/v1/responses')
async def list_responses(request: Request, state: str | None = None):
    require_admin(request)
    return {'responses': await asyncio.to_thread(list_responses_query, state)}


def approve_response(request_id, approved_by):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM response_requests WHERE request_id=%s FOR UPDATE',
                           (request_id,)).fetchone()
        if not row:
            return 'missing'
        if row[0] != 'pending_approval':
            return row[0]
        conn.execute('''UPDATE response_requests SET state='approved',approved_by=%s,
          updated_at=now() WHERE request_id=%s''', (approved_by, request_id))
    return 'approved'


@app.post('/v1/responses/{request_id}/approve')
async def response_approve(request_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    approved_by = payload.get('approved_by') if isinstance(payload, dict) else None
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise HTTPException(422, 'approved_by is required')
    state = await asyncio.to_thread(approve_response, request_id, approved_by[:256])
    if state == 'missing':
        raise HTTPException(404, 'response request not found')
    return {'request_id': request_id, 'state': state}


def list_training_query(state):
    query = '''SELECT request_id,branch,trigger_type,state,dataset_query,
      trigger_evidence,created_at,approved_at,completed_at FROM training_requests'''
    params = []
    if state:
        query += ' WHERE state=%s'
        params.append(state)
    query += ' ORDER BY created_at DESC LIMIT 500'
    with db_connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{'request_id': r[0], 'branch': r[1], 'trigger_type': r[2], 'state': r[3],
             'dataset_query': r[4], 'trigger_evidence': r[5],
             'created_at': r[6].isoformat(),
             'approved_at': r[7].isoformat() if r[7] else None,
             'completed_at': r[8].isoformat() if r[8] else None} for r in rows]


@app.get('/v1/training/requests')
async def training_requests(request: Request, state: str | None = None):
    require_admin(request)
    return {'requests': await asyncio.to_thread(list_training_query, state)}


def approve_training(request_id):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM training_requests WHERE request_id=%s FOR UPDATE',
                           (request_id,)).fetchone()
        if not row:
            return 'missing'
        if row[0] == 'pending_approval':
            conn.execute("UPDATE training_requests SET state='approved',approved_at=now() WHERE request_id=%s",
                         (request_id,))
            return 'approved'
        return row[0]


@app.post('/v1/training/requests/{request_id}/approve')
async def training_approve(request_id: str, request: Request):
    require_admin(request)
    state = await asyncio.to_thread(approve_training, request_id)
    if state == 'missing':
        raise HTTPException(404, 'training request not found')
    return {'request_id': request_id, 'state': state,
            'note': 'approval does not run a notebook; an external runner must claim it'}


def claim_training(request_id, runner_id):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM training_requests WHERE request_id=%s FOR UPDATE', (request_id,)).fetchone()
        if not row:
            return 'missing'
        if row[0] != 'approved':
            return row[0]
        conn.execute("UPDATE training_requests SET state='running', trigger_evidence = jsonb_set(COALESCE(trigger_evidence, '{}'::jsonb), '{claimed_by}', %s) WHERE request_id=%s",
                     (Jsonb(runner_id), request_id))
    return 'running'


@app.post('/v1/training/requests/{request_id}/claim')
async def training_claim(request_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    runner_id = payload.get('runner_id', 'runner-default') if isinstance(payload, dict) else 'runner-default'
    state = await asyncio.to_thread(claim_training, request_id, str(runner_id))
    if state == 'missing':
        raise HTTPException(404, 'training request not found')
    return {'request_id': request_id, 'state': state}


def complete_training(request_id, bundle_id, metrics):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM training_requests WHERE request_id=%s FOR UPDATE', (request_id,)).fetchone()
        if not row:
            return 'missing'
        conn.execute('''UPDATE training_requests SET state='completed', completed_at=now(),
          trigger_evidence = jsonb_set(jsonb_set(COALESCE(trigger_evidence, '{}'::jsonb), '{candidate_bundle_id}', %s), '{candidate_metrics}', %s)
          WHERE request_id=%s''', (Jsonb(bundle_id), Jsonb(metrics), request_id))
    return 'completed'


@app.post('/v1/training/requests/{request_id}/complete')
async def training_complete(request_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 256 * 1024)
    bundle_id = payload.get('candidate_bundle_id') if isinstance(payload, dict) else None
    metrics = payload.get('metrics', {}) if isinstance(payload, dict) else {}
    if not bundle_id:
        raise HTTPException(422, 'candidate_bundle_id is required')
    state = await asyncio.to_thread(complete_training, request_id, bundle_id, metrics)
    if state == 'missing':
        raise HTTPException(404, 'training request not found')
    return {'request_id': request_id, 'state': state}


def claim_response(request_id, executor_id):
    with db_connect() as conn:
        row = conn.execute('SELECT state, alert_id, host_id, action FROM response_requests WHERE request_id=%s FOR UPDATE', (request_id,)).fetchone()
        if not row:
            return 'missing', None
        if row[0] != 'approved':
            return row[0], None
        conn.execute("UPDATE response_requests SET state='executing', execution = jsonb_set(COALESCE(execution, '{}'::jsonb), '{claimed_by}', %s) WHERE request_id=%s",
                     (Jsonb(executor_id), request_id))
    return 'executing', {'alert_id': row[1], 'host_id': row[2], 'action': row[3]}


@app.post('/v1/responses/{request_id}/claim')
async def response_claim(request_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 64 * 1024)
    executor_id = payload.get('executor_id', 'controller-default') if isinstance(payload, dict) else 'controller-default'
    state, details = await asyncio.to_thread(claim_response, request_id, str(executor_id))
    if state == 'missing':
        raise HTTPException(404, 'response request not found')
    return {'request_id': request_id, 'state': state, 'details': details}


def complete_response(request_id, execution_details):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM response_requests WHERE request_id=%s FOR UPDATE', (request_id,)).fetchone()
        if not row:
            return 'missing'
        conn.execute("UPDATE response_requests SET state='completed', execution = %s, updated_at=now() WHERE request_id=%s",
                     (Jsonb(execution_details), request_id))
    return 'completed'


@app.post('/v1/responses/{request_id}/complete')
async def response_complete(request_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 128 * 1024)
    details = payload.get('execution', {}) if isinstance(payload, dict) else {}
    state = await asyncio.to_thread(complete_response, request_id, details)
    if state == 'missing':
        raise HTTPException(404, 'response request not found')
    return {'request_id': request_id, 'state': state}


def fail_response(request_id, error_details):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM response_requests WHERE request_id=%s FOR UPDATE', (request_id,)).fetchone()
        if not row:
            return 'missing'
        conn.execute("UPDATE response_requests SET state='failed', execution = %s, updated_at=now() WHERE request_id=%s",
                     (Jsonb(error_details), request_id))
    return 'failed'


@app.post('/v1/responses/{request_id}/fail')
async def response_fail(request_id: str, request: Request):
    require_admin(request)
    payload = await json_body(request, 128 * 1024)
    details = payload.get('error', {}) if isinstance(payload, dict) else {}
    state = await asyncio.to_thread(fail_response, request_id, details)
    if state == 'missing':
        raise HTTPException(404, 'response request not found')
    return {'request_id': request_id, 'state': state}


SOC_HTML = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>KLTN SOC Analyst Workspace</title>
<style>
:root{--primary:#1e40af;--bg:#f8fafc;--card:#ffffff;--border:#e2e8f0;--text:#0f172a;--text-muted:#64748b;--danger:#dc2626;--warning:#d97706;--success:#16a34a;--info:#0284c7}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);padding:1.5rem}
.header{display:flex;justify-content:space-between;align-items:center;background:var(--card);padding:1rem 1.5rem;border-radius:.5rem;border:1px solid var(--border);margin-bottom:1.5rem}
.header h1{font-size:1.4rem;font-weight:700;display:flex;align-items:center;gap:.5rem}
.auth-bar{display:flex;align-items:center;gap:.75rem}
input,select,textarea{padding:.5rem .75rem;border:1px solid var(--border);border-radius:.375rem;font-size:.9rem}
button{padding:.5rem 1rem;background:var(--primary);color:#fff;border:none;border-radius:.375rem;cursor:pointer;font-weight:600;font-size:.9rem;transition:opacity .15s}
button:hover{opacity:.9}
.btn-success{background:var(--success)}.btn-warning{background:var(--warning)}.btn-secondary{background:var(--text-muted)}
.btn-sm{padding:.3rem .6rem;font-size:.8rem}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--card);padding:1rem;border-radius:.5rem;border:1px solid var(--border);text-align:center}
.stat-val{font-size:1.8rem;font-weight:700;color:var(--primary)}
.stat-lbl{font-size:.8rem;color:var(--text-muted);text-transform:uppercase}
.layout{display:grid;grid-template-columns:42% 58%;gap:1.5rem;align-items:start}
.panel{background:var(--card);border-radius:.5rem;border:1px solid var(--border);padding:1rem;max-height:calc(100vh - 220px);overflow-y:auto}
.panel-title{font-size:1.1rem;font-weight:700;margin-bottom:1rem;display:flex;justify-content:space-between;align-items:center}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{padding:.6rem .75rem;border-bottom:1px solid var(--border);text-align:left}
th{background:#f1f5f9;color:var(--text-muted);font-weight:600}
tr.clickable{cursor:pointer}tr.clickable:hover{background:#f8fafc}
tr.selected{background:#eff6ff;border-left:3px solid var(--primary)}
.badge{padding:.2rem .5rem;border-radius:1rem;font-size:.75rem;font-weight:700;display:inline-block}
.badge-critical{background:#fee2e2;color:#b91c1c}.badge-high{background:#fef3c7;color:#b45309}.badge-medium{background:#e0f2fe;color:#0369a1}
.badge-state{background:#f1f5f9;color:var(--text-muted)}.badge-confirmed{background:#dcfce7;color:#15803d}.badge-fp{background:#fee2e2;color:#b91c1c}
.card-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin:1rem 0}
.sub-card{background:#f8fafc;padding:.75rem;border-radius:.375rem;border:1px solid var(--border)}
.sub-card-title{font-weight:700;font-size:.85rem;margin-bottom:.3rem;color:var(--primary)}
.timeline{list-style:none;margin-top:.75rem;padding-left:1rem;border-left:2px solid var(--border)}
.timeline-item{position:relative;margin-bottom:1rem}
.timeline-item::before{content:"";position:absolute;left:-1.35rem;top:.2rem;width:.6rem;height:.6rem;border-radius:50%;background:var(--primary)}
.timeline-time{font-size:.75rem;color:var(--text-muted)}
.action-box{margin-top:1.5rem;padding:1rem;background:#f8fafc;border-radius:.5rem;border:1px solid var(--border)}
.evidence-box{background:#0f172a;color:#e2e8f0;padding:.75rem;border-radius:.375rem;font-family:monospace;font-size:.8rem;max-height:200px;overflow-y:auto;white-space:pre-wrap;margin-top:.5rem}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ KLTN Unified SOC Portal</h1>
  <div class="auth-bar">
    <input id="token" type="password" placeholder="Admin Bearer Token" size="32" autocomplete="off">
    <button onclick="loadAlerts()">Load Alerts</button>
    <a href="/v1/soc/verified-dataset" target="_blank" style="text-decoration:none"><button class="btn-secondary" type="button">Export Verified Dataset</button></a>
  </div>
</div>

<div class="stats-row">
  <div class="stat-card"><div class="stat-val" id="stat-total">0</div><div class="stat-lbl">Total Alerts</div></div>
  <div class="stat-card"><div class="stat-val" id="stat-pending">0</div><div class="stat-lbl">Needs Review</div></div>
  <div class="stat-card"><div class="stat-val" id="stat-confirmed" style="color:var(--danger)">0</div><div class="stat-lbl">Confirmed Attacks</div></div>
  <div class="stat-card"><div class="stat-val" id="stat-fp" style="color:var(--success)">0</div><div class="stat-lbl">False Positives</div></div>
</div>

<div class="layout">
  <div class="panel">
    <div class="panel-title">
      <span>Alert Queue</span>
      <select id="stateFilter" onchange="filterAlerts()" style="font-size:.8rem;padding:.2rem .4rem">
        <option value="">All States</option>
        <option value="needs_review">Needs Review</option>
        <option value="confirmed">Confirmed</option>
        <option value="false_positive">False Positive</option>
        <option value="dismissed">Dismissed</option>
      </select>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Host</th><th>Risk</th><th>Severity</th><th>State</th></tr></thead>
      <tbody id="alertRows"><tr><td colspan="5" style="text-align:center;color:var(--text-muted)">Enter token and click Load Alerts</td></tr></tbody>
    </table>
  </div>

  <div class="panel" id="detailPanel">
    <div class="panel-title"><span>Evidence & Review Drill-down</span><span id="selectedAlertId" style="font-size:.8rem;font-weight:400;color:var(--text-muted)"></span></div>
    <div id="detailContent" style="color:var(--text-muted);text-align:center;padding:3rem">Select an alert from the left panel to inspect model scores and evidence.</div>
  </div>
</div>

<script>
let allAlerts = [];
let currentAlert = null;

function getToken(){
  return document.querySelector('#token').value.trim();
}

async function loadAlerts(){
  let t = getToken();
  if(!t){ alert('Please enter the central admin token'); return; }
  try{
    let r = await fetch('/v1/alerts?limit=500', {headers: {Authorization: 'Bearer ' + t}});
    if(!r.ok){ alert('HTTP ' + r.status + ': Failed to load alerts'); return; }
    let data = await r.json();
    allAlerts = data.alerts || [];
    updateStats();
    renderAlertTable(allAlerts);
  }catch(e){ alert('Error loading alerts: ' + e); }
}

function updateStats(){
  let total = allAlerts.length;
  let confirmed = allAlerts.filter(a => a.state === 'confirmed').length;
  let fp = allAlerts.filter(a => a.state === 'false_positive').length;
  let pending = allAlerts.filter(a => a.state === 'needs_review' || !a.state).length;
  document.querySelector('#stat-total').textContent = total;
  document.querySelector('#stat-confirmed').textContent = confirmed;
  document.querySelector('#stat-fp').textContent = fp;
  document.querySelector('#stat-pending').textContent = pending;
}

function filterAlerts(){
  let state = document.querySelector('#stateFilter').value;
  let filtered = state ? allAlerts.filter(a => a.state === state || (!a.state && state==='needs_review')) : allAlerts;
  renderAlertTable(filtered);
}

function renderAlertTable(list){
  let tbody = document.querySelector('#alertRows');
  if(!list.length){ tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No alerts match filter</td></tr>'; return; }
  tbody.innerHTML = list.map(a => {
    let state = a.state || 'needs_review';
    let sClass = state === 'confirmed' ? 'badge-confirmed' : (state === 'false_positive' ? 'badge-fp' : 'badge-state');
    let isSel = currentAlert && currentAlert.alert_id === a.alert_id ? 'selected' : '';
    return `<tr class="clickable ${isSel}" onclick="selectAlert('${a.alert_id}')">
      <td>${a.created_at.slice(11,19)}</td>
      <td>${a.host_id}</td>
      <td><strong>${(a.risk_score || 0).toFixed(4)}</strong></td>
      <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
      <td><span class="badge ${sClass}">${state}</span></td>
    </tr>`;
  }).join('');
}

async function selectAlert(alertId){
  let t = getToken();
  let r = await fetch('/v1/alerts/' + alertId, {headers: {Authorization: 'Bearer ' + t}});
  if(!r.ok){ alert('Failed to fetch alert details'); return; }
  currentAlert = await r.json();
  renderAlertTable(allAlerts);
  renderDetail();
}

function renderDetail(){
  let a = currentAlert;
  if(!a) return;
  document.querySelector('#selectedAlertId').textContent = 'ID: ' + a.alert_id.slice(0, 16) + '...';
  let ev = a.evidence || {};
  let branches = ev.branches || {};
  let host = branches.host_ml || {};
  let net = branches.network_dl || {};
  let mask = ev.source_mask || {};

  let reviewsHtml = (a.reviews || []).map(r => `
    <li class="timeline-item">
      <div><strong>${r.reviewer}</strong> marked as <span class="badge badge-state">${r.decision}</span></div>
      <div style="margin-top:.2rem;font-size:.85rem">${r.notes || 'No notes provided'}</div>
      <div class="timeline-time">${r.created_at}</div>
    </li>
  `).join('');

  let eventsHtml = (a.events || []).map(e => `
    <tr>
      <td>${e.source}</td>
      <td><strong>${e.event_type}</strong></td>
      <td>${e.process_path || '-'}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.command_line || (e.network ? JSON.stringify(e.network) : '-')}</td>
    </tr>
  `).join('');

  document.querySelector('#detailContent').innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <div>
        <h2>Host: ${a.host_id}</h2>
        <div style="font-size:.8rem;color:var(--text-muted)">Created: ${a.created_at}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:1.4rem;font-weight:700;color:var(--danger)">Risk: ${(a.risk_score || 0).toFixed(4)}</div>
        <span class="badge badge-${a.severity}">${a.severity}</span>
        <span class="badge badge-state">State: ${a.state || 'needs_review'}</span>
      </div>
    </div>

    <div class="card-grid">
      <div class="sub-card">
        <div class="sub-card-title">Host ML (LightGBM)</div>
        <div>Score: <strong>${host.score !== undefined ? Number(host.score).toFixed(4) : 'N/A'}</strong></div>
        <div style="font-size:.75rem;color:var(--text-muted)">Bundle: ${host.bundle_id || 'N/A'}</div>
        <div style="font-size:.75rem">Mask: ${mask.host_ml ? 'Active' : 'Missing'} | Domain: ${host.domain_validation || 'N/A'}</div>
      </div>
      <div class="sub-card">
        <div class="sub-card-title">Network DL (BiLSTM)</div>
        <div>Score: <strong>${net.score !== undefined ? Number(net.score).toFixed(4) : 'N/A'}</strong></div>
        <div style="font-size:.75rem;color:var(--text-muted)">Bundle: ${net.bundle_id || 'N/A'}</div>
        <div style="font-size:.75rem">Mask: ${mask.network_dl ? 'Active' : 'Missing'} | Domain: ${net.domain_validation || 'N/A'}</div>
      </div>
    </div>

    <div style="margin-top:1rem">
      <h3 style="font-size:.95rem;margin-bottom:.5rem">Normalized Telemetry Events (${(a.events || []).length})</h3>
      <table style="font-size:.8rem">
        <thead><tr><th>Source</th><th>Event Type</th><th>Process</th><th>Command / Network</th></tr></thead>
        <tbody>${eventsHtml || '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No linked events</td></tr>'}</tbody>
      </table>
    </div>

    <div class="action-box">
      <h3 style="font-size:.95rem;margin-bottom:.5rem">Analyst Review Action</h3>
      <div style="display:grid;grid-template-columns:1fr 2fr;gap:.5rem;margin-bottom:.5rem">
        <input id="reviewerInput" placeholder="Reviewer Name (e.g. Analyst_1)">
        <input id="notesInput" placeholder="Investigation notes / justification">
      </div>
      <div style="display:flex;gap:.5rem">
        <button class="btn-success" onclick="submitReview('confirmed')">✓ Confirmed Incident (Attack)</button>
        <button class="btn-warning" onclick="submitReview('false_positive')">✗ False Positive (Benign)</button>
        <button class="btn-secondary" onclick="submitReview('dismissed')">⊘ Dismiss</button>
      </div>
    </div>

    <div style="margin-top:1.5rem">
      <h3 style="font-size:.95rem;margin-bottom:.5rem">Audit History</h3>
      <ul class="timeline">${reviewsHtml || '<li style="color:var(--text-muted);font-size:.85rem">No reviews recorded yet</li>'}</ul>
    </div>
  `;
}

async function submitReview(decision){
  if(!currentAlert) return;
  let reviewer = document.querySelector('#reviewerInput').value.trim();
  let notes = document.querySelector('#notesInput').value.trim();
  if(!reviewer){ alert('Please enter Reviewer Name'); return; }
  let t = getToken();
  try{
    let r = await fetch('/v1/alerts/' + currentAlert.alert_id + '/reviews', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + t},
      body: JSON.stringify({decision: decision, reviewer: reviewer, notes: notes})
    });
    if(!r.ok){ alert('HTTP ' + r.status + ': Failed to submit review'); return; }
    await loadAlerts();
    await selectAlert(currentAlert.alert_id);
  }catch(e){ alert('Error submitting review: ' + e); }
}
</script>
</body>
</html>'''


@app.get('/soc', response_class=HTMLResponse)
async def soc_dashboard():
    return SOC_HTML
