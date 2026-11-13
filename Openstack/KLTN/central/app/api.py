"""Central API (General Architecture, CENTRAL VM): Log Receive, Score/ML Result Relay, SOC verification, approval-gated
response requests, training requests and the deployment ledger of model bundles.

Auth: per-host bearer tokens for telemetry/scores/summaries (a host can only write its own data); the admin token for
everything an analyst or operator does. Every state change that leads to an action on infrastructure or models
(response, training, activation) is a separate, explicit approval.
"""
import asyncio
import hmac
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType, StreamConfig
from psycopg.types.json import Jsonb

from audit_display import exact_command
from common import connect_nats, db_connect, event_record, secrets
from framework import (APPROVAL_POLICIES, RESPONSE_ACTIONS, REVIEW_DECISIONS, ContractError, approval_allowed,
                       canonical_hash, validate_score, validate_summary)

MAX_BODY = 4 * 1024 * 1024
SOURCES = {'audit', 'journal', 'sysmon', 'security', 'powershell', 'smoke'}
BRANCHES = {'host_ml', 'host_dl'}
# response approvals: two_person (default) or single_operator (compose.yaml; the lab owner's choice for a closed lab)
APPROVAL_POLICY = os.environ.get('KLTN_APPROVAL_POLICY', 'two_person')
if APPROVAL_POLICY not in APPROVAL_POLICIES:
    raise SystemExit(f'KLTN_APPROVAL_POLICY must be one of {sorted(APPROVAL_POLICIES)}')


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
                                max_bytes=2 * 1024**3, max_msg_size=1024**2, discard=DiscardPolicy.NEW))
        except Exception:
            pass
    app.state.js = js
    yield
    await nc.drain()


app = FastAPI(lifespan=lifespan, title='KLTN central')


def authorized(request, expected):
    return bool(expected) and hmac.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + expected)


def require_admin(request):
    if not authorized(request, secrets()['admin_token']):
        raise HTTPException(401, 'unauthorized')


def host_from_token(request, allow_admin=True):
    if allow_admin and authorized(request, secrets()['admin_token']):
        return None
    for host_id, host in secrets()['hosts'].items():
        if authorized(request, host['token']):
            return host_id
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


def q(sql, params=(), one=False):
    with db_connect() as conn:
        cur = conn.execute(sql, params)
        return cur.fetchone() if one else cur.fetchall()


def iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


# ------------------------------------------------------------------------------------------------ ingest
@app.get('/healthz')
async def health():
    try:
        await app.state.js.stream_info('KLTN_EVENTS')
    except Exception:
        raise HTTPException(503, 'queue unavailable')
    return {'status': 'ok', 'framework': 'kltn-il3'}


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
    if not isinstance(records, list) or not 1 <= len(records) <= 5000 or any(not isinstance(r, dict) for r in records):
        raise HTTPException(422, 'expected 1..5000 event objects')
    encoded = [json.dumps(event_record(host_id, source, r), ensure_ascii=False).encode() for r in records]
    if any(len(r) > 900000 for r in encoded):
        raise HTTPException(413, 'record too large')
    try:   # publish ACK precedes HTTP success; the DB primary key deduplicates re-deliveries
        for data in encoded:
            await app.state.js.publish('kltn.events', data)
    except Exception:
        raise HTTPException(503, 'queue unavailable; retry batch')
    return {'accepted': len(records)}


def store_scores(records):
    inserted = 0
    with db_connect() as conn:
        for s in records:
            row = conn.execute('''INSERT INTO scores(score_id,schema_version,host_id,branch,bundle_id,status,score,threshold,
              prediction,domain,domain_validation,event_refs,score_window,evidence,event_time,processed_at)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(score_id) DO NOTHING RETURNING score_id''',
                               (s['score_id'], s['schema_version'], s['host_id'], s['branch'], s['bundle_id'], s['status'],
                                s['score'], s['threshold'], s['prediction'], s['domain'], s['domain_validation'],
                                Jsonb(s['event_refs']), Jsonb(s['window']) if s['window'] else None, Jsonb(s['evidence']),
                                s['event_time'], s['processed_at'])).fetchone()
            inserted += int(row is not None)
    return inserted


@app.post('/v1/scores')
async def ingest_scores(request: Request):
    host_id = host_from_token(request)
    payload = await json_body(request)
    records = payload if isinstance(payload, list) else [payload]
    if not 1 <= len(records) <= 1000:
        raise HTTPException(422, 'expected 1..1000 score objects')
    try:
        validated = [validate_score(item, host_id) for item in records]
    except ContractError as exc:
        raise HTTPException(422, str(exc))
    try:
        inserted = await asyncio.to_thread(store_scores, validated)
    except Exception:
        raise HTTPException(503, 'score storage unavailable; retry batch')
    return {'accepted': len(validated), 'inserted': inserted}


def store_summaries(items):
    with db_connect() as conn:
        for s in items:
            conn.execute('''INSERT INTO endpoint_summaries(summary_id,host_id,bundle_id,domain,period_start,period_end,payload)
              VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(summary_id) DO NOTHING''',
                         (s['summary_id'], s['host_id'], s['bundle_id'], s['domain'], s['period_start'], s['period_end'],
                          Jsonb(s['payload'])))


@app.post('/v1/summaries')
async def ingest_summaries(request: Request):
    host_id = host_from_token(request)
    payload = await json_body(request)
    records = payload if isinstance(payload, list) else [payload]
    if not 1 <= len(records) <= 500:
        raise HTTPException(422, 'expected 1..500 summaries')
    try:
        items = [validate_summary(item, host_id) for item in records]
    except ContractError as exc:
        raise HTTPException(422, str(exc))
    await asyncio.to_thread(store_summaries, items)
    return {'accepted': len(items)}


# ------------------------------------------------------------------------------------------------ status
@app.get('/v1/status')
async def status(request: Request):
    require_admin(request)
    rows = await asyncio.to_thread(q, '''SELECT host_id, source, count(*), max(received_at) FROM events
      GROUP BY host_id, source ORDER BY host_id, source''')
    info = await app.state.js.stream_info('KLTN_EVENTS')
    return {'queue_pending': info.state.messages,
            'sources': [{'host_id': r[0], 'source': r[1], 'count': r[2], 'last_received': iso(r[3])} for r in rows]}


def framework_status_query():
    with db_connect() as conn:
        counts = {t: conn.execute(f'SELECT count(*) FROM {t}').fetchone()[0] for t in
                  ('events', 'host_events', 'scores', 'endpoint_summaries', 'fusion_results', 'alerts', 'model_registry',
                   'training_requests', 'response_requests', 'drift_snapshots')}
        services = conn.execute('SELECT service,updated_at,state,pending,runtime FROM serving_status ORDER BY service').fetchall()
        models = conn.execute('''SELECT bundle_id,branch,algorithm,stage,domain_validation,created_at,activated_at,mlflow,
          manifest->'activation', manifest->>'parent_bundle_id', manifest->'domains' FROM model_registry ORDER BY created_at DESC''').fetchall()
    return {'counts': counts,
            'services': [{'service': r[0], 'updated_at': iso(r[1]), 'state': r[2], 'pending': r[3], 'runtime': r[4]} for r in services],
            'models': [{'bundle_id': r[0], 'branch': r[1], 'algorithm': r[2], 'stage': r[3], 'domain_validation': r[4],
                        'created_at': iso(r[5]), 'activated_at': iso(r[6]), 'mlflow': r[7], 'activation': r[8],
                        'parent_bundle_id': r[9],
                        'domains': {d: {k: v.get(k) for k in ('threshold', 'threshold_logit', 'validation', 'threshold_source')}
                                    for d, v in (r[10] or {}).items() if isinstance(v, dict)}} for r in models]}


def drift_query():
    with db_connect() as conn:
        snaps = conn.execute('''SELECT DISTINCT ON (d.host_id) h.name, d.host_id, d.domain, d.state, d.value, d.sample_count,
          d.window_start, d.window_end, d.details->>'score_psi', d.details->'reference'->>'oov_rate', d.details->>'bundle_id',
          d.details->'reference_window', d.created_at FROM drift_snapshots d LEFT JOIN hosts h USING (host_id)
          ORDER BY d.host_id, d.created_at DESC''').fetchall()
        cur = dict(conn.execute('''SELECT name, value FROM framework_cursors WHERE name IN ('drift-il3','drift-baseline')''').fetchall())
    return {'latest': [{'host': r[0], 'host_id': r[1], 'domain': r[2], 'state': r[3], 'oov_rate': r[4], 'rows': r[5],
                        'window': [iso(r[6]), iso(r[7])], 'score_psi': r[8], 'reference_oov_rate': r[9], 'bundle_id': r[10],
                        'reference_window': r[11], 'at': iso(r[12])} for r in snaps],
            'last_tick': cur.get('drift-il3'), 'baseline': cur.get('drift-baseline'),
            'policy': {'reference': 'first 24 h of the current bundle (after the baseline mark)', 'oov_ceiling': 0.20,
                       'oov_ratio': 1.5, 'psi': 0.25, 'min_rows': 1000}}


@app.get('/v1/drift')
async def drift(request: Request):
    require_admin(request)
    return await asyncio.to_thread(drift_query)


@app.get('/v1/framework/status')
async def framework_status(request: Request):
    require_admin(request)
    return await asyncio.to_thread(framework_status_query)


def hosts_query():
    with db_connect() as conn:
        hosts = {r[0]: {'host_id': r[0], 'name': r[1], 'os': r[2], 'domain': r[3], 'address': r[4]}
                 for r in conn.execute('SELECT host_id,name,os,domain,address FROM hosts').fetchall()}
        for h, src, n, last in conn.execute('''SELECT host_id, source, count(*), max(received_at) FROM events
          WHERE received_at > now() - interval '1 hour' GROUP BY host_id, source''').fetchall():
            hosts.setdefault(h, {'host_id': h}).setdefault('raw_last_hour', {})[src] = {'count': n, 'last': iso(last)}
        for h, p, end in conn.execute('''SELECT DISTINCT ON (host_id) host_id, payload, period_end FROM endpoint_summaries
          ORDER BY host_id, period_end DESC''').fetchall():
            hosts.setdefault(h, {'host_id': h})['last_summary'] = {'at': iso(end), 'bundle_id': p.get('bundle_id'),
                                                                     'counts': p.get('counts'),
                                                                     'oov_rate': (p.get('featurizer') or {}).get('oov_rate')}
        for h, b, n, mx, last in conn.execute('''SELECT host_id, branch, count(*), max(score), max(event_time) FROM scores
          WHERE received_at > now() - interval '1 hour' GROUP BY host_id, branch''').fetchall():
            hosts.setdefault(h, {'host_id': h}).setdefault('scores_last_hour', {})[b] = {'count': n, 'max': mx, 'last': iso(last)}
    return list(hosts.values())


@app.get('/v1/hosts')
async def hosts(request: Request):
    require_admin(request)
    return {'hosts': await asyncio.to_thread(hosts_query)}


# ------------------------------------------------------------------------------------------------ alerts / SOC
@app.get('/v1/alerts')
async def list_alerts(request: Request, limit: int = 200, state: str | None = None):
    require_admin(request)
    if not 1 <= limit <= 1000:
        raise HTTPException(422, 'limit must be 1..1000')
    sql = 'SELECT alert_id,host_id,risk_score,state,severity,shadow,first_seen,last_seen,created_at FROM alerts'
    params = []
    if state:
        sql += ' WHERE state=%s'
        params.append(state)
    sql += ' ORDER BY last_seen DESC LIMIT %s'
    params.append(limit)
    rows = await asyncio.to_thread(q, sql, params)
    return {'alerts': [{'alert_id': r[0], 'host_id': r[1], 'risk_score': r[2], 'state': r[3], 'severity': r[4],
                        'shadow': r[5], 'first_seen': iso(r[6]), 'last_seen': iso(r[7]), 'created_at': iso(r[8])} for r in rows]}


def alert_detail_query(alert_id: str):
    with db_connect() as conn:
        a = conn.execute('''SELECT alert_id,host_id,risk_score,state,severity,shadow,first_seen,last_seen,evidence,created_at,
          updated_at FROM alerts WHERE alert_id=%s''', (alert_id,)).fetchone()
        if not a:
            return None
        ev = a[8] or {}
        reviews = conn.execute('''SELECT review_id,decision,reviewer,notes,labels,created_at FROM alert_reviews
          WHERE alert_id=%s ORDER BY created_at''', (alert_id,)).fetchall()
        responses = conn.execute('''SELECT request_id,action,state,requested_by,approved_by,execution,updated_at
          FROM response_requests WHERE alert_id=%s ORDER BY created_at''', (alert_id,)).fetchall()
        refs = []
        for e in ev.get('ml_events', []):
            refs += e.get('event_refs', [])
        dl_keys = [t['ref'] for w in ev.get('dl_windows', []) for t in w.get('top_events', []) if t.get('ref')]
        raw = conn.execute('''SELECT event_id, source, received_at, payload->'raw' FROM events WHERE event_id = ANY(%s)
          ORDER BY seq LIMIT 1000''', (refs[:1000],)).fetchall() if refs else []
        hev = conn.execute('''SELECT event_key, kind, ts, image, cmd, target, principal, rule_keys, raw_refs FROM host_events
          WHERE event_key = ANY(%s) ORDER BY ts_us LIMIT 400''', (dl_keys[:400],)).fetchall() if dl_keys else []
        hev_refs = sorted({r for h in hev for r in (h[8] or [])})[:4000]
        hev_raw = dict(conn.execute('''SELECT event_id, payload->'raw'->>'log' FROM events WHERE event_id = ANY(%s)''',
                                    (hev_refs,)).fetchall()) if hev_refs else {}
        host = conn.execute('SELECT name, os, domain, address FROM hosts WHERE host_id=%s', (a[1],)).fetchone()
    # exact command lines for the analyst (the models' own `cmd` view is kept in the evidence; see audit_display)
    raw_log = {r[0]: (r[3] or {}).get('log') for r in raw if isinstance(r[3], dict)}
    ml_commands = {}
    for e in ev.get('ml_events', []):
        cmd = exact_command(raw_log.get(x) for x in e.get('event_refs', []))
        if cmd is not None and e.get('score_id'):
            ml_commands[e['score_id']] = cmd
    return {'alert_id': a[0], 'host_id': a[1], 'host': dict(zip(('name', 'os', 'domain', 'address'), host)) if host else None,
            'risk_score': a[2], 'state': a[3], 'severity': a[4], 'shadow': a[5], 'first_seen': iso(a[6]),
            'last_seen': iso(a[7]), 'evidence': ev, 'created_at': iso(a[9]), 'updated_at': iso(a[10]),
            'reviews': [{'review_id': r[0], 'decision': r[1], 'reviewer': r[2], 'notes': r[3], 'labels': r[4],
                         'created_at': iso(r[5])} for r in reviews],
            'responses': [{'request_id': r[0], 'action': r[1], 'state': r[2], 'requested_by': r[3], 'approved_by': r[4],
                           'execution': r[5], 'updated_at': iso(r[6])} for r in responses],
            'raw_records': [{'event_id': r[0], 'source': r[1], 'received_at': iso(r[2]), 'raw': r[3]} for r in raw[:400]],
            'ml_event_commands': ml_commands, 'approval_policy': APPROVAL_POLICY,
            'dl_events': [{'event_key': r[0], 'kind': r[1], 'ts': iso(r[2]), 'image': r[3], 'cmd': r[4], 'target': r[5],
                           'principal': r[6], 'rule_keys': r[7],
                           'cmd_exact': exact_command(hev_raw.get(x) for x in (r[8] or []))} for r in hev]}


@app.get('/v1/alerts/{alert_id}')
async def alert_detail(alert_id: str, request: Request):
    require_admin(request)
    detail = await asyncio.to_thread(alert_detail_query, alert_id)
    if detail is None:
        raise HTTPException(404, 'alert not found')
    return detail


def review_alert(alert_id, decision, reviewer, notes, labels):
    review_id = canonical_hash(['review.v2', alert_id, decision, reviewer, notes, labels, datetime.now(timezone.utc).isoformat()])
    with db_connect() as conn:
        if not conn.execute('SELECT 1 FROM alerts WHERE alert_id=%s', (alert_id,)).fetchone():
            return None
        conn.execute('''INSERT INTO alert_reviews(review_id,alert_id,decision,reviewer,notes,labels) VALUES (%s,%s,%s,%s,%s,%s)''',
                     (review_id, alert_id, decision, reviewer, notes, Jsonb(labels)))
        conn.execute('UPDATE alerts SET state=%s,updated_at=now() WHERE alert_id=%s', (decision, alert_id))
    return review_id


@app.post('/v1/alerts/{alert_id}/reviews')
async def create_review(alert_id: str, request: Request):
    """decision for the whole alert + optional per-event labels (the IL training signal):
    {"decision": ..., "reviewer": ..., "notes": ..., "labels": {"attack_refs": [...], "benign_refs": [...],
     "stage": "execution_discovery"}}"""
    require_admin(request)
    p = await json_body(request, 256 * 1024)
    if not isinstance(p, dict) or p.get('decision') not in REVIEW_DECISIONS or not str(p.get('reviewer', '')).strip():
        raise HTTPException(422, 'invalid decision or reviewer')
    notes, labels = p.get('notes', ''), p.get('labels', {})
    if not isinstance(notes, str) or len(notes) > 10000 or not isinstance(labels, dict):
        raise HTTPException(422, 'invalid notes or labels')
    for k in ('attack_refs', 'benign_refs'):
        v = labels.get(k, [])
        if not isinstance(v, list) or len(v) > 5000 or any(not isinstance(x, str) or len(x) > 160 for x in v):
            raise HTTPException(422, f'invalid labels.{k}')
    rid = await asyncio.to_thread(review_alert, alert_id, p['decision'], str(p['reviewer'])[:256], notes, labels)
    if rid is None:
        raise HTTPException(404, 'alert not found')
    return {'review_id': rid, 'state': p['decision']}


def verified_dataset_query():
    rows = q('''SELECT a.alert_id, a.host_id, a.state, a.risk_score, a.first_seen, a.last_seen, a.evidence, r.decision,
      r.reviewer, r.notes, r.labels, r.created_at FROM alerts a JOIN LATERAL (SELECT decision, reviewer, notes, labels,
      created_at FROM alert_reviews WHERE alert_id=a.alert_id ORDER BY created_at DESC LIMIT 1) r ON true
      WHERE a.state IN ('confirmed','false_positive') ORDER BY r.created_at DESC LIMIT 5000''')
    return [{'alert_id': r[0], 'host_id': r[1], 'decision': r[2], 'label': int(r[2] == 'confirmed'), 'risk_score': r[3],
             'first_seen': iso(r[4]), 'last_seen': iso(r[5]), 'reviewer': r[8], 'notes': r[9], 'labels': r[10],
             'reviewed_at': iso(r[11]), 'buckets': (r[6] or {}).get('buckets', {})} for r in rows]


@app.get('/v1/soc/verified-dataset')
async def soc_verified_dataset(request: Request):
    require_admin(request)
    return {'dataset': await asyncio.to_thread(verified_dataset_query)}


# ------------------------------------------------------------------------------------------------ responses
def create_response(alert_id, action, requested_by):
    with db_connect() as conn:
        row = conn.execute('SELECT host_id,state FROM alerts WHERE alert_id=%s', (alert_id,)).fetchone()
        if not row:
            return None
        if action != 'collect_evidence' and row[1] != 'confirmed':
            raise ContractError('network actions require a confirmed SOC review')
        request_id = canonical_hash(['response.v2', alert_id, row[0], action, datetime.now(timezone.utc).isoformat()])
        conn.execute('''INSERT INTO response_requests(request_id,alert_id,host_id,action,requested_by) VALUES (%s,%s,%s,%s,%s)''',
                     (request_id, alert_id, row[0], action, requested_by))
    return request_id


@app.post('/v1/alerts/{alert_id}/responses')
async def response_request(alert_id: str, request: Request):
    require_admin(request)
    p = await json_body(request, 64 * 1024)
    if not isinstance(p, dict) or p.get('action') not in RESPONSE_ACTIONS or not str(p.get('requested_by', '')).strip():
        raise HTTPException(422, 'invalid response action or requester')
    try:
        rid = await asyncio.to_thread(create_response, alert_id, p['action'], str(p['requested_by'])[:256])
    except ContractError as exc:
        raise HTTPException(409, str(exc))
    if rid is None:
        raise HTTPException(404, 'alert not found')
    who = 'a second person' if APPROVAL_POLICY == 'two_person' else 'an operator (the requester may approve: single_operator policy)'
    return {'request_id': rid, 'state': 'pending_approval', 'note': f'{who} must approve; the controller executes'}


@app.get('/v1/responses')
async def list_responses(request: Request, state: str | None = None):
    require_admin(request)
    sql = '''SELECT request_id,alert_id,host_id,action,state,requested_by,approved_by,execution,created_at,updated_at
      FROM response_requests'''
    params = []
    if state:
        sql += ' WHERE state=%s'
        params.append(state)
    rows = await asyncio.to_thread(q, sql + ' ORDER BY created_at DESC LIMIT 500', params)
    return {'responses': [{'request_id': r[0], 'alert_id': r[1], 'host_id': r[2], 'action': r[3], 'state': r[4],
                           'requested_by': r[5], 'approved_by': r[6], 'execution': r[7], 'created_at': iso(r[8]),
                           'updated_at': iso(r[9])} for r in rows]}


def approve_response(request_id, approved_by):
    with db_connect() as conn:
        row = conn.execute('SELECT state, requested_by FROM response_requests WHERE request_id=%s FOR UPDATE',
                           (request_id,)).fetchone()
        if not row:
            return 'missing'
        if row[0] != 'pending_approval':
            return row[0]
        if not approval_allowed(APPROVAL_POLICY, row[1], approved_by):
            return 'requires_second_person'
        approval = {'policy': APPROVAL_POLICY, 'self_approved': row[1].strip().lower() == approved_by.strip().lower(),
                    'at': datetime.now(timezone.utc).isoformat()}
        conn.execute('''UPDATE response_requests SET state='approved',approved_by=%s,updated_at=now(),execution=execution || %s
          WHERE request_id=%s''', (approved_by, Jsonb({'approval': approval}), request_id))
    return 'approved'


@app.post('/v1/responses/{request_id}/approve')
async def response_approve(request_id: str, request: Request):
    require_admin(request)
    p = await json_body(request, 64 * 1024)
    approved_by = p.get('approved_by') if isinstance(p, dict) else None
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise HTTPException(422, 'approved_by is required')
    state = await asyncio.to_thread(approve_response, request_id, approved_by[:256])
    if state == 'missing':
        raise HTTPException(404, 'response request not found')
    if state == 'requires_second_person':
        raise HTTPException(409, 'the approver must differ from the requester')
    return {'request_id': request_id, 'state': state}


# ------------------------------------------------------------------------------------------------ training / models
@app.get('/v1/training/requests')
async def training_requests(request: Request, state: str | None = None):
    require_admin(request)
    sql = '''SELECT request_id,branch,trigger_type,state,dataset_query,trigger_evidence,result,created_at,approved_at,
      approved_by,completed_at FROM training_requests'''
    params = []
    if state:
        sql += ' WHERE state=%s'
        params.append(state)
    rows = await asyncio.to_thread(q, sql + ' ORDER BY created_at DESC LIMIT 500', params)
    return {'requests': [{'request_id': r[0], 'branch': r[1], 'trigger_type': r[2], 'state': r[3], 'dataset_query': r[4],
                          'trigger_evidence': r[5], 'result': r[6], 'created_at': iso(r[7]), 'approved_at': iso(r[8]),
                          'approved_by': r[9], 'completed_at': iso(r[10])} for r in rows]}


@app.post('/v1/training/requests')
async def training_create(request: Request):
    """Manual trigger (operator): {"branch": "host_ml"|"host_dl", "reason": "...", "dataset_query": {...}}"""
    require_admin(request)
    p = await json_body(request, 64 * 1024)
    if not isinstance(p, dict) or p.get('branch') not in BRANCHES or not str(p.get('reason', '')).strip():
        raise HTTPException(422, 'branch and reason are required')
    rid = canonical_hash(['training.v2', p['branch'], 'manual', datetime.now(timezone.utc).isoformat()])
    await asyncio.to_thread(q_exec, '''INSERT INTO training_requests(request_id,branch,trigger_type,dataset_query,trigger_evidence)
      VALUES (%s,%s,'manual',%s,%s)''', (rid, p['branch'], Jsonb(p.get('dataset_query', {})), Jsonb({'reason': p['reason']})))
    return {'request_id': rid, 'state': 'pending_approval'}


def q_exec(sql, params):
    with db_connect() as conn:
        conn.execute(sql, params)


def approve_training(request_id, approved_by):
    with db_connect() as conn:
        row = conn.execute('SELECT state FROM training_requests WHERE request_id=%s FOR UPDATE', (request_id,)).fetchone()
        if not row:
            return 'missing'
        if row[0] != 'pending_approval':
            return row[0]
        conn.execute('''UPDATE training_requests SET state='approved',approved_at=now(),approved_by=%s WHERE request_id=%s''',
                     (approved_by, request_id))
    return 'approved'


@app.post('/v1/training/requests/{request_id}/approve')
async def training_approve(request_id: str, request: Request):
    require_admin(request)
    p = await json_body(request, 64 * 1024)
    who = p.get('approved_by') if isinstance(p, dict) else None
    if not isinstance(who, str) or not who.strip():
        raise HTTPException(422, 'approved_by is required')
    state = await asyncio.to_thread(approve_training, request_id, who[:256])
    if state == 'missing':
        raise HTTPException(404, 'training request not found')
    return {'request_id': request_id, 'state': state, 'note': 'the IL service claims approved requests'}


def register_model(manifest, mlflow_info):
    required = ('bundle_id', 'branch', 'algorithm', 'domain_validation', 'artifacts', 'parity', 'activation')
    if any(k not in manifest for k in required):
        raise ContractError('incomplete bundle manifest')
    if manifest['branch'] not in BRANCHES:
        raise ContractError('unsupported model branch')
    digest = canonical_hash(manifest)
    with db_connect() as conn:
        existing = conn.execute('SELECT manifest_sha256 FROM model_registry WHERE bundle_id=%s', (manifest['bundle_id'],)).fetchone()
        if existing and not hmac.compare_digest(existing[0], digest):
            raise ContractError('bundle_id is immutable; publish a new bundle ID')
        conn.execute('''INSERT INTO model_registry(bundle_id,branch,algorithm,manifest_sha256,manifest,stage,domain_validation,mlflow)
          VALUES (%s,%s,%s,%s,%s,'candidate',%s,%s) ON CONFLICT(bundle_id) DO UPDATE SET mlflow=excluded.mlflow''',
                     (manifest['bundle_id'], manifest['branch'], manifest['algorithm'], digest, Jsonb(manifest),
                      manifest['domain_validation'], Jsonb(mlflow_info or {})))
    return digest


@app.post('/v1/models')
async def model_register(request: Request):
    require_admin(request)
    p = await json_body(request)
    manifest = p.get('manifest', p) if isinstance(p, dict) else None
    if not isinstance(manifest, dict):
        raise HTTPException(422, 'manifest must be an object')
    try:
        digest = await asyncio.to_thread(register_model, manifest, p.get('mlflow') if 'manifest' in p else None)
    except ContractError as exc:
        raise HTTPException(422, str(exc))
    return {'bundle_id': manifest['bundle_id'], 'manifest_sha256': digest, 'stage': 'candidate'}


@app.get('/v1/models')
async def model_list(request: Request):
    require_admin(request)
    return {'models': (await asyncio.to_thread(framework_status_query))['models']}


def activate_model(bundle_id, approved_by):
    with db_connect() as conn:
        row = conn.execute('SELECT branch, manifest FROM model_registry WHERE bundle_id=%s', (bundle_id,)).fetchone()
        if not row:
            return 'missing', None
        branch, manifest = row
        if not manifest.get('activation', {}).get('eligible') or manifest.get('parity', {}).get('passed') is not True:
            return 'blocked', None
        prev = conn.execute("SELECT bundle_id FROM model_registry WHERE branch=%s AND stage='active' AND bundle_id<>%s",
                            (branch, bundle_id)).fetchone()
        prev_id = prev[0] if prev else None
        if prev_id:
            conn.execute("UPDATE model_registry SET stage='retired' WHERE bundle_id=%s", (prev_id,))
        conn.execute("UPDATE model_registry SET stage='active', activated_at=now() WHERE bundle_id=%s", (bundle_id,))
        conn.execute('''INSERT INTO deployment_rollouts(rollout_id,bundle_id,target,mode,state,details) VALUES (%s,%s,%s,%s,%s,%s)''',
                     (canonical_hash(['rollout.v2', bundle_id, datetime.now(timezone.utc).isoformat()]), bundle_id, 'all',
                      'activate', 'pending_deploy', Jsonb({'previous_bundle_id': prev_id, 'approved_by': approved_by})))
    return 'active', prev_id


@app.post('/v1/models/{bundle_id}/activate')
async def model_activate(bundle_id: str, request: Request):
    require_admin(request)
    p = await json_body(request, 64 * 1024)
    who = p.get('approved_by') if isinstance(p, dict) else None
    if not isinstance(who, str) or not who.strip():
        raise HTTPException(422, 'approved_by is required')
    state, prev = await asyncio.to_thread(activate_model, bundle_id, who[:256])
    if state == 'missing':
        raise HTTPException(404, 'bundle not found')
    if state == 'blocked':
        raise HTTPException(409, 'activation blocked: bundle not eligible or parity not passed')
    return {'bundle_id': bundle_id, 'stage': state, 'previous_bundle_id': prev,
            'note': 'scripts/deploy_bundles.sh rolls the active bundles out (endpoints, DL worker)'}


@app.get('/soc', response_class=HTMLResponse)
async def soc_dashboard():
    return (Path(__file__).resolve().parent / 'soc.html').read_text()
