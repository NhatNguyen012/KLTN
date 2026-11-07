"""Central normalization follow-up, fusion, drift and lifecycle coordinator.

The worker is intentionally model-agnostic.  It fuses persisted scores in
shadow mode, creates reviewable alerts, measures categorical drift and creates
approval-gated training requests.  It never trains, deploys or isolates a VM.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import time

from psycopg.types.json import Jsonb

from common import DDL, db_connect
from framework import (ContractError, FUSION_POLICY, alert_severity,
                       canonical_hash, fuse_scores, population_stability_index)
from normalization import json_view, normalize_record

SERVICE = "framework-worker"
BUCKET_SECONDS = FUSION_POLICY["bucket_seconds"]


def _bucket(value: datetime) -> datetime:
    seconds = int(value.timestamp())
    return datetime.fromtimestamp(seconds - seconds % BUCKET_SECONDS, tz=timezone.utc)


def normalize_backlog(conn, limit: int = 250) -> int:
    rows = conn.execute('''SELECT e.payload,e.received_at FROM events e
      LEFT JOIN normalized_events n ON n.event_id=e.event_id
      WHERE n.event_id IS NULL ORDER BY e.received_at,e.event_id LIMIT %s''',
      (limit,)).fetchall()
    for record, received_at in rows:
        event = normalize_record(record, received_at)
        conn.execute('''INSERT INTO normalized_events(
          event_id,host_id,source,event_time,received_at,event_type,
          process_id,parent_process_id,process_path,parent_path,command_line,
          principal,object_path,network,missing_fields,adapter_version,normalized)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
          ON CONFLICT(event_id) DO NOTHING''',
          (event['event_id'], event['host_id'], event['source'], event['event_time'],
           event['received_at'], event['event_type'], event['process_id'],
           event['parent_process_id'], event['process_path'], event['parent_path'],
           event['command_line'], event['principal'], event['object_path'],
           Jsonb(event['network']), Jsonb(event['missing_fields']),
           event['adapter_version'], Jsonb(json_view(event))))
    return len(rows)


def fuse_pending(conn) -> int:
    groups = conn.execute('''SELECT host_id,
      to_timestamp(floor(extract(epoch from processed_at)/%s)*%s) AS bucket
      FROM scores s WHERE status IN ('ready_shadow','ready_active')
      AND NOT EXISTS (SELECT 1 FROM fusion_score_ledger l WHERE l.score_id=s.score_id)
      GROUP BY host_id,bucket ORDER BY bucket LIMIT 100''',
      (BUCKET_SECONDS, BUCKET_SECONDS)).fetchall()
    created = 0
    for host_id, bucket_start in groups:
        rows = conn.execute('''SELECT score_id,host_id,branch,bundle_id,status,score,
          threshold,prediction,domain_validation,event_refs,processed_at
          FROM scores WHERE host_id=%s AND processed_at>=%s AND processed_at<%s
          ORDER BY processed_at''',
          (host_id, bucket_start, bucket_start + timedelta(seconds=BUCKET_SECONDS))).fetchall()
        payload = [{
            'score_id': row[0], 'host_id': row[1], 'branch': row[2],
            'bundle_id': row[3], 'status': row[4], 'score': row[5],
            'threshold': row[6], 'prediction': row[7],
            'domain_validation': row[8], 'event_refs': row[9],
            'processed_at': row[10],
        } for row in rows]
        try:
            fusion = fuse_scores(payload, bucket_start)
        except ContractError:
            continue
        inserted = conn.execute('''INSERT INTO fusion_results(
          fusion_id,host_id,bucket_start,bucket_end,algorithm,policy_version,
          risk_score,threshold,prediction,source_mask,score_refs,evidence)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
          ON CONFLICT(fusion_id) DO NOTHING RETURNING fusion_id''',
          (fusion['fusion_id'], fusion['host_id'], fusion['bucket_start'],
           fusion['bucket_end'], fusion['algorithm'], fusion['policy_version'],
           fusion['risk_score'], fusion['threshold'], fusion['prediction'],
           Jsonb(fusion['source_mask']), Jsonb(fusion['score_refs']),
           Jsonb(fusion['evidence']))).fetchone()
        if not inserted:
            # This can occur only for a retry of an identical score set. Bind
            # the ledger so it does not starve newer buckets.
            for score_ref in fusion['score_refs']:
                conn.execute('''INSERT INTO fusion_score_ledger(score_id,fusion_id)
                  VALUES (%s,%s) ON CONFLICT(score_id) DO NOTHING''',
                  (score_ref, fusion['fusion_id']))
            continue
        created += 1
        for score_ref in fusion['score_refs']:
            conn.execute('''INSERT INTO fusion_score_ledger(score_id,fusion_id)
              VALUES (%s,%s) ON CONFLICT(score_id) DO UPDATE SET
              fusion_id=excluded.fusion_id,fused_at=now()''',
              (score_ref, fusion['fusion_id']))
        if fusion['prediction']:
            alert_id = canonical_hash(['alert.v1', fusion['host_id'],
                                       fusion['bucket_start'].isoformat()])
            evidence = dict(fusion['evidence'], source_mask=fusion['source_mask'],
                            policy_version=fusion['policy_version'])
            conn.execute('''INSERT INTO alerts(
              alert_id,fusion_id,host_id,risk_score,severity,evidence)
              VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(alert_id) DO UPDATE SET
              fusion_id=excluded.fusion_id,risk_score=excluded.risk_score,
              severity=excluded.severity,evidence=excluded.evidence,updated_at=now()''',
              (alert_id, fusion['fusion_id'], fusion['host_id'], fusion['risk_score'],
               alert_severity(fusion['risk_score']), Jsonb(evidence)))
    return created


def event_histogram(conn, start: datetime, end: datetime) -> dict[str, int]:
    rows = conn.execute('''SELECT event_type,count(*) FROM normalized_events
      WHERE COALESCE(event_time,received_at)>=%s AND COALESCE(event_time,received_at)<%s
      GROUP BY event_type''', (start, end)).fetchall()
    return {name: count for name, count in rows}


def drift_tick(conn, now: datetime) -> tuple[str, float | None, int]:
    current_start = now - timedelta(hours=24)
    current = event_histogram(conn, current_start, now)
    current_count = sum(current.values())
    cursor = conn.execute("SELECT value FROM framework_cursors WHERE name='drift-reference-v1'").fetchone()
    if cursor is None:
        if current_count >= 1000:
            conn.execute('''INSERT INTO framework_cursors(name,value) VALUES
              ('drift-reference-v1',%s) ON CONFLICT(name) DO NOTHING''',
              (Jsonb({'histogram': current, 'start': current_start.isoformat(),
                      'end': now.isoformat()}),))
            return 'reference_created', None, current_count
        return 'insufficient_data', None, current_count
    reference = cursor[0].get('histogram', {})
    psi = population_stability_index(reference, current)
    state = 'insufficient_data' if current_count < 1000 else ('drift' if psi is not None and psi >= 0.25 else 'stable')
    snapshot_id = canonical_hash(['drift.v1', 'all', current_start.date().isoformat(), state])
    conn.execute('''INSERT INTO drift_snapshots(snapshot_id,branch,domain,window_start,
      window_end,sample_count,metric,value,threshold,state,details)
      VALUES (%s,'all','observed',%s,%s,%s,'categorical_psi',%s,0.25,%s,%s)
      ON CONFLICT(snapshot_id) DO NOTHING''',
      (snapshot_id, current_start, now, current_count, psi, state,
       Jsonb({'reference_total': sum(reference.values()), 'current_histogram': current})))
    return state, psi, current_count


def lifecycle_tick(conn, now: datetime, drift_state: str, psi: float | None) -> list[str]:
    """Create idempotent requests for enough-data, schedule and drift triggers."""
    verified = conn.execute("SELECT count(*) FROM alert_reviews WHERE decision IN ('confirmed','false_positive')").fetchone()[0]
    created: list[str] = []

    def request(trigger: str, identity: str, evidence: dict):
        request_id = canonical_hash(['training.v1', trigger, identity])
        row = conn.execute('''INSERT INTO training_requests(request_id,branch,trigger_type,
          dataset_query,trigger_evidence) VALUES (%s,'all',%s,%s,%s)
          ON CONFLICT(request_id) DO NOTHING RETURNING request_id''',
          (request_id, trigger,
           Jsonb({'review_decisions': ['confirmed', 'false_positive']}),
           Jsonb(evidence))).fetchone()
        if row:
            created.append(request_id)

    if verified >= 100:
        request('enough_data', str(verified // 100), {'verified_labels': verified,
                'minimum_verified_labels': 100})
        month = now.strftime('%Y-%m')
        request('scheduled', month, {'schedule': 'monthly', 'verified_labels': verified})
        if drift_state == 'drift':
            request('drift', now.date().isoformat(), {'psi': psi,
                    'threshold': 0.25, 'verified_labels': verified})
    return created


def tick() -> dict:
    now = datetime.now(timezone.utc)
    with db_connect() as conn:
        normalized = normalize_backlog(conn)
        fused = fuse_pending(conn)
        drift_state, psi, samples = drift_tick(conn, now)
        training_created = lifecycle_tick(conn, now, drift_state, psi)
        pending = conn.execute("SELECT count(*) FROM alerts WHERE state='needs_review'").fetchone()[0]
        runtime = {
            'fusion_policy': FUSION_POLICY,
            'normalized_backlog_rows': normalized,
            'fusion_results_created': fused,
            'drift_state': drift_state,
            'drift_psi': psi,
            'drift_samples': samples,
            'training_requests_created': training_created,
            'response_execution': 'approval_gated_external_controller',
            'incremental_training': 'approval_gated_external_runner',
        }
        conn.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime)
          VALUES (%s,now(),'ready_shadow',%s,%s)
          ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,
          state=excluded.state,pending=excluded.pending,runtime=excluded.runtime''',
          (SERVICE, pending, Jsonb(runtime)))
    return runtime


if __name__ == '__main__':
    with db_connect() as db:
        db.execute(DDL)
    print(json.dumps({'service': SERVICE, 'state': 'ready_shadow'}), flush=True)
    while True:
        try:
            result = tick()
            if result['fusion_results_created']:
                print(json.dumps(result), flush=True)
        except Exception as exc:
            print(json.dumps({'service': SERVICE, 'state': 'error',
                              'error_type': type(exc).__name__}), flush=True)
        time.sleep(10)
