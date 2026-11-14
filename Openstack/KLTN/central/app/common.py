import hashlib
import json
import os
from pathlib import Path

SECRETS = Path(os.environ.get('KLTN_SECRETS', '/run/kltn/secrets.json'))
if not SECRETS.exists():
    local_secrets = Path(__file__).resolve().parents[2] / 'runtime/secrets.json'
    if local_secrets.exists():
        SECRETS = local_secrets


def secrets():
    return json.loads(SECRETS.read_text())


def event_record(host_id, source, raw):
    # date is Fluent Bit's transport timestamp, not source identity. Preserve it
    # in raw but exclude it from identity so a replay keeps the original ID.
    identity = {k: v for k, v in raw.items() if k != 'date'}
    canonical = json.dumps([host_id, source, identity], sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return {'event_id': hashlib.sha256(canonical.encode()).hexdigest(),
            'host_id': host_id, 'source': source, 'schema_version': 1, 'raw': raw}


async def connect_nats():
    import nats
    s = secrets()
    return await nats.connect('nats://127.0.0.1:14222', token=s['nats_token'], max_reconnect_attempts=-1)


def db_connect():
    import psycopg
    return psycopg.connect(host='127.0.0.1', port=15432, dbname='kltn', user='kltn', password=secrets()['postgres_password'])


# Schema v2 (IL3 deployment). Raw records stay immutable in `events`; `host_events` holds the model-ready events the
# central normalizer builds from them (auditd groups, Sysmon mapped to CBC semantics); every derived row keeps the ids
# of the raw records it came from.
DDL = '''CREATE TABLE IF NOT EXISTS events (
 event_id TEXT PRIMARY KEY, seq BIGSERIAL UNIQUE, host_id TEXT NOT NULL, source TEXT NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now(), payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_host_source_seq ON events(host_id, source, seq);
CREATE INDEX IF NOT EXISTS events_host_time ON events(host_id, received_at);

CREATE TABLE IF NOT EXISTS hosts (
 host_id TEXT PRIMARY KEY, name TEXT NOT NULL, os TEXT NOT NULL, domain TEXT NOT NULL,
 address TEXT, details JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS host_events (
 id BIGSERIAL PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, host_id TEXT NOT NULL, os TEXT NOT NULL,
 source TEXT NOT NULL, domain TEXT NOT NULL, ts_us BIGINT NOT NULL, ts TIMESTAMPTZ NOT NULL, kind TEXT NOT NULL,
 image TEXT, cmd TEXT, target TEXT, pid BIGINT, ppid BIGINT, principal TEXT, rule_keys TEXT[],
 event JSONB NOT NULL, raw_refs JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS host_events_host_ts ON host_events(host_id, ts_us);
CREATE INDEX IF NOT EXISTS host_events_host_id ON host_events(host_id, id);

CREATE TABLE IF NOT EXISTS scores (
 score_id TEXT PRIMARY KEY, seq BIGSERIAL UNIQUE, schema_version TEXT NOT NULL, host_id TEXT NOT NULL,
 branch TEXT NOT NULL, bundle_id TEXT NOT NULL, status TEXT NOT NULL,
 score DOUBLE PRECISION, threshold DOUBLE PRECISION, prediction SMALLINT,
 domain TEXT NOT NULL, domain_validation TEXT NOT NULL,
 event_refs JSONB NOT NULL, score_window JSONB, evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
 event_time TIMESTAMPTZ, processed_at TIMESTAMPTZ NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK (score IS NULL OR (score >= 0 AND score <= 1)),
 CHECK (threshold IS NULL OR (threshold >= 0 AND threshold <= 1)),
 CHECK (prediction IS NULL OR prediction IN (0,1))
);
CREATE INDEX IF NOT EXISTS scores_host_event_time ON scores(host_id, event_time);
CREATE INDEX IF NOT EXISTS scores_branch_time ON scores(branch, processed_at);
CREATE INDEX IF NOT EXISTS scores_received ON scores(received_at);

CREATE TABLE IF NOT EXISTS endpoint_summaries (
 summary_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, bundle_id TEXT NOT NULL, domain TEXT NOT NULL,
 period_start TIMESTAMPTZ NOT NULL, period_end TIMESTAMPTZ NOT NULL, payload JSONB NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoint_summaries_host_time ON endpoint_summaries(host_id, period_end);

CREATE TABLE IF NOT EXISTS serving_status (
 service TEXT PRIMARY KEY, updated_at TIMESTAMPTZ NOT NULL, state TEXT NOT NULL,
 pending BIGINT NOT NULL, runtime JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS fusion_results (
 fusion_id TEXT PRIMARY KEY, host_id TEXT NOT NULL,
 bucket_start TIMESTAMPTZ NOT NULL, bucket_end TIMESTAMPTZ NOT NULL,
 algorithm TEXT NOT NULL, policy_version TEXT NOT NULL,
 risk_score DOUBLE PRECISION NOT NULL, threshold DOUBLE PRECISION NOT NULL,
 prediction SMALLINT NOT NULL, source_mask JSONB NOT NULL,
 score_refs JSONB NOT NULL, evidence JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (host_id, bucket_start, policy_version),
 CHECK (risk_score >= 0 AND risk_score <= 1),
 CHECK (prediction IN (0,1))
);
CREATE INDEX IF NOT EXISTS fusion_host_time ON fusion_results(host_id,bucket_start);

CREATE TABLE IF NOT EXISTS alerts (
 alert_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, risk_score DOUBLE PRECISION NOT NULL,
 state TEXT NOT NULL DEFAULT 'needs_review', severity TEXT NOT NULL, shadow BOOLEAN NOT NULL DEFAULT false,
 first_seen TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL, fusion_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
 evidence JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_state_time ON alerts(state,created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_host_last ON alerts(host_id,last_seen DESC);

CREATE TABLE IF NOT EXISTS alert_reviews (
 review_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
 decision TEXT NOT NULL, reviewer TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
 labels JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS model_registry (
 bundle_id TEXT PRIMARY KEY, branch TEXT NOT NULL, algorithm TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL, manifest JSONB NOT NULL,
 stage TEXT NOT NULL DEFAULT 'candidate', domain_validation TEXT NOT NULL,
 mlflow JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), activated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS deployment_rollouts (
 rollout_id TEXT PRIMARY KEY, bundle_id TEXT NOT NULL REFERENCES model_registry(bundle_id),
 target TEXT NOT NULL, mode TEXT NOT NULL, state TEXT NOT NULL,
 details JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS drift_snapshots (
 snapshot_id TEXT PRIMARY KEY, branch TEXT NOT NULL, domain TEXT NOT NULL, host_id TEXT,
 window_start TIMESTAMPTZ NOT NULL, window_end TIMESTAMPTZ NOT NULL,
 sample_count BIGINT NOT NULL, metric TEXT NOT NULL, value DOUBLE PRECISION,
 threshold DOUBLE PRECISION, state TEXT NOT NULL, details JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS training_requests (
 request_id TEXT PRIMARY KEY, branch TEXT NOT NULL, trigger_type TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending_approval', dataset_query JSONB NOT NULL,
 trigger_evidence JSONB NOT NULL, result JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 approved_at TIMESTAMPTZ, approved_by TEXT, completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS response_requests (
 request_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
 host_id TEXT NOT NULL, action TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending_approval',
 requested_by TEXT NOT NULL, approved_by TEXT, execution JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_exports (
 export_id TEXT PRIMARY KEY, alert_id TEXT REFERENCES alerts(alert_id), host_id TEXT NOT NULL,
 path TEXT NOT NULL, sha256 TEXT NOT NULL, rows BIGINT NOT NULL, details JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS framework_cursors (
 name TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
'''
