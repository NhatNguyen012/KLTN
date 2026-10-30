import hashlib
import json
import os
from pathlib import Path

SECRETS = Path(os.environ.get('KLTN_SECRETS', '/run/kltn/secrets.json'))


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


DDL = '''CREATE TABLE IF NOT EXISTS events (
 event_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, source TEXT NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now(), payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_host_time ON events(host_id, received_at);
'''
