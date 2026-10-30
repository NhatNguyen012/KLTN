"""Stage bounded event-reference jobs, without consuming the archive queue.
No model, sequence construction or predictions are performed in preparation mode.
"""
import json
import os
from pathlib import Path
import time
import psycopg
import torch

PIPELINE = 'dl-preparation-v1'
LIMIT = 50000


def connect():
    cfg = json.loads(Path(os.environ.get('KLTN_DL_CONFIG', '/run/kltn/dl.json')).read_text())
    return psycopg.connect(host='127.0.0.1', port=15432, dbname='kltn', user='kltn_dl', password=cfg['password'], connect_timeout=5)


def tick():
    with connect() as db:
        # A singleton lock keeps the cap correct even if a second worker is started.
        db.execute('SELECT pg_advisory_xact_lock(18443001)')
        pending = db.execute('SELECT count(*) FROM dl_jobs WHERE pipeline_version=%s', (PIPELINE,)).fetchone()[0]
        room = max(0, min(250, LIMIT - pending))
        if room:
            db.execute('''INSERT INTO dl_jobs(event_id, pipeline_version)
              SELECT e.event_id, %s FROM events e
              WHERE NOT EXISTS (SELECT 1 FROM dl_jobs j WHERE j.event_id=e.event_id AND j.pipeline_version=%s)
              ORDER BY e.received_at, e.event_id LIMIT %s ON CONFLICT DO NOTHING''', (PIPELINE, PIPELINE, room))
        count = db.execute('SELECT count(*) FROM dl_jobs WHERE pipeline_version=%s', (PIPELINE,)).fetchone()[0]
        db.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime)
          VALUES ('dl-worker',now(),'waiting_for_model',%s,%s)
          ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,
          state=excluded.state,pending=excluded.pending,runtime=excluded.runtime''',
                   (count, json.dumps({'torch': torch.__version__, 'device': 'cpu', 'max_jobs': LIMIT,
                                      'capacity_reached': count >= LIMIT, 'scores_emitted': 0,
                                      'adapters': 'pending_training_contract'})))
    # Health file only after successful DB commit. Atomic publication, no secrets.
    tmp = Path('/tmp/dl-health.tmp')
    tmp.write_text(json.dumps({'updated_at': time.time(), 'state': 'waiting_for_model', 'pending': count}))
    tmp.replace('/tmp/dl-health.json')


if __name__ == '__main__':
    torch.set_num_threads(2)
    print(json.dumps({'service': 'dl-worker', 'state': 'waiting_for_model', 'torch': torch.__version__}), flush=True)
    while True:
        try:
            tick()
        except Exception as exc:
            # Do not print connection configuration or raw events.
            print(json.dumps({'state': 'error', 'error_type': type(exc).__name__}), flush=True)
        time.sleep(5)
