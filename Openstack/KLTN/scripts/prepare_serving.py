#!/usr/bin/env python3
"""Create isolated model-free DL tables/role; never delete archived telemetry."""
import json
from pathlib import Path
import secrets
import subprocess
from prepare_central import ROOT, RUNTIME, private_write

MIGRATION = r'''
import json,sys
from psycopg import sql
from common import db_connect
cfg=json.load(sys.stdin)
with db_connect() as db:
    if not db.execute("SELECT 1 FROM pg_roles WHERE rolname='kltn_dl'").fetchone():
        db.execute(sql.SQL("CREATE ROLE kltn_dl LOGIN PASSWORD {}").format(sql.Literal(cfg['password'])))
    else:
        db.execute(sql.SQL("ALTER ROLE kltn_dl PASSWORD {}").format(sql.Literal(cfg['password'])))
    db.execute("""CREATE TABLE IF NOT EXISTS dl_jobs (
      event_id TEXT NOT NULL REFERENCES events(event_id),
      pipeline_version TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'waiting_for_model',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(event_id,pipeline_version));
      CREATE TABLE IF NOT EXISTS serving_status (
      service TEXT PRIMARY KEY, updated_at TIMESTAMPTZ NOT NULL, state TEXT NOT NULL,
      pending BIGINT NOT NULL, runtime JSONB NOT NULL);
      GRANT CONNECT ON DATABASE kltn TO kltn_dl;
      GRANT USAGE ON SCHEMA public TO kltn_dl;
      GRANT SELECT ON events TO kltn_dl;
      GRANT SELECT,INSERT ON dl_jobs TO kltn_dl;
      GRANT SELECT,INSERT,UPDATE ON serving_status TO kltn_dl;
    """)
print('DL preparation schema and restricted role ready.')
'''


def main():
    p = RUNTIME / 'dl.json'
    if not p.exists():
        private_write(p, json.dumps({'password': secrets.token_urlsafe(32)}))
    (RUNTIME / 'models/dl').mkdir(parents=True, exist_ok=True)
    subprocess.run(['docker', 'compose', '-f', str(ROOT/'central/compose.yaml'),
                    'exec', '-T', 'api', 'python', '-c', MIGRATION],
                   input=p.read_text(), text=True, check=True)


if __name__ == '__main__':
    main()
