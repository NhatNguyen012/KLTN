#!/usr/bin/env python3
"""Database roles and host inventory for the IL3 stack (additive, idempotent; never deletes telemetry).

* kltn_dl: the DL worker reads host events and writes only its own scores / cursors / status;
* mlflow: owner of the `mlflow` database (MLflow backend store);
* hosts: inventory mirror (name, OS, model domain, address) from runtime/secrets.json, used by the normalizer,
  the SOC page and the response controller.
Runs inside the api container (it has the DB credentials), passwords are passed on stdin.
"""
import json
import subprocess

from prepare_central import ROOT, RUNTIME

MIGRATION = r'''
import json, sys
from psycopg import sql
from psycopg.types.json import Jsonb
from common import DDL, db_connect
cfg = json.load(sys.stdin)
with db_connect() as db:
    db.execute(DDL)
    for role, pw in (("kltn_dl", cfg["dl_password"]), ("mlflow", cfg["mlflow_password"])):
        verb = "ALTER" if db.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone() else "CREATE"
        db.execute(sql.SQL(verb + " ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(pw)))
    db.execute("""GRANT CONNECT ON DATABASE kltn TO kltn_dl; GRANT USAGE ON SCHEMA public TO kltn_dl;
      GRANT SELECT ON host_events, hosts TO kltn_dl; GRANT SELECT, INSERT ON scores TO kltn_dl;
      GRANT USAGE ON SEQUENCE scores_seq_seq TO kltn_dl;
      GRANT SELECT, INSERT, UPDATE ON serving_status, framework_cursors TO kltn_dl;""")
    for host_id, h in cfg["hosts"].items():
        os_type = {"ubuntu": "linux"}.get(h.get("os_type"), h.get("os_type") or "unknown")
        domain = {"linux": "linux-audit", "windows": "windows-sysmon"}.get(os_type, "unknown")
        db.execute("""INSERT INTO hosts(host_id,name,os,domain,address) VALUES (%s,%s,%s,%s,%s)
          ON CONFLICT(host_id) DO UPDATE SET name=excluded.name, os=excluded.os, domain=excluded.domain,
          address=excluded.address, updated_at=now()""", (host_id, h.get("name", host_id), os_type, domain, h.get("address")))
db = __import__("psycopg").connect(host="127.0.0.1", port=15432, dbname="kltn", user="kltn",
                                   password=json.load(open("/run/kltn/secrets.json"))["postgres_password"], autocommit=True)
if not db.execute("SELECT 1 FROM pg_database WHERE datname='mlflow'").fetchone():
    db.execute("CREATE DATABASE mlflow OWNER mlflow")
print("roles, grants, hosts and the mlflow database are ready")
'''


def main():
    secrets = json.loads((RUNTIME / 'secrets.json').read_text())
    payload = {'dl_password': json.loads((RUNTIME / 'dl.json').read_text())['password'],
               'mlflow_password': secrets['mlflow_db_password'], 'hosts': secrets['hosts']}
    subprocess.run(['docker', 'compose', '-f', str(ROOT / 'central/compose.yaml'), 'exec', '-T', 'api', 'python', '-c',
                    MIGRATION], input=json.dumps(payload), text=True, check=True)


if __name__ == '__main__':
    main()
