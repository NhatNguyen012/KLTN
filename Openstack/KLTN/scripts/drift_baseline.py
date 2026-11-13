#!/usr/bin/env python3
"""Restart the drift reference (General Architecture: drift trigger of the IL loop) after a change that alters the
telemetry on purpose -- a sensor policy change, a new benign workload -- so it is not reported as model drift.

The framework worker builds each host's reference from the first 24 h of endpoint summaries of the host's current
bundle; this mark moves that start forward (all hosts, or one). Recorded with who and why; nothing is deleted.
  scripts/drift_baseline.py --by <operator> --reason "sysmon v3 + audit pipeline exclusion" [--from ISO] [--host NAME]
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central/app'))
from common import db_connect  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--from', dest='start', default=None, help='ISO time (default: now)')
    p.add_argument('--host', default=None, help='host name (default: every host)')
    p.add_argument('--by', required=True)
    p.add_argument('--reason', required=True)
    a = p.parse_args()
    start = datetime.fromisoformat(a.start) if a.start else datetime.now(timezone.utc)
    if start.tzinfo is None:
        sys.exit('--from needs a time zone (e.g. 2026-11-14T00:00:00+00:00)')
    with db_connect() as conn:
        key = '*'
        if a.host:
            row = conn.execute('SELECT host_id FROM hosts WHERE name=%s', (a.host,)).fetchone()
            if not row:
                sys.exit(f'unknown host {a.host}')
            key = row[0]
        cur = conn.execute("SELECT value FROM framework_cursors WHERE name='drift-baseline'").fetchone()
        value = dict(cur[0]) if cur else {}
        value[key] = {'from': start.isoformat(), 'by': a.by, 'reason': a.reason,
                      'set_at': datetime.now(timezone.utc).isoformat()}
        conn.execute('''INSERT INTO framework_cursors(name,value) VALUES ('drift-baseline',%s) ON CONFLICT(name) DO UPDATE
          SET value=excluded.value, updated_at=now()''', (Jsonb(value),))
    print(json.dumps({'drift_baseline': value}, indent=1))


if __name__ == '__main__':
    main()
