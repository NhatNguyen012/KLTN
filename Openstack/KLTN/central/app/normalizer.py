"""Central Normalization & Correlation (General Architecture, CENTRAL VM).

Raw records (table `events`, written by the archiver) -> model-ready host events (table `host_events`) with the same
adapters the endpoints use (kltn_features): auditd lines are grouped into events by audit serial, Sysmon records are
mapped onto CBC-EDR semantics with the per-host process / signer / DNS tables. Every host event keeps the ids of the
raw records it came from, so alerts can always be traced back to raw evidence.

Per (host, source) the normalizer keeps a cursor = the lowest raw `seq` still needed (the oldest line of a pending
audit group). After a restart it replays raw records from two hours before that cursor to rebuild the causal state;
re-emitted events hit the unique event_key and are ignored.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DDL, db_connect  # noqa: E402
from kltn_features.auditd_stream import AuditStream  # noqa: E402
from kltn_features.sysmon import SysmonMapper, parse_event  # noqa: E402

SERVICE = "normalizer"
SOURCES = {"audit": ("linux", "linux-audit"), "sysmon": ("windows", "windows-sysmon")}
BATCH = 5000
IDLE_FLUSH_S = 3.0
REPLAY_S = 2 * 3600


def iso(ts_us: int) -> datetime:
    return datetime.fromtimestamp(ts_us / 1e6, timezone.utc)


class Lane:
    """State of one (host, source)."""

    def __init__(self, host_id: str, source: str, name: str):
        self.host_id, self.source = host_id, source
        self.os, self.domain = SOURCES[source]
        self.adapter = AuditStream(name) if source == "audit" else SysmonMapper(name)
        self.cursor = 0                  # all raw rows with seq < cursor are fully reflected in host_events
        self.last_input = time.monotonic()
        self.pending_seq: dict = {}      # audit group key -> lowest seq of its lines

    def feed(self, seq: int, event_id: str, raw: dict) -> list[dict]:
        if self.source == "audit":
            line = str(raw.get("log") or raw.get("message") or "")
            out = self.adapter.feed(line, ref=event_id)
            return out
        fields = parse_event(raw)
        if fields is None:
            return []
        e = self.adapter.map(fields)
        if e is None:
            return []
        e["refs"] = [event_id]
        return [e]

    def flush(self) -> list[dict]:
        return self.adapter.flush() if self.source == "audit" else []


def row_of(lane: Lane, e: dict) -> tuple:
    refs = list(e.pop("refs", []) or [])
    if lane.source == "audit":
        key = f"{lane.host_id}:audit:{e['ts'] // 1_000_000}:{e['line']}"
        kind, image, cmd, target = e["kind"], e.get("image"), e.get("cmd"), e.get("tpath")
        principal = f"uid={e.get('uid')} auid={e.get('auid')}"
        rule_keys = e.get("rule_keys") or []
    else:
        key = f"{lane.host_id}:sysmon:{e['record_id'] or e['ts']}"
        kind, image = e["event_type"], e.get("path")
        cmd = e.get("tcmd") or e.get("cmd")
        target = e.get("domain") or e.get("tpath")
        principal, rule_keys = e.get("user"), []
    event = {k: v for k, v in e.items() if k not in ("coarse_tactics",)}
    return (key, lane.host_id, lane.os, lane.source, lane.domain, int(e["ts"]), iso(int(e["ts"])), kind,
            (image or "")[:4096], (cmd or "")[:8192], (target or "")[:4096], e.get("pid"), e.get("ppid"),
            (principal or "")[:512], rule_keys, Jsonb(event), Jsonb(refs))


INSERT = '''INSERT INTO host_events(event_key,host_id,os,source,domain,ts_us,ts,kind,image,cmd,target,pid,ppid,principal,
  rule_keys,event,raw_refs) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_key) DO NOTHING'''


class Normalizer:
    def __init__(self):
        self.lanes: dict[tuple[str, str], Lane] = {}

    def lane(self, conn, host_id: str, source: str) -> Lane:
        k = (host_id, source)
        if k not in self.lanes:
            name = conn.execute("SELECT name FROM hosts WHERE host_id=%s", (host_id,)).fetchone()
            lane = Lane(host_id, source, name[0] if name else host_id)
            cur = conn.execute("SELECT value FROM framework_cursors WHERE name=%s", (f"norm:{host_id}:{source}",)).fetchone()
            if cur:
                # replay window to rebuild causal state (process tables, open audit groups)
                row = conn.execute('''SELECT min(seq) FROM events WHERE host_id=%s AND source=%s AND received_at >=
                  (SELECT received_at FROM events WHERE seq=%s) - make_interval(secs => %s)''',
                                   (host_id, source, cur[0]["seq"], REPLAY_S)).fetchone()
                lane.cursor = int(row[0]) if row and row[0] else int(cur[0]["seq"])
            self.lanes[k] = lane
        return self.lanes[k]

    def tick(self) -> dict:
        inserted, read = 0, 0
        with db_connect() as conn:
            pairs = conn.execute('''SELECT DISTINCT host_id, source FROM events
              WHERE source = ANY(%s) AND received_at > now() - interval '7 days' ''', (list(SOURCES),)).fetchall()
            for host_id, source in pairs:
                lane = self.lane(conn, host_id, source)
                rows = conn.execute('''SELECT seq, event_id, payload FROM events WHERE host_id=%s AND source=%s AND seq>=%s
                  ORDER BY seq LIMIT %s''', (host_id, source, lane.cursor, BATCH)).fetchall()
                out = []
                for seq, event_id, payload in rows:
                    out += lane.feed(seq, event_id, payload.get("raw", {}))
                if rows:
                    lane.last_input = time.monotonic()
                    lane.cursor = rows[-1][0] + 1
                    read += len(rows)
                elif time.monotonic() - lane.last_input > IDLE_FLUSH_S:
                    out += lane.flush()
                if out:
                    with conn.cursor() as cur:
                        cur.executemany(INSERT, [row_of(lane, e) for e in out])
                    inserted += len(out)
                # durable cursor: the oldest raw line still held in an open audit group (or the next row)
                safe = lane.cursor
                if lane.source == "audit" and lane.adapter.pending:
                    ref = lane.adapter.oldest_ref()
                    if ref:
                        r = conn.execute("SELECT seq FROM events WHERE event_id=%s", (ref,)).fetchone()
                        if r:
                            safe = min(safe, int(r[0]))
                conn.execute('''INSERT INTO framework_cursors(name,value) VALUES (%s,%s) ON CONFLICT(name) DO UPDATE
                  SET value=excluded.value, updated_at=now()''', (f"norm:{host_id}:{source}", Jsonb({"seq": safe})))
            conn.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime) VALUES (%s,now(),'running',%s,%s)
              ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,state=excluded.state,
              pending=excluded.pending,runtime=excluded.runtime''',
                         (SERVICE, sum(l.adapter.pending for l in self.lanes.values() if l.source == "audit"),
                          Jsonb({"lanes": len(self.lanes), "last_read": read, "last_inserted": inserted})))
        return {"read": read, "inserted": inserted}


def main():
    with db_connect() as conn:
        conn.execute(DDL)
    n = Normalizer()
    print(json.dumps({"service": SERVICE, "state": "started"}), flush=True)
    while True:
        try:
            r = n.tick()
            if r["read"] == 0:
                time.sleep(1)
        except Exception as exc:  # keep running; the cursor makes the retry idempotent
            print(json.dumps({"service": SERVICE, "error": f"{type(exc).__name__}: {exc}"[:500]}), flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
