"""Log Receive -> raw storage: NATS JetStream (work queue) -> immutable `events` rows (deduplicated by event_id).
Normalization happens in normalizer.py from the stored raw records, so the raw archive never depends on an adapter."""
import asyncio
import json
import logging

from nats.errors import TimeoutError
from psycopg.types.json import Jsonb

from common import DDL, connect_nats, db_connect


def store(records):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.executemany('INSERT INTO events(event_id,host_id,source,payload) VALUES (%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING',
                            [(r['event_id'], r['host_id'], r['source'], Jsonb(r)) for r in records])


async def main():
    with db_connect() as conn:
        conn.execute(DDL)
    nc = await connect_nats()
    js = nc.jetstream()
    sub = await js.pull_subscribe('kltn.events', durable='archive')
    while True:
        try:
            messages = await sub.fetch(500, timeout=5)
        except TimeoutError:
            continue
        try:
            await asyncio.to_thread(store, [json.loads(m.data) for m in messages])
            for m in messages:
                await m.ack()
        except Exception:
            logging.exception('archive batch failed; messages will be redelivered')
            for m in messages:
                await m.nak(delay=5)


if __name__ == '__main__':
    asyncio.run(main())
