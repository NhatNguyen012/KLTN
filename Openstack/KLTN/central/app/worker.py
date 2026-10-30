import asyncio
import json
import logging
from common import DDL, connect_nats, db_connect
from psycopg.types.json import Jsonb
from nats.errors import TimeoutError


def store(record):
    with db_connect() as conn:
        conn.execute('INSERT INTO events(event_id,host_id,source,payload) VALUES (%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING',
                     (record['event_id'], record['host_id'], record['source'], Jsonb(record)))


async def main():
    with db_connect() as conn:
        conn.execute(DDL)
    nc = await connect_nats()
    js = nc.jetstream()
    sub = await js.pull_subscribe('kltn.events', durable='archive')
    while True:
        try:
            messages = await sub.fetch(100, timeout=5)
        except TimeoutError:
            continue
        for message in messages:
            try:
                record = json.loads(message.data)
                await asyncio.to_thread(store, record)
                await message.ack()
            except Exception:
                logging.exception('Archive failed; event will be retried')
                await message.nak(delay=5)


if __name__ == '__main__':
    asyncio.run(main())
