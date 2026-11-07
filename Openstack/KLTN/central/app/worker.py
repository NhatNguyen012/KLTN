import asyncio
import json
import logging
from common import DDL, connect_nats, db_connect
from normalization import json_view, normalize_record
from psycopg.types.json import Jsonb
from nats.errors import TimeoutError


def store(record):
    with db_connect() as conn:
        inserted = conn.execute(
            'INSERT INTO events(event_id,host_id,source,payload) VALUES (%s,%s,%s,%s) '
            'ON CONFLICT (event_id) DO NOTHING RETURNING received_at',
            (record['event_id'], record['host_id'], record['source'], Jsonb(record))).fetchone()
        if inserted:
            event = normalize_record(record, inserted[0])
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
