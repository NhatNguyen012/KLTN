"""Read-only CDM enrichment. Subject values are eligible at their explicit CDM start timestamp.

UUIDs/PIDs are join keys, never model features. No labels are consulted.
Archive identity and scanner hash invalidate the atomic persisted index.
"""
from pathlib import Path
from bisect import bisect_right
import hashlib
import json
import os
import sqlite3
import tarfile


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def unwrap(value):
    return next(iter(value.values()), '') if isinstance(value, dict) else value


def ensure_raw_context(data_dir, output):
    data_dir, output = Path(data_dir).resolve(), Path(output).resolve()
    if output == data_dir or data_dir in output.parents:
        raise ValueError('RAW context output must be outside dataset')
    archives = sorted((data_dir / 'RAW').glob('*.tar.gz'))
    if not archives:
        raise FileNotFoundError('RAW CDM archives required for principal/PID/parent enrichment')
    identity = {'scanner_sha256': digest(__file__),
                'archives': {p.name: digest(p) for p in archives},
                'availability': 'Subject.startTimestampNanos; invariant Principal identity; conflicting equal-time snapshots suppressed'}
    if output.exists():
        with sqlite3.connect(f'file:{output}?mode=ro', uri=True) as db:
            if json.loads(db.execute('select value from metadata').fetchone()[0]) == identity:
                return output
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_suffix('.sqlite.partial')
    partial.unlink(missing_ok=True)
    try:
        with sqlite3.connect(partial) as db:
            db.executescript('''
                CREATE TABLE subject (uuid TEXT, observed INTEGER, parent TEXT, principal TEXT,
                                      pid TEXT, path TEXT, cmd TEXT);
                CREATE TABLE principal (uuid TEXT, observed INTEGER, uid TEXT);
                CREATE TABLE metadata (value TEXT);
                CREATE TABLE endpoint_evidence (uuid TEXT, payload TEXT);
            ''')
            for archive in archives:
                watermark = 0
                subjects = principals = 0
                with tarfile.open(archive, 'r|gz') as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        for line in tar.extractfile(member):
                            if b'"timestampNanos":' in line:
                                # Avoid JSON decoding millions of events just for the watermark.
                                tail = line.split(b'"timestampNanos":', 1)[1].lstrip()
                                stamp = tail.split(b',', 1)[0].split(b'}', 1)[0]
                                watermark = max(watermark, int(stamp) // 1000)
                            kind = None
                            for name in ('Subject', 'Principal'):
                                if ('"com.bbn.tc.schema.avro.cdm18.' + name + '":{').encode() in line:
                                    kind = name
                                    break
                            if not kind:
                                if b'"80370C6E-9DB7-FFFF-FFFF-000000000040"' in line and b'"com.bbn.tc.schema.avro.cdm18.NetFlowObject":{' in line:
                                    db.execute('insert into endpoint_evidence values (?,?)',
                                               ('80370C6E-9DB7-FFFF-FFFF-000000000040', line.decode()))
                                continue
                            obj = next(iter(json.loads(line)['datum'].values()))
                            uuid = obj['uuid'].upper()
                            if kind == 'Principal':
                                db.execute('insert into principal values (?,?,?)',
                                           (uuid, 0, str(obj.get('userId') or '')))
                                principals += 1
                            else:
                                props = (obj.get('properties') or {}).get('map', {})
                                if obj.get('startTimestampNanos') is None:
                                    continue
                                observed = int(obj['startTimestampNanos']) // 1000
                                pid = str(props.get('tgid') or obj.get('cid') or '')
                                db.execute('insert into subject values (?,?,?,?,?,?,?)',
                                           (uuid, observed, str(unwrap(obj.get('parentSubject')) or '').upper(),
                                            str(unwrap(obj.get('localPrincipal')) or '').upper(), pid,
                                            props.get('path', ''), str(unwrap(obj.get('cmdLine')) or '')))
                                subjects += 1
                db.commit()
                print(f'RAW context: {archive.name}: {subjects} subjects, {principals} principals', flush=True)
            # Export order is not time order. A global event watermark can place
            # an April-12 subject after April-13 and suppress all of its context.
            # Equal-time conflicting snapshots cannot be safely ordered: suppress.
            db.execute("""UPDATE subject SET parent='', principal='', pid='', path='', cmd=''
                          WHERE (uuid, observed) IN
                          (SELECT uuid, observed FROM subject GROUP BY uuid, observed
                           HAVING COUNT(DISTINCT parent || '|' || principal || '|' || pid || '|' || path || '|' || cmd) > 1)""")
            db.execute("""UPDATE principal SET uid='' WHERE uuid IN
                          (SELECT uuid FROM principal GROUP BY uuid HAVING COUNT(DISTINCT uid) > 1)""")
            db.execute('create index subject_uuid on subject(uuid, observed)')
            db.execute('create index principal_uuid on principal(uuid, observed)')
            db.execute('insert into metadata values (?)', (json.dumps(identity, sort_keys=True),))
        with partial.open('rb') as f:
            os.fsync(f.fileno())
        os.replace(partial, output)
    finally:
        partial.unlink(missing_ok=True)
    return output


class RawContext:
    def __init__(self, path):
        self.subjects, self.principals = {}, {}
        with sqlite3.connect(f'file:{Path(path).resolve()}?mode=ro', uri=True) as db:
            self.identity = json.loads(db.execute('select value from metadata').fetchone()[0])
            for uuid, observed, *values in db.execute('select * from subject order by observed, rowid'):
                entry = self.subjects.setdefault(uuid, ([], []))
                entry[0].append(observed)
                entry[1].append(values)
            for uuid, observed, uid in db.execute('select * from principal order by observed, rowid'):
                entry = self.principals.setdefault(uuid, ([], []))
                entry[0].append(observed)
                entry[1].append(uid)

    @staticmethod
    def latest(history, timestamp):
        if not history:
            return None
        if isinstance(history, tuple):
            stamps, values = history
            if len(stamps) == 1:
                return values[0] if timestamp >= stamps[0] else None
            idx = bisect_right(stamps, timestamp)
            return values[idx - 1] if idx else None
        if len(history) == 1:
            return history[0][1] if timestamp >= history[0][0] else None
        idx = bisect_right(history, timestamp, key=lambda item: item[0])
        return history[idx - 1][1] if idx else None

    def subject(self, uuid, timestamp):
        return self.latest(self.subjects.get(uuid, None), timestamp)

    def uid(self, uuid, timestamp):
        return self.latest(self.principals.get(uuid, None), timestamp)
