"""Durable central DL staging and checksum-gated BiLSTM shadow inference."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import time
from typing import Any

import numpy as np
import psycopg
from psycopg.types.json import Jsonb
import torch

from bilstm import BiLSTMBaseline

PIPELINE = 'network-dl-live-v1'
LIMIT = 50000
MAX_SEQUENCE = 512
WINDOW_SECONDS = 900
ALLOWED_LATENESS_SECONDS = 30


class BundleError(Exception):
    pass


def config():
    return json.loads(Path(os.environ.get('KLTN_DL_CONFIG', '/run/kltn/dl.json')).read_text())


def connect():
    cfg = config()
    return psycopg.connect(host='127.0.0.1', port=15432, dbname='kltn',
                           user='kltn_dl', password=cfg['password'], connect_timeout=5)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def verify_bundle(root: Path) -> dict:
    root = root.resolve()
    try:
        manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError) as exc:
        raise BundleError('manifest_missing_or_invalid') from exc
    if (manifest.get('schema_version') != 'bundle.v1' or
            manifest.get('branch') != 'network_dl' or manifest.get('algorithm') != 'bilstm'):
        raise BundleError('bundle_contract_incompatible')
    if not manifest.get('activation', {}).get('eligible', False):
        raise BundleError('bundle_not_activation_eligible')
    if manifest.get('domain_validation') != 'validated':
        raise BundleError('bundle_domain_not_validated')
    if manifest.get('parity', {}).get('passed') is not True:
        raise BundleError('bundle_parity_not_passed')
    artifacts = manifest.get('artifacts', {})
    if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > 100:
        raise BundleError('artifact_manifest_invalid')
    for relative, metadata in artifacts.items():
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise BundleError('artifact_path_escape') from exc
        if not path.is_file() or path.is_symlink():
            raise BundleError('artifact_missing_or_symlink')
        expected = metadata.get('sha256') if isinstance(metadata, dict) else None
        if not isinstance(expected, str) or not hmac.compare_digest(sha256_file(path), expected):
            raise BundleError('artifact_checksum_mismatch')
    return manifest


class NetworkModel:
    def __init__(self, root: Path):
        self.root = root
        self.manifest = verify_bundle(root)
        map_document = json.loads((root / 'preprocess/network_category_maps.json').read_text())
        fields = ['app_family', 'proto', 'resp_port_class', 'image_dir_class']
        try:
            self.maps = {field: map_document['fields'][field]['mapping'] for field in fields}
        except (KeyError, TypeError) as exc:
            raise BundleError('category_map_contract_invalid') from exc
        self.cards = [max(int(value) for value in self.maps[field].values()) + 1 for field in fields]
        model_cfg = self.manifest.get('model_config', {})
        self.model = BiLSTMBaseline(
            categorical_cardinalities=self.cards, numerical_dim=0, binary_dim=1,
            event_dim=int(model_cfg.get('event_dim', 64)),
            hidden_dim=int(model_cfg.get('hidden_dim', 64)),
            lstm_layers=int(model_cfg.get('lstm_layers', 1)),
            dropout=float(model_cfg.get('dropout', 0.2)),
        )
        checkpoint = torch.load(root / 'model/weights.pt', map_location='cpu', weights_only=True)
        state = checkpoint.get('model_state_dict', checkpoint) if isinstance(checkpoint, dict) else checkpoint
        self.model.load_state_dict(state, strict=True)
        self.model.eval()
        self.threshold = float(self.manifest['policy']['threshold'])
        if not 0 <= self.threshold <= 1:
            raise BundleError('threshold_invalid')
        self.bundle_id = self.manifest['bundle_id']

    @staticmethod
    def basename(path: str | None) -> str:
        return (path or '').replace('/', '\\').rstrip('\\').split('\\')[-1].lower()

    @staticmethod
    def image_dir(path: str | None) -> str:
        value = (path or '').replace('/', '\\').lower()
        if not value:
            return 'MISSING'
        if '\\' not in value:
            return 'BARE_NAME'
        if '\\windows\\system32\\' in value:
            return 'SYSTEM32'
        if '\\program files' in value:
            return 'PROGRAM_FILES'
        if '\\users\\' in value and ('\\appdata\\' in value or '\\temp\\' in value):
            return 'TEMP_OR_APPDATA'
        if '\\windows\\' in value:
            return 'WINDOWS_OTHER'
        if '\\users\\' in value:
            return 'USERS_OTHER'
        return 'OTHER'

    @staticmethod
    def port_class(value: Any) -> str:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return '<MISSING>'
        mapping = {443: 'PORT_443_HTTPS', 80: 'PORT_80_HTTP', 8080: 'PORT_8080_HTTP_ALT',
                   53: 'PORT_53_DNS', 445: 'PORT_445_SMB', 22: 'PORT_22_SSH',
                   3389: 'PORT_3389_RDP'}
        return mapping.get(port, 'REGISTERED' if port >= 1024 else 'WELL_KNOWN_OTHER')

    def category(self, field: str, value: str | None) -> int:
        mapping = self.maps[field]
        return int(mapping.get(value, mapping.get('<MISSING>' if not value else '<UNK>', 0)))

    def encode(self, rows: list[dict]) -> tuple[dict[str, torch.Tensor], list[str]]:
        rows = rows[:MAX_SEQUENCE]
        categorical = np.zeros((len(rows), 4), dtype=np.int64)
        deltas = np.zeros((len(rows), 1), dtype=np.float32)
        previous = None
        refs = []
        for index, row in enumerate(rows):
            network = row.get('network') or {}
            path = row.get('process_path')
            categorical[index] = [
                self.category('app_family', self.basename(path)),
                self.category('proto', (network.get('protocol') or '').lower() or None),
                self.category('resp_port_class', self.port_class(network.get('destination_port'))),
                self.category('image_dir_class', self.image_dir(path)),
            ]
            when = row['event_time'] or row['received_at']
            if previous is not None:
                deltas[index, 0] = math.log1p(max(0.0, (when - previous).total_seconds()))
            previous = when
            refs.append(row['event_id'])
        length = len(rows)
        tensors = {
            'x_cat': torch.from_numpy(categorical).unsqueeze(0),
            'x_num': torch.zeros((1, length, 0), dtype=torch.float32),
            'x_num_missing': torch.zeros((1, length, 0), dtype=torch.float32),
            'x_bin': torch.zeros((1, length, 1), dtype=torch.float32),
            'delta_t_log1p': torch.from_numpy(deltas).unsqueeze(0),
            'lengths': torch.tensor([length], dtype=torch.long),
        }
        return tensors, refs

    def predict(self, rows: list[dict]) -> tuple[float, list[str]]:
        tensors, refs = self.encode(rows)
        with torch.inference_mode():
            probability = float(torch.sigmoid(self.model(**tensors))[0])
        if not 0 <= probability <= 1:
            raise BundleError('model_emitted_invalid_probability')
        return probability, refs


def stage_jobs(db) -> int:
    db.execute('SELECT pg_advisory_xact_lock(18443001)')
    pending = db.execute('SELECT count(*) FROM dl_jobs WHERE pipeline_version=%s AND state<>%s',
                         (PIPELINE, 'scored')).fetchone()[0]
    room = max(0, min(250, LIMIT - pending))
    if room:
        db.execute('''INSERT INTO dl_jobs(event_id,pipeline_version)
          SELECT n.event_id,%s FROM normalized_events n
          WHERE n.source IN ('sysmon','security','powershell')
          AND NOT EXISTS (SELECT 1 FROM dl_jobs j WHERE j.event_id=n.event_id
            AND j.pipeline_version=%s)
          ORDER BY COALESCE(n.event_time,n.received_at),n.event_id
          LIMIT %s ON CONFLICT DO NOTHING''',
          (PIPELINE, PIPELINE, room))
    return db.execute('SELECT count(*) FROM dl_jobs WHERE pipeline_version=%s AND state<>%s',
                      (PIPELINE, 'scored')).fetchone()[0]


def next_window(db) -> list[dict]:
    first = db.execute('''SELECT n.host_id,COALESCE(n.event_time,n.received_at)
      FROM dl_jobs j JOIN normalized_events n ON n.event_id=j.event_id
      WHERE j.pipeline_version=%s AND j.state IN ('waiting_for_model','waiting')
      AND n.source IN ('sysmon','security','powershell')
      ORDER BY COALESCE(n.event_time,n.received_at),n.event_id LIMIT 1''', (PIPELINE,)).fetchone()
    if not first:
        return []
    host_id, start = first
    result = db.execute('''SELECT n.event_id,n.host_id,n.event_time,n.received_at,
      n.event_type,n.process_path,n.network
      FROM dl_jobs j JOIN normalized_events n ON n.event_id=j.event_id
      WHERE j.pipeline_version=%s AND j.state IN ('waiting_for_model','waiting')
      AND n.host_id=%s AND COALESCE(n.event_time,n.received_at)>=%s
      AND COALESCE(n.event_time,n.received_at)<%s
      ORDER BY COALESCE(n.event_time,n.received_at),n.event_id LIMIT %s''',
      (PIPELINE, host_id, start, start + timedelta(seconds=WINDOW_SECONDS), MAX_SEQUENCE)).fetchall()
    return [{'event_id': row[0], 'host_id': row[1], 'event_time': row[2],
             'received_at': row[3], 'event_type': row[4], 'process_path': row[5],
             'network': row[6]} for row in result]


def infer_one(db, model: NetworkModel) -> bool:
    rows = next_window(db)
    if len(rows) < 2:
        return False
    start = rows[0]['event_time'] or rows[0]['received_at']
    declared_end = start + timedelta(seconds=WINDOW_SECONDS)
    if len(rows) < MAX_SEQUENCE and datetime.now(timezone.utc) < (
            declared_end + timedelta(seconds=ALLOWED_LATENESS_SECONDS)):
        return False
    probability, refs = model.predict(rows)
    processed = datetime.now(timezone.utc)
    window = {'start': start.isoformat(), 'end': declared_end.isoformat(),
              'partial': False, 'truncated': len(rows) >= MAX_SEQUENCE,
              'allowed_lateness_seconds': ALLOWED_LATENESS_SECONDS}
    score_id = canonical_hash(['score.v1', rows[0]['host_id'], 'network_dl',
                               model.bundle_id, refs, window, processed.isoformat()])
    db.execute('''INSERT INTO scores(score_id,schema_version,host_id,branch,bundle_id,
      status,score,threshold,prediction,domain,domain_validation,event_refs,score_window,
      evidence,processed_at) VALUES (%s,'score.v1',%s,'network_dl',%s,'ready_shadow',
      %s,%s,%s,'windows-network',%s,%s,%s,%s,%s)
      ON CONFLICT(score_id) DO NOTHING''',
      (score_id, rows[0]['host_id'], model.bundle_id, probability, model.threshold,
       int(probability >= model.threshold), model.manifest['domain_validation'],
       Jsonb(refs), Jsonb(window),
       Jsonb({'sequence_length': len(rows), 'pipeline_version': PIPELINE,
              'late_policy': '30-second close watermark; later events form a new scored chunk',
              'limitation': 'completed-window shadow inference'}), processed))
    db.execute('''UPDATE dl_jobs SET state='scored',completed_at=now(),score_id=%s
      WHERE pipeline_version=%s AND event_id=ANY(%s)''', (score_id, PIPELINE, refs))
    return True


def heartbeat(db, state: str, pending: int, model: NetworkModel | None, error: str | None = None):
    runtime = {'torch': torch.__version__, 'device': 'cpu', 'max_jobs': LIMIT,
               'capacity_reached': pending >= LIMIT, 'pipeline_version': PIPELINE,
               'bundle_id': model.bundle_id if model else None,
               'adapter': 'network-sequence-live-v1', 'error': error}
    db.execute('''INSERT INTO serving_status(service,updated_at,state,pending,runtime)
      VALUES ('dl-worker',now(),%s,%s,%s)
      ON CONFLICT(service) DO UPDATE SET updated_at=excluded.updated_at,
      state=excluded.state,pending=excluded.pending,runtime=excluded.runtime''',
      (state, pending, Jsonb(runtime)))
    tmp = Path('/tmp/dl-health.tmp')
    tmp.write_text(json.dumps({'updated_at': time.time(), 'state': state, 'pending': pending}))
    tmp.replace('/tmp/dl-health.json')


def load_model() -> tuple[NetworkModel | None, str, str | None]:
    root = Path(os.environ.get('KLTN_DL_BUNDLE', '/models/current'))
    if not (root / 'manifest.json').exists():
        return None, 'waiting_for_model', None
    try:
        return NetworkModel(root), 'ready_shadow', None
    except Exception as exc:
        return None, 'incompatible_schema', type(exc).__name__


def tick(model: NetworkModel | None, state: str, error: str | None):
    with connect() as db:
        pending = stage_jobs(db)
        if model is not None:
            for _ in range(8):
                if not infer_one(db, model):
                    break
            pending = db.execute('SELECT count(*) FROM dl_jobs WHERE pipeline_version=%s AND state<>%s',
                                 (PIPELINE, 'scored')).fetchone()[0]
        heartbeat(db, state, pending, model, error)


if __name__ == '__main__':
    torch.set_num_threads(2)
    model, state, error = load_model()
    print(json.dumps({'service': 'dl-worker', 'state': state,
                      'bundle_id': model.bundle_id if model else None}), flush=True)
    while True:
        try:
            tick(model, state, error)
        except Exception as exc:
            print(json.dumps({'state': 'error', 'error_type': type(exc).__name__}), flush=True)
        time.sleep(5)
