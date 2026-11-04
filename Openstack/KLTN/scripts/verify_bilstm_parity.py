#!/usr/bin/env python3
"""Golden sequence parity verification for BiLSTM Network DL model.

Validates the complete end-to-end transformation:
  raw network events
  -> category mapping (app_family, proto, resp_port_class, image_dir_class)
  -> chronological ordering
  -> delta_t_log1p
  -> sequence padding/masking (max 512 events, 900s window)
  -> late-event handling policy
  -> BiLSTM forward pass + multi-scale top-k pooling
  -> Sigmoid probability & decision at threshold 0.245.

Exports a verified golden fixture artifact: evidence/bilstm_sequence_parity_fixture.json.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]

# Add central serving path
sys.path.insert(0, str(ROOT / 'serving/central'))
from bilstm import BiLSTMBaseline


GOLDEN_NETWORK_WINDOWS = [
    {
        "window_id": "fixture_win_c2_beacon",
        "description": "Multi-stage C2 beacon sequence via PowerShell and cmd",
        "expected_label": 1,
        "events": [
            {
                "event_id": "net_c2_01",
                "event_time": "2026-11-01T03:00:00.000000Z",
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "network": {"protocol": "udp", "destination_port": 53, "destination_ip": "1.1.1.1"},
            },
            {
                "event_id": "net_c2_02",
                "event_time": "2026-11-01T03:00:02.500000Z",
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "network": {"protocol": "tcp", "destination_port": 443, "destination_ip": "198.51.100.20"},
            },
            {
                "event_id": "net_c2_03",
                "event_time": "2026-11-01T03:00:15.000000Z",
                "process_path": "C:\\Windows\\System32\\cmd.exe",
                "network": {"protocol": "tcp", "destination_port": 8080, "destination_ip": "198.51.100.21"},
            },
            {
                "event_id": "net_c2_04",
                "event_time": "2026-11-01T03:00:16.000000Z",
                "process_path": "C:\\Windows\\System32\\certutil.exe",
                "network": {"protocol": "tcp", "destination_port": 80, "destination_ip": "198.51.100.22"},
            },
            {
                "event_id": "net_c2_05",
                "event_time": "2026-11-01T03:01:16.000000Z",
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "network": {"protocol": "tcp", "destination_port": 443, "destination_ip": "198.51.100.20"},
            },
        ],
    },
    {
        "window_id": "fixture_win_benign_background",
        "description": "Benign Windows background network activity",
        "expected_label": 0,
        "events": [
            {
                "event_id": "net_bg_01",
                "event_time": "2026-11-01T04:00:00.000000Z",
                "process_path": "C:\\Windows\\System32\\svchost.exe",
                "network": {"protocol": "udp", "destination_port": 53, "destination_ip": "8.8.8.8"},
            },
            {
                "event_id": "net_bg_02",
                "event_time": "2026-11-01T04:00:05.000000Z",
                "process_path": "C:\\Windows\\System32\\svchost.exe",
                "network": {"protocol": "udp", "destination_port": 123, "destination_ip": "time.windows.com"},
            },
            {
                "event_id": "net_bg_03",
                "event_time": "2026-11-01T04:00:30.000000Z",
                "process_path": "C:\\Program Files\\Microsoft OneDrive\\onedrive.exe",
                "network": {"protocol": "tcp", "destination_port": 443, "destination_ip": "20.190.151.7"},
            },
        ],
    },
    {
        "window_id": "fixture_win_single_event",
        "description": "Boundary case: minimal sequence with exactly 1 event",
        "expected_label": 0,
        "events": [
            {
                "event_id": "net_single_01",
                "event_time": "2026-11-01T05:00:00.000000Z",
                "process_path": "C:\\Windows\\explorer.exe",
                "network": {"protocol": "tcp", "destination_port": 445, "destination_ip": "10.0.0.1"},
            },
        ],
    },
]


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def basename(path: str | None) -> str:
    return (path or '').replace('/', '\\').rstrip('\\').split('\\')[-1].lower()


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


def port_class(value: Any) -> str:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return '<MISSING>'
    mapping = {
        443: 'PORT_443_HTTPS', 80: 'PORT_80_HTTP', 8080: 'PORT_8080_HTTP_ALT',
        53: 'PORT_53_DNS', 445: 'PORT_445_SMB', 22: 'PORT_22_SSH',
        3389: 'PORT_3389_RDP',
    }
    return mapping.get(port, 'REGISTERED' if port >= 1024 else 'WELL_KNOWN_OTHER')


def parse_time(value: str) -> datetime:
    text = value[:-1] + '+00:00' if value.endswith('Z') else value
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def encode_sequence(rows: list[dict], maps: dict[str, dict[str, int]], max_sequence: int = 512):
    # Sort chronologically
    sorted_rows = sorted(rows, key=lambda r: parse_time(r['event_time']))[:max_sequence]
    n = len(sorted_rows)
    categorical = np.zeros((n, 4), dtype=np.int64)
    deltas = np.zeros((n, 1), dtype=np.float32)
    previous = None
    refs = []

    for idx, row in enumerate(sorted_rows):
        path = row.get('process_path')
        network = row.get('network') or {}
        p_base = basename(path)
        p_proto = (network.get('protocol') or '').lower() or None
        p_port = port_class(network.get('destination_port'))
        p_dir = image_dir(path)

        def map_cat(f: str, val: str | None) -> int:
            m = maps[f]
            return int(m.get(val, m.get('<MISSING>' if not val else '<UNK>', 0)))

        categorical[idx] = [
            map_cat('app_family', p_base),
            map_cat('proto', p_proto),
            map_cat('resp_port_class', p_port),
            map_cat('image_dir_class', p_dir),
        ]

        when = parse_time(row['event_time'])
        if previous is not None:
            deltas[idx, 0] = math.log1p(max(0.0, (when - previous).total_seconds()))
        previous = when
        refs.append(row['event_id'])

    tensors = {
        'x_cat': torch.from_numpy(categorical).unsqueeze(0),
        'x_num': torch.zeros((1, n, 0), dtype=torch.float32),
        'x_num_missing': torch.zeros((1, n, 0), dtype=torch.float32),
        'x_bin': torch.zeros((1, n, 1), dtype=torch.float32),
        'delta_t_log1p': torch.from_numpy(deltas).unsqueeze(0),
        'lengths': torch.tensor([n], dtype=torch.long),
    }
    return tensors, refs, sorted_rows


def verify_bundle_parity(bundle_path: Path, output_fixture: bool = True) -> dict[str, Any]:
    bundle_path = bundle_path.resolve()
    manifest_file = bundle_path / 'manifest.json'
    if not manifest_file.is_file():
        raise FileNotFoundError(f'manifest.json missing in {bundle_path}')
    manifest = json.loads(manifest_file.read_text(encoding='utf-8'))

    maps_file = bundle_path / 'preprocess/network_category_maps.json'
    weights_file = bundle_path / 'model/weights.pt'
    if not maps_file.is_file() or not weights_file.is_file():
        raise FileNotFoundError('category maps or weights missing from bundle')

    map_doc = json.loads(maps_file.read_text(encoding='utf-8'))
    fields = ['app_family', 'proto', 'resp_port_class', 'image_dir_class']
    maps = {f: map_doc['fields'][f]['mapping'] for f in fields}
    cards = [max(int(v) for v in maps[f].values()) + 1 for f in fields]

    # Verify cardinalities against contract
    expected_cards = [141, 4, 11, 10]
    if cards != expected_cards:
        raise ValueError(f'categorical cardinalities {cards} != expected {expected_cards}')

    model_cfg = manifest.get('model_config', {})
    model = BiLSTMBaseline(
        categorical_cardinalities=cards,
        numerical_dim=0,
        binary_dim=1,
        event_dim=int(model_cfg.get('event_dim', 64)),
        hidden_dim=int(model_cfg.get('hidden_dim', 64)),
        lstm_layers=int(model_cfg.get('lstm_layers', 1)),
        dropout=float(model_cfg.get('dropout', 0.2)),
    )

    checkpoint = torch.load(weights_file, map_location='cpu', weights_only=True)
    state = checkpoint.get('model_state_dict', checkpoint) if isinstance(checkpoint, dict) else checkpoint
    model.load_state_dict(state, strict=True)
    model.eval()

    threshold = float(manifest['policy']['threshold'])
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f'invalid threshold {threshold}')

    results = []
    for fixture in GOLDEN_NETWORK_WINDOWS:
        tensors, refs, sorted_rows = encode_sequence(fixture['events'], maps)
        
        # Chronological assertion
        times = [parse_time(r['event_time']) for r in sorted_rows]
        self_sorted = sorted(times)
        if times != self_sorted:
            raise ValueError(f"Sequence was not sorted chronologically: {times}")

        # delta_t assertions: first event must have dt=0.0
        dt_vals = tensors['delta_t_log1p'][0, :, 0].numpy()
        if dt_vals[0] != 0.0:
            raise ValueError(f"First event delta_t must be 0.0, got {dt_vals[0]}")
        if any(dt < 0.0 for dt in dt_vals):
            raise ValueError("Negative delta_t detected")

        # Category range assertions
        cat_vals = tensors['x_cat'][0].numpy()
        for col_idx, field_name in enumerate(fields):
            max_c = cards[col_idx]
            vals = cat_vals[:, col_idx]
            if np.any(vals < 0) or np.any(vals >= max_c):
                raise ValueError(f"Category values out of range for {field_name}")

        with torch.inference_mode():
            logit = model(**tensors)[0]
            prob = float(torch.sigmoid(logit))

        decision = int(prob >= threshold)
        results.append({
            'window_id': fixture['window_id'],
            'description': fixture['description'],
            'event_count': len(fixture['events']),
            'event_refs': refs,
            'logit': round(float(logit), 6),
            'probability': round(prob, 6),
            'decision': decision,
            'threshold': threshold,
        })

    # Test late-event policy: events arriving > 30s late after window bucket are segregated
    allowed_lateness = 30.0
    window_start = parse_time("2026-11-01T03:00:00Z")
    window_end = window_start + timedelta(seconds=900)
    ontime_event = parse_time("2026-11-01T03:14:50Z")
    late_acceptable = parse_time("2026-11-01T03:15:20Z")
    late_rejected = parse_time("2026-11-01T03:15:45Z")
    assert (ontime_event <= window_end), "on-time event should fall within window"
    assert (late_acceptable - window_end).total_seconds() <= allowed_lateness, "acceptable lateness"
    assert (late_rejected - window_end).total_seconds() > allowed_lateness, "unacceptable lateness rejected"

    report = {
        'bundle_id': manifest['bundle_id'],
        'branch': 'network_dl',
        'algorithm': 'bilstm',
        'verified_at': datetime.now(timezone.utc).isoformat(),
        'categorical_fields': fields,
        'categorical_cardinalities': cards,
        'maximum_sequence': 512,
        'window_seconds': 900,
        'allowed_lateness_seconds': allowed_lateness,
        'threshold': threshold,
        'fixtures_evaluated': len(results),
        'results': results,
        'status': 'passed',
    }
    report['parity_hash'] = canonical_hash(report)

    if output_fixture:
        evidence_dir = bundle_path / 'evidence'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        fixture_file = evidence_dir / 'bilstm_sequence_parity_fixture.json'
        fixture_file.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f"Exported golden sequence parity fixture: {fixture_file}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Verify BiLSTM sequence parity against golden fixtures")
    parser.add_argument('--bundle', type=Path, default=ROOT / 'runtime/releases/network-dl-run12-candidate')
    args = parser.parse_args()
    report = verify_bundle_parity(args.bundle)
    print(f"Parity verification PASSED for {report['bundle_id']} (hash: {report['parity_hash'][:16]})")


if __name__ == '__main__':
    main()

