#!/usr/bin/env python3
"""Live TLS/auth/retry smoke test; leaves one identifiable synthetic event."""
import json
import ssl
import time
import urllib.error
import urllib.request
import uuid
from prepare_central import RUNTIME

cfg = json.loads((RUNTIME / 'secrets.json').read_text())
ctx = ssl.create_default_context(cafile=str(RUNTIME / 'tls/server.crt'))
base = f'https://{cfg["bind_ip"]}:18443'
host, credentials = next(iter(cfg['hosts'].items()))
marker = 'kltn-ingest-' + uuid.uuid4().hex

def request(path, token, data=None):
    req = urllib.request.Request(base + path, data=None if data is None else json.dumps(data).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
        return json.load(response)

path = f'/v1/events/{host}/smoke'
try:
    request(path, 'invalid', {'marker': marker})
except urllib.error.HTTPError as exc:
    assert exc.code == 401, exc.code
else:
    raise AssertionError('Invalid token was accepted')
for date in (1, 2):
    assert request(path, credentials['token'], {'marker': marker, 'date': date})['accepted'] == 1
print(json.dumps({'tls_verified': True, 'invalid_token_rejected': True, 'duplicate_deliveries_accepted': 2, 'marker': marker, 'host_id': host}))
# Database deduplication must be verified separately against this marker.
