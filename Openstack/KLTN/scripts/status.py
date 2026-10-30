#!/usr/bin/env python3
import json
import ssl
import urllib.request
from prepare_central import RUNTIME

cfg = json.loads((RUNTIME / 'secrets.json').read_text())
ctx = ssl.create_default_context(cafile=str(RUNTIME / 'tls/server.crt'))
req = urllib.request.Request(f'https://{cfg["bind_ip"]}:18443/v1/status', headers={'Authorization': 'Bearer ' + cfg['admin_token']})
with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
    print(json.dumps(json.load(r), indent=2))
