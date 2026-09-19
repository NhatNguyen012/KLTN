import json
import gzip
from pathlib import Path

encoded_cmd = ""
for file_path in Path('host-malicious').rglob('*.json.gz'):
    try:
        with gzip.open(file_path, 'rt') as f:
            for line in f:
                event = json.loads(line)
                cmd = event.get('properties', {}).get('command_line', '')
                if '-enc' in cmd.lower() or '-encodedcommand' in cmd.lower():
                    encoded_cmd = cmd
                    break
        if encoded_cmd: break
    except Exception:
        continue
print(encoded_cmd)
