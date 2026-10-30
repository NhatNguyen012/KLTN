#!/usr/bin/env python3
"""Cache official Windows packages; verify Fluent Bit published SHA256."""
import hashlib
import json
from pathlib import Path
import subprocess
from prepare_central import RUNTIME, private_write

ASSETS = {
 'fluent-bit.zip': ('https://packages.fluentbit.io/windows/fluent-bit-5.1.5-win64.zip', '96e9489e6eb339a748afaa1b38c7d90ca532bc407eb55f76d028d3c006d04bcd'),
 # Sysmon is verified by Authenticode in guest (Ansible task), not by hash here,
 # because Microsoft updates the zip without versioned URLs.
 'Sysmon.zip': ('https://download.sysinternals.com/files/Sysmon.zip', None),
}


def main():
    folder = RUNTIME / 'assets'
    folder.mkdir(exist_ok=True)
    manifest = {}
    for name, (url, expected) in ASSETS.items():
        p = folder / name
        if not p.exists():
            tmp = p.with_suffix('.partial')
            subprocess.run(['curl', '-4', '--http1.1', '--connect-timeout', '15', '--max-time', '300', '--fail', '--location', '--retry', '3', '--silent', '--show-error', '--output', str(tmp), url], check=True)
            tmp.replace(p)
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        if expected and digest != expected:
            raise RuntimeError(f'Checksum mismatch: {name}')
        manifest[name] = {'url': url, 'sha256': digest}
    private_write(folder / 'manifest.json', json.dumps(manifest, indent=2))
    print('Cached official Windows assets; Sysmon Authenticode is verified in guest before installation.')


if __name__ == '__main__':
    main()
