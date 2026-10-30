#!/usr/bin/env python3
"""Pinned official downloads; observed SHA256 recorded at initial HTTPS fetch.
Python installer is additionally Authenticode-checked in the guest.
"""
import hashlib
import json
import subprocess
import sys
from prepare_central import ROOT, RUNTIME, private_write

ASSETS = {
 'vc_redist.x64.exe': ('https://aka.ms/vs/17/release/vc_redist.x64.exe', 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'),
 'python-3.12.10-amd64.exe': ('https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe', '67b5635e80ea51072b87941312d00ec8927c4db9ba18938f7ad2d27b328b95fb'),
 'WinSW-x64.exe': ('https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe', '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da'),
}


def main():
    folder = RUNTIME / 'assets'
    folder.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in ASSETS.items():
        dest = folder / name
        if not dest.exists():
            tmp = dest.with_suffix('.partial')
            subprocess.run(['curl', '-4', '--http1.1', '-fLsS', '--retry', '3', '--max-time', '300', url, '-o', str(tmp)], check=True)
            if hashlib.sha256(tmp.read_bytes()).hexdigest() != digest:
                raise RuntimeError('Installer checksum mismatch: ' + name)
            tmp.replace(dest)
        if hashlib.sha256(dest.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Installer checksum mismatch: ' + name)
    wheel_dir = folder/'agent-wheels'
    subprocess.run([sys.executable, '-m', 'pip', 'download', '--only-binary=:all:',
        '--platform', 'win_amd64', '--python-version', '312', '--implementation', 'cp', '--abi', 'cp312',
        '-r', str(ROOT/'serving/endpoint/requirements.txt'), '-d', str(wheel_dir)], check=True)
    private_write(folder/'serving-manifest.json', json.dumps({
        'installers': {n: {'url': u, 'sha256': h} for n, (u,h) in ASSETS.items()},
        'wheels': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(wheel_dir.glob('*.whl'))}
    }, indent=2))


if __name__ == '__main__':
    main()
