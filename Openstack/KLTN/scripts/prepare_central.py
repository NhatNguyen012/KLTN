#!/usr/bin/env python3
"""Generate private, idempotent central configuration from Terraform outputs."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'runtime'


def private_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    tmp.replace(path)


def hosts():
    return json.loads(subprocess.check_output(['terraform', f'-chdir={ROOT / "terraform"}', 'output', '-json', 'ansible_hosts']))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bind-ip', default='172.31.250.1')
    args = p.parse_args()
    ipaddress.IPv4Address(args.bind_ip)
    RUNTIME.mkdir(exist_ok=True, mode=0o700)
    path = RUNTIME / 'secrets.json'
    cfg = json.loads(path.read_text()) if path.exists() else {
        'postgres_password': secrets.token_hex(24), 'nats_token': secrets.token_hex(24),
        'admin_token': secrets.token_hex(24), 'hosts': {}}
    current = hosts()
    cfg['hosts'] = {v['host_id']: cfg['hosts'].get(v['host_id'], {'name': k, 'token': secrets.token_hex(24)}) for k, v in current.items()}
    cfg['bind_ip'] = args.bind_ip
    private_write(path, json.dumps(cfg, indent=2))
    private_write(RUNTIME / 'postgres-password', cfg['postgres_password'])
    private_write(RUNTIME / 'nats.conf', f'listen: "127.0.0.1:14222"\nauthorization {{ token: "{cfg["nats_token"]}" }}\njetstream {{ store_dir: "/data", max_mem_store: 64MB, max_file_store: 1GB }}\n')
    tls = RUNTIME / 'tls'
    tls.mkdir(exist_ok=True, mode=0o700)
    if not (tls / 'server.crt').exists():
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
                        '-keyout', str(tls / 'server.key'), '-out', str(tls / 'server.crt'),
                        '-subj', '/CN=KLTN Lab Ingest', '-addext', f'subjectAltName=IP:{args.bind_ip},IP:127.0.0.1',
                        '-addext', 'basicConstraints=critical,CA:TRUE'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (tls / 'server.key').chmod(0o600)
    # Refuse reusing a certificate for a different bind address.
    subprocess.run(['openssl', 'x509', '-in', str(tls / 'server.crt'), '-noout', '-checkip', args.bind_ip], check=True)
    private_write(RUNTIME / 'Caddyfile', f'''{{
 admin off
 auto_https off
}}
https://{args.bind_ip}:18443 {{
 bind {args.bind_ip}
 tls /tls/server.crt /tls/server.key
 request_body {{
  max_size 4MB
 }}
 reverse_proxy 127.0.0.1:18080
}}
''')
    print('Private config ready in runtime/; no credentials printed.')


if __name__ == '__main__':
    main()
