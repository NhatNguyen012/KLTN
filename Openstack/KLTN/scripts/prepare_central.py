#!/usr/bin/env python3
"""Generate private, idempotent central configuration from the Terraform outputs (no credential is printed).

* runtime/secrets.json keeps every existing host token: hosts are added from Terraform, never removed because a
  Terraform call failed (the earlier version rewrote the host map to {} on any error);
* runtime/postgres-password, nats.conf, Caddyfile, TLS certificate (CA:TRUE, SAN = bind ip);
* runtime/dl.json (DL worker DB role), runtime/mlflow.env (MLflow backend store URI with its own DB role).
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'runtime'


def private_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    tmp.replace(path)


def terraform_hosts(tf_dir: Path) -> dict:
    """ansible_hosts output of one Terraform state; raises if Terraform fails (callers must not guess)."""
    raw = subprocess.check_output(['terraform', f'-chdir={tf_dir}', 'output', '-json', 'ansible_hosts'],
                                  stderr=subprocess.DEVNULL)
    return json.loads(raw)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bind-ip', default='172.31.250.1')
    p.add_argument('--terraform-dir', action='append', default=None,
                   help='state(s) to read hosts from (default: terraform/)')
    p.add_argument('--no-terraform', action='store_true', help='keep the current host map')
    args = p.parse_args()
    ipaddress.IPv4Address(args.bind_ip)
    RUNTIME.mkdir(exist_ok=True, mode=0o700)
    path = RUNTIME / 'secrets.json'
    cfg = json.loads(path.read_text()) if path.exists() else {
        'postgres_password': secrets.token_hex(24), 'nats_token': secrets.token_hex(24),
        'admin_token': secrets.token_hex(24), 'hosts': {}}
    cfg.setdefault('hosts', {})
    if not args.no_terraform:
        current = {}
        for d in args.terraform_dir or [str(ROOT / 'terraform')]:
            try:
                current.update(terraform_hosts(Path(d)))
            except (subprocess.CalledProcessError, ValueError, FileNotFoundError) as exc:
                sys.exit(f'terraform output failed for {d} ({type(exc).__name__}); host map left unchanged')
        for name, v in current.items():
            entry = cfg['hosts'].get(v['host_id']) or {'token': secrets.token_hex(24)}
            entry.update(name=name, os_type=v.get('os_type'), address=v.get('address'))
            cfg['hosts'][v['host_id']] = entry
    cfg['bind_ip'] = args.bind_ip
    cfg.setdefault('mlflow_db_password', secrets.token_hex(24))
    private_write(path, json.dumps(cfg, indent=2))
    private_write(RUNTIME / 'postgres-password', cfg['postgres_password'])
    private_write(RUNTIME / 'nats.conf', f'listen: "127.0.0.1:14222"\nauthorization {{ token: "{cfg["nats_token"]}" }}\n'
                                         'jetstream { store_dir: "/data", max_mem_store: 64MB, max_file_store: 4GB }\n')
    if not (RUNTIME / 'dl.json').exists():
        private_write(RUNTIME / 'dl.json', json.dumps({'password': secrets.token_urlsafe(32)}))
    private_write(RUNTIME / 'mlflow.env',
                  f'MLFLOW_BACKEND_STORE_URI=postgresql+psycopg2://mlflow:{cfg["mlflow_db_password"]}@127.0.0.1:15432/mlflow\n')
    for d in ('models/dl/releases', 'mlflow-artifacts', 'evidence', 'il'):
        (RUNTIME / d).mkdir(parents=True, exist_ok=True)
    os.chmod(RUNTIME / 'mlflow-artifacts', 0o777)   # written by the MLflow container user (uid 1000)
    tls = RUNTIME / 'tls'
    tls.mkdir(exist_ok=True, mode=0o700)
    if not (tls / 'server.crt').exists():
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
                        '-keyout', str(tls / 'server.key'), '-out', str(tls / 'server.crt'),
                        '-subj', '/CN=KLTN Lab Ingest', '-addext', f'subjectAltName=IP:{args.bind_ip},IP:127.0.0.1',
                        '-addext', 'basicConstraints=critical,CA:TRUE'], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        (tls / 'server.key').chmod(0o600)
    subprocess.run(['openssl', 'x509', '-in', str(tls / 'server.crt'), '-noout', '-checkip', args.bind_ip], check=True,
                   stdout=subprocess.DEVNULL)
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
    print(json.dumps({'hosts': sorted(v.get('name', '?') for v in cfg['hosts'].values()),
                      'note': 'private config ready in runtime/; no credentials printed'}))


if __name__ == '__main__':
    main()
