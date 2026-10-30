#!/usr/bin/env python3
"""Resolve Terraform hosts; recover Windows password/TLS trust via trusted local QGA."""
import base64
import json
import ipaddress
from pathlib import Path
import subprocess
import time
import yaml
from prepare_central import ROOT, RUNTIME, hosts, private_write


def qga(uuid, command):
    raw = subprocess.run(['docker', 'exec', 'nova_libvirt', 'virsh', 'qemu-agent-command', uuid, json.dumps(command)], capture_output=True, text=True, timeout=20)
    if raw.returncode:
        raise RuntimeError('Guest agent not ready')
    return json.loads(raw.stdout)['return']


def execute(uuid, program, args, timeout=30):
    result = qga(uuid, {'execute': 'guest-exec', 'arguments': {'path': program, 'arg': args, 'capture-output': True}})
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = qga(uuid, {'execute': 'guest-exec-status', 'arguments': {'pid': result['pid']}})
        if status.get('exited'):
            if status.get('exitcode') != 0:
                stderr = base64.b64decode(status.get('err-data', '')).decode('utf-8-sig', errors='replace')
                # Strip CLIXML progress noise from stderr before reporting
                import re as _re
                clean_err = _re.sub(r'#<\s*CLIXML.*', '', stderr, flags=_re.DOTALL).strip()
                raise RuntimeError(f'Guest command exit={status["exitcode"]}: {clean_err[:300] or "(no stderr)"}')
            return base64.b64decode(status.get('out-data', '')).decode('utf-8-sig')
        time.sleep(2)
    raise RuntimeError('Guest command timed out')


def windows_credentials(uuid, address):
    address = str(ipaddress.ip_address(address))
    code = r'''
from pathlib import Path
import json, winreg, base64
p = next(Path(x+":/openstack/latest/meta_data.json") for x in "DEFGHIJKLMNOPQRSTUVWXYZ" if Path(x+":/openstack/latest/meta_data.json").exists())
password = json.loads(p.read_text())["admin_pass"]
# Read the actual HTTPS listener cert from the certificate store via PowerShell
# separately; password is captured in memory, never printed to the controller log.
print(json.dumps({"password": password}))
'''
    data = json.loads(execute(uuid, r'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\Python\python.exe', ['-c', code]))
    ps = r'''$ProgressPreference='SilentlyContinue'; $l=Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } | Select-Object -First 1; $t=(Get-Item ($l.PSPath+'\CertificateThumbprint')).Value; $c=Get-Item ('Cert:\LocalMachine\My\'+$t); [Convert]::ToBase64String($c.RawData)'''
    # Reconcile WinRM HTTPS listener via winrm.cmd (not Set-Item WSMan provider,
    # which blocks in NonInteractive sessions). Steps:
    # 1. Find current listener cert; check if it has IP SAN matching our address.
    # 2. If not, create new self-signed cert with IP SAN.
    # 3. Delete old HTTPS listener and recreate with new cert thumbprint.
    # All via winrm.cmd which works from QGA without interactive session.
    reconcile_ps = r"""$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1 -Force
powercfg /change standby-timeout-ac 0; powercfg /change hibernate-timeout-ac 0; powercfg /hibernate off
$ip='ADDRESS'
$l=Get-ChildItem WSMan:\localhost\Listener|Where-Object{$_.Keys -contains 'Transport=HTTPS'}|Select-Object -First 1
$need_new=$true
if ($l) {
  $t=(Get-Item ($l.PSPath+'\CertificateThumbprint')).Value
  $c=Get-Item ('Cert:\LocalMachine\My\'+$t) -ErrorAction SilentlyContinue
  if ($c -and $c.NotAfter -gt (Get-Date).AddDays(7)) {
    $san=$c.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.17'}|ForEach-Object{$_.Format(1)}
    if ($san -match ('(?i)IP\s*Address=' + [regex]::Escape($ip))) { $need_new=$false }
  }
}
if ($need_new) {
  $c=New-SelfSignedCertificate -Subject ('CN='+$ip) -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(1) -TextExtension @('2.5.29.17={text}IPAddress='+$ip)
  Write-Host ('thumb=' + $c.Thumbprint)
} else { Write-Host 'cert_ok' }""".replace('ADDRESS', address)

    recon_out = execute(uuid, r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                        ['-NoProfile', '-NonInteractive', '-EncodedCommand',
                         base64.b64encode(reconcile_ps.encode('utf-16le')).decode()])
    recon_out = recon_out.strip()
    print(f'  WinRM cert reconcile: {recon_out}')

    if recon_out.startswith('thumb='):
        # New cert created — recreate listener via winrm.cmd (works in NonInteractive)
        new_thumb = recon_out.split('=', 1)[1].strip()
        # Delete existing HTTPS listener (ignore if not found)
        try:
            execute(uuid, r'C:\Windows\System32\winrm.cmd',
                    ['delete', 'winrm/config/Listener?Address=*+Transport=HTTPS'])
        except RuntimeError:
            pass
        execute(uuid, r'C:\Windows\System32\winrm.cmd',
                ['create', 'winrm/config/Listener?Address=*+Transport=HTTPS',
                 f'@{{CertificateThumbprint="{new_thumb}"}}'])
        print('  WinRM listener recreated with IP SAN cert')

    der = execute(uuid, r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(ps.encode('utf-16le')).decode()]).strip()
    data['cert'] = '-----BEGIN CERTIFICATE-----\n' + '\n'.join(der[i:i+64] for i in range(0, len(der), 64)) + '\n-----END CERTIFICATE-----\n'
    return data


def main():
    cfg = json.loads((RUNTIME / 'secrets.json').read_text())
    groups = {'linux': {'hosts': {}}, 'windows': {'hosts': {}}}
    for name, node in hosts().items():
        identity = node['host_id']
        entry = {'ansible_host': node['address'], 'host_id': identity, 'ingest_token': cfg['hosts'][identity]['token']}
        if node['os_type'] == 'ubuntu':
            entry.update(ansible_user='ubuntu', ansible_ssh_private_key_file=str(Path.home() / '.ssh/openstack_ed25519'),
                ansible_ssh_common_args=f'-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={RUNTIME / "known_hosts"} -o HostKeyAlias={identity}')
            groups['linux']['hosts'][name] = entry
        else:
            data = windows_credentials(identity, node['address'])
            cert = RUNTIME / f'{identity}-winrm.pem'
            private_write(cert, data['cert'])
            entry.update(ansible_user='Admin', ansible_password=data['password'], ansible_connection='winrm',
                ansible_port=5986, ansible_winrm_scheme='https', ansible_winrm_transport='ntlm',
                ansible_winrm_server_cert_validation='validate', ansible_winrm_ca_trust_path=str(cert))
            groups['windows']['hosts'][name] = entry
    inv = {'all': {'vars': {'central_ip': cfg['bind_ip'], 'central_port': 18443,
           'runtime_dir': str(RUNTIME), 'endpoint_agent_enabled': (RUNTIME / 'serving-enabled').exists()}, 'children': groups}}
    private_write(RUNTIME / 'inventory.yml', yaml.safe_dump(inv))
    print('Private inventory ready; WinRM certificate validation enabled.')


if __name__ == '__main__':
    main()
