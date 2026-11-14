import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'central/app'))
sys.path.insert(0, str(ROOT / 'serving'))

from audit_display import exact_command  # noqa: E402


def rec(typ, body, serial=7):
    return f'type={typ} msg=audit(1794610809.924:{serial}): {body}'


class ExactCommand(unittest.TestCase):
    def test_quoted_hex_looking_arguments_stay_literal(self):
        # what the lab recorded for `df -h`, `tail -n 20 ...`, `curl --max-time 10 ...`, `nc -lvp 4444`
        self.assertEqual(exact_command([rec('EXECVE', 'argc=2 a0="df" a1="-h"')]), 'df -h')
        self.assertEqual(exact_command([rec('EXECVE', 'argc=4 a0="tail" a1="-n" a2="20" a3="/var/log/syslog"')]),
                         'tail -n 20 /var/log/syslog')
        self.assertEqual(exact_command([rec('EXECVE', 'argc=3 a0="nc" a1="-lvp" a2="4444"')]), 'nc -lvp 4444')

    def test_model_view_differs(self):
        """The vendored training decoder is kept for the models; this documents why the SOC needs its own."""
        from kltn_features._vendor.ainception_adapters import kv, unhex
        a = kv('argc=2 a0="df" a1="-h"')
        self.assertEqual(' '.join(unhex(a[f'a{i}']) for i in range(2)), '� -h')

    def test_unquoted_hex_and_split_arguments(self):
        hexarg = 'import json; print(1)'.encode().hex().upper()
        self.assertEqual(exact_command([rec('EXECVE', f'argc=3 a0="python3" a1="-c" a2={hexarg}')]),
                         'python3 -c import json; print(1)')
        long = 'A B' * 3
        h = long.encode().hex().upper()
        lines = [rec('EXECVE', f'argc=2 a0="echo" a1_len={len(long)} a1[0]={h[:6]}'), rec('EXECVE', f'a1[1]={h[6:]}')]
        self.assertEqual(exact_command(lines), 'echo ' + long)

    def test_proctitle_and_sudo_fallbacks(self):
        pt = '/opt/fluent-bit/bin/fluent-bit\x00-c\x00/etc/fluent-bit.conf'.encode().hex().upper()
        self.assertEqual(exact_command([rec('SYSCALL', 'arch=c000003e syscall=42'), rec('PROCTITLE', f'proctitle={pt}')]),
                         '/opt/fluent-bit/bin/fluent-bit -c /etc/fluent-bit.conf')
        self.assertEqual(exact_command([rec('PROCTITLE', 'proctitle="bash"')]), 'bash')
        cmd = '/bin/sh -c id'.encode().hex().upper()
        self.assertEqual(exact_command([rec('USER_CMD', f"pid=1 uid=0 msg='cwd=\"/\" cmd={cmd} exe=\"/usr/bin/sudo\" res=success'")]),
                         '/bin/sh -c id')

    def test_not_audit(self):
        self.assertIsNone(exact_command([None, '<Event/>', '']))


if __name__ == '__main__':
    unittest.main()
