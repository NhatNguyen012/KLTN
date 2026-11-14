"""kltn_features: online audit grouping, Sysmon mapping, featurizer and DL windowing (no research code needed)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'serving'))
from kltn_features.auditd_stream import AuditStream  # noqa: E402
from kltn_features.dl_stream import MAX_LEN, STRIDE_US, WINDOW_US, Windower  # noqa: E402
from kltn_features.sysmon import SysmonMapper, parse_event, to_canonical, to_dl_record  # noqa: E402


def line(typ, sec, ms, serial, body):
    return f'type={typ} msg=audit({sec}.{ms:03d}:{serial}): {body}'


EXEC = ('arch=c000003e syscall=59 success=yes exit=0 a0=55 a1=55 a2=55 a3=0 items=2 ppid=100 pid=200 auid=1000 uid=0 '
        'gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="id" exe="/usr/bin/id" key="T1033_System_Owner_User_Discovery"')


class AuditGrouping(unittest.TestCase):
    def test_contiguous_records_form_one_event_and_rule_keys(self):
        s = AuditStream('h', reorder_us=0)
        out = []
        out += s.feed(line('SYSCALL', 100, 5, 7, EXEC), ref='r1')
        out += s.feed(line('EXECVE', 100, 5, 7, 'argc=1 a0="id"'), ref='r2')
        out += s.feed(line('PROCTITLE', 100, 5, 7, 'proctitle=6964'), ref='r3')
        out += s.feed(line('SYSCALL', 101, 0, 8, EXEC), ref='r4')
        out += s.flush()
        self.assertEqual(len(out), 2)
        e = out[0]
        self.assertEqual((e['kind'], e['cmd'], e['image'], e['pid'], e['ppid'], e['ses']), ('procstart', 'id', '/usr/bin/id', 200, 100, 3))
        self.assertEqual(e['refs'], ['r1', 'r2', 'r3'])
        self.assertEqual(e['rule_keys'], ['T1033_System_Owner_User_Discovery'])

    def test_late_written_event_is_reordered(self):
        # a blocking syscall is stamped at entry (t=100) but written after a younger event (t=103)
        s = AuditStream('h', reorder_us=10_000_000)
        s.feed(line('SYSCALL', 103, 0, 9, EXEC))
        s.feed(line('SYSCALL', 100, 0, 8, EXEC.replace('syscall=59', 'syscall=42')))
        s.feed(line('SOCKADDR', 100, 0, 8, 'saddr=02000050C0A80101'))
        out = s.flush()
        self.assertEqual([e['line'] for e in out], [8, 9])
        self.assertEqual((out[0]['kind'], out[0]['rip'], out[0]['rport']), ('netconn', '192.168.1.1', 80))


SYSMON1 = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
           '<EventID>{eid}</EventID><EventRecordID>{rid}</EventRecordID><Computer>WIN1</Computer>'
           '<TimeCreated SystemTime="2026-11-14T01:00:00.000Z"/></System><EventData>{data}</EventData></Event>')


def sysmon(eid, rid, **fields):
    data = ''.join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return {'System': SYSMON1.format(eid=eid, rid=rid, data=data)}


class SysmonMapping(unittest.TestCase):
    def test_procstart_is_parent_centric_like_cbc(self):
        m = SysmonMapper('win1')
        f = parse_event(sysmon(1, 1, UtcTime='2026-11-14 01:00:00.100', ProcessGuid='{A}', ProcessId='10',
                               Image='C:\\Windows\\System32\\cmd.exe', CommandLine='cmd /c whoami', User='WIN1\\u',
                               ParentProcessGuid='{P}', ParentImage='C:\\Windows\\explorer.exe', ParentCommandLine='explorer.exe',
                               ParentUser='WIN1\\u'))
        e = m.map(f)
        self.assertEqual((e['event_type'], e['path'], e['tpath'], e['tcmd']),
                         ('PROCESS_START', 'c:\\windows\\explorer.exe', 'c:\\windows\\system32\\cmd.exe', 'cmd /c whoami'))
        ce = to_canonical(e)
        self.assertEqual((ce.process_path, ce.target_path, ce.process_guid), ('c:\\windows\\explorer.exe', e['tpath'], 'p'))
        self.assertEqual(to_dl_record(e)['kind'], 'procstart')

    def test_netconn_domain_from_dns_and_direction(self):
        m = SysmonMapper('win1')
        m.map(parse_event(sysmon(22, 2, UtcTime='2026-11-14 01:00:00.000', ProcessGuid='{A}', QueryName='example.org',
                                 QueryResults='type:  5 x;::ffff:93.184.216.34;')))
        e = m.map(parse_event(sysmon(3, 3, UtcTime='2026-11-14 01:00:01.000', ProcessGuid='{A}', Image='C:\\x.exe',
                                     Protocol='tcp', Initiated='true', SourceIp='10.0.0.5', SourcePort='50000',
                                     DestinationIp='93.184.216.34', DestinationPort='443')))
        self.assertEqual((e['event_type'], e['rip'], e['rport'], e['inbound'], e['domain']),
                         ('FLOW_START', '93.184.216.34', 443, False, 'example.org'))
        r = to_dl_record(e)
        self.assertEqual((r['kind'], r['proto'], r['domain']), ('netconn', 'PROTO_TCP', 'example.org'))

    def test_file_filter_like_atlasv2_dl(self):
        m = SysmonMapper('win1')
        e = m.map(parse_event(sysmon(11, 4, UtcTime='2026-11-14 01:00:00.000', ProcessGuid='{A}', Image='C:\\x.exe',
                                     TargetFilename='C:\\Users\\u\\a.txt')))
        self.assertIsNone(to_dl_record(e))
        e = m.map(parse_event(sysmon(11, 5, UtcTime='2026-11-14 01:00:00.000', ProcessGuid='{A}', Image='C:\\x.exe',
                                     TargetFilename='C:\\Users\\u\\a.ps1')))
        self.assertEqual(to_dl_record(e)['kind'], 'filemod')

    def test_rejects_entity_expansion(self):
        self.assertIsNone(parse_event({'System': '<!DOCTYPE x [<!ENTITY a "b">]><Event/>'}))


class Windowing(unittest.TestCase):
    def rec(self, ts, label=True):
        return {'ts': ts, 'is_label': label, 'kind_raw': 'procstart' if label else 'filemod', 'flags': [0.0] * 18,
                'tok': ('procstart',) + ('x',) * 10, 'optc': ('a', 'b', 'c', 'd'), 'bag': []}

    def test_window_grid_and_watermark(self):
        w = Windower(origin_us=0)
        w.add([self.rec(t * 1_000_000) for t in (1, 2, 100, 250)])
        got = list(w.ready(watermark_us=200_000_000))
        self.assertTrue(all(end <= 200_000_000 for _, _, _, end, _ in got))
        self.assertEqual(got[0][2], 0)
        self.assertEqual(STRIDE_US, 30_000_000)
        self.assertEqual(WINDOW_US, 180_000_000)

    def test_chunks_of_512(self):
        w = Windower(origin_us=None)
        w.add([self.rec(1_000_000 + i) for i in range(MAX_LEN + 10)])
        chunks = [c for c in w.ready(None, final=True) if c[0] == 0]
        self.assertEqual([len(c[4]) for c in chunks], [MAX_LEN, 10])


if __name__ == '__main__':
    unittest.main()
