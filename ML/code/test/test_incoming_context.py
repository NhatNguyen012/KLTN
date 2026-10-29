import json
import tempfile
import unittest
from pathlib import Path
from ML.code.preprocess.process_context_tracker import HostProcessContextTracker, ProcessContextConfig

A = '003b14a0-43d3-4886-ac24-8c7dec12c150'
B = '903916d0-e580-45ef-ad75-1d3504662129'
C = '45815554-827b-47ff-b591-c4236a3a1bd9'

def event(t, actor=A, target=B, kind='open', host='sysclient0351', **props):
    return dict(hostname=host, actorID=actor, objectID=target,
                timestamp=t, object='THREAD' if kind=='remote_create' else 'PROCESS',
                action=kind.upper(), principal='', properties=props)

class IncomingTests(unittest.TestCase):
    def tokens(self, tr, t, host='sysclient0351'):
        return tr.get_context_tokens(event(t, actor=B, host=host))

    def test_direction_ownership_sequence_and_causality(self):
        tr=HostProcessContextTracker()
        tr.observe(event(10, image_path=r'C:\Users\u\AppData\Local\Temp\f.exe', command_line='WRONG_TARGET_CMD'))
        self.assertFalse(any('incoming' in t for t in self.tokens(tr,10)))
        tr.observe(event(20, target=C, kind='remote_create', tgt_pid_uuid=B, image_path=r'C:\Temp\f.exe'))
        ts=self.tokens(tr,21)
        self.assertIn('ctx::incoming::thread_remote_create::prior_process_open=true',ts)
        self.assertIn('ctx::incoming::thread_remote_create::source_exe=f.exe',ts)
        self.assertFalse(any('WRONG' in t or A in t or B in t for t in ts))
        self.assertFalse(any('thread_remote_create' in t for t in self.tokens(tr,20)))
        self.assertFalse(any('incoming' in t for t in tr.get_context_tokens(event(21,actor=A))))
        self.assertFalse(any('incoming' in t for t in self.tokens(tr,21,'another-host')))
        self.assertEqual(tr.hosts['sysclient0351'][B].parent_edges,[])

    def test_bounds_ttl_and_remote_retention(self):
        tr=HostProcessContextTracker(ProcessContextConfig(incoming_per_kind=2,incoming_ttl_seconds=.0001))
        tr.observe(event(1,kind='remote_create',tgt_pid_uuid=B))
        for t in range(2,20): tr.observe(event(t))
        self.assertLessEqual(len(tr.hosts['sysclient0351'][B].incoming),4)
        self.assertTrue(any('thread_remote_create' in t for t in self.tokens(tr,20)))
        self.assertFalse(any('incoming' in t for t in self.tokens(tr,121)))

    def test_strict_uuid_no_pid_fallback_self_or_thread_object_join(self):
        tr=HostProcessContextTracker()
        for e in [event(1,kind='remote_create',tgt_pid='1256'),event(2,target='bad'),event(3,actor=B),event(4,actor='bad')]:tr.observe(e)
        self.assertFalse(any(n.incoming for n in tr.hosts['sysclient0351'].values()))

    def test_checkpoint_resume_and_label_independence(self):
        a=HostProcessContextTracker();a.observe(event(10,image_path='f.exe'))
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'c.json';a.save_checkpoint(p);b=HostProcessContextTracker();b.load_checkpoint(p)
            for tr,label in [(a,0),(b,1)]:
                e=event(20,kind='remote_create',tgt_pid_uuid=B,image_path='f.exe');e['label']=label;tr.observe(e)
            self.assertEqual(self.tokens(a,30),self.tokens(b,30))
            self.assertEqual(a.hosts,b.hosts)
            d=json.loads(p.read_text());d['schema_version']=3;p.write_text(json.dumps(d))
            with self.assertRaisesRegex(ValueError,'expected 4'):b.load_checkpoint(p)

    def test_same_timestamp_is_not_prior_open(self):
        tr=HostProcessContextTracker();tr.observe(event(10));tr.observe(event(10,kind='remote_create',tgt_pid_uuid=B))
        self.assertNotIn('ctx::incoming::thread_remote_create::prior_process_open=true',self.tokens(tr,11))

    def test_background_batch_context_and_same_time_exclusion(self):
        from ML.code.preprocess.stratified_pipeline import _flush_timestamp_batch
        tr=HostProcessContextTracker()
        remote=event(10,kind='remote_create',tgt_pid_uuid=B)
        query=event(10,actor=B)
        rows=list(_flush_timestamp_batch([(0,1,remote),(1,2,query)],10,tr))
        self.assertFalse(any('incoming' in t for t in rows[0][2]['_context_tokens']))
        rows=list(_flush_timestamp_batch([(1,3,event(11,actor=B))],11,tr))
        self.assertIn('ctx::incoming::thread_remote_create::present=true',rows[0][2]['_context_tokens'])

    def test_missing_incoming_checkpoint_rejected(self):
        tr=HostProcessContextTracker();tr.observe(event(10))
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'c.json';tr.save_checkpoint(p);d=json.loads(p.read_text())
            del d['hosts']['sysclient0351'][B]['incoming'];p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):HostProcessContextTracker().load_checkpoint(p)

if __name__=='__main__':unittest.main()
