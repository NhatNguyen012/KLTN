"""Synthetic regression tests; no corpus scans or model training."""
from pathlib import Path
import contextlib
import copy
import gzip
import io
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE/'preprocess'))
sys.path.insert(0, str(HERE/'model'))
from common import sha, digest, safe
from graph import connect, observe, Encoder, FEATURES, COL, timestamp, identity
from ego import EgoGraphs
import build_graph
from build_graph import build, source_identity, ontology_audit
from host_shards import ShardBuffer, HostShardDataset, decode_shard, FORMAT, SCHEMA


def event(sec, actor='p', obj='FILE', action='WRITE', target='x', host='a.example', **props):
    return dict(timestamp=f'2019-09-23T00:00:{sec:02d}+00:00', hostname=host, actorID=actor,
                object=obj, action=action, objectID=target, properties=props, label=1)


def fixture(root):
    records = [event(1, 'root', 'PROCESS', 'CREATE', 'parent', image_path='powershell.exe', parent_image_path='services.exe', command_line='powershell -enc ABC'),
               event(3, 'parent', 'PROCESS', 'CREATE', 'child', image_path='notepad.exe', parent_image_path='powershell.exe'),
               event(6, 'child', image_path='notepad.exe'), event(8, 'child'), event(10, 'child'), event(12, 'parent')]
    (root/'raw').mkdir()
    source = root/'raw/events.jsonl';source.write_text(''.join(json.dumps(r)+'\n' for r in records))
    si = source_identity(source);sid = digest(si)
    splitdir = root/'split';splitdir.mkdir();mask=splitdir/'events.split.gz'
    assignment = [0,0,1,2,3,1]
    with gzip.open(mask,'wb') as f:f.write(bytes(assignment))
    split = dict(entries=[dict(source=si,artifact=mask.name,sha256=sha(mask))],seed=2)
    sp=splitdir/'manifest.json';sp.write_text(json.dumps(split));sh=sha(sp)
    base=root/'baseline';assets=base/'assets';assets.mkdir(parents=True)
    (assets/'vocab.json').write_text('{"base::present": 0}')
    vh=sha(assets/'vocab.json');(assets/'vocab_metadata.json').write_text(json.dumps(dict(split_sha256=sh,vocabulary_sha256=vh)))
    (assets/'split_manifest.json').write_bytes(sp.read_bytes())
    volume=base/'volume';volume.mkdir();parts=[]
    for c,name in [(1,'train'),(2,'val'),(3,'test')]:
        buf=ShardBuffer(1)
        for i,v in enumerate(assignment):
            if v==c:buf.append([0],i%2,i+1)
        payload,p=buf.encode();(volume/f'{name}.npz').write_bytes(payload)
        p.update(source_id=sid,split=name,volume='base',path=f'{name}.npz');parts.append(p)
    totals={s:{k:sum(p[k] for p in parts if p['split']==s) for k in ['rows','nnz','label_0','label_1','bytes']} for s in ['train','val','test']}
    m=dict(format=FORMAT,schema=SCHEMA,complete=True,seed=2,vocab_size=1,split_sha256=sh,vocabulary_sha256=vh,
           volumes={'base':str(volume)},sources=[dict(source=si,source_id=sid,file_host='a',day='2019-09-23')],
           shards=parts,splits=totals,assets_sha256={n:sha(assets/n) for n in ['vocab.json','vocab_metadata.json','split_manifest.json']})
    manifest=base/'manifest.json';manifest.write_text(json.dumps(m))
    args=SimpleNamespace(baseline=manifest,split=sp,context_index=None,output=root/'graph',max_sources=0,max_lines=0,
                         checkpoint_rows=2,max_db_gib=1,reserve_gib=0,dry_run=False)
    return args,records


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'graph.sqlite';self.db=connect(self.path)
    def tearDown(self):
        self.db.close();self.tmp.cleanup()
    def insert(self,*rows):
        for i,r in enumerate(rows):observe(self.db,r,'source',i+1)
        self.db.commit()
    def tokens(self, sec=20, proc='child', host='a.example'):
        return {FEATURES[c] for c in Encoder(self.db).encode(host,proc,timestamp(event(sec)['timestamp']))}
    def test_two_hops_and_actor_semantics(self):
        self.insert(event(1,'root','PROCESS','CREATE','parent',image_path='powershell.exe',parent_image_path='services.exe',command_line='powershell -enc XYZ'),
                    event(3,'parent','PROCESS','CREATE','child',image_path='notepad.exe',parent_image_path='powershell.exe'))
        t=self.tokens();self.assertIn('graph::parent::launch=encoded',t);self.assertIn('graph::grandparent::role=service',t)
        self.assertIn('graph::actor::role=other',t)
        # CREATE row's actor is the parent, not the new child.
        self.assertEqual(identity(event(3,'parent','PROCESS','CREATE','child'))[1],'parent')
    def test_future_and_same_timestamp_excluded(self):
        self.insert(event(10,'parent','PROCESS','CREATE','child',image_path='notepad.exe'))
        self.assertIn('graph::parent::missing',self.tokens(10));self.assertIn('graph::parent::present',self.tokens(11))

    def test_exact_microsecond_cutoff_keeps_prior_same_second_event(self):
        parent_event = event(0, 'parent', 'PROCESS', 'CREATE', 'child', image_path='cmd.exe')
        parent_event['timestamp'] = '2019-09-23T00:00:00.123456+00:00'
        self.insert(parent_event)
        target_time = timestamp('2019-09-23T00:00:00.987654+00:00')
        exact = EgoGraphs(self.db, quantum_us=1).build('a.example', 'child', target_time)
        self.assertEqual(exact['cutoff_us'], target_time)
        self.assertIn('creates', [edge[2] for edge in exact['edges']])
        self.assertTrue(all(item['timestamp_us'] < exact['cutoff_us'] for item in exact['evidence']))
        with self.assertRaisesRegex(ValueError, 'quantum_us=1'):
            EgoGraphs(self.db, quantum_us=1_000_000)

    def test_event_at_exact_target_timestamp_is_excluded(self):
        parent_event = event(0, 'parent', 'PROCESS', 'CREATE', 'child')
        parent_event['timestamp'] = '2019-09-23T00:00:00.987654+00:00'
        self.insert(parent_event)
        target_time = timestamp(parent_event['timestamp'])
        exact = EgoGraphs(self.db, quantum_us=1).build('a.example', 'child', target_time)
        self.assertEqual(exact['cutoff_us'], target_time)
        self.assertNotIn('creates', [edge[2] for edge in exact['edges']])
    def test_future_grandparent_cannot_retroactively_parent_older_child(self):
        self.insert(event(3,'parent','PROCESS','CREATE','child'),event(8,'root','PROCESS','CREATE','parent'))
        self.assertIn('graph::grandparent::missing',self.tokens())
    def test_open_is_not_parent_and_pid_not_a_join_key(self):
        r=event(1,'parent','PROCESS','OPEN','child',image_path='powershell.exe');r.update(pid=1,ppid=2)
        self.insert(r);self.assertIn('graph::parent::missing',self.tokens())
    def test_host_isolation(self):
        self.insert(event(1,'parent','PROCESS','CREATE','child',host='b.example'))
        self.assertIn('graph::parent::missing',self.tokens())
    def test_conflicting_parents_are_not_arbitrarily_selected(self):
        self.insert(event(1,'p1','PROCESS','CREATE','child'),event(2,'p2','PROCESS','CREATE','child'))
        self.assertIn('graph::parent::conflict',self.tokens())
    def test_cycles_stop(self):
        self.insert(event(1,'child','PROCESS','CREATE','child'))
        self.assertIn('graph::parent::cycle',self.tokens())
    def test_labels_and_identifiers_never_become_features(self):
        a=event(1,'parent','PROCESS','CREATE','child',image_path='powershell.exe');self.insert(a)
        before=self.tokens();a['label']=0;a['malicious']=True;a['scenario']='SC3';a['pid']=999999;self.insert(a)
        self.assertEqual(before,self.tokens())
        self.assertFalse(any('parentID' in f or 'label=' in f or 'scenario=' in f for f in FEATURES))
    def test_first_fact_causality_and_out_of_order_input(self):
        self.insert(event(15,'parent','PROCESS','CREATE','child',image_path='powershell.exe'),
                    event(5,'parent','PROCESS','CREATE','child',image_path='notepad.exe'))
        self.assertNotIn('graph::actor::role=shell',self.tokens(10));self.assertIn('graph::actor::role=other',self.tokens(10))
    def test_no_missing_hostname_fallback(self):
        self.insert(event(1,host=''))
        self.assertEqual(self.db.execute('SELECT count(*) FROM fact').fetchone()[0],0)
    def test_invalid_or_naive_timestamp(self):
        self.assertIsNone(timestamp('bad'));self.assertIsNone(timestamp('2019-01-01T00:00:00'))
        self.assertEqual(Encoder(self.db).encode('a','p',None),(COL['graph::event::missing_identity_or_time'],))
    def test_host_two_hop_and_unresolved_mapping(self):
        def flow(sec,host,src,dst):
            return event(sec,host=host,obj='FLOW',direction='outbound',src_ip=src,dest_ip=dst,dest_port=445)
        self.insert(flow(1,'a.example','10.0.0.1','10.0.0.2'),flow(3,'b.example','10.0.0.2','10.0.0.3'),
                    flow(4,'c.example','10.0.0.3','8.8.8.8'))
        self.assertIn('graph::host::unresolved_peer',self.tokens(2))
        self.assertIn('graph::host::two_hop_out::one',self.tokens())
    def test_ip_ambiguity_and_fanout_cap(self):
        for n in range(4):self.insert(event(1,obj='FLOW',direction='outbound',src_ip='10.0.0.1',dest_ip=f'10.0.0.{n+2}',dest_port=22))
        self.insert(event(2,host='b',obj='FLOW',direction='outbound',src_ip='10.0.0.2',dest_ip='1.1.1.1'),
                    event(3,host='c',obj='FLOW',direction='outbound',src_ip='10.0.0.2',dest_ip='1.1.1.1'))
        cols=Encoder(self.db,fanout=1).encode('a.example','p',timestamp(event(10)['timestamp']))
        self.assertIn(COL['graph::host::ambiguous_ip'],cols);self.assertIn(COL['graph::host::fanout_capped'],cols)
    def test_trace_contains_evidence_not_malicious_claim(self):
        self.insert(event(1,'parent','PROCESS','CREATE','child'))
        trace=Encoder(self.db).explain('a.example','child',timestamp(event(20)['timestamp']))
        self.assertEqual(trace['edges'][0]['source_line'],1)
        self.assertLess(trace['edges'][0]['timestamp_us'],trace['cutoff_us'])
    def test_protected_paths_and_symlinks(self):
        with self.assertRaises(ValueError):safe(HERE.parents[1]/'host-malicious/new.db')
        with self.assertRaises(ValueError):safe(HERE.parent/'output/host_ml_seed02/new.db')
        p=Path(self.tmp.name)/'link';p.symlink_to(HERE.parent/'output/host_ml_seed02',target_is_directory=True)
        with self.assertRaises(ValueError):safe(p/'new.db')


class PipelineTests(unittest.TestCase):
    def test_build_resume_and_ontology(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            args,_=fixture(Path(tmp));build(args);before=sha(args.output/'graph.sqlite');build(args)
            self.assertEqual(before,sha(args.output/'graph.sqlite'))
            db=connect(args.output/'graph.sqlite',readonly=True);audit=ontology_audit(db);db.close()
            self.assertEqual(audit['process'][3],1)

    def test_interrupted_source_resumes_without_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            args,_=fixture(Path(tmp));original=build_graph.observe
            def stop(db,record,source,line):
                if line==4:raise RuntimeError('interruption')
                return original(db,record,source,line)
            with patch('build_graph.observe',side_effect=stop):
                with self.assertRaisesRegex(RuntimeError,'interruption'):build(args)
            build(args)
            db=connect(args.output/'graph.sqlite',readonly=True)
            self.assertEqual(db.execute('SELECT count(*) FROM target').fetchone()[0],4)
            self.assertEqual(db.execute('SELECT count(*) FROM parent').fetchone()[0],2)
            db.close()

    def test_corruption_rejected(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            args,_=fixture(Path(tmp));build(args)
            with (args.output/'graph.sqlite').open('ab') as f:f.write(b'corrupt')
            with self.assertRaisesRegex(ValueError,'differs'):build(args)


if __name__=='__main__':unittest.main()
