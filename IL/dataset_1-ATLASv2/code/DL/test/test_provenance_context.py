import dataclasses
from pathlib import Path
import sys
import unittest
import torch

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/'preprocess'),str(DL/'model')]
from provenance_context import observation,ProvenanceContext
from bilstm import BiLSTMBaseline


def raw(kind='crossproc', actor='a', target='b', flag=False, action='ACTION_OPEN_PROCESS_HANDLE', host='h1'):
    return dict(type='endpoint.event.'+kind,process_guid=actor,process_path='c:\\temp\\powershell.exe',
        process_cmdline='powershell -nop',crossproc_guid=target,crossproc_name='c:\\windows\\system32\\cmd.exe',
        crossproc_target=flag,crossproc_action=action,device_name=host,childproc_guid=target,
        childproc_name='c:\\windows\\system32\\cmd.exe',action='ACTION_CREATE_PROCESS')


class ProvenanceTests(unittest.TestCase):
    def test_label_reputation_ioc_invariance(self):
        r=raw();a=observation(r,10,1)
        r.update(label=1,stage=4,malicious=True,reputation='KNOWN_MALWARE',scenario='m6',attack_guid='secret')
        b=observation(r,10,1)
        self.assertEqual(a,b)
        tr=ProvenanceContext();self.assertEqual(tr.features(a),tr.features(b))

    def test_target_side_direction(self):
        e=observation(raw(flag=True),10,1)
        self.assertEqual((e.actor,e.target),('b','a'))
        self.assertEqual(e.actor_command,'')
        tr=ProvenanceContext();tr.observe_batch([e])
        q=observation(raw(actor='a'),11,2)
        self.assertTrue(any('incoming::process_open' in t for t in tr.features(q)[0]))
        self.assertFalse(any('incoming' in t for t in tr.features(dataclasses.replace(q,actor='b'))[0]))

    def test_strict_time_host_and_kind(self):
        tr=ProvenanceContext()
        e=observation(raw(action='ACTION_OPEN_THREAD_HANDLE'),10,1);tr.observe_batch([e])
        q=observation(raw(actor='b'),10,2)
        self.assertFalse(any('incoming' in t for t in tr.features(q)[0]))
        ts=tr.features(dataclasses.replace(q,timestamp=11))[0]
        self.assertTrue(any('thread_open' in t for t in ts))
        self.assertFalse(any('remote_thread_create' in t for t in ts))
        self.assertFalse(any('incoming' in t for t in tr.features(dataclasses.replace(q,timestamp=11,host='h2'))[0]))

    def test_remote_thread_prior_open_and_bounds(self):
        tr=ProvenanceContext(per_kind=2,capacity=2,ttl_micros=100)
        tr.observe_batch([observation(raw(),1,1)])
        tr.observe_batch([observation(raw(action='ACTION_CREATE_REMOTE_THREAD'),2,2)])
        for t in range(3,20):tr.observe_batch([observation(raw(),t,t)])
        self.assertLessEqual(len(tr.incoming[('h1','b')]['process_open']),2)
        self.assertEqual(len(tr.incoming[('h1','b')]['remote_thread_create']),1)
        q=observation(raw(actor='b'),20,20)
        self.assertFalse(any('incoming' in t for t in tr.features(dataclasses.replace(q,timestamp=121))[0]))

    def test_parent_and_equal_time_batch(self):
        tr=ProvenanceContext();p=observation(raw(kind='procstart'),10,1)
        q=observation(raw(actor='b'),10,2)
        self.assertIn('parent::status=unobserved',tr.features(q)[0])
        tr.observe_batch([p,q])
        self.assertIn('parent::family=powershell',tr.features(dataclasses.replace(q,timestamp=11))[0])

    def test_image_writer_is_past_path_join(self):
        tr=ProvenanceContext()
        r=raw(kind='filemod');r['filemod_name']='c:\\temp\\image.exe';r['action']='ACTION_FILE_WRITE'
        writer=observation(r,10,1);tr.observe_batch([writer])
        q=observation(raw(kind='procstart'),10,2)
        q=dataclasses.replace(q,target_path='c:\\temp\\image.exe')
        self.assertFalse(any(t.startswith('filectx::') for t in tr.features(q)[0]))
        tokens,evidence=tr.features(dataclasses.replace(q,timestamp=11))
        self.assertIn('filectx::executed_image_writer_family=powershell',tokens)
        self.assertTrue(all(p.timestamp<11 for _,p in evidence))
        self.assertFalse(any(t.startswith('filectx::') for t in tr.features(dataclasses.replace(q,timestamp=300_000_011))[0]))

    def test_conflict_and_unknown_direction_do_not_invent_relationship(self):
        tr=ProvenanceContext()
        tr.observe_batch([observation(raw(kind='procstart'),10,1)])
        tr.observe_batch([observation(raw(kind='procstart',actor='c'),20,2)])
        q=observation(raw(actor='b'),21,3)
        self.assertIn('parent::status=conflict',tr.features(q)[0])
        unknown=observation(raw(actor='z',target='q',flag=None),22,4);tr.observe_batch([unknown])
        self.assertNotIn(('h1','q'),tr.incoming)

    def test_zero_adapter_preserves_pretrained_logits(self):
        torch.set_num_threads(1);torch.manual_seed(3)
        base=BiLSTMBaseline(categorical_cardinalities=[4]*4,num_stages=4).eval()
        ext=BiLSTMBaseline(categorical_cardinalities=[4]*4,num_stages=4,context_dim=3).eval()
        state=ext.state_dict();state.update(base.state_dict());ext.load_state_dict(state)
        batch=dict(x_cat=torch.zeros(2,4,4,dtype=torch.long),x_num=torch.zeros(2,4,0),
            x_num_missing=torch.zeros(2,4,0),x_bin=torch.zeros(2,4,1),delta_t_log1p=torch.zeros(2,4,1),lengths=torch.tensor([4,2]))
        with torch.no_grad():
            a=base(**batch);b=ext(**batch,x_context=torch.ones(2,4,3))
        torch.testing.assert_close(a,b,rtol=0,atol=0)
        ext(**batch,x_context=torch.ones(2,4,3)).sum().backward()
        self.assertGreater(float(ext.context_projection.weight.grad.abs().sum()),0)


if __name__=='__main__':unittest.main()
