import copy
from dataclasses import asdict
from pathlib import Path
import sys
import unittest
import numpy as np
import torch

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/'preprocess'),str(DL/'model')]
from provenance_context import observation,ProvenanceContext
from process_graph_data import ObservationIndex,build_window_graph,review_targets
from process_graph import ProcessGraphMIL,collate_graphs


def record(t,line,actor='p',target='q'):
    raw=dict(type='endpoint.event.procstart',device_name='host',process_guid=actor,
        process_path='c:\\windows\\cmd.exe',process_cmdline='cmd /c whoami',childproc_guid=target,
        childproc_name='c:\\windows\\powershell.exe',action='ACTION_CREATE_PROCESS')
    e=observation(raw,t,line);tokens,_=ProvenanceContext().features(e)
    return dict(source='fixture',line=line,event=asdict(e),tokens=tokens,evidence=[])


def sample():
    r=record(10,1);v={t:i for i,t in enumerate(r['tokens'])}
    g,_=build_window_graph([r],ObservationIndex([r]),v)
    g['edge_kind']=np.ones(len(g['edge_kind']),np.int64)
    return dict(features=g,sample_id='fixture',original_label=1,
        targets=dict(original_stages=np.array([1,1,0,0],np.float32),reviewed_stages=np.array([0,1,0,0],np.float32),review_mask=True)),len(v)


class ProcessGraphTests(unittest.TestCase):
    def test_portal_unknown_is_not_negative(self):
        p=dict(stage='1',event_type='FLOW_START',process='firefox.exe',target='detectportal.firefox.com',line='3')
        target=review_targets([p],scenario='m6',original_label=1)
        self.assertFalse(target['review_mask']);self.assertEqual(target['reviewed_binary'],1)
        mixed=review_targets([p,dict(p,stage='2',target='other')],scenario='m6',original_label=1)
        self.assertTrue(mixed['review_mask']);np.testing.assert_array_equal(mixed['reviewed_stages'],[0,1,0,0])

    def test_s3_time_contradiction_remains_unknown(self):
        self.assertFalse(review_targets([],scenario='s3',original_label=0)['review_mask'])

    def test_future_record_does_not_change_features(self):
        r=record(10,1);future=record(20,2,actor='z',target='p');future['event']['actor_command']='changed future'
        vocab={t:i for i,t in enumerate(r['tokens'])}
        a,ia=build_window_graph([r],ObservationIndex([r]),vocab)
        b,ib=build_window_graph([r],ObservationIndex([r,future]),vocab)
        for k in ['node_attr','lengths','edge_index','edge_age']:np.testing.assert_array_equal(a[k],b[k])
        self.assertEqual(a['edge_kind'],b['edge_kind']);self.assertLessEqual(ib['max_edge_timestamp'],10)

    def test_supervision_never_enters_model_features(self):
        item,dim=sample()
        n=item['features']['central_count']
        item['targets']['process_stage_target']=np.ones((n,4),np.float32)
        item['targets']['process_target_mask']=np.ones(n,bool)
        changed=copy.deepcopy(item);changed['original_label']=0
        changed['targets']['process_stage_target'][:]=0
        changed['targets']['process_target_mask'][:]=False
        changed['targets']['reviewed_stages'][:]=0;changed['targets']['review_mask']=False
        a,b=collate_graphs([item]),collate_graphs([changed])
        torch.manual_seed(1);model=ProcessGraphMIL(dim,2).eval()
        with torch.no_grad():torch.testing.assert_close(model(a),model(b),rtol=0,atol=0)

    def test_zero_graph_residual_matches_process_control_and_learns(self):
        item,dim=sample();batch=collate_graphs([item]);torch.manual_seed(1)
        a=ProcessGraphMIL(dim,2,graph=False).eval();b=ProcessGraphMIL(dim,2,graph=True).eval();b.load_state_dict(a.state_dict())
        with torch.no_grad():torch.testing.assert_close(a(batch),b(batch),rtol=0,atol=0)
        b(batch).sum().backward()
        self.assertGreater(float(b.layers[-1].update[-1].weight.grad.abs().sum()),0.)

    def test_batch_has_no_cross_sample_graph_edges(self):
        item,dim=sample();batch=collate_graphs([item,item]);n=len(item['features']['node_attr'])
        src,dst=batch['edge_index'];self.assertTrue(torch.equal(src<n,dst<n))


if __name__=='__main__':torch.set_num_threads(1);unittest.main()
