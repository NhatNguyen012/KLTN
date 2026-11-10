import sys
import unittest
from pathlib import Path
import tempfile
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'preprocess'))
from build_host_shards import FileSessionIndex, extract_domain_shift_tokens, PREDEFINED_DOMAIN_TOKENS
from preprocess.common_schema import CanonicalEvent
from preprocess.raw_context import RawContext
from preprocess.theia_adapter import THEIAAdapter


def event(**kwargs):
    return CanonicalEvent(**(dict(event_id='E', timestamp=100, hostname='host', scenario='train',
                                 event_type='FILE_READ', process_guid='C', process_path='/bin/native') | kwargs))


class HostContextTests(unittest.TestCase):
    def test_stable_replay_preserves_original_identity(self):
        from event_replay import ordered_csv
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'source').mkdir(); source=root/'source/input.csv'
            source.write_text('src,srcid,op,dst,dstid,uuid,ts\nP,1,EVENT_READ,F,2,A,3000\nP,1,EVENT_READ,F,2,B,1000\nP,1,EVENT_READ,F,2,C,1000\n')
            path=ordered_csv(source,root/'cache')
            rows=path.read_text().splitlines()
            self.assertEqual([r.split(',')[5] for r in rows[1:]],['B','C','A'])
            self.assertEqual([r.split(',')[-1] for r in rows[1:]],['3','4','2'])
            self.assertEqual(path,ordered_csv(source,root/'cache'))
            source.write_text(source.read_text()+'P,1,EVENT_READ,F,2,D,500\n')
            self.assertEqual(ordered_csv(source,root/'cache').read_text().splitlines()[1].split(',')[5],'D')

    def test_two_hops_and_no_future_ancestor(self):
        s = FileSessionIndex()
        s.add_event(event(process_guid='P', timestamp=10, parent_guid='G', parent_path='/opt/firefox'))
        s.add_event(event(timestamp=20, parent_guid='P', parent_path='/bin/dash'))
        tokens = s.tokens(event())
        self.assertIn('ctx_host::lineage=browser>shell>native', tokens)
        self.assertIn('ctx_host::grandparent_missing', s.tokens(event(timestamp=15)))
        s.add_event(event(process_guid='G', timestamp=30, parent_guid='C', parent_path='/bin/native'))
        self.assertEqual(len(s.ancestors('C', 100)), 2)

    def test_clone_creator_survives_subject_reparenting(self):
        r=RawContext.__new__(RawContext)
        r.subjects={'C':[(1,['I','','','/bin/native',''])],
                    'I':[(1,['','','','/sbin/init',''])],
                    'P':[(1,['','','','/bin/dash',''])]}
        s=FileSessionIndex(raw_context=r,source_stream=True)
        s.observe_row('EVENT_CLONE',1,2,10,2,{1:('P','/bin/dash',''),2:('C','/bin/native','')},{})
        e=event(timestamp=11,parent_guid='I',parent_path='/sbin/init')
        s.add_event(e)
        self.assertEqual(e.parent_guid,'P')
        self.assertEqual(e.parent_path,'/bin/dash')
        self.assertEqual(s.get_parent('C',11)[0],'P')
        self.assertEqual(s.get_parent('C',9)[0],'I')

    def test_raw_two_hop_fallback_is_timestamp_gated(self):
        r = RawContext.__new__(RawContext)
        r.subjects = {'C': [(10, ['P','','','/bin/native',''])],
                      'P': [(10, ['G','','','/bin/dash',''])],
                      'G': [(50, ['','','','/opt/firefox',''])]}
        s=FileSessionIndex(raw_context=r)
        self.assertEqual(len(s.ancestors('C', 49)),1)
        self.assertIn('ctx_host::lineage=browser>shell>native',s.tokens(event()))

    def test_incoming_history_and_strictly_prior_activity(self):
        s=FileSessionIndex()
        procs={1:('S','/bin/bash',''),2:('C','/bin/native','')}
        s.observe_row('EVENT_SHM',1,2,100,2,procs,{})
        self.assertNotIn('ctx_host::incoming::family=shell',s.tokens(event(timestamp=100)))
        self.assertIn('ctx_host::incoming::family=shell',s.tokens(event(timestamp=101)))
        # A socket object is not a target process; it must not create an IPC edge.
        s.observe_row('EVENT_CONNECT',1,3,102,3,procs,{})
        self.assertNotIn('3',s.nodes)

    def test_write_execute_relation_and_self_exclusion(self):
        s=FileSessionIndex()
        procs={1:('P','/bin/bash',''),2:('C','/tmp/payload','')}
        files={3:('F','/tmp/payload')}
        s.observe_row('EVENT_WRITE',1,3,10,2,procs,files)
        s.observe_row('EVENT_CLONE',1,2,20,3,procs,files)
        s.observe_row('EVENT_EXECUTE',3,2,30,4,procs,files)
        e=event(timestamp=30,raw_operation='EVENT_EXECUTE',target_path='/tmp/payload',target_file_guid='F')
        self.assertIn('ctx_host::execution::prior_writer=parent',s.tokens(e))
        e.target_file_guid='different-file-at-same-path'
        self.assertFalse(any(t.startswith('ctx_host::execution::prior_writer') for t in s.tokens(e)))
        e.target_file_guid='F'
        self.assertNotIn('ctx_host::actor::prior_exec_30s=1',s.tokens(e))
        self.assertIn('ctx_host::actor::prior_exec_30s=1',s.tokens(event(timestamp=31)))

    def test_pre_sampling_observer_and_no_label_argument(self):
        class Refiner:
            attack_edge_uuids=set()
            attack_process_uuids={}
            def get_attack_chain_for_process(self,g):return ''
            def refine_event_label(self,e):return 0
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'events.csv'
            p.write_text('src,si,op,dst,di,id,ts\n'
                         'p,1,EVENT_READ,f,2,00000001-0000,1000000000000100000\n'
                         'p,1,EVENT_WRITE,f,3,00000000-0000,1000000000000200000\n')
            a=THEIAAdapter(Refiner(),temp);a._loaded_node_tables=True
            a.process_nodes={1:('C','/bin/native','')}
            a.file_nodes={2:('F','/etc/passwd'),3:('G','/tmp/a')}
            s=FileSessionIndex(source_stream=True)
            rows=list(a.stream_canonical_events(p,undersample_benign_ratio=30,context_observer=s.observe_row))
            self.assertEqual(len(rows),1)
            self.assertIn('ctx_host::actor::prior_read_auth_30s=1',s.tokens(rows[0]))
            self.assertEqual(s.stats['source_rows'],2)

    def test_bounds_ttl_and_label_independence(self):
        s=FileSessionIndex(max_processes=2,max_files=2,max_history=3,ttl_micros=100)
        procs={i:(str(i),'/bin/native','') for i in range(5)}
        for i in range(5):s.observe_row('EVENT_CONNECT',i,99,i,2+i,procs,{})
        self.assertLessEqual(len(s.nodes),2)
        for t in range(10,30):s.observe_row('EVENT_CONNECT',4,99,t,t,procs,{})
        self.assertLessEqual(len(s.nodes['4']['network']),3)
        files={i:(f'F{i}',f'/tmp/file{i}') for i in range(10,15)}
        for i in files:s.observe_row('EVENT_WRITE',4,i,30,i,procs,files)
        self.assertLessEqual(len(s.writes),2)
        a=extract_domain_shift_tokens(event(process_guid='4',timestamp=31,label=0),s)
        b=extract_domain_shift_tokens(event(process_guid='4',timestamp=31,label=1),s)
        self.assertEqual(a,b)
        s.observe_row('EVENT_CONNECT',3,99,300,300,procs,{})
        self.assertFalse(s.has_netconn('4',300))
        self.assertIn('ctx_host::late_beyond_window',s.tokens(event(timestamp=31)))

    def test_structural_tokens_preseeded_and_no_network_values(self):
        from preprocess.host_context import CONTEXT_TOKENS
        self.assertTrue(set(CONTEXT_TOKENS).issubset(PREDEFINED_DOMAIN_TOKENS))
        a=event(remote_ip='8.8.8.8',remote_port=443,proto='tcp')
        b=event(remote_ip='192.0.2.1',remote_port=22,proto='udp')
        s=FileSessionIndex()
        self.assertEqual(extract_domain_shift_tokens(a,s),extract_domain_shift_tokens(b,s))

    def test_export_one_booster_real_checkpoints(self):
        import lightgbm as lgb
        from scipy import sparse
        from single_booster import combine_boosters, assert_prediction_parity
        from frozen_atlas import FrozenAtlasModel
        base=FrozenAtlasModel(ROOT/'preprocess/output/pretrained_optc_model/model-slot-0.txt')
        residual=lgb.Booster(model_file=str(ROOT/'output/kaggle_output/7/results/incremental/model/model-slot-1.txt'))
        rng=np.random.default_rng(17)
        X=sparse.random(100,residual.num_feature(),density=.003,random_state=rng,format='csr')
        X.data[:]=1
        for alpha in (.0,.4,.8):
            components=[(base.anchor,alpha*base.alpha),(base.residual,alpha),(residual,1.)]
            combined=combine_boosters(components)
            self.assertLess(assert_prediction_parity(combined,components,X),1e-10)
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'model.txt';combined.save_model(str(path))
                loaded=lgb.Booster(model_file=str(path))
                self.assertLess(assert_prediction_parity(loaded,components,X),1e-10)

    def test_notebook_selects_on_validation_only(self):
        import json, os
        from contextlib import nullcontext
        from unittest.mock import patch
        notebook=json.loads((ROOT/'notebook/lgbm_atlasv2_theia.ipynb').read_text())
        source=''.join(notebook['cells'][3]['source']).split('    # 3. One booster for deployment')[0]
        calls=[]
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); checkpoint=root/'frozen.txt';checkpoint.write_text('fixture')
            def fit(*args, **kwargs):
                args[3].mkdir(parents=True,exist_ok=True)
                alpha=kwargs.get('base_margin_alpha',0)
                weight=kwargs.get('hard_negative_weight',1)
                calls.append((alpha,weight))
                return object(), lambda X:(alpha,weight), {'sha256':f'{alpha}-{weight}'}
            def evaluate(data, split, predictor, *args, **kwargs):
                self.assertEqual(split,'val')
                alpha, weight=predictor(None)
                return {'pr_auc_binned':.5 if alpha==.4 and weight==1 else .1,'f1':0.}
            ns=dict(phase=lambda *a:nullcontext(),prepare_sample=lambda *a,**k:{'sample_id':'fixture'},
                    data=type('FixtureData', (), {'protected': []})(),SAMPLE_DIR=root/'sample',TRAIN_TARGET_ROWS=None,NEG_PER_POS=30,
                    SEED=1,LOADER_WORKERS=1,MAX_SAMPLE_NNZ=1000,OUTPUT=root/'output',MODEL_NAME='lgbm',
                    CPU_THREADS=1,MAX_MATRIX_GIB=1,DEVICE='cpu',BALANCE_CLASSES=True,BOOST_ROUNDS=1,
                    RF_TREES=1,PREDICT_THREADS=1,DEDUPE_PREDICTION=False,DEDUPE_BUDGET_MIB=1,
                    fit_sample_model=fit,ExactPredictor=lambda fn,**kw:fn,PRETRAINED_MODEL=checkpoint,
                    BASE_MARGIN_ALPHA=.8,HARD_NEGATIVE_WEIGHT=5.,evaluate_resumable=evaluate,
                    RANKING_BINS=100,atomic_json=lambda *a:None,os=os)
            with patch.dict(os.environ,{},clear=True):exec(compile(source,'<selection-test>','exec'),ns)
            self.assertEqual(ns['BASE_MARGIN_ALPHA'],.4)
            self.assertEqual(ns['HARD_NEGATIVE_WEIGHT'],1.)
            self.assertEqual(len(calls),5)  # scratch control + four offline configurations
            self.assertEqual(ns['raw_predict_il'](None),(.4,1.))


if __name__=='__main__':unittest.main()
