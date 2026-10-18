"""Regression checks for shared sampling, CPU prediction and durable resume."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from scipy import sparse

sys.path.insert(0, str(Path(__file__).resolve().parent/'kaggle'))
import host_training_runtime as rt
from host_shards import ShardBuffer, sha256


def fixture(base, n=240):
    root = base/'input'
    (root/'assets').mkdir(parents=True)
    (root/'assets/vocab.json').write_text(json.dumps({'a':0,'b':1,'c':2}))
    vocab_sha = sha256(root/'assets/vocab.json')
    (root/'assets/vocab_metadata.json').write_text(json.dumps(
        dict(split_sha256='fixture-split', vocabulary_sha256=vocab_sha)))
    parts, totals = [], {}
    for split in ('train','val','test'):
        totals[split] = dict(rows=0, nnz=0, label_0=0, label_1=0, bytes=0)
        for block in range(4):
            buffer = ShardBuffer(3)
            for i in range(n//4):
                positive = int(i%7 == 0)
                columns = [1] if positive else ([0,2] if i%2 else [])
                buffer.append(columns, positive, i+1)
            payload, meta = buffer.encode()
            path = root/'volumes/disk'/f'{split}-{block}.npz'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            part = dict(meta, split=split, source_id='one', volume='disk', path=path.name)
            parts.append(part)
            for key in totals[split]:
                totals[split][key] += meta[key]
    meta = dict(format='host_binary_delta_npz', schema=1, complete=True, vocab_size=3,
                split_sha256='fixture-split', vocabulary_sha256=vocab_sha,
                volumes={'disk':str(root/'volumes/disk')}, sources=[{'source_id':'one'}],
                shards=parts, splits=totals,
                assets_sha256={name:sha256(root/'assets'/name) for name in ('vocab.json','vocab_metadata.json')})
    (root/'manifest.json').write_text(json.dumps(meta))
    return rt.TrainingDataset(root/'manifest.json')


class RuntimeTests(unittest.TestCase):
    def test_exact_plan_above_numpy_population_limit(self):
        class Data:
            meta = dict(splits={'train':dict(rows=3_600_000_080, label_0=3_600_000_000,label_1=80)},
                        shards=[dict(split='train', label_0=450_000_000,label_1=10) for _ in range(8)])
        plan = rt.sample_plan(Data(), target_rows=100_000_000)
        self.assertEqual(plan['rows'],100_000_000)
        self.assertEqual(sum(p['negatives'] for p in plan['entries']),99_999_920)
        self.assertEqual(plan,rt.sample_plan(Data(),target_rows=100_000_000))

    def test_exact_sample_preserves_positives_and_resume_and_guards(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base = Path(tmp); data = fixture(base)
            before = sha256(data.manifest_path)
            state = rt.prepare_sample(data,base/'sample',target_rows=120,workers=2,checkpoint_every=1)
            self.assertEqual(state['rows'],120)
            self.assertEqual(state['positives'],data.meta['splits']['train']['label_1'])
            X,y = rt.materialize_sample(base/'sample',state,10**8)
            self.assertEqual(X.shape,(120,3)); self.assertEqual(int(y.sum()),state['positives'])
            self.assertEqual(X.indices.dtype,np.int32)
            with patch.object(rt,'decode_shard',side_effect=AssertionError('should reuse sample')):
                again = rt.prepare_sample(data,base/'sample',target_rows=120)
            self.assertEqual(state,again)
            self.assertEqual(before,sha256(data.manifest_path))
            with self.assertRaisesRegex(ValueError,'configuration'):
                rt.prepare_sample(data,base/'sample',target_rows=121)
            with self.assertRaises(MemoryError): rt.materialize_sample(base/'sample',state,1)
            with self.assertRaises(ValueError): rt.prepare_sample(data,data.manifest_path.parent/'bad',target_rows=120)
            with self.assertRaises(ValueError): rt.output_path(base/'host-begnin'/'bad')
            link=base/'alias';link.symlink_to(data.manifest_path.parent,target_is_directory=True)
            with self.assertRaises(ValueError):rt.output_path(link/'bad',data.protected)

    def test_nguyen_keeps_previous_bernoulli_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = fixture(Path(tmp));plan = rt.sample_plan(data,neg_per_pos=2)
            rng=np.random.default_rng(1)
            for entry in plan['entries']:
                part=data.meta['shards'][entry['index']]
                X,y,_=rt.decode_shard(data.path_for(part),data.width,part)
                negatives=np.flatnonzero(y==0)
                selected=negatives[rng.random(len(negatives))<plan['keep_probability']]
                expected=np.sort(np.r_[np.flatnonzero(y==1),selected])
                np.testing.assert_array_equal(rt.selected_rows(y,entry,plan),expected)

    def test_dedup_exact_empty_and_wide_rows(self):
        X=sparse.csr_matrix([[0,0,0],[1,0,1],[0,1,0],[1,0,1],[0,0,0]],dtype=np.float32)
        unique,inverse=rt.unique_binary_rows(X)
        np.testing.assert_array_equal(unique[inverse].toarray(),X.toarray())
        self.assertEqual(unique.shape[0],3)
        raw=lambda batch: np.asarray(batch @ np.array([.1,.7,.2])).ravel()
        predictor=rt.ExactPredictor(raw)
        np.testing.assert_array_equal(predictor(X),raw(X))
        self.assertEqual(predictor.scored,3)
        unchanged,inverse=rt.unique_binary_rows(X,budget_bytes=1)
        self.assertIs(unchanged,X);self.assertIsNone(inverse)
        empty=sparse.csr_matrix((5,3),dtype=np.float32)
        unique,inverse=rt.unique_binary_rows(empty)
        self.assertEqual(unique.shape[0],1)
        np.testing.assert_array_equal(unique[inverse].toarray(),empty.toarray())

    def test_eval_resume_matches_full_and_rejects_stale_model(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);data=fixture(base)
            raw=lambda X:np.asarray(X @ np.array([.1,.9,.1])).ravel()
            full=rt.evaluate_resumable(data,'val',rt.ExactPredictor(raw),base/'full.npz','model',workers=2)
            calls=0
            def interrupted(X):
                nonlocal calls
                calls+=1
                if calls==3:raise RuntimeError('simulated timeout')
                return raw(X)
            with self.assertRaisesRegex(RuntimeError,'timeout'):
                rt.evaluate_resumable(data,'val',interrupted,base/'resume.npz','model',checkpoint_every=1)
            resumed=rt.evaluate_resumable(data,'val',raw,base/'resume.npz','model')
            self.assertEqual(full,resumed)
            test=rt.evaluate_resumable(data,'test',raw,base/'test.npz','model',threshold=full['threshold'])
            self.assertEqual(test['f1'],1)
            self.assertEqual(test['rows'],240)
            with self.assertRaisesRegex(ValueError,'checkpoint'):
                rt.evaluate_resumable(data,'val',raw,base/'resume.npz','different-model')
            with self.assertRaises(ValueError):rt.evaluate_resumable(data,'test',raw,base/'bad.npz','model')

    def test_cpu_budget_honors_quota(self):
        with patch('joblib.cpu_count',return_value=4):
            self.assertEqual(rt.cpu_budget(),4)
            self.assertEqual(rt.cpu_budget(64),4)
            self.assertEqual(rt.cpu_budget(2),2)

    def test_sample_interruption_and_corruption(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);data=fixture(base)
            original=rt.decode_shard
            def stop(path,*args,**kwargs):
                if path.name=='train-2.npz':raise RuntimeError('sample interrupted')
                return original(path,*args,**kwargs)
            with patch.object(rt,'decode_shard',side_effect=stop):
                with self.assertRaisesRegex(RuntimeError,'interrupted'):
                    rt.prepare_sample(data,base/'sample',target_rows=120,checkpoint_every=1)
            resumed=rt.prepare_sample(data,base/'sample',target_rows=120)
            fresh=rt.prepare_sample(data,base/'fresh',target_rows=120)
            self.assertEqual(resumed,fresh)
            (base/'sample'/resumed['parts'][0]['path']).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'checksum'):
                rt.prepare_sample(data,base/'sample',target_rows=120)

    def test_standalone_notebook_cells_end_to_end(self):
        from refresh_host_notebooks import notebook
        runtime=(Path(rt.__file__)).read_text()
        for profile in ('kaggle','ec2-100m'):
            for model in ('rf','xgb','lgbm'):
                with self.subTest(profile=profile,model=model), tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                    base=Path(tmp);data=fixture(base,480)
                    nb=notebook(model,profile,runtime)
                    scope={}
                    with patch.dict('os.environ',OPTC_MANIFEST=str(data.manifest_path),OPTC_OUTPUT=str(base/'out'),OPTC_DEVICE='cpu'), patch.object(sys,'path',list(sys.path)):
                        exec(''.join(nb['cells'][1]['source']),scope)
                        scope.update(TRAIN_TARGET_ROWS=300, BOOST_ROUNDS=3, RF_TREES=3,
                                     CPU_THREADS=2, PREDICT_THREADS=2, LOADER_WORKERS=1)
                        exec(''.join(nb['cells'][2]['source']),scope)
                        exec(''.join(nb['cells'][3]['source']),scope)
                        self.assertEqual(scope['report']['train_sampling']['rows'],300)
                        self.assertEqual(scope['report']['test']['rows'],480)
                        self.assertEqual(scope['report']['test']['threshold'],scope['report']['validation']['threshold'])

    def test_training_checkpoint_resume_three_estimators(self):
        import importlib.util
        for name, package in [('rf','sklearn'),('xgb','xgboost'),('lgbm','lightgbm')]:
            if importlib.util.find_spec(package) is None:
                self.skipTest(f'{package} missing; run in the notebook test environment')
            with self.subTest(model=name), tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                base=Path(tmp);data=fixture(base,480)
                sample=rt.prepare_sample(data,base/'sample',target_rows=300)
                args=(data,base/'sample',sample,base/'resumed',name,2,10**8)
                original=rt.atomic_json
                def stop_after_checkpoint(path,value,protected=()):
                    original(path,value,protected)
                    if Path(path).name=='latest.json' and not value['complete']:
                        raise RuntimeError('simulated training timeout')
                with patch.object(rt,'atomic_json',side_effect=stop_after_checkpoint):
                    with self.assertRaisesRegex(RuntimeError,'training timeout'):
                        rt.fit_sample_model(*args,rounds=3,rf_trees=3,checkpoint_every=1)
                model,predict,receipt=rt.fit_sample_model(*args,rounds=3,rf_trees=3,checkpoint_every=1)
                self.assertTrue(receipt['complete'])
                X,_=rt.materialize_sample(base/'sample',sample,10**8)
                with patch.object(rt,'materialize_sample',side_effect=AssertionError('completed model must not reload TRAIN')):
                    _,again,_=rt.fit_sample_model(*args,rounds=3,rf_trees=3,checkpoint_every=1)
                np.testing.assert_allclose(predict(X),again(X),rtol=1e-6)
                _,fresh,_=rt.fit_sample_model(data,base/'sample',sample,base/'fresh',name,2,10**8,
                                             rounds=3,rf_trees=3,checkpoint_every=1)
                np.testing.assert_allclose(predict(X),fresh(X),rtol=1e-5,atol=1e-6)

    def test_isoforest_cpu_notebook(self):
        path=Path(rt.__file__).with_name('host_isoforest_shards.ipynb')
        if not path.exists():
            self.skipTest('Isolation Forest notebook is not present on this branch')
        nb=json.loads(path.read_text())
        if not any('BEGIN EMBEDDED RUNTIME' in ''.join(c['source']) for c in nb['cells']):
            self.skipTest('CPU Isolation Forest update applies to Nguyen only')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);data=fixture(base,480);scope={}
            with patch.dict('os.environ',OPTC_MANIFEST=str(data.manifest_path),OPTC_OUTPUT=str(base/'out'),OPTC_DEVICE='cpu'), patch.object(sys,'path',list(sys.path)):
                for c in nb['cells']:
                    if c['cell_type']!='code':continue
                    source=''.join(c['source']).replace('TRAIN_SAMPLE_ROWS = 4_000_000','TRAIN_SAMPLE_ROWS = 300').replace('n_estimators=300','n_estimators=3')
                    exec(source,scope)
                    scope.update(CPU_THREADS=2,PREDICT_THREADS=2,LOADER_WORKERS=1)
                self.assertEqual(scope['report']['test']['rows'],480)
                self.assertEqual(scope['test']['threshold'],scope['validation']['threshold'])


if __name__=='__main__':unittest.main()
