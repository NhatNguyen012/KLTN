"""Focused tests for streaming diagnostics, provenance and post-hoc curves."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
from ML.code.test.test_host_training_runtime import fixture, rt


class DiagnosticTests(unittest.TestCase):
    def test_standalone_setup_without_python311_file_digest(self):
        import hashlib
        import sys
        from unittest.mock import patch
        from refresh_host_notebooks import notebook
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp);data=fixture(root)
            runtime=Path(rt.__file__).read_text()
            setup=''.join(notebook('xgb','kaggle',runtime)['cells'][1]['source'])
            scope={}
            with patch.dict('os.environ',OPTC_MANIFEST=str(data.manifest_path),OPTC_OUTPUT=str(root/'out'),OPTC_DEVICE='cpu'), patch.object(sys,'path',list(sys.path)), patch.object(rt._host_shards,'sha256',rt._host_shards.sha256), patch.dict(hashlib.__dict__):
                hashlib.__dict__.pop('file_digest',None)
                exec(setup,scope)
                self.assertEqual(scope['sha256'](data.manifest_path),hashlib.sha256(data.manifest_path.read_bytes()).hexdigest())
                part=data.meta['shards'][0]
                X,y,lines=scope['decode_shard'](data.path_for(part),data.width,part)
                self.assertEqual(len(y),part['rows'])

    def test_preflight_rejects_old_scipy_before_runtime_import(self):
        from unittest.mock import patch
        from refresh_host_notebooks import notebook
        from importlib.metadata import version as real_version
        setup=''.join(notebook('xgb','kaggle',Path(rt.__file__).read_text())['cells'][1]['source'])
        with patch('importlib.metadata.version',side_effect=lambda name:'1.7.3' if name=='scipy' else real_version(name)):
            with self.assertRaisesRegex(RuntimeError,'scipy=1.7.3'):
                exec(setup,{})

    def test_resume_keeps_exact_groups_probe_and_error_provenance(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp);data=fixture(root)
            def predictor(X):
                return np.asarray(X @ np.array([.45,.2,.45])).ravel()
            a=rt.XGBDiagnostics(data,probe_negative=10,probe_positive=5,examples=4)
            full=rt.evaluate_resumable(data,'test',predictor,root/'full.npz','model',threshold=.5,diagnostics=a)
            b=rt.XGBDiagnostics(data,probe_negative=10,probe_positive=5,examples=4)
            count=0
            def interrupt(X):
                nonlocal count
                count+=1
                if count==3:raise RuntimeError('timeout')
                return predictor(X)
            with self.assertRaisesRegex(RuntimeError,'timeout'):
                rt.evaluate_resumable(data,'test',interrupt,root/'resume.npz','model',threshold=.5,diagnostics=b,checkpoint_every=1)
            c=rt.XGBDiagnostics(data,probe_negative=10,probe_positive=5,examples=4)
            resumed=rt.evaluate_resumable(data,'test',predictor,root/'resume.npz','model',threshold=.5,diagnostics=c)
            self.assertEqual(full,resumed);self.assertEqual(a.state,c.state)
            self.assertEqual(c.state['groups']['host']['unknown'],list(full['confusion'].values()))
            c.publish(root/'diagnostics','test',.5)
            result=json.loads((root/'diagnostics/test_errors.json').read_text())
            self.assertEqual({r['error'] for r in result['examples']},{'FP','FN'})
            for r in result['examples']:
                self.assertGreater(r['source_line'],0)
                self.assertTrue(r['shard'].startswith('test-'))
                self.assertEqual(len(r['tokens']),len(r['columns']))
            self.assertEqual([len(p) for p in c.state['probe']],[10,5])
            wrong=rt.XGBDiagnostics(data,probe_negative=11,probe_positive=5,examples=4)
            with self.assertRaisesRegex(ValueError,'checkpoint'):
                rt.evaluate_resumable(data,'test',predictor,root/'resume.npz','model',threshold=.5,diagnostics=wrong)

    def test_curve_uses_no_test_data_and_exports_full_validation_grid(self):
        import importlib.util
        if importlib.util.find_spec('xgboost') is None:
            self.skipTest('xgboost missing; run in the notebook test environment')
        import xgboost as xgb
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp);data=fixture(root)
            sample=rt.prepare_sample(data,root/'sample',target_rows=120)
            model,predict,_=rt.fit_sample_model(data,root/'sample',sample,root/'model','xgb',1,10**8,rounds=3)
            probe=rt.XGBDiagnostics(data,probe_negative=1000,probe_positive=1000,examples=2)
            val=rt.evaluate_resumable(data,'val',predict,root/'validation-state.npz','model',diagnostics=probe)
            curve=rt.xgb_posthoc_learning_curve(data,root/'sample',sample,model,probe,root/'diagnostics',val['threshold'],every=2)
            self.assertEqual({r['split'] for r in curve['curve']},{'train','val'})
            self.assertEqual({r['trees'] for r in curve['curve']},{1,2,3})
            self.assertTrue((root/'diagnostics/learning_curve.csv').exists())
            with np.load(root/'diagnostics/validation_threshold_curve.npz') as grid:
                i=int(round(val['threshold']*100000))
                self.assertAlmostEqual(float(grid['f1'][i]),val['f1'])
            X,y=probe.matrix()
            p=model.predict(xgb.DMatrix(X),iteration_range=(0,3))
            self.assertEqual(len(p),data.meta['splits']['val']['rows'])
            again=rt.xgb_posthoc_learning_curve(data,root/'sample',sample,model,probe,root/'diagnostics',val['threshold'],every=2)
            self.assertEqual(curve['curve'],again['curve'])

    def test_rf_and_lgbm_posthoc_learning_curves(self):
        import importlib.util
        for m_name in ('rf', 'lgbm'):
            pkg = 'lightgbm' if m_name == 'lgbm' else 'sklearn'
            if importlib.util.find_spec(pkg) is None:
                continue
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                root = Path(tmp)
                data = fixture(root)
                sample = rt.prepare_sample(data, root/'sample', target_rows=120)
                model, predict, _ = rt.fit_sample_model(
                    data, root/'sample', sample, root/'model', m_name, 1, 10**8,
                    rounds=3, rf_trees=3)
                probe = rt.XGBDiagnostics(data, probe_negative=1000, probe_positive=1000, examples=2, model_name=m_name)
                val = rt.evaluate_resumable(data, 'val', predict, root/'validation-state.npz', 'model', diagnostics=probe)
                curve = rt.posthoc_learning_curve(data, root/'sample', sample, model, probe, root/'diagnostics', val['threshold'], model_name=m_name, every=2)
                self.assertEqual({r['split'] for r in curve['curve']}, {'train', 'val'})
                self.assertEqual({r['trees'] for r in curve['curve']}, {1, 2, 3})
                self.assertTrue((root/'diagnostics/learning_curve.csv').exists())
                self.assertTrue((root/'diagnostics/validation_threshold_curve.npz').exists())

    def test_sparse_budget_and_input_write_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            data=fixture(Path(tmp));part=data.meta['shards'][0]
            X,y,lines=rt.decode_shard(data.path_for(part),data.width,part)
            probe=rt.XGBDiagnostics(data,max_probe_nnz=1)
            with self.assertRaises(MemoryError):probe.update(part,X,y,lines,np.zeros(len(y)))
            probe=rt.XGBDiagnostics(data)
            with self.assertRaises(ValueError):probe.publish(data.manifest_path.parent/'bad','val',.5)


if __name__=='__main__':unittest.main()
