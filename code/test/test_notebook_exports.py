"""Execute export against portable shard schema; no training or telemetry scans."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE/'preprocess'),str(CODE/'kaggle'),str(CODE/'kaggle/scripts')]
from refresh_host_notebooks import RESULT_EXPORT_CELL, notebook
from host_training_runtime import output_path, sha256


class ExportTests(unittest.TestCase):
    def test_all_notebooks_match_generator(self):
        for model in ('rf','xgb','lgbm'):
            value=json.loads((CODE/f'kaggle/notebooks/host_{model}_shards.ipynb').read_text())
            self.assertEqual(''.join(value['cells'][-1]['source']),RESULT_EXPORT_CELL)
            for profile in ('kaggle','ec2-100m'):
                generated=notebook(model,profile,'# runtime stub')
                self.assertEqual(''.join(generated['cells'][-1]['source']),RESULT_EXPORT_CELL)
                for cell in generated['cells']:
                    if cell['cell_type']=='code':compile(''.join(cell['source']),'<notebook>','exec')

    def test_generator_reproduces_approved_v4_notebooks(self):
        runtime = (CODE/'kaggle/host_training_runtime.py').read_text()
        for model in ('rf', 'xgb', 'lgbm'):
            frozen = json.loads((CODE/f'output/host_ml_seed02/model_input/host_{model}_shards.ipynb').read_text())
            self.assertEqual(notebook(model, 'kaggle', runtime), frozen)

    def test_archive_has_distinct_manifests_and_correct_source_mapping(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);inputs=base/'input';assets=inputs/'assets';assets.mkdir(parents=True)
            for name in ('vocab.json','vocab_metadata.json','split_manifest.json'):(assets/name).write_text('{}')
            (inputs/'manifest.json').write_text('{}')
            output=base/'output';output.mkdir();(output/'model.bin').write_bytes(b'model')
            diagnostics=output/'diagnostics';diagnostics.mkdir()
            (diagnostics/'test_fn_examples.jsonl').write_text('{"source_id":"s","source_line":23}\n')
            meta=dict(sources=[dict(source_id='s',source=dict(path='/raw/host-malicious/events.json.gz'),file_host='host',day='day')],
                      shards=[dict(source_id='s',volume=v,path='same.npz',split='test',label_0=2,label_1=0) for v in ('a','b')])
            data=SimpleNamespace(meta=meta,manifest_path=inputs/'manifest.json',protected=[inputs])
            cwd=Path.cwd()
            try:
                os.chdir(base)
                env=dict(MODEL_NAME='rf',PROFILE='test',OUTPUT=output,DIAGNOSTICS=diagnostics,data=data,output_path=output_path,sha256=sha256)
                exec(compile(RESULT_EXPORT_CELL,'<export>','exec'),env)
                with zipfile.ZipFile(base/'rf_test_results.zip') as z:
                    self.assertEqual(len(z.namelist()),len(set(z.namelist())))
                    self.assertIn('provenance/split_manifest.json',z.namelist())
                    self.assertIn('provenance/shard_manifest.json',z.namelist())
                    mapping=json.loads(z.read('provenance/shard_source_index.json'))
                    self.assertEqual(set(mapping),{'a/same.npz','b/same.npz'})
                    self.assertEqual(mapping['a/same.npz']['source_gz'],'/raw/host-malicious/events.json.gz')
                    self.assertIn(b'1-based',z.read('provenance/README.txt'))
            finally:os.chdir(cwd)


if __name__=='__main__':unittest.main()
