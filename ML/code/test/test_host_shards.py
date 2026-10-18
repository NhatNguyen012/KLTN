"""Lossless full-data shard roundtrips, quotas/resume and estimator adapters."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import types
from unittest.mock import patch
import numpy as np
from scipy import sparse

from host_shards import ShardBuffer,decode_shard,HostShardDataset,xgboost_iterator
from shard_storage import initialize_ledger,write_shard,load_volumes,exclusive_lock
from stratified_pipeline import index_main,split_main,load_manifest,split_rows,digest
from build_vocab import main as build_vocab
from build_model_input import main as build_input
from verify_model_input import main as verify
from shard_metrics import evaluate_stream
from ecar_tokenizer import tokenize_record,flatten_tokens
import ML.code.test.test_stratified_pipeline as test_stratified_pipeline


class ShardTests(unittest.TestCase):
    def test_roundtrip_empty_rows_labels_large_lines(self):
        buffer=ShardBuffer(204969)
        rows=[([0,1,100,204968],0,1),([],1,2),([0],1,2**32+9),([],0,2**32+10)]
        for cols,label,line in rows:buffer.append(cols,label,line)
        blob,meta=buffer.encode()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'part.npz';p.write_bytes(blob)
            X,y,lines=decode_shard(p,204969,meta)
            self.assertEqual(list(y),[r[1] for r in rows])
            self.assertEqual(list(lines),[r[2] for r in rows])
            for i,row in enumerate(rows):self.assertEqual(list(X[i].indices),row[0])
            p.write_bytes(blob+b'bad')
            with self.assertRaisesRegex(ValueError,'checksum'):decode_shard(p,204969,meta)

    def test_quota_spill_resume_and_disk_reserve(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);a=base/'a';b=base/'b';a.mkdir();b.mkdir()
            volumes=[dict(id='a',path=str(a),max_bytes=6,reserve_free_bytes=0),dict(id='b',path=str(b),max_bytes=10,reserve_free_bytes=0)]
            initialize_ledger(base,volumes)
            self.assertEqual(write_shard(base,'r/one.npz',b'123456')['volume'],'a')
            self.assertEqual(write_shard(base,'r/two.npz',b'1234567')['volume'],'b')
            self.assertEqual(write_shard(base,'r/one.npz',b'123456')['volume'],'a')
            with self.assertRaisesRegex(OSError,'quota/free'):write_shard(base,'r/three.npz',b'1234')
            before=json.loads((base/'storage_ledger.json').read_text())['used']
            initialize_ledger(base,volumes)
            self.assertEqual(json.loads((base/'storage_ledger.json').read_text())['used'],before)
            with patch('shard_storage.shutil.disk_usage') as usage:
                usage.return_value.free=0
                with self.assertRaises(OSError):write_shard(base,'r/small.npz',b'1')

    def test_full_pipeline_lossless_no_global_matrix_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);benign,attack=test_stratified_pipeline.SharedSplitTests().dataset(base)
            index_main(['--benign-root',str(benign),'--malicious-root',str(attack),'--output-dir',str(base/'index'),'--workers','1'])
            split_main(['--index',str(base/'index/manifest.json'),'--output-dir',str(base/'split'),'--workers','1'])
            sp=base/'split/manifest.json';vocab=base/'vocab.json';vm=base/'vocab_metadata.json'
            build_vocab(['--split',str(sp),'--output',str(vocab),'--metadata-output',str(vm),'--workers','1'])
            cfg=base/'storage.json';cfg.write_text(json.dumps(dict(volumes=[dict(id='disk',path=str(base/'data'),max_bytes=10**8,reserve_free_bytes=0)])))
            out=base/'output'
            args=['--split',str(sp),'--vocab',str(vocab),'--vocab-metadata',str(vm),'--storage-config',str(cfg),'--output-dir',str(out),'--rows-per-shard','7','--workers','2']
            build_input(args)
            dataset=HostShardDataset(out/'manifest.json')
            self.assertEqual(sum(v['rows'] for v in dataset.meta['splits'].values()),160)
            expected={s:{} for s in ('train','val','test')}
            sm,_=load_manifest(sp,'host_random_split');voc=json.loads(vocab.read_text())
            for entry in sm['entries']:
                sid=digest(entry['source'])
                for code,line,row in split_rows(entry,base/'split'):
                    cols=sorted({voc[t] for t in flatten_tokens(tokenize_record(row)[0]) if t in voc})
                    expected[('train','val','test')[code-1]][(sid,line)]=(cols,row['label'])
            for split in expected:
                found={}
                for X,y,provenance in dataset.iter_batches(split,with_provenance=True):
                    sid=provenance['source']['source_id']
                    for i,line in enumerate(provenance['source_lines']):found[(sid,int(line))]=(list(X[i].indices),int(y[i]))
                self.assertEqual(found,expected[split])
            verify(['--manifest',str(out/'manifest.json'),'--decode'])
            self.assertFalse(list(out.rglob('*.jsonl')))
            self.assertFalse((out/'X_train.npz').exists())
            # Simulate interrupted final publication. Completed source receipts survive.
            (out/'manifest.json').unlink()
            build_input(args)
            meta=json.loads((out/'manifest.json').read_text())
            self.assertEqual(meta['resumed_files'],2)
            # Corrupt one shard and rerun before final publication: rescan just that source.
            (out/'manifest.json').unlink()
            part=meta['shards'][0];(base/'data'/part['path']).write_bytes(b'corrupt')
            build_input(args)
            meta=json.loads((out/'manifest.json').read_text())
            self.assertEqual(meta['resumed_files'],1)
            dataset=HostShardDataset(out/'manifest.json')
            X,y=dataset.materialize('train',10**7)
            self.assertEqual(X.shape[0],120)
            with self.assertRaises(MemoryError):dataset.materialize('train',1)
            from sklearn.ensemble import RandomForestClassifier
            model=RandomForestClassifier(n_estimators=3,random_state=1).fit(X,y)
            predict=lambda batch:model.predict_proba(batch)[:,1]
            val=evaluate_stream(dataset,'val',predict)
            test=evaluate_stream(dataset,'test',predict,threshold=val['threshold'])
            self.assertEqual(test['rows'],24)
            with self.assertRaisesRegex(ValueError,'frozen'):evaluate_stream(dataset,'test',predict)
            # Relocation needs only a volume mapping, not edited source identities.
            (base/'data').rename(base/'moved')
            moved=HostShardDataset(out/'manifest.json',{'disk':base/'moved'})
            self.assertEqual(sum(len(y) for X,y in moved.iter_batches('test')),24)

    def test_storage_boundary_and_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);cfg=base/'cfg.json'
            cfg.write_text(json.dumps(dict(volumes=[dict(id='x',path=str(base/'input'),max_bytes=100,reserve_free_bytes=0)])))
            with self.assertRaises(ValueError):load_volumes(cfg,[base/'input'])
            volumes=[dict(id='x',path=str(base/'a'),max_bytes=100,reserve_free_bytes=0),dict(id='y',path=str(base/'a/b'),max_bytes=100,reserve_free_bytes=0)]
            cfg.write_text(json.dumps(dict(volumes=volumes)))
            with self.assertRaisesRegex(ValueError,'overlap'):load_volumes(cfg)
            with exclusive_lock(base/'lock',nonblocking=True):
                with self.assertRaisesRegex(RuntimeError,'another builder'):
                    with exclusive_lock(base/'lock',nonblocking=True):pass

    def test_xgboost_iterator_interface_and_streamed_metrics(self):
        class Data:
            def iter_batches(self,split):
                yield sparse.csr_matrix([[.1],[.9]],dtype=np.float32),np.array([0,1])
                yield sparse.csr_matrix([[.2],[.8]],dtype=np.float32),np.array([0,1])
        class Base:
            def __init__(self,cache_prefix):self.cache_prefix=cache_prefix
        with patch.dict('sys.modules',{'xgboost':types.SimpleNamespace(DataIter=Base)}):
            it=xgboost_iterator(Data(),'train','/tmp/fixture_cache')
            seen=[]
            capture=lambda **kw:seen.extend(kw['label'].tolist())
            self.assertTrue(it.next(capture));self.assertTrue(it.next(capture));self.assertFalse(it.next(capture))
            it.reset();self.assertTrue(it.next(capture));self.assertEqual(seen,[0,1,0,1,0,1])
        predict=lambda X:X.toarray().ravel()
        val=evaluate_stream(Data(),'val',predict,bins=10)
        test=evaluate_stream(Data(),'test',predict,threshold=val['threshold'],bins=10)
        self.assertEqual(test['f1'],1.0)
        self.assertEqual(test['roc_auc_binned'],1.0)
        self.assertEqual(test['pr_auc_binned'],1.0)

if __name__=='__main__':unittest.main()
