"""Real synthetic index -> split -> two-class vocab -> shared sparse matrices."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
from scipy import sparse
from build_vocab import main as build_vocab
from build_matrix import main as build_matrix
from package_kaggle_input import main as package
from ecar_tokenizer import tokenize_record, flatten_tokens
from pipeline_contract import load_vocabulary, load_training_bundle
from stratified_pipeline import (index_main,split_main,load_manifest,split_rows,quota,
                                 file_hash,index_file,identity)
from test_build_vocab import event,write_gzip

class SharedSplitTests(unittest.TestCase):
    def dataset(self,base):
        benign,attack=base/'benign',base/'attack'
        for root,day,malicious in [(benign,'2019-09-16',False),(attack,'2019-09-23',True)]:
            rows=[]
            for i in range(80):
                word=('malicious' if malicious else 'benign')+chr(97+i//26)+chr(97+i%26)
                row=event(word=word,label=int(malicious and i%2==0))
                row.update(id=f'{day}-{i}',timestamp=day+'T12:00:00-04:00')
                rows.append(row)
            rows.append(dict(event(),object='FLOW'))
            write_gzip(root,rows,day=day)
        return benign,attack

    def test_complete_pipeline_train_only_features_exact_counts_and_parallel_split(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp); benign,attack=self.dataset(base)
            idx=base/'index'; sp=base/'split'
            index_main(['--benign-root',str(benign),'--malicious-root',str(attack),'--output-dir',str(idx),'--workers','2'])
            for workers,name in [(1,'split'),(2,'split_parallel')]:
                split_main(['--index',str(idx/'manifest.json'),'--output-dir',str(base/name),'--workers',str(workers),'--seed','01'])
            manifest,sha=load_manifest(sp/'manifest.json','host_random_split')
            other,_=load_manifest(base/'split_parallel/manifest.json','host_random_split')
            self.assertEqual(manifest['counts'],{'train':{'label_0':90,'label_1':30},'val':{'label_0':12,'label_1':4},'test':{'label_0':18,'label_1':6}})
            for e,f in zip(manifest['entries'],other['entries']):
                with gzip.open(sp/e['artifact'],'rb') as a,gzip.open(base/'split_parallel'/f['artifact'],'rb') as b:
                    self.assertEqual(a.read(),b.read())
            fitted=base/'fit';out=base/'matrix'
            build_vocab(['--split',str(sp/'manifest.json'),'--workers','2','--output',str(fitted/'vocab.json'),'--metadata-output',str(fitted/'vocab_metadata.json')])
            vocab,meta=load_vocabulary(fitted/'vocab.json',fitted/'vocab_metadata.json',split_sha256=sha)
            self.assertEqual(meta['fit_counts'],{'label_0':90,'label_1':30})
            derived=base/'fit_derived'
            build_vocab([
                '--split', str(sp/'manifest.json'),
                '--selection-source-vocab', str(fitted/'vocab.json'),
                '--selection-source-metadata', str(fitted/'vocab_metadata.json'),
                '--output', str(derived/'vocab.json'),
                '--metadata-output', str(derived/'vocab_metadata.json'),
                '--min-frequency', '2', '--min-document-frequency', '2',
                '--max-vocab-size', '20', '--rank-by', 'document-frequency',
            ])
            derived_vocab,derived_meta=load_vocabulary(
                derived/'vocab.json', derived/'vocab_metadata.json', split_sha256=sha)
            self.assertEqual(len(derived_vocab),20)
            self.assertFalse(derived_meta['checkpoint']['telemetry_rescanned'])
            self.assertEqual(derived_meta['frequency_policy']['min_document_frequency'],2)
            tokens={1:set(),2:set(),3:set()}; assigned={s:set() for s in (1,2,3)}
            for e in manifest['entries']:
                for code,line,row in split_rows(e,sp):
                    assigned[code].add((e['source']['path'],line))
                    tokens[code].update(flatten_tokens(tokenize_record(row)[0]))
            self.assertFalse(set(vocab) & ((tokens[2]|tokens[3])-tokens[1]))
            self.assertTrue(any('malicious' in token for token in vocab))
            self.assertTrue(any('benign' in token for token in vocab))
            build_matrix(['--split',str(sp/'manifest.json'),'--vocab',str(fitted/'vocab.json'),'--output-dir',str(out),'--workers','2','--chunk-rows','7'])
            m=json.loads((out/'split_metadata.json').read_text())
            self.assertEqual(m['split_sha256'],sha)
            for code,s in enumerate(('train','val','test'),1):
                y=np.load(out/f'y_{s}.npy'); x=sparse.load_npz(out/f'X_{s}.npz')
                self.assertEqual(x.shape,(len(assigned[code]),len(vocab)))
                self.assertEqual(int(y.sum()),manifest['counts'][s]['label_1'])
                self.assertTrue(np.all(x.data==1))
                side=[json.loads(l) for l in (out/f'row_sidecar_{s}.jsonl').read_text().splitlines()]
                self.assertEqual({(r['source_file'],r['source_line']) for r in side},assigned[code])
            with self.assertRaisesRegex(ValueError,'exact shared split'):
                load_vocabulary(fitted/'vocab.json',fitted/'vocab_metadata.json',split_sha256='wrong')
            with contextlib.redirect_stderr(io.StringIO()):
                package(['--input-dir',str(fitted),'--matrix-dir',str(out),'--output-dir',str(base/'package')])
            _, provenance = load_training_bundle(base/'package')
            self.assertEqual(provenance['split_sha256'],sha)
            artifact=base/'package/matrix/y_val.npy'
            artifact.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'artifact checksum'):
                load_training_bundle(base/'package')
            mask=sp/manifest['entries'][0]['artifact']
            mask.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'checksum'):
                load_manifest(sp/'manifest.json','host_random_split')

    def test_checkpoint_corruption_source_change_and_invalid_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); benign,attack=self.dataset(base)
            path=next(attack.rglob('*.gz')); work=base/'work';work.mkdir()
            entry=dict(source=identity(path),benign=False)
            result=index_file(entry,work)
            artifact=work/result['artifact']; artifact.write_bytes(b'corrupt')
            repaired=index_file(entry,work)
            self.assertEqual(file_hash(artifact),repaired['sha256'])
            row=event(label=None)
            path=write_gzip(attack,[row],day='2019-09-23')
            with self.assertRaisesRegex(ValueError,'corrected integer'):
                index_file(dict(source=identity(path),benign=False),work)

    def test_quotas_preserve_counts(self):
        for n in range(1000):
            q=quota(n)
            self.assertEqual(sum(q),n)
            self.assertTrue(all(abs(a-n*r)<1 for a,r in zip(q,(.75,.10,.15))))

    def test_cross_host_event_preserved_and_audited(self):
        from stratified_pipeline import split_file, matrix_file
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); work=base/'work'; work.mkdir()
            row=event(host='sysclient0501',label=1)
            source=write_gzip(base/'attack',[row],day='2019-09-24',host='sysclient0503')
            entry=dict(source=identity(source),benign=False)
            result=index_file(entry,work)
            self.assertEqual(result['counts']['2'],1)
            self.assertEqual(result['counts']['hostname_differs_from_file'],1)
            assigned=split_file(result,{'1':[0,0,0],'2':[1,0,0]},work,work,1)
            parsed=list(split_rows(assigned,work))
            self.assertEqual(parsed[0][2]['hostname'],row['hostname'])
            vocab={t:i for i,t in enumerate(sorted(set(flatten_tokens(tokenize_record(row)[0]))))}
            parts=matrix_file(assigned,work,vocab,work,1)
            train=parts[0]
            side=json.loads((Path(train['directory'])/(train['chunks'][0]['stem']+'.jsonl')).read_text())
            self.assertEqual(side['host'],'sysclient0501')
            self.assertEqual(side['file_host'],'sysclient0503')
            self.assertEqual(side['label'],1)
            for invalid in [dict(row,hostname=None),None,dict(row,label=None)]:
                write_gzip(base/'attack',[invalid],day='2019-09-24',host='sysclient0503')
                with self.assertRaisesRegex(ValueError,r'sysclient0503.*:1:'):
                    index_file(dict(source=identity(source),benign=False),work)

    def test_empty_source_checkpoint_transforms_without_rows(self):
        from stratified_pipeline import split_file
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);work=base/'work';work.mkdir()
            source=write_gzip(base/'input',[],day='2019-09-23')
            indexed=index_file(dict(source=identity(source),benign=False),work)
            assigned=split_file(indexed,{'1':[0,0,0],'2':[0,0,0]},work,work,1)
            self.assertEqual(list(split_rows(assigned,work)),[])

if __name__=='__main__':unittest.main()
