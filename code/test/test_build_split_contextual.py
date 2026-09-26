"""Synthetic Option B selection through TRAIN vocabulary and lossless shards."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'preprocess'))
import build_split_contextual as contextual
from stratified_pipeline import index_main, load_manifest, split_rows, quota
from build_vocab import main as build_vocab
from build_model_input import main as build_input
from host_shards import HostShardDataset


class ContextualTests(unittest.TestCase):
    def fixture(self, base):
        for day, directory in [('2019-09-21','benign'),('2019-09-22','benign'),('2019-09-23','attack')]:
            folder = base/directory
            folder.mkdir(exist_ok=True)
            with gzip.open(folder/f'ecar-{day}-sysclient0001.json.gz','wt') as out:
                times = ['09:59:59','10:00:00','10:15:00','10:29:59','10:30:00'] if directory=='benign' else ['12:59:59']+['13:00:00']*20+['13:30:00']*20+['13:30:01']
                for i,time in enumerate(times):
                    row = dict(hostname='sysclient0001.systemia.com', timestamp=f'{day}T{time}-04:00',
                               object='PROCESS', action='CREATE', label=int(directory=='attack' and 1<=i<=40 and i%2==0),
                               properties=dict(image_path='cmd.exe',command_line='cmd.exe /c whoami'))
                    out.write(json.dumps(row)+'\n')
                out.write(json.dumps(dict(row,object='FLOW'))+'\n')
        index_main(['--benign-root',str(base/'benign'),'--malicious-root',str(base/'attack'),
                    '--output-dir',str(base/'index'),'--workers','1'])
        return ['--index',str(base/'index/manifest.json'),'--output-dir',str(base/'split')]

    def context(self):
        return patch.multiple(contextual, ATTACKED_HOSTS={'sysclient0001'},
            ATTACK_WINDOWS={('sysclient0001','2019-09-23'):('2019-09-23T13:00:00-04:00','2019-09-23T13:30:00-04:00')})

    def test_selection_resume_determinism_and_downstream(self):
        with tempfile.TemporaryDirectory() as tmp, self.context(), contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);args=self.fixture(base)
            contextual.main(args+['--dry-run'])
            self.assertFalse((base/'split').exists())
            original=contextual.select_file
            calls=[]
            def interrupted(*a):
                calls.append(1)
                if len(calls)==2: raise RuntimeError('interrupt')
                return original(*a)
            with patch.object(contextual,'select_file',side_effect=interrupted), self.assertRaises(RuntimeError):
                contextual.main(args)
            self.assertFalse((base/'split/manifest.json').exists())
            receipts=list(base.rglob('*.selection.json'));self.assertEqual(len(receipts),1)
            contextual.main(args)
            manifest,sha=load_manifest(base/'split/manifest.json','host_random_split')
            self.assertEqual([manifest['counts'][s]['label_0'] for s in ('train','val','test')],quota(26))
            self.assertEqual([manifest['counts'][s]['label_1'] for s in ('train','val','test')],quota(20))
            before=(base/'split/manifest.json').read_bytes();contextual.main(args)
            self.assertEqual(before,(base/'split/manifest.json').read_bytes())
            rows=[(e['day'],line,r['label']) for e in manifest['entries'] for _,line,r in split_rows(e,base/'split')]
            self.assertEqual(len(rows),46)
            self.assertEqual({line for day,line,_ in rows if day=='2019-09-21'},{2,3,4})
            contextual.main(args[:-1]+[str(base/'split2')])
            other,_=load_manifest(base/'split2/manifest.json','host_random_split')
            for a,b in zip(manifest['entries'],other['entries']):
                with gzip.open(base/'split'/a['artifact'],'rb') as x,gzip.open(base/'split2'/b['artifact'],'rb') as y:
                    self.assertEqual(x.read(),y.read())
            build_vocab(['--split',str(base/'split/manifest.json'),'--output',str(base/'vocab.json'),
                         '--metadata-output',str(base/'vocab_metadata.json'),'--workers','1'])
            meta=json.loads((base/'vocab_metadata.json').read_text())
            self.assertEqual(meta['fit_counts'],manifest['counts']['train'])
            config=base/'volumes.json'
            config.write_text(json.dumps(dict(volumes=[dict(id='test',path=str(base/'volume'),max_bytes=100000000,reserve_free_bytes=0)])))
            build_input(['--split',str(base/'split/manifest.json'),'--vocab',str(base/'vocab.json'),
                         '--vocab-metadata',str(base/'vocab_metadata.json'),'--output-dir',str(base/'shards'),
                         '--storage-config',str(config),'--workers','1'])
            data=HostShardDataset(base/'shards/manifest.json')
            self.assertEqual(sum(p['rows'] for p in data.meta['shards']),46)
            self.assertEqual((base/'shards/assets/split_manifest.json').read_bytes(),before)

    def test_stale_index_eligibility_outside_attack_and_boundary(self):
        with tempfile.TemporaryDirectory() as tmp, self.context(), contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);args=self.fixture(base)
            # A historical tokenizer hash is allowed only because raw eligibility
            # is checked again against every original index code during selection.
            p=base/'index/manifest.json';index=json.loads(p.read_text());index['tokenizer_sha256']={'old':'hash'};p.write_text(json.dumps(index))
            with patch.object(contextual,'ATTACK_WINDOWS',{('sysclient0001','2019-09-23'):('2019-09-23T13:00:00-04:00','2019-09-23T13:01:00-04:00')}):
                with self.assertRaisesRegex(ValueError,'malicious event outside'):
                    contextual.main(args)
            self.assertFalse((base/'split/manifest.json').exists())
            with patch.object(contextual, 'label_of', return_value=0):
                with self.assertRaisesRegex(ValueError, 'indexed label/eligibility'):
                    contextual.main(args)
            contextual.main(args)
            with self.assertRaisesRegex(ValueError,'outside source'):
                contextual.main(args[:-1]+[str(base/'index/forbidden'),'--dry-run'])
            with patch.object(contextual,'ATTACKED_HOSTS',{'sysclient0001','sysclient0002'}):
                with self.assertRaisesRegex(ValueError,'missing baseline'):
                    contextual.main(args+['--dry-run','--require-complete-baseline'])

    def test_missing_attack_is_fatal(self):
        with self.context():
            with self.assertRaisesRegex(ValueError, 'required attack'):
                contextual.select_entries({'entries': []})

    def test_timestamp_offsets_and_naive_rejection(self):
        self.assertEqual(contextual._parse_ts('2019-09-21T14:00:00Z'),contextual._parse_ts('2019-09-21T10:00:00-0400'))
        with self.assertRaises(ValueError): contextual._parse_ts('2019-09-21T10:00:00')


if __name__=='__main__': unittest.main()
