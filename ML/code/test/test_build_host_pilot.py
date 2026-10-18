"""Pilot sampling, corrected-label reconciliation, and checkpoint regression tests."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io
import numpy as np
from scipy import sparse
from build_host_pilot import process, main
from ecar_tokenizer import tokenize_record, flatten_tokens
from ML.code.test.test_build_vocab import event, write_gzip

class PilotTests(unittest.TestCase):
    def setup_data(self, base):
        rows = []
        for i in range(101):
            row = event(host='sysclient0051', label=int(i == 100))
            row.update(id=f'event-{i}', timestamp='2019-09-25T12:00:00-04:00')
            rows.append(row)
        source = write_gzip(base / 'input', rows, day='2019-09-25', host='sysclient0051')
        gt = base / 'reference.json.gz'
        with gzip.open(gt, 'wt') as handle:
            handle.write(json.dumps(rows[-1]) + '\n')
        entry = dict(path=str(source), reference=str(gt), split='test', scenario=3, benign_quota=10)
        vocab = {t:i for i,t in enumerate(sorted(set(flatten_tokens(tokenize_record(rows[0])[0]))))}
        return entry, vocab, rows

    def test_eof_selection_resume_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            entry, vocab, rows = self.setup_data(base)
            results = [process(entry, vocab, base / f'checkpoint{i}', 4, 42) for i in (1,2)]
            selections = []
            for result in results:
                self.assertEqual(result['stats']['label_0'],10)
                self.assertEqual(result['stats']['label_1'],1)
                selected = []
                for chunk in result['chunks']:
                    self.assertEqual(sparse.load_npz(Path(result['directory']) / (chunk['stem']+'.npz')).shape[1],len(vocab))
                    selected += [json.loads(line) for line in (Path(result['directory']) / (chunk['stem']+'.jsonl')).read_text().splitlines()]
                selections.append(selected)
                self.assertIn(101,[row['source_line'] for row in selected])
                self.assertTrue(any(row['source_line']>11 for row in selected if row['label']==0))
            self.assertEqual(selections[0],selections[1])
            self.assertTrue(process(entry,vocab,base/'checkpoint1',4,42)['resumed'])
            chunk = Path(results[0]['directory']) / (results[0]['chunks'][0]['stem']+'.npz')
            chunk.write_bytes(b'bad')
            self.assertFalse(process(entry,vocab,base/'checkpoint1',4,42)['resumed'])

    def test_label_disagreement_and_missing_reference_event_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            entry, vocab, rows = self.setup_data(base)
            rows[-1]['label'] = 0
            write_gzip(base/'input', rows, day='2019-09-25',host='sysclient0051')
            with self.assertRaisesRegex(ValueError,'disagrees'):
                process(entry,vocab,base/'checkpoint',4,42)
            write_gzip(base/'input', rows[:-1], day='2019-09-25',host='sysclient0051')
            with self.assertRaisesRegex(ValueError,'missing from source'):
                process(entry,vocab,base/'checkpoint',4,42)

    def test_main_publishes_only_train_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            test, vocab, rows = self.setup_data(base)
            for row in rows:
                row['hostname'] = 'sysclient0201'
                row['id'] = 'train-' + row['id']
            source = write_gzip(base/'train', rows, day='2019-09-25', host='sysclient0201')
            reference = base/'train_reference.json.gz'
            with gzip.open(reference,'wt') as handle:
                handle.write(json.dumps(rows[-1])+'\n')
            train = dict(test, path=str(source), reference=str(reference), split='train', scenario=2)
            out = base/'matrix'
            with patch('build_host_pilot.make_plan', return_value=[train,test]), patch('build_host_pilot.load_vocabulary', return_value=(vocab, {'vocabulary_sha256':'fixture'})), contextlib.redirect_stdout(io.StringIO()):
                main(['--output-dir',str(out),'--workers','1','--chunk-rows','4'])
            meta = json.loads((out/'split_metadata.json').read_text())
            self.assertEqual(set(meta['splits']), {'train','test'})
            self.assertFalse((out/'X_val.npz').exists())
            for split in ('train','test'):
                self.assertEqual(set(np.load(out/f'y_{split}.npy')), {0,1})
                self.assertTrue(np.all(sparse.load_npz(out/f'X_{split}.npz').data == 1))

if __name__ == '__main__':
    unittest.main()
