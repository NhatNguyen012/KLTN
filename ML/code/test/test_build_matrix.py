"""Synthetic end-to-end tests for counts, safe publication and checkpoint reuse."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np
from scipy import sparse

from build_matrix import main, _process_file
from build_vocab import main as build_vocab
from package_kaggle_input import main as package
from ML.code.test.test_build_vocab import event, write_gzip


class MatrixTests(unittest.TestCase):
    def setup_data(self, base):
        benign, malicious, fitted = base / 'benign', base / 'malicious', base / 'fitted'
        write_gzip(benign, [event(), event()])
        write_gzip(benign, [event()], day='2019-09-21')
        write_gzip(benign, [event()], day='2019-09-22')
        for host in ('sysclient0001', 'sysclient0401', 'sysclient0451'):
            write_gzip(malicious, [event(host=host, label=1)], day='2019-09-23', host=host)
        with contextlib.redirect_stderr(io.StringIO()):
            build_vocab(['--roots', str(benign), '--fit-purpose', 'training', '--read-to-eof', '--workers', '1',
                         '--output', str(fitted / 'vocab.json'), '--metadata-output', str(fitted / 'vocab_metadata.json')])
        return benign, malicious, fitted

    def test_counts_binary_sidecars_and_parallel_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            benign, malicious, fitted = self.setup_data(base)
            vocab = json.loads((fitted / 'vocab.json').read_text())
            for workers in (1, 2):
                out = base / f'out{workers}'
                with contextlib.redirect_stdout(io.StringIO()):
                    main(['--benign-root', str(benign), '--malicious-root', str(malicious),
                          '--vocab', str(fitted / 'vocab.json'), '--output-dir', str(out),
                          '--workers', str(workers), '--chunk-rows', '1', '--representation', 'both'])
                for split in ('train', 'val', 'test'):
                    binary = sparse.load_npz(out / f'X_{split}.npz')
                    count = sparse.load_npz(out / f'X_{split}_count.npz')
                    column = vocab['command_line::cmd::repeatword']
                    self.assertTrue(np.all(binary[:, column].toarray() == 1))
                    self.assertTrue(np.all(count[:, column].toarray() == 2))
                    self.assertEqual(set(np.load(out / f'y_{split}.npy')), {0, 1})
                    sidecars = [json.loads(line) for line in (out / f'row_sidecar_{split}.jsonl').read_text().splitlines()]
                    self.assertEqual([r['row_id'] for r in sidecars], list(range(binary.shape[0])))
                    self.assertTrue(all('source_line' in r for r in sidecars))
                    if workers == 2:
                        self.assertEqual((count != sparse.load_npz(base / 'out1' / f'X_{split}_count.npz')).nnz, 0)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(package(['--input-dir', str(fitted), '--matrix-dir', str(base / 'out1'),
                                          '--output-dir', str(base / 'package')]), 0)
            for name in ('command_syntax.py', 'pipeline_contract.py', 'evaluation_metrics.py', 'train_rf.py'):
                self.assertTrue((base / 'package' / name).is_file())
            with self.assertRaisesRegex(ValueError, 'already exists'):
                package(['--output-dir', str(base / 'package')])

    def test_failed_input_preserves_checkpoints_and_no_final_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            benign, malicious, fitted = self.setup_data(base)
            broken = write_gzip(malicious, ['invalid json\n'], day='2019-09-23', host='sysclient0499')
            out = base / 'out'
            args = ['--benign-root', str(benign), '--malicious-root', str(malicious), '--vocab', str(fitted / 'vocab.json'),
                    '--output-dir', str(out), '--workers', '1', '--chunk-rows', '1']
            with self.assertRaises(ValueError):
                main(args)
            self.assertFalse(out.exists())
            self.assertTrue(list(base.glob('.out.checkpoints/*/*/manifest.json')))
            write_gzip(malicious, [event(host='sysclient0499', label=1)], day='2019-09-23', host='sysclient0499')
            with contextlib.redirect_stdout(io.StringIO()):
                main(args)
            meta = json.loads((out / 'split_metadata.json').read_text())
            self.assertGreater(meta['checkpoint']['resumed_files'], 0)
            before = (out / 'X_train.npz').read_bytes()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                main(args)
            self.assertEqual((out / 'X_train.npz').read_bytes(), before)

    def test_chunk_corruption_forces_rescan_and_missing_attack_label_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_gzip(base / 'input', [event(), event()])
            from ecar_tokenizer import tokenize_record, flatten_tokens
            vocab = {t: i for i, t in enumerate(sorted(set(flatten_tokens(tokenize_record(event())[0]))))}
            first = _process_file(source, vocab, False, 0, 1, base / 'checkpoint', True)
            (Path(first['directory']) / next(iter(first['chunks'][0]['sha256']))).write_bytes(b'corrupt')
            second = _process_file(source, vocab, False, 0, 1, base / 'checkpoint', True)
            self.assertFalse(second['resumed'])
            self.assertEqual(second['stats']['eligible_records'], 2)
            row = event()
            del row['label']
            attack = write_gzip(base / 'attack', [row], day='2019-09-23')
            with self.assertRaisesRegex(ValueError, 'explicit 0/1'):
                _process_file(attack, vocab, True, 0, 1, base / 'checkpoint', True)


if __name__ == '__main__':
    unittest.main()
