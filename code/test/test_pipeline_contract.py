"""Output boundaries and frozen vocabulary validation, using temporary inputs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pipeline_contract import DATA_ROOT_NAMES, TRAIN_BENIGN_DAYS, code_hashes, load_vocabulary, validate_output_path, validate_fit_input_path


class ContractTests(unittest.TestCase):
    def test_all_roots_and_symlinks_are_protected(self):
        with tempfile.TemporaryDirectory() as tmp, patch('pipeline_contract.PROJECT_ROOT', Path(tmp)):
            base = Path(tmp)
            for name in DATA_ROOT_NAMES:
                (base / name).mkdir()
                with self.assertRaisesRegex(ValueError, 'outside source'):
                    validate_output_path(base / name / 'generated.json')
            (base / 'alias').symlink_to(base / 'bro', target_is_directory=True)
            with self.assertRaises(ValueError):
                validate_output_path(base / 'alias' / 'cache')
            self.assertEqual(validate_output_path(base / 'out.json'), base / 'out.json')
            for name in DATA_ROOT_NAMES[1:]:
                with self.assertRaisesRegex(ValueError, 'fit cannot include'):
                    validate_fit_input_path(base / name / 'innocent-filename.json.gz')

    def test_frozen_identity_checksum_and_train_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            vocab, meta = Path(tmp) / 'vocab.json', Path(tmp) / 'vocab_metadata.json'
            vocab.write_text('{"token": 0}')
            data = {'vocabulary_sha256': hashlib.sha256(vocab.read_bytes()).hexdigest(),
                    'source_sha256': code_hashes(), 'scan': {'days': {'2019-09-16': 1}}}
            meta.write_text(json.dumps(data))
            self.assertEqual(load_vocabulary(vocab, meta, training_days=TRAIN_BENIGN_DAYS)[0], {'token': 0})
            data['scan']['days']['2019-09-21'] = 1
            meta.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'held-out'):
                load_vocabulary(vocab, meta, training_days=TRAIN_BENIGN_DAYS)
            data['source_sha256']['command_syntax.py'] = 'old'
            meta.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'incompatible'):
                load_vocabulary(vocab, meta)
            vocab.write_text('{"different": 0}')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                load_vocabulary(vocab, meta)


if __name__ == '__main__':
    unittest.main()
