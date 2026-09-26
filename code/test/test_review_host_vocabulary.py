"""Protect semantic boundaries in the frozen-vocabulary review mapping."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'audit'))
from review_host_vocabulary import canonical_token


class VocabularyReviewTests(unittest.TestCase):
    def test_aliases_and_dynamic_ids(self):
        self.assertEqual(canonical_token('command_line::structure::switch=/q'),
                         ('command_line::syntax::switch=/q', 'canonical_alias'))
        self.assertEqual(canonical_token('command_line::launcher=cmd.exe'),
                         ('command_line::anchor::launcher=cmd.exe', 'canonical_alias'))
        self.assertEqual(canonical_token('command_line::native::usgthrfltpipemssgthrpipe117_'),
                         ('command_line::native::usgthrfltpipemssgthrpipe_number_value_', 'dynamic_literal'))
        self.assertEqual(canonical_token('command_line::cmd::0xdeadbeef'),
                         ('command_line::cmd::hex_value', 'dynamic_literal'))

    def test_scopes_roles_and_unfamiliar_anchors_survive(self):
        for token in ('module_path::basename=kernel32.dll', 'file_path::system_stem=kernel32',
                      'command_line::anchor::command=cmd.exe', 'command_line::cmd::strange_name',
                      'command_line::native::exe', 'shell::parameter_role=path->file'):
            self.assertEqual(canonical_token(token), (token, 'retain'))


if __name__ == '__main__':
    unittest.main()
