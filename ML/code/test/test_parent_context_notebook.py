"""Contract of the parent-context notebook, without local model training."""
import json
from pathlib import Path
import unittest

CODE = Path(__file__).resolve().parents[1]

class ParentNotebookTests(unittest.TestCase):
    def test_cells_compile_and_input_is_guarded(self):
        n = json.loads((CODE/'kaggle/notebooks/lgbm.ipynb').read_text())
        sources = [''.join(c['source']) for c in n['cells'] if c['cell_type']=='code']
        for s in sources: compile(s, 'notebook', 'exec')
        setup = next(s for s in sources if 'BEGIN EMBEDDED RUNTIME' in s)
        self.assertIn("_input_meta.get('context_policy')", setup)
        self.assertIn("_input_meta.get('split_sha256')", setup)
        self.assertIn('parent-context-seed02-', setup)
        self.assertFalse(any('from relational_sage' in s or 'from ego import' in s for s in sources))
        evaluation = next(s for s in sources if "with phase('full validation evaluation')" in s)
        self.assertIn("threshold=validation['threshold']", evaluation)

if __name__ == '__main__': unittest.main()
