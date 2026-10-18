"""Frozen-model audit error semantics, feature collisions and source-line tracing."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'audit'),str(Path(__file__).resolve().parents[1]/'preprocess')]
from audit_xgb_run import classify_error, collision_stats, trace_raw, fixed_feature_f1_ceiling
from extract_error_rows import main as extract
from stratified_pipeline import identity


class AuditTests(unittest.TestCase):
    def test_threshold_ties_and_labels(self):
        self.assertEqual(classify_error(0,.5,.5),'FP')
        self.assertIsNone(classify_error(1,.5,.5))
        self.assertEqual(classify_error(1,.49,.5),'FN')
        self.assertIsNone(classify_error(0,.49,.5))

    def test_collision_lower_bound(self):
        groups=[{'counts':[3,2,0,0,9,1]},{'counts':[0,4,0,0,0,8]},{'counts':[0,0,0,0,2,3]}]
        self.assertEqual(collision_stats(groups,4),dict(mixed_signatures=2,rows_in_mixed_signatures=15,minimum_unavoidable_errors=3))
        self.assertEqual(collision_stats(groups,0)['minimum_unavoidable_errors'],2)

    def test_empirical_f1_oracle_matches_exhaustive_choices(self):
        import itertools
        pairs=[(9,1),(2,3),(0,4),(7,0)]
        groups=[dict(counts=list(pair)) for pair in pairs]
        positives=sum(p for b,p in pairs)
        scores=[]
        for choices in itertools.product((0,1),repeat=len(pairs)):
            tp=sum(p*c for (b,p),c in zip(pairs,choices))
            fp=sum(b*c for (b,p),c in zip(pairs,choices))
            scores.append(2*tp/(positives+tp+fp))
        self.assertAlmostEqual(fixed_feature_f1_ceiling(groups,positives,0)['f1'],max(scores))

    def test_raw_resume_and_complete_export(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            base=Path(tmp);source=base/'raw.json.gz'
            with gzip.open(source,'wt') as h:
                for n in range(5):h.write(json.dumps(dict(label=n%2,event=n))+'\n')
            sources={'id':dict(source_id='id',source=identity(source))}
            work=base/'work';work.mkdir()
            rows=trace_raw({'id':{2,5}},sources,work)
            self.assertEqual([r['record']['event'] for r in rows],[1,4])
            with patch('audit_xgb_run.gzip.open',side_effect=AssertionError('should resume')):
                self.assertEqual(rows,trace_raw({'id':{2,5}},sources,work))
            inputs=base/'inputs';inputs.mkdir()
            manifest=inputs/'manifest.json';manifest.write_text(json.dumps(dict(sources=list(sources.values()))))
            errors=inputs/'errors.jsonl';errors.write_text(json.dumps(dict(source_id='id',source_line=2,label=1,split='test'))+'\n')
            extract(['--errors',str(errors),'--manifest',str(manifest),'--output-dir',str(base/'out')])
            row=json.loads((base/'out/test_all_errors_raw.jsonl').read_text())
            self.assertEqual(row['raw_event'],dict(label=1,event=1))
            with self.assertRaisesRegex(ValueError,'outside source'):
                extract(['--errors',str(errors),'--manifest',str(manifest),'--output-dir',str(inputs/'forbidden')])

    def test_changed_raw_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'raw.json.gz';source.write_bytes(b'a')
            sources={'id':dict(source_id='id',source=identity(source))};source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'identity changed'):trace_raw({'id':{1}},sources,base)


if __name__=='__main__':unittest.main()
