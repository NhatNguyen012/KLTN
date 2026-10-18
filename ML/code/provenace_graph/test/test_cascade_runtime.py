import sys
import unittest
import json
import pickle
import tempfile
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'model'))
from cascade_runtime import choose, counts, load_host_model, metrics, policies, predictions

class CascadeRuntimeTest(unittest.TestCase):
    def test_validation_uses_all_routed_rows_and_fallback(self):
        ml = np.array([.05, .4, .8, .995])
        graph = np.array([np.nan, .9, np.nan, np.nan])
        p = dict(mode='cascade', low=.1, high=.99, graph=.7, baseline_threshold=.94)
        np.testing.assert_array_equal(predictions(ml, graph, p), [False, True, False, True])
        c = counts(np.array([0, 0, 1, 1]), predictions(ml, graph, p))
        self.assertEqual(metrics(c)['confusion'], dict(tp=1, fp=1, fn=1, tn=1))

    def test_rf_loader_returns_positive_class_probability(self):
        import sklearn
        from sklearn.ensemble import RandomForestClassifier
        from scipy import sparse
        x = sparse.csr_matrix([[0, 1], [1, 0], [0, 0], [1, 1]])
        y = np.array([0, 1, 0, 1])
        model = RandomForestClassifier(n_estimators=4, random_state=1).fit(x, y)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / 'models').mkdir()
            (bundle / 'models/rf_model.pkl').write_bytes(pickle.dumps(model))
            (bundle / 'bundle_manifest.json').write_text(json.dumps({
                'model_identities': {'rf': {'library_version': sklearn.__version__}}}))
            predict, version = load_host_model(bundle, 'rf')
            self.assertEqual(version, sklearn.__version__)
            np.testing.assert_allclose(predict(x), model.predict_proba(x)[:, 1])

    def test_xgb_loader_predicts_sparse_rows(self):
        import xgboost as xgb
        from scipy import sparse
        x = sparse.csr_matrix([[0, 1], [1, 0], [0, 0], [1, 1]], dtype=np.float32)
        y = np.array([0, 1, 0, 1])
        model = xgb.train({'objective': 'binary:logistic', 'nthread': 1},
                          xgb.DMatrix(x, label=y), num_boost_round=2)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / 'models').mkdir()
            model.save_model(str(bundle / 'models/xgb_model.ubj'))
            predict, version = load_host_model(bundle, 'xgb')
            self.assertEqual(version, xgb.__version__)
            np.testing.assert_allclose(predict(x), model.inplace_predict(x))

    def test_unknown_host_model_rejected(self):
        with self.assertRaises(ValueError):
            load_host_model(Path('.'), 'unknown')

    def test_baseline_wins_tie(self):
        opts = policies(.94)
        c = np.tile(np.array([1, 0, 0, 9]), (len(opts), 1))
        self.assertEqual(choose(opts, c)['mode'], 'baseline')

if __name__ == '__main__': unittest.main()
