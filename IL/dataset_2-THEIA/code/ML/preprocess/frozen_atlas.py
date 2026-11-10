"""Reconstruct the Task-1 predictor; a residual booster is not a standalone model."""
import hashlib
import json
from pathlib import Path
import numpy as np
from scipy import sparse
from scipy.special import expit


class FrozenAtlasModel:
    def __init__(self, residual_path):
        import lightgbm as lgb
        residual_path = Path(residual_path)
        config_path = residual_path.parent / 'composition.json'
        config = json.loads(config_path.read_text())
        def verified(entry):
            p = (config_path.parent / entry['path']).resolve()
            if hashlib.sha256(p.read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError(f'Frozen model hash mismatch: {p}')
            return p
        anchor = verified(config['anchor'])
        residual = verified(config['residual'])
        if residual != residual_path.resolve():
            raise ValueError('Residual path differs from composition manifest')
        self.anchor = lgb.Booster(model_file=str(anchor))
        self.residual = lgb.Booster(model_file=str(residual))
        self.alpha = float(config['alpha'])
        self.composition_sha256 = hashlib.sha256(config_path.read_bytes()).hexdigest()

    def num_feature(self):
        return self.residual.num_feature()

    def num_trees(self):
        return self.anchor.num_trees() + self.residual.num_trees()

    @staticmethod
    def align(X, width):
        if X.shape[1] >= width:
            return X[:, :width]
        return sparse.hstack([X, sparse.csr_matrix((X.shape[0], width-X.shape[1]))], format='csr')

    def predict(self, X, raw_score=False, num_threads=1, **kwargs):
        z = self.alpha * self.anchor.predict(self.align(X, self.anchor.num_feature()),
                                             raw_score=True, num_threads=num_threads)
        z += self.residual.predict(self.align(X, self.residual.num_feature()),
                                   raw_score=True, num_threads=num_threads)
        return z if raw_score else expit(z)
