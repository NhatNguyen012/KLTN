import json
import hashlib
from pathlib import Path
import numpy as np

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()

MANIFEST = Path('code/output/host_ml/model_input/manifest.json')
data = json.loads(MANIFEST.read_text())

def sample_plan(data, target_rows=None, neg_per_pos=30, seed=1):
    info = data['splits']['train']
    rng = np.random.default_rng(seed)
    remaining = info['label_0']
    needed = None if target_rows is None else target_rows - info['label_1']
    keep_p = min(1.0, neg_per_pos * info['label_1'] / info['label_0'])
    entries = []
    for index, part in enumerate(data['shards']):
        if part['split'] != 'train':
            continue
        n = part['label_0']
        if target_rows is None:
            state = rng.bit_generator.state
            k = int(np.count_nonzero(rng.random(n) < keep_p))
        else:
            raise NotImplementedError
        # NumPy random state contains tuples/arrays that are not JSON serializable directly
        # Let's fix the serialization of rng_state
        if isinstance(state, dict):
            # The state dict from PCG64 has 'state' (dict) and 'bit_generator' (str)
            # Need to make sure it's serialized exactly as in Kaggle
            pass
        entries.append(dict(index=index, negatives=k, rng_state=state))
    rows = sum(e['negatives'] + data['shards'][e['index']]['label_1'] for e in entries)
    return dict(method='random_negative_undersampling',
                seed=seed, target_rows=target_rows, neg_per_pos=neg_per_pos, keep_probability=keep_p,
                rows=rows, positives=info['label_1'], negatives=rows-info['label_1'], entries=entries)

# Note: numpy rng state contains integers that might be too large for standard JS/JSON or might be serialized differently
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

def digest2(obj):
    return hashlib.sha256(json.dumps(obj, cls=NumpyEncoder, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()

plan = sample_plan(data, target_rows=None, neg_per_pos=30, seed=1)

config = dict(format=data.get('format'), schema=data.get('schema'))
print("config:", config)
sample_id = digest2(dict(config=config, plan=plan))
print("Generated sample_id:", sample_id)

# Calculate nnz
data_shards = data['shards']
nnz = 0
for entry in plan['entries']:
    shard = data_shards[entry['index']]
    # Wait, the number of non-zeros depends on WHICH negative rows were kept!
    # I can't calculate nnz without decoding the shards!

