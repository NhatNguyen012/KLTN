import numpy as np
import json
import hashlib

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

rng = np.random.default_rng(1)
state = rng.bit_generator.state
print(json.dumps(state, sort_keys=True, separators=(',', ':')))
print(digest(state))
