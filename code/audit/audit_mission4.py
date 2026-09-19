#!/usr/bin/env python3
import json
import numpy as np
import scipy.sparse as sparse
from pathlib import Path
import hashlib
import multiprocessing as mp
from collections import defaultdict
import sys

sys.path.insert(0, 'code/kaggle')
sys.path.insert(0, 'code')
try:
    import host_shards
    HostShardDataset = host_shards.HostShardDataset
except ImportError:
    pass

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'
TEST_ERRORS_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/diagnostics/test_errors.json'
METRICS_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/xgb_metrics.json'
OUTPUT_DIR = PROJECT_ROOT / 'code/output/audits/mission4'

data = HostShardDataset(MANIFEST_PATH)
meta = data.meta
vocab_size = meta['vocab_size']

def sample_plan(data_meta, seed=1):
    info = data_meta['splits']['train']
    rng = np.random.default_rng(seed)
    # The negative sampling ratio used in Kaggle was 30
    keep_p = min(1.0, 30 * info['label_1'] / info['label_0'])
    entries = []
    for index, part in enumerate(data_meta['shards']):
        if part['split'] != 'train':
            continue
        n = part['label_0']
        state = rng.bit_generator.state
        if isinstance(state, dict):
            pass
        k = int(np.count_nonzero(rng.random(n) < keep_p))
        entries.append(dict(index=index, negatives=k, rng_state=state))
    return keep_p, entries

def process_shard(args):
    entry, keep_p = args
    shard = meta['shards'][entry['index']]
    
    path = Path('code/output/host_ml/model_input/volumes') / shard['volume'] / shard['path']
    if not path.exists():
        raise ValueError(f"Shard not found: {path}")
    X, y, lines = host_shards.decode_shard(path, vocab_size, shard)
    
    neg = np.flatnonzero(y == 0)
    rng = np.random.default_rng()
    rng.bit_generator.state = entry['rng_state']
    kept_neg = neg[rng.random(len(neg)) < keep_p]
    
    pos = np.flatnonzero(y == 1)
    
    # We want to extract the signatures for all selected rows
    # X is CSR format
    local_sigs = defaultdict(lambda: [0, 0, []]) # benign_count, mal_count, list of raw mappings
    
    host = shard.get('host', 'unknown')
    day = shard.get('day', 'unknown')
    
    def add_to_sigs(row_idx, label):
        start = X.indptr[row_idx]
        end = X.indptr[row_idx+1]
        sig = tuple(X.indices[start:end])
        
        counts = local_sigs[sig]
        if label == 0:
            counts[0] += 1
        else:
            counts[1] += 1
            
        # Keep up to 5 examples per signature for A/B analysis
        if len(counts[2]) < 5:
            # stable mapping: (shard_index, host, day, source_line)
            counts[2].append((entry['index'], host, day, int(lines[row_idx])))
            
    for r in kept_neg:
        add_to_sigs(r, 0)
    for r in pos:
        add_to_sigs(r, 1)
        
    return dict(local_sigs)

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Generating sampling plan...")
    keep_p, entries = sample_plan(meta)
    
    print("Scanning 34,700 TRAIN shards to build canonical selected signatures...")
    args = [(e, keep_p) for e in entries]
    
    global_sigs = defaultdict(lambda: [0, 0, []])
    
    with mp.Pool(16) as p:
        for i, local_sigs in enumerate(p.imap_unordered(process_shard, args)):
            if (i+1) % 1000 == 0:
                print(f"  Processed {i+1} shards...")
            for sig, counts in local_sigs.items():
                g = global_sigs[sig]
                g[0] += counts[0]
                g[1] += counts[1]
                if len(g[2]) < 5:
                    g[2].extend(counts[2])
                    g[2] = g[2][:5]
                    
    print(f"Total unique signatures in sampled TRAIN: {len(global_sigs)}")
    
    # Write to a checkpoint so we don't have to rescan if we need to do NN search
    import pickle
    with open(OUTPUT_DIR / 'train_signatures.pkl', 'wb') as f:
        pickle.dump(dict(global_sigs), f)
        
    print("Done. Wrote checkpoint.")

if __name__ == '__main__':
    main()
