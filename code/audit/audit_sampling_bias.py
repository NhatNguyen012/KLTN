import json
import numpy as np
import scipy.sparse as sparse
from pathlib import Path
import multiprocessing as mp
import sys
import csv

sys.path.insert(0, 'code/preprocess')
sys.path.insert(0, 'code/kaggle')
sys.path.insert(0, 'code')
import host_shards

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'
VOCAB_PATH = PROJECT_ROOT / 'code/output/host_ml/vocab.json'
TEST_ERRORS_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/diagnostics/test_errors.json'
OUTPUT_CSV = PROJECT_ROOT / 'code/output/audits/mission4/benign_sampling_representativeness.csv'

def process_shard(args):
    shard_dict, target_indices, keep_p, seed_state, width = args
    
    path = Path('code/output/host_ml/model_input/volumes') / shard_dict['volume'] / shard_dict['path']
    if not path.exists():
        return None
        
    try:
        X, y, _ = host_shards.decode_shard(path, width)
    except Exception as e:
        print(f"Error decoding {path}: {e}")
        return None
        
    neg = np.flatnonzero(y == 0)
    
    rng = np.random.default_rng()
    rng.bit_generator.state = seed_state
    kept_neg = neg[rng.random(len(neg)) < keep_p]
    
    # We want counts for targets in FULL neg, and SAMPLED neg
    # target_indices is a list of sets of column indices
    
    counts = []
    
    # Convert X to CSC or just iterate. Since X is CSR, checking if specific columns exist is fast if we just dot product.
    # Actually, we can just build an indicator matrix for the targets and dot product.
    # Or just iterate the target sets.
    
    # For each target set:
    for target_set in target_indices:
        # A row has the target if ALL indices in target_set are present.
        # We can sum the columns for target_set. If the sum == len(target_set), it's a match.
        target_list = list(target_set)
        
        # Extract only the target columns
        X_target = X[:, target_list]
        # Sum across the columns
        row_sums = X_target.sum(axis=1).A1
        
        # Match mask
        match_mask = (row_sums == len(target_list))
        
        # Full count (only in neg)
        full_count = np.sum(match_mask[neg])
        # Sampled count
        sampled_count = np.sum(match_mask[kept_neg])
        
        counts.append((full_count, sampled_count))
        
    return counts, len(neg), len(kept_neg)

def main():
    print("Loading vocab and manifest...")
    with open(VOCAB_PATH) as f:
        vocab = json.load(f)
        
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
        
    with open(TEST_ERRORS_PATH) as f:
        test_errors = json.load(f)['examples']
        
    # 1. Identify targets
    idx_to_token = {v: k for k, v in vocab.items()}
    fp_invocations = set()
    for ex in test_errors:
        if ex['label'] == 0:
            for col in ex['columns']:
                token = idx_to_token.get(col, "")
                if token.startswith("shell::invocation="):
                    fp_invocations.add(token)
                    
    target_names = []
    target_indices = []
    
    def add_target(name, keys):
        indices = []
        for k in keys:
            if k in vocab:
                indices.append(vocab[k])
        if len(indices) == len(keys):
            target_names.append(name)
            target_indices.append(set(indices))
            
    add_target('object=SHELL', ['object::shell'])
    add_target('action=COMMAND', ['action::command'])
    add_target('powershell.exe', ['image_path::basename=powershell.exe'])
    add_target('powershell.exe + COMMAND', ['image_path::basename=powershell.exe', 'action::command'])
    add_target('powershell.exe + SHELL', ['image_path::basename=powershell.exe', 'object::shell'])
    
    for inv in sorted(fp_invocations):
        add_target(inv, [inv])
        
    print(f"Tracking {len(target_names)} targets.")
    
    # 2. Prepare shards
    info = manifest['splits']['train']
    keep_p = min(1.0, 30 * info['label_1'] / info['label_0'])
    
    vocab_size = len(vocab)
    rng = np.random.default_rng(1)
    args = []
    for shard in manifest['shards']:
        if shard['split'] == 'train':
            state = rng.bit_generator.state
            k = int(np.count_nonzero(rng.random(shard['label_0']) < keep_p))
            args.append((shard, target_indices, keep_p, state, vocab_size))
            
    print(f"Scanning {len(args)} train shards...")
    
    full_counts = [0] * len(target_names)
    sampled_counts = [0] * len(target_names)
    total_full_neg = 0
    total_sampled_neg = 0
    
    with mp.Pool(16) as p:
        for i, res in enumerate(p.imap_unordered(process_shard, args)):
            if res is None: continue
            
            counts, n_full, n_sampled = res
            total_full_neg += n_full
            total_sampled_neg += n_sampled
            
            for j, (f_c, s_c) in enumerate(counts):
                full_counts[j] += f_c
                sampled_counts[j] += s_c
                
            if (i+1) % 1000 == 0:
                print(f"Processed {i+1}/{len(args)} shards...")
                
    # 3. Write results
    results = []
    for j, name in enumerate(target_names):
        fc = full_counts[j]
        sc = sampled_counts[j]
        rate = sc / fc if fc > 0 else 0
        p_f = fc / total_full_neg if total_full_neg > 0 else 0
        p_s = sc / total_sampled_neg if total_sampled_neg > 0 else 0
        
        results.append({
            'Feature': name,
            'Full_Count': fc,
            'Sampled_Count': sc,
            'Sampling_Rate': rate,
            'P_Feature|Benign_Full': p_f,
            'P_Feature|Benign_Sampled': p_s
        })
        
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    print(f"Audit complete. Total full benign: {total_full_neg}. Total sampled benign: {total_sampled_neg}.")
    print(f"Results saved to {OUTPUT_CSV}")

if __name__ == '__main__':
    main()
