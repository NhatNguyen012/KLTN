#!/usr/bin/env python3
import json
import pickle
import numpy as np
import scipy.sparse as sparse
from pathlib import Path

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
NO_EXACT_MATCHES_PATH = PROJECT_ROOT / 'code/output/audits/mission4/no_exact_matches.json'
CHECKPOINT_PATH = PROJECT_ROOT / 'code/output/audits/mission4/train_signatures.pkl'
OUTPUT_DIR = PROJECT_ROOT / 'code/output/audits/mission4'

def main():
    if not NO_EXACT_MATCHES_PATH.exists():
        print("No exact matches file found. Run audit_classify.py first.")
        return
        
    with open(NO_EXACT_MATCHES_PATH) as f:
        test_errors = json.load(f)
        
    if not test_errors:
        print("No errors without exact matches. NN not needed.")
        return
        
    print("Loading train signatures checkpoint...")
    with open(CHECKPOINT_PATH, 'rb') as f:
        train_signatures = pickle.load(f)
        
    print(f"Total unique signatures in TRAIN: {len(train_signatures)}")
    
    # 1. Build the unique signatures matrix
    # We will build a CSR matrix where each row is a unique signature
    row_ptrs = [0]
    col_indices = []
    
    sig_list = []
    
    for sig, counts in train_signatures.items():
        sig_list.append((sig, counts[0], counts[1], counts[2]))
        col_indices.extend(sig)
        row_ptrs.append(len(col_indices))
        
    row_ptrs = np.array(row_ptrs, dtype=np.int32)
    col_indices = np.array(col_indices, dtype=np.int32)
    data = np.ones(len(col_indices), dtype=np.float32)
    
    # Vocab size is roughly 250,000. Let's find max index.
    max_vocab = max(col_indices) + 1 if len(col_indices) > 0 else 0
    
    sigs_matrix = sparse.csr_matrix((data, col_indices, row_ptrs), shape=(len(sig_list), max_vocab))
    # Pre-calculate magnitude for jaccard (number of non-zeros per signature)
    sigs_nnz = np.diff(row_ptrs)
    
    print(f"Matrix shape: {sigs_matrix.shape}")
    
    results = []
    
    print("Computing Nearest Neighbors...")
    for i, err in enumerate(test_errors):
        cols = sorted(err['columns'])
        # Build vector for test error
        err_vec = sparse.csr_matrix((np.ones(len(cols), dtype=np.float32), cols, [0, len(cols)]), shape=(1, max_vocab))
        
        # Intersection = Sigs * Err.T
        intersections = sigs_matrix.dot(err_vec.T).toarray().flatten()
        
        err_nnz = len(cols)
        unions = sigs_nnz + err_nnz - intersections
        
        jaccard = intersections / np.where(unions == 0, 1, unions)
        
        # Find best matches at thresholds 0.7, 0.8, 0.9
        thresholds = [0.9, 0.8, 0.7]
        matches_at_threshold = {}
        
        best_idx = np.argmax(jaccard)
        best_score = jaccard[best_idx]
        best_match = None
        if best_score > 0:
            best_sig, b_cnt, m_cnt, mappings = sig_list[best_idx]
            best_match = {
                'score': float(best_score),
                'benign_count': b_cnt,
                'malicious_count': m_cnt,
                'representative_mappings': mappings
            }
            
        for t in thresholds:
            t_indices = np.where(jaccard >= t)[0]
            m_count = 0
            b_count = 0
            for idx in t_indices:
                _, b, m, _ = sig_list[idx]
                b_count += b
                m_count += m
                
            matches_at_threshold[f">={t}"] = {
                'unique_signatures': int(len(t_indices)),
                'total_benign': int(b_count),
                'total_malicious': int(m_count)
            }
            
        err['nearest_neighbors'] = matches_at_threshold
        err['best_match'] = best_match
        results.append(err)
        
        if (i+1) % 100 == 0:
            print(f"  Processed {i+1}/{len(test_errors)} errors...")
            
    with open(OUTPUT_DIR / 'nn_matches.json', 'w') as f:
        json.dump(results, f, indent=2)
        
    print("Nearest neighbor analysis complete.")

if __name__ == '__main__':
    main()
