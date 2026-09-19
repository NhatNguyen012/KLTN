#!/usr/bin/env python3
import json
import pickle
import numpy as np
import scipy.sparse as sparse
from pathlib import Path
import csv

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
NO_EXACT_MATCHES_PATH = PROJECT_ROOT / 'code/output/audits/mission4/no_exact_matches.json'
CHECKPOINT_PATH = PROJECT_ROOT / 'code/output/audits/mission4/train_signatures.pkl'
OUTPUT_CSV = PROJECT_ROOT / 'code/output/audits/mission4/neighborhood_majority.csv'
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'

def main():
    print("Loading test errors...")
    with open(NO_EXACT_MATCHES_PATH) as f:
        test_errors = json.load(f)
        
    print("Loading train signatures checkpoint...")
    with open(CHECKPOINT_PATH, 'rb') as f:
        train_signatures = pickle.load(f)
        
    with open(MANIFEST_PATH) as f:
        vocab_size = json.load(f)['vocab_size']
        
    print(f"Total unique signatures in sample: {len(train_signatures)}")
    
    # Build M matrix
    indptr = [0]
    indices = []
    data = []
    
    W_0 = np.zeros(len(train_signatures), dtype=np.int32)
    W_1 = np.zeros(len(train_signatures), dtype=np.int32)
    
    for i, (sig, counts) in enumerate(train_signatures.items()):
        indices.extend(sig)
        data.extend([1.0] * len(sig))
        indptr.append(len(indices))
        W_0[i] = counts[0]
        W_1[i] = counts[1]
        
    M = sparse.csr_matrix((data, indices, indptr), shape=(len(train_signatures), vocab_size))
    M_sum = np.array(M.sum(axis=1)).flatten()
    
    # Build E matrix
    e_indptr = [0]
    e_indices = []
    e_data = []
    
    for ex in test_errors:
        cols = sorted(ex['columns'])
        e_indices.extend(cols)
        e_data.extend([1.0] * len(cols))
        e_indptr.append(len(e_indices))
        
    E = sparse.csr_matrix((e_data, e_indices, e_indptr), shape=(len(test_errors), vocab_size))
    E_sum = np.array(E.sum(axis=1)).flatten()
    
    print("Computing Jaccard similarities...")
    intersection = E.dot(M.T).toarray()
    
    results = []
    cat_counts = {'COVERAGE_OR_REPRESENTATION': 0, 'D': 0}
    
    for j, ex in enumerate(test_errors):
        # Calculate Jaccard
        union = E_sum[j] + M_sum - intersection[j]
        union[union == 0] = 1
        jaccard = intersection[j] / union
        
        # Count neighbors at thresholds
        t_counts = {
            0.9: [0, 0],
            0.8: [0, 0],
            0.7: [0, 0]
        }
        
        for t in [0.9, 0.8, 0.7]:
            mask = jaccard >= t
            if np.any(mask):
                t_counts[t][0] = int(np.sum(W_0[mask]))
                t_counts[t][1] = int(np.sum(W_1[mask]))
                
        # Determine C vs D
        category = 'D' # Default to Model Failure
        
        # 1. Look for highest threshold with matches
        highest_t = None
        for t in [0.9, 0.8, 0.7]:
            if t_counts[t][0] + t_counts[t][1] > 0:
                highest_t = t
                break
                
        if highest_t is None:
            # 2. No neighbors at 0.7 -> Missing Training Coverage
            category = 'COVERAGE_OR_REPRESENTATION'
        else:
            # 3. Check majority
            c_0, c_1 = t_counts[highest_t]
            predicted = ex['label'] # It predicted WRONG, so wait, ex['label'] is the TRUE label
            # If test_label is 1, model predicted 0 (FN).
            # If test_label is 0, model predicted 1 (FP).
            
            # Did the model correctly generalize the local neighborhood?
            # If neighborhood majority is the OPPOSITE of true label (i.e. same as prediction),
            # then the model learned the neighborhood correctly, but the neighborhood itself
            # doesn't contain the true label. So it's Missing Training Coverage.
            # If neighborhood majority IS the true label, then model ignored the neighborhood -> Model Failure (D).
            
            true_label = ex['label']
            if true_label == 1:
                # FN. Model predicted 0.
                if c_0 > c_1: category = 'COVERAGE_OR_REPRESENTATION'
                elif c_1 > c_0: category = 'D'
                else: category = 'UNRESOLVED' # Tied
            else:
                # FP. Model predicted 1.
                if c_1 > c_0: category = 'COVERAGE_OR_REPRESENTATION'
                elif c_0 > c_1: category = 'D'
                else: category = 'UNRESOLVED'
                
        res = {
            'source_id': ex['source_id'],
            'test_label': ex['label'],
            'test_error_type': ex['error'],
            'n_09_benign': t_counts[0.9][0],
            'n_09_mal': t_counts[0.9][1],
            'n_08_benign': t_counts[0.8][0],
            'n_08_mal': t_counts[0.8][1],
            'n_07_benign': t_counts[0.7][0],
            'n_07_mal': t_counts[0.7][1],
            'category': category
        }
        results.append(res)
        if category in cat_counts:
            cat_counts[category] += 1
            
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        fieldnames = list(results[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    print(f"Total Non-Exact Matches analyzed: {len(results)}")
    print(f"Category COVERAGE_OR_REPRESENTATION: {cat_counts['COVERAGE_OR_REPRESENTATION']}")
    print(f"Category D (Model Failure): {cat_counts['D']}")
    
if __name__ == '__main__':
    main()
