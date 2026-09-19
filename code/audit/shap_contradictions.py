#!/usr/bin/env python3
import json
import xgboost as xgb
import numpy as np
import scipy.sparse as sparse
from pathlib import Path
import csv

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
EXACT_MATCHES_PATH = PROJECT_ROOT / 'code/output/audits/mission4/exact_matches.json'
MODEL_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/model/model-slot-1.ubj'
VOCAB_PATH = PROJECT_ROOT / 'code/output/host_ml/vocab.json'
OUTPUT_CSV = PROJECT_ROOT / 'code/output/audits/mission4/shap_contradictions.csv'
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'

def main():
    print("Loading exact matches...")
    with open(EXACT_MATCHES_PATH) as f:
        exact = json.load(f)
        
    print("Loading vocabulary...")
    with open(VOCAB_PATH) as f:
        vocab = json.load(f)
        idx_to_token = {v: k for k, v in vocab.items()}
        
    with open(MANIFEST_PATH) as f:
        vocab_size = json.load(f)['vocab_size']
        
    # Find contradictions
    contradictions = []
    for ex in exact:
        b_cnt = ex['exact_match']['benign_count']
        m_cnt = ex['exact_match']['malicious_count']
        t_label = ex['label']
        
        # Predicted wrong, but training vectors are 100% the true label
        if (t_label == 0 and b_cnt > 0 and m_cnt == 0) or (t_label == 1 and m_cnt > 0 and b_cnt == 0):
            contradictions.append(ex)
            
    print(f"Found {len(contradictions)} homogeneous-exact contradictions.")
    
    if not contradictions:
        print("No contradictions to analyze.")
        return
        
    # Build CSR matrix
    indptr = [0]
    indices = []
    data = []
    
    for ex in contradictions:
        cols = sorted(ex['columns'])
        indices.extend(cols)
        data.extend([1.0] * len(cols))
        indptr.append(len(indices))
        
    X = sparse.csr_matrix((data, indices, indptr), shape=(len(contradictions), vocab_size))
    dmatrix = xgb.DMatrix(X)
    
    print("Loading XGBoost model...")
    booster = xgb.Booster()
    booster.load_model(MODEL_PATH)
    
    print("Computing SHAP values...")
    # pred_contribs returns shape (N, num_features + 1), where the last column is the base margin (bias)
    shap_values = booster.predict(dmatrix, pred_contribs=True)
    
    results = []
    
    for i, ex in enumerate(contradictions):
        # SHAP values for features
        shaps = shap_values[i, :-1]
        bias = shap_values[i, -1]
        
        logit = np.sum(shaps) + bias
        prob = 1 / (1 + np.exp(-logit))
        
        predicted = 1 if prob >= 0.5 else 0
        
        # We want features that pushed the logit towards the WRONG prediction.
        # If predicted 1 (wrong), logit is > 0, we want largest POSITIVE shaps.
        # If predicted 0 (wrong), logit is < 0, we want most NEGATIVE shaps.
        
        # Sort all non-zero active features by absolute magnitude descending
        active_indices = np.nonzero(X[i].toarray().flatten())[0]
        
        # Or sort all active features by raw SHAP value descending if it pushed to 1,
        # but let's just sort by absolute SHAP value to see the most influential either way.
        sorted_indices = sorted(active_indices, key=lambda idx: abs(shaps[idx]), reverse=True)
            
        top_features = []
        for idx in sorted_indices:
            val = shaps[idx]
            token = idx_to_token.get(idx, f"UNKNOWN_{idx}")
            top_features.append(f"{token} ({val:.4f})")
                
        res = {
            'source_id': ex['source_id'],
            'true_label': ex['label'],
            'predicted_prob': prob,
            'logit': logit,
            'bias': bias,
            'all_contributors': " | ".join(top_features)
        }
        results.append(res)
        
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        fieldnames = list(results[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    print(f"SHAP analysis saved to {OUTPUT_CSV}")

if __name__ == '__main__':
    main()
