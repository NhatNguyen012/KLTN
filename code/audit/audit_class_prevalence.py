import json
import pickle
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
CHECKPOINT_PATH = PROJECT_ROOT / 'code/output/audits/mission4/train_signatures.pkl'
VOCAB_PATH = PROJECT_ROOT / 'code/output/host_ml/vocab.json'
TEST_ERRORS_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/diagnostics/test_errors.json'
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'

def main():
    print("Loading vocab...")
    with open(VOCAB_PATH) as f:
        vocab = json.load(f)
        
    print("Loading test errors...")
    with open(TEST_ERRORS_PATH) as f:
        test_errors = json.load(f)['examples']
        
    # Find shell invocations in FPs
    fp_invocations = set()
    idx_to_token = {v: k for k, v in vocab.items()}
    
    for ex in test_errors:
        if ex['label'] == 0: # FP (true label 0, predicted 1)
            for col in ex['columns']:
                token = idx_to_token.get(col, "")
                if token.startswith("shell::invocation="):
                    fp_invocations.add(token)
                    
    print(f"Found {len(fp_invocations)} unique shell invocations in FPs: {fp_invocations}")
    
    print("Loading train signatures...")
    with open(CHECKPOINT_PATH, 'rb') as f:
        train_signatures = pickle.load(f)
        
    # We want to audit:
    # 1. powershell.exe
    # 2. action::command
    # 3. powershell.exe AND action::command
    # 4. Each fp_invocation
    
    ps_idx = vocab.get('image_path::basename=powershell.exe')
    cmd_idx = vocab.get('action::command')
    
    # Store indices of interest
    targets = {}
    if ps_idx is not None: targets['powershell.exe'] = {ps_idx}
    if cmd_idx is not None: targets['action::command'] = {cmd_idx}
    if ps_idx is not None and cmd_idx is not None:
        targets['powershell.exe AND action::command'] = {ps_idx, cmd_idx}
        
    for inv in fp_invocations:
        idx = vocab.get(inv)
        if idx is not None:
            targets[inv] = {idx}
            
    counts = {name: {'benign': 0, 'malicious': 0} for name in targets}
    total_benign = 0
    total_malicious = 0
    
    for sig, (b_cnt, m_cnt, _) in train_signatures.items():
        total_benign += b_cnt
        total_malicious += m_cnt
        
        sig_set = set(sig)
        for name, target_indices in targets.items():
            if target_indices.issubset(sig_set):
                counts[name]['benign'] += b_cnt
                counts[name]['malicious'] += m_cnt
                
    print(f"\nTotal TRAIN Benign: {total_benign}")
    print(f"Total TRAIN Malicious: {total_malicious}\n")
    
    print("--- Prevalence Audit ---")
    for name, c in counts.items():
        b = c['benign']
        m = c['malicious']
        p_b = b / total_benign if total_benign > 0 else 0
        p_m = m / total_malicious if total_malicious > 0 else 0
        
        print(f"Feature: {name}")
        print(f"  Count (Benign): {b}  (Malicious): {m}")
        print(f"  P(feature|benign) = {p_b:.6f} ({p_b*100:.4f}%)")
        print(f"  P(feature|malicious) = {p_m:.6f} ({p_m*100:.4f}%)")
        print("-" * 40)

if __name__ == '__main__':
    main()
