import json
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
EXACT_MATCHES_PATH = PROJECT_ROOT / 'code/output/audits/mission4/exact_matches.json'
NN_MATCHES_PATH = PROJECT_ROOT / 'code/output/audits/mission4/nn_matches.json'
OUTPUT_DIR = PROJECT_ROOT / 'code/output/audits/mission4'

def main():
    with open(EXACT_MATCHES_PATH) as f:
        exact = json.load(f)
    with open(NN_MATCHES_PATH) as f:
        nn = json.load(f)
        
    results = []
    category_counts = Counter()
    
    # Process Exact Matches (A / B / UNRESOLVED)
    for err in exact:
        match_info = err['exact_match']
        b_cnt = match_info['benign_count']
        m_cnt = match_info['malicious_count']
        
        # We need raw events for A vs B. We can't do it automatically without LLM/analyst.
        # So we just dump them into a JSONL that the analyst can review, OR we flag them as UNRESOLVED.
        category = "UNRESOLVED_EXACT_MATCH"
        if b_cnt > 0 and m_cnt > 0:
            category = "MIXED_EXACT_MATCH (Needs A/B review)"
        elif b_cnt > 0 and m_cnt == 0:
            if err['label'] == 1:
                category = "TRAIN_ONLY_BENIGN (FN logical for model)"
            else:
                # err['label'] == 0 but it's an FP? If train was only benign, model should predict benign. 
                # Why did it predict malicious?
                category = "D_MODEL_FAILURE (Train benign, predicted mal)"
        elif m_cnt > 0 and b_cnt == 0:
            if err['label'] == 0:
                category = "TRAIN_ONLY_MALICIOUS (FP logical for model)"
            else:
                category = "D_MODEL_FAILURE (Train mal, predicted benign)"
                
        err['category_guess'] = category
        category_counts[category] += 1
        results.append(err)
        
    # Process No Exact Matches (C / D)
    for err in nn:
        best_match = err.get('best_match')
        category = "UNRESOLVED_NO_MATCH"
        if not best_match:
            category = "C_TRAIN_COVERAGE_GAP (No similar neighbors)"
        else:
            score = best_match['score']
            if score >= 0.9:
                category = "D_MODEL_FAILURE or C_COVERAGE (High similarity)"
            elif score >= 0.7:
                category = "C_TRAIN_COVERAGE_GAP (Moderate similarity)"
            else:
                category = "C_TRAIN_COVERAGE_GAP (Low similarity)"
                
        err['category_guess'] = category
        category_counts[category] += 1
        results.append(err)
        
    print("--- Categorization Summary ---")
    for k, v in category_counts.items():
        print(f"{v:4d} : {k}")
        
if __name__ == '__main__':
    main()
