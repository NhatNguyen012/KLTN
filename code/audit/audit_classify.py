#!/usr/bin/env python3
import json
import pickle
from pathlib import Path

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
TEST_ERRORS_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/diagnostics/test_errors.json'
CHECKPOINT_PATH = PROJECT_ROOT / 'code/output/audits/mission4/train_signatures.pkl'
OUTPUT_DIR = PROJECT_ROOT / 'code/output/audits/mission4'

def get_raw_event(host, day, source_line):
    # Try benign first
    path = PROJECT_ROOT / f"host-begnin/{host}/{day}.json"
    if not path.exists():
        path = PROJECT_ROOT / f"host-malicious/{host}/{day}.json"
    if not path.exists():
        return None
        
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i + 1 == source_line:
                return json.loads(line)
    return None

def main():
    with open(TEST_ERRORS_PATH) as f:
        test_errors = json.load(f)['examples']
        
    print("Loading train signatures...")
    with open(CHECKPOINT_PATH, 'rb') as f:
        train_signatures = pickle.load(f)
        
    exact_matches = []
    no_exact_matches = []
    
    for err in test_errors:
        sig = tuple(sorted(err['columns']))
        if sig in train_signatures:
            counts = train_signatures[sig]
            err['exact_match'] = {
                'benign_count': counts[0],
                'malicious_count': counts[1],
                'p_sample': counts[1] / (counts[0] + counts[1]) if counts[0] + counts[1] > 0 else 0,
                # We won't load raw events here, we'll do it selectively if needed
                'representative_mappings': counts[2]
            }
            exact_matches.append(err)
        else:
            no_exact_matches.append(err)
            
    print(f"Total Test Errors: {len(test_errors)}")
    print(f"Errors with Exact Matches in Sample: {len(exact_matches)}")
    print(f"Errors with NO Exact Match in Sample: {len(no_exact_matches)}")
    
    with open(OUTPUT_DIR / 'exact_matches.json', 'w') as f:
        json.dump(exact_matches, f, indent=2)
        
    with open(OUTPUT_DIR / 'no_exact_matches.json', 'w') as f:
        json.dump(no_exact_matches, f, indent=2)

if __name__ == '__main__':
    main()
