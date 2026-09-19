#!/usr/bin/env python3
import json
import gzip
from pathlib import Path
import sys
import numpy as np
import scipy.sparse as sparse
from collections import defaultdict

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'
TEST_ERRORS_PATH = PROJECT_ROOT / 'code/output/reviews/original_runs/xgb/v3/diagnostics/test_errors.json'
OUTPUT_DIR = PROJECT_ROOT / 'code/output/audits/mission4_fn_fp'

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
        
    with open(TEST_ERRORS_PATH) as f:
        test_errors = json.load(f)['examples']
        
    vocab_size = manifest['vocab_size']
    num_errors = len(test_errors)
    
    print(f"Loaded {num_errors} error events.")
    
    # Build E matrix
    indptr = [0]
    indices = []
    data = []
    
    for ex in test_errors:
        cols = sorted(ex['columns'])
        indices.extend(cols)
        data.extend([1.0] * len(cols))
        indptr.append(len(indices))
        
    E = sparse.csr_matrix((data, indices, indptr), shape=(num_errors, vocab_size))
    E_sum = np.array(E.sum(axis=1)).flatten()
    
    # Store top 3 matches for each error
    # shape: [num_errors][label][3] -> (score, source_id, source_line)
    top_matches = [[[(0.0, None, None)] * 3 for _ in range(2)] for _ in range(num_errors)]
    
    train_shards = [s for s in manifest['shards'] if s['split'] == 'train']
    
    # Let's scan max 1000 shards (100 million rows) to keep it under 30 seconds
    MAX_SHARDS = min(1000, len(train_shards))
    print(f"Scanning {MAX_SHARDS} TRAIN shards (~{MAX_SHARDS * 100000} rows)...")
    
    sources = {s['source_id']: s for s in manifest['sources']}
    volumes = manifest['volumes']
    
    sys.path.insert(0, str(PROJECT_ROOT / 'code/output/host_ml/model_input'))
    from host_shards import decode_shard
    
    for i in range(MAX_SHARDS):
        shard = train_shards[i]
        vol_path = Path(volumes[shard['volume']])
        shard_path = vol_path / shard['path']
        
        X, labels, source_rows = decode_shard(shard_path, vocab_size, shard)
        
        X_sum = np.array(X.sum(axis=1)).flatten()
        intersection = E.dot(X.T).toarray()
        
        for j in range(num_errors):
            # Calculate Jaccard
            union = E_sum[j] + X_sum - intersection[j]
            # Avoid division by zero
            union[union == 0] = 1
            jaccard = intersection[j] / union
            
            for label in (0, 1):
                mask = (labels == label)
                if not np.any(mask):
                    continue
                    
                masked_jaccard = jaccard.copy()
                masked_jaccard[~mask] = -1
                
                # Get top 3
                # argpartition is faster than argsort
                if np.sum(mask) >= 3:
                    top3_idx = np.argpartition(masked_jaccard, -3)[-3:]
                    top3_idx = top3_idx[np.argsort(masked_jaccard[top3_idx])][::-1]
                else:
                    top3_idx = np.where(mask)[0]
                    top3_idx = top3_idx[np.argsort(masked_jaccard[top3_idx])][::-1]
                    
                for idx in top3_idx:
                    score = float(masked_jaccard[idx])
                    if score > top_matches[j][label][-1][0]:
                        s_id = shard['source_id']
                        s_line = int(source_rows[idx]) + 1 # Convert to 1-indexed
                        
                        top_matches[j][label].append((score, s_id, s_line))
                        top_matches[j][label].sort(key=lambda x: x[0], reverse=True)
                        top_matches[j][label] = top_matches[j][label][:3]
                        
        if (i + 1) % 50 == 0:
            print(f"Processed {i + 1}/{MAX_SHARDS} shards")
            
    print("Search complete. Fetching raw events efficiently...")
    
    # queries[ (day, host) ] = [ (line, type, j, label, rank) ]
    queries = defaultdict(list)
    for j, ex in enumerate(test_errors):
        queries[(ex['day'], ex['host'])].append((ex['source_line'], "failed", j, None, None))
        for label in (0, 1):
            for rank, (score, s_id, s_line) in enumerate(top_matches[j][label], 1):
                if s_id is not None:
                    s_info = sources[s_id]
                    n_day = s_info.get('day', 'unknown')
                    n_host = s_info.get('host', s_info.get('file_host', 'unknown'))
                    queries[(n_day, n_host)].append((s_line, "neighbor", j, label, rank))
                    
    # results[j][type][label][rank] = json
    results_failed = {}
    results_neighbors = defaultdict(lambda: defaultdict(dict))
    
    for (day, host), reqs in queries.items():
        reqs.sort(key=lambda x: x[0])
        line_to_reqs = defaultdict(list)
        for r in reqs:
            line_to_reqs[r[0]].append(r)
            
        found = 0
        total = len(reqs)
        
        for root_dir in [PROJECT_ROOT / 'host-malicious', PROJECT_ROOT / 'host-begnin']:
            for path in root_dir.rglob(f'*{host}*.json.gz'):
                if day in str(path):
                    with gzip.open(path, 'rt', encoding='utf-8') as f:
                        for i, line in enumerate(f, 1):
                            if i in line_to_reqs:
                                raw = json.loads(line)
                                for r in line_to_reqs[i]:
                                    _, r_type, j, label, rank = r
                                    if r_type == 'failed':
                                        results_failed[j] = raw
                                    else:
                                        results_neighbors[j][label][rank] = raw
                                    found += 1
                            if found == total:
                                break
                if found == total:
                    break
            if found == total:
                break
    
    report_path = OUTPUT_DIR / 'error_trace_report.md'
    with open(report_path, 'w') as f:
        f.write("# Error Trace Analysis (Nearest Neighbors in TRAIN)\n\n")
        
        for j, ex in enumerate(test_errors):
            f.write(f"## {ex['error']} | {ex['host']} - {ex['day']} - Line {ex['source_line']}\n")
            f.write(f"**Score:** {ex['score']:.4f}\n\n")
            
            raw = results_failed.get(j, {"error": "Not found"})
            f.write("### The Failed Event\n")
            f.write("```json\n" + json.dumps(raw, indent=2) + "\n```\n\n")
            
            for label, label_name in [(0, "Benign"), (1, "Malicious")]:
                f.write(f"### Top 3 {label_name} Neighbors in TRAIN\n")
                for rank, (score, s_id, s_line) in enumerate(top_matches[j][label], 1):
                    if s_id is None:
                        continue
                        
                    s_info = sources[s_id]
                    n_day = s_info.get('day', 'unknown')
                    n_host = s_info.get('host', s_info.get('file_host', 'unknown'))
                    n_raw = results_neighbors[j][label].get(rank, {"error": "Not found"})
                    
                    f.write(f"**{rank}. Similarity: {score*100:.1f}%** (File: {n_host} {n_day} Line: {s_line})\n")
                    f.write("```json\n" + json.dumps(n_raw, indent=2) + "\n```\n\n")
                    
            f.write("---\n\n")
            
    print(f"Report saved to {report_path}")

if __name__ == '__main__':
    main()
