import json
from pathlib import Path
import gzip
from collections import defaultdict

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
EXACT_MATCHES = PROJECT_ROOT / 'code/output/audits/mission4/exact_matches.json'
OUTPUT_RAW = PROJECT_ROOT / 'code/output/audits/mission4/raw_event_examples.jsonl'
MANIFEST_PATH = PROJECT_ROOT / 'code/output/host_ml/model_input/manifest.json'

def main():
    with open(EXACT_MATCHES) as f:
        exact = json.load(f)
        
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
        
    sources_dict = {s['source_id']: s for s in manifest['sources']}
    shards_dict = manifest['shards']
    
    # 1. Collect all line requests per file
    # file_requests[path] = [ (source_line, ref_dict) ]
    file_requests = defaultdict(list)
    
    # We will build a list of tasks to process later
    tasks = []
    
    for j, err in enumerate(exact):
        b_cnt = err['exact_match']['benign_count']
        m_cnt = err['exact_match']['malicious_count']
        label = err['label']
            
        test_source = sources_dict.get(err['source_id'])
        if not test_source:
            continue
            
        test_path = test_source['source']['path']
        
        task_info = {
            'err_index': j,
            'err': err,
            'test_raw_event': None,
            'train_benign_events': [],
            'train_malicious_events': []
        }
        tasks.append(task_info)
        
        file_requests[test_path].append((err['source_line'], task_info, 'test_raw_event', None))
        
        b_added = 0
        m_added = 0
        
        for mapping in err['exact_match']['representative_mappings']:
            shard_idx, _, _, line = mapping
            shard = shards_dict[shard_idx]
            s_id = shard['source_id']
            train_source = sources_dict[s_id]
            train_path = train_source['source']['path']
            
            # Decide if benign or malicious
            is_benign = "host-begnin" in train_path
            
            if is_benign and b_added < 3:
                file_requests[train_path].append((line, task_info, 'train_benign_events', s_id))
                b_added += 1
            elif not is_benign and m_added < 3:
                file_requests[train_path].append((line, task_info, 'train_malicious_events', s_id))
                m_added += 1
                
    print(f"Collected requests across {len(file_requests)} files.")
    
    # 2. Process each file once
    for file_idx, (path, reqs) in enumerate(file_requests.items(), 1):
        # reqs is list of (line, task_info, target_list, s_id)
        line_to_reqs = defaultdict(list)
        for r in reqs:
            line_to_reqs[r[0]].append(r)
            
        try:
            with gzip.open(path, 'rt', encoding='utf-8') as f:
                for i, line in enumerate(f, 1): # 1-indexed
                    if i in line_to_reqs:
                        raw = json.loads(line)
                        for r in line_to_reqs[i]:
                            _, task_info, target_list, s_id = r
                            
                            # Add provenance if it's a train event
                            if s_id is not None:
                                train_source = sources_dict[s_id]
                                raw['_provenance'] = {
                                    'source_id': s_id,
                                    'host': train_source.get('file_host', train_source.get('host')),
                                    'day': train_source.get('day'),
                                    'source_line': i
                                }
                            
                            if target_list == 'test_raw_event':
                                task_info['test_raw_event'] = raw
                            else:
                                task_info[target_list].append(raw)
                                
        except Exception as e:
            print(f"Error reading {path}: {e}")
            
        if file_idx % 10 == 0:
            print(f"Processed {file_idx}/{len(file_requests)} files...")
            
    # 3. Write output
    with open(OUTPUT_RAW, 'w') as out:
        for t in tasks:
            err = t['err']
            out.write(json.dumps({
                'test_error_id': err['source_id'],
                'test_label': err['label'],
                'test_score': err['score'],
                'test_error_type': err['error'],
                'benign_count_in_train': err['exact_match']['benign_count'],
                'malicious_count_in_train': err['exact_match']['malicious_count'],
                'test_raw_event': t['test_raw_event'],
                'train_benign_events': t['train_benign_events'],
                'train_malicious_events': t['train_malicious_events']
            }) + '\n')
            
    print(f"Finished extracting raw events for {len(tasks)} errors.")

if __name__ == '__main__':
    main()
