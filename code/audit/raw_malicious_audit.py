#!/usr/bin/env python3
import gzip
import json
import csv
import hashlib
from collections import defaultdict, Counter
from pathlib import Path
import sys
import re

# Add current directory to path to import tokenizer
sys.path.insert(0, str(Path(__file__).parent.resolve()))
from ecar_tokenizer import tokenize_record, flatten_tokens

MALICIOUS_ROOT = Path('/mnt/SSD_Data/optc/host-malicious')
BENIGN_ROOT = Path('/mnt/SSD_Data/optc/host-begnin')
OUTPUT_DIR = Path('/mnt/SSD_Data/optc/code/output/audits/raw_malicious_recheck')
VOCAB_PATH = Path('/mnt/SSD_Data/optc/code/output/host_ml/vocab.json')
TEST_ERRORS_PATH = Path('/mnt/SSD_Data/optc/code/output/reviews/original_runs/xgb/v3/diagnostics/test_errors.json')

TARGET_HOSTS = {
    'sysclient0351', 'sysclient0051', 'sysclient0005', 'sysclient0974',
    'sysclient0501', 'sysclient0201', 'sysclient0402'
}

def load_vocab():
    with open(VOCAB_PATH) as f:
        return json.load(f)

def get_sparse_signature(tokens, vocab):
    # map tokens to vocab IDs
    indices = sorted([vocab[t] for t in tokens if t in vocab])
    return hashlib.md5(str(tuple(indices)).encode()).hexdigest()

def extract_nested_keys(d, prefix=''):
    keys = []
    if isinstance(d, dict):
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.append(full_key)
            if isinstance(v, dict):
                keys.extend(extract_nested_keys(v, full_key))
    return keys

def get_nested_val(d, target_key):
    # simple search in dict for target_key, prioritizing root, then 'properties'
    if target_key in d: return d[target_key]
    if 'properties' in d and target_key in d['properties']:
        return d['properties'][target_key]
    return None

def main():
    vocab = load_vocab()
    
    # Load test errors to get FN examples
    with open(TEST_ERRORS_PATH) as f:
        test_errors = json.load(f)
    
    # FN signatures we want to track
    fn_signatures = set()
    for ex in test_errors.get("examples", []):
        if ex.get("label") == 1:
            # Reconstruct the signature from the column indices
            sig = hashlib.md5(str(tuple(sorted(ex["columns"]))).encode()).hexdigest()
            fn_signatures.add(sig)
            
    print(f"Loaded {len(fn_signatures)} sample FN signatures.")
    
    malicious_files = list(MALICIOUS_ROOT.rglob('*.json.gz'))
    target_files = []
    
    for f in malicious_files:
        match = re.search(r'(sysclient\d+)', f.name, re.IGNORECASE)
        host = match.group(1).casefold() if match else "unknown"
        if host in TARGET_HOSTS:
            day = f.parent.parent.name if 'AIA' in f.parent.name else f.parent.name
            target_files.append((f, host, day))
            
    schema_coverage = defaultdict(lambda: {'total': 0, 'fields': Counter()})
    
    # Missing positives tracking
    total_positives = 0
    missing_positives_by_obj = Counter()
    
    # Signal loss
    module_signal_loss = []
    cmd_signal_loss = []
    
    # Collisions
    host_pos_sigs = defaultdict(set)
    host_neg_sigs = defaultdict(set)
    host_pos_sig_counts = defaultdict(Counter)
    
    # Action/Object collision tracking
    action_obj_pos_sigs = defaultdict(lambda: defaultdict(set))
    action_obj_neg_sigs = defaultdict(lambda: defaultdict(set))
    action_obj_pos_sig_counts = defaultdict(lambda: defaultdict(Counter))
    
    fn_collision_count = 0
    fn_non_collision_count = 0
    
    for file_path, host, day in target_files:
        print(f"Reading {file_path.name} ...")
        
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line: continue
                try:
                    record = json.loads(line)
                except:
                    continue
                    
                obj = record.get('object', 'UNKNOWN')
                action = record.get('action', 'UNKNOWN')
                label = record.get('label')
                
                if label == 1:
                    total_positives += 1
                
                # Schema extraction (deep)
                schema_coverage[obj]['total'] += 1
                for k in extract_nested_keys(record):
                    schema_coverage[obj]['fields'][k] += 1
                    
                grouped_tokens, audit = tokenize_record(record)
                
                if not audit['eligible']:
                    if label == 1:
                        missing_positives_by_obj[obj] += 1
                    continue
                    
                tokens = flatten_tokens(grouped_tokens)
                sig = get_sparse_signature(tokens, vocab)
                
                if label == 1:
                    host_pos_sigs[host].add(sig)
                    host_pos_sig_counts[host][sig] += 1
                    action_obj_pos_sigs[host][(action, obj)].add(sig)
                    action_obj_pos_sig_counts[host][(action, obj)][sig] += 1
                    
                    if obj == 'MODULE' and action == 'LOAD_IMAGE':
                        if len(module_signal_loss) < 1000:
                            module_signal_loss.append({
                                'host': host, 'day': day, 'action': action, 'object': obj,
                                'image_path': get_nested_val(record, 'image_path'),
                                'module_path': get_nested_val(record, 'module_path'),
                                'tokens': ';'.join(tokens)
                            })
                            
                    if obj == 'PROCESS' and action == 'CREATE':
                        cmdline = str(get_nested_val(record, 'command_line') or '').lower()
                        if any(x in cmdline for x in ['cmd.exe', 'powershell', 'ping', 'reg', 'schtasks']):
                            if len(cmd_signal_loss) < 1000:
                                cmd_signal_loss.append({
                                    'host': host, 'day': day, 'action': action, 'object': obj,
                                    'image_path': get_nested_val(record, 'image_path'),
                                    'command_line': get_nested_val(record, 'command_line'),
                                    'tokens': ';'.join(tokens)
                                })
                                
                elif label == 0:
                    host_neg_sigs[host].add(sig)
                    action_obj_neg_sigs[host][(action, obj)].add(sig)

    # Missing positives report
    with open(OUTPUT_DIR / 'missing_positives_report.json', 'w') as f:
        json.dump({
            "total_raw_positives": total_positives,
            "missing_positives_by_object": dict(missing_positives_by_obj)
        }, f, indent=2)

    # Schema output
    final_schema = {}
    for obj, stats in schema_coverage.items():
        total = stats['total']
        coverage = {k: f"{(v/total)*100:.2f}%" for k, v in stats['fields'].items()}
        final_schema[obj] = {'total_records': total, 'coverage': coverage}
        
    with open(OUTPUT_DIR / 'nested_schema_by_object.json', 'w') as f:
        json.dump(final_schema, f, indent=2)

    # Compile Step 7
    with open(OUTPUT_DIR / 'module_signal_loss_repaired.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['host', 'day', 'action', 'object', 'image_path', 'module_path', 'tokens'])
        writer.writeheader()
        writer.writerows(module_signal_loss)
        
    # Compile Step 8
    with open(OUTPUT_DIR / 'commandline_signal_loss_repaired.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['host', 'day', 'action', 'object', 'image_path', 'command_line', 'tokens'])
        writer.writeheader()
        writer.writerows(cmd_signal_loss)

    # Compile Collisions
    collision_report = {}
    for host in TARGET_HOSTS:
        pos = host_pos_sigs[host]
        neg = host_neg_sigs[host]
        collisions = pos.intersection(neg)
        
        positive_events = sum(host_pos_sig_counts[host].values())
        positive_colliding = sum(host_pos_sig_counts[host][sig] for sig in collisions)
        
        collision_report[host] = {
            'positive_events': positive_events,
            'positive_colliding_with_benign': positive_colliding,
            'collision_rate': round(positive_colliding / positive_events, 4) if positive_events > 0 else 0
        }
        
    with open(OUTPUT_DIR / 'sparse_vector_collision_report.json', 'w') as f:
        json.dump(collision_report, f, indent=2)

    # Collision by Action/Object
    with open(OUTPUT_DIR / 'collision_by_action_object.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['host', 'action', 'object', 'positive_events', 'colliding_events', 'collision_rate'])
        for host in TARGET_HOSTS:
            for (action, obj) in action_obj_pos_sigs[host].keys():
                pos = action_obj_pos_sigs[host][(action, obj)]
                neg = action_obj_neg_sigs[host][(action, obj)]
                collisions = pos.intersection(neg)
                
                positive_events = sum(action_obj_pos_sig_counts[host][(action, obj)].values())
                colliding_events = sum(action_obj_pos_sig_counts[host][(action, obj)][sig] for sig in collisions)
                rate = round(colliding_events / positive_events, 4) if positive_events > 0 else 0
                writer.writerow([host, action, obj, positive_events, colliding_events, rate])

    # FN Collision mapping
    global_neg_sigs = set()
    for host in TARGET_HOSTS:
        global_neg_sigs.update(host_neg_sigs[host])
        
    for sig in fn_signatures:
        if sig in global_neg_sigs:
            fn_collision_count += 1
        else:
            fn_non_collision_count += 1
            
    with open(OUTPUT_DIR / 'fn_collision_mapping.json', 'w') as f:
        json.dump({
            "sampled_fn_count": len(fn_signatures),
            "fn_colliding_with_benign": fn_collision_count,
            "fn_non_colliding": fn_non_collision_count
        }, f, indent=2)

if __name__ == '__main__':
    main()
