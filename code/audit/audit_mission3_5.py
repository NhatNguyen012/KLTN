#!/usr/bin/env python3
import json
import csv
import hashlib
from collections import defaultdict, deque, Counter
from pathlib import Path
import sys
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.resolve()))
from ecar_tokenizer import tokenize_record, flatten_tokens
from stratified_pipeline import load_manifest, split_rows

OUTPUT_DIR = Path('/mnt/SSD_Data/optc/code/output/audits/mission3_5')
VOCAB_PATH = Path('/mnt/SSD_Data/optc/code/output/host_ml/vocab.json')
SPLIT_MANIFEST = Path('/mnt/SSD_Data/optc/code/output/host_ml/split/manifest.json')

TARGET_HOSTS = [
    'sysclient0501', 'sysclient0351', 'sysclient0201', 'sysclient0402',
    'sysclient0051', 'sysclient0005', 'sysclient0974'
]

def load_vocab():
    with open(VOCAB_PATH) as f:
        return json.load(f)

def get_sparse_signature(tokens, vocab):
    indices = tuple(sorted(list(set([vocab.get(t) for t in tokens if t in vocab]))))
    return hash(indices)

def get_sig(parts):
    if isinstance(parts, list): parts = tuple(parts)
    return hash(parts)

class RollingWindow:
    def __init__(self, time_ms):
        self.q = deque()
        self.time_ms = time_ms
        self.splits_count = {1: 0, 2: 0, 3: 0, 0: 0} # 1: TRAIN, 2: VAL, 3: TEST
        self.count = 0
        self.cp = 0
        self.op = 0
        self.lm = 0
        self.wf = 0
        self.obj_process = 0
        self.obj_file = 0
        self.obj_module = 0
        self.entity_counts = Counter()
        
    def add(self, e):
        # e = (ts, action, obj, split, actor, obj_id, image)
        self.q.append(e)
        self.count += 1
        self.splits_count[e[3]] += 1
        a, o, img = e[1], e[2], e[6]
        
        if a == 'CREATE' and o == 'PROCESS': self.cp += 1
        elif a == 'OPEN' and o == 'PROCESS': self.op += 1
        elif a == 'LOAD' and o == 'MODULE': self.lm += 1
        elif a == 'WRITE' and o == 'FILE': self.wf += 1
        
        if o == 'PROCESS': self.obj_process += 1
        elif o == 'FILE': self.obj_file += 1
        elif o == 'MODULE': self.obj_module += 1
        
        if img != 'unknown':
            self.entity_counts[img] += 1
        
    def update_to_time(self, current_ts):
        while self.q and current_ts - self.q[0][0] > self.time_ms:
            e = self.q.popleft()
            self.count -= 1
            self.splits_count[e[3]] -= 1
            a, o, img = e[1], e[2], e[6]
            
            if a == 'CREATE' and o == 'PROCESS': self.cp -= 1
            elif a == 'OPEN' and o == 'PROCESS': self.op -= 1
            elif a == 'LOAD' and o == 'MODULE': self.lm -= 1
            elif a == 'WRITE' and o == 'FILE': self.wf -= 1
            
            if o == 'PROCESS': self.obj_process -= 1
            elif o == 'FILE': self.obj_file -= 1
            elif o == 'MODULE': self.obj_module -= 1
            
            if img != 'unknown':
                self.entity_counts[img] -= 1
                if self.entity_counts[img] == 0:
                    del self.entity_counts[img]
            
    def get_feats(self):
        # Returns (total_count, object_counts, action_counts, unique_entities)
        return (
            self.count,
            (self.obj_process, self.obj_file, self.obj_module),
            (self.cp, self.op, self.lm, self.wf),
            len(self.entity_counts)
        )

def process_host(host, manifest_entries, split_dir, vocab):
    print(f"--- Started processing {host} ---")
    host_entries = [e for e in manifest_entries if e['host'] == host]
    host_entries.sort(key=lambda x: x['day'])
    
    # PASS 1: Build Lineage Graph with SPLIT info
    process_map = {}
    for entry in host_entries:
        for code, number, rec in split_rows(entry, split_dir):
            if rec.get('action') == 'CREATE' and rec.get('object') == 'PROCESS':
                obj_id = rec.get('objectID')
                if obj_id:
                    props = rec.get('properties', {})
                    process_map[obj_id] = {
                        'image': props.get('image_path', '').lower().split('\\\\')[-1].split('\\')[-1],
                        'parent_actor': rec.get('actorID'),
                        'split': code
                    }
                    
    # Initialize trackers
    w5 = RollingWindow(5000)
    w30 = RollingWindow(30000)
    w60 = RollingWindow(60000)
    w300 = RollingWindow(300000)
    
    dist = defaultdict(lambda: Counter())
    
    test_events = 0
    t_leakage = {5: 0, 30: 0, 60: 0, 300: 0}
    p_in_train = 0
    gp_in_train = 0
    
    p_s = defaultdict(set)
    n_s = defaultdict(set)
    
    # PASS 2: Calculate and aggregate
    for entry in host_entries:
        for code, number, rec in split_rows(entry, split_dir):
            grouped, audit = tokenize_record(rec)
            # eligibility guaranteed by code > 0 from split_rows
            
            action = rec.get('action', 'UNKNOWN')
            obj = rec.get('object', 'UNKNOWN')
            label = rec.get('label')
            actor_id = rec.get('actorID')
            ts_str = rec.get('timestamp')
            ts = int(datetime.fromisoformat(ts_str).timestamp() * 1000) if ts_str else 0
            
            actor_img = "unknown"
            parent_img = "unknown"
            gp_img = "unknown"
            
            p_split = 0
            gp_split = 0
            
            if actor_id in process_map:
                node = process_map[actor_id]
                actor_img = node['image']
                p_id = node['parent_actor']
                if p_id in process_map:
                    p_node = process_map[p_id]
                    parent_img = p_node['image']
                    p_split = p_node['split']
                    gp_id = p_node['parent_actor']
                    if gp_id in process_map:
                        gp_img = process_map[gp_id]['image']
                        gp_split = process_map[gp_id]['split']
                        
            w5.update_to_time(ts)
            w30.update_to_time(ts)
            w60.update_to_time(ts)
            w300.update_to_time(ts)
            
            if code == 3: # TEST split
                test_events += 1
                if w5.splits_count[1] > 0 or w5.splits_count[2] > 0: t_leakage[5] += 1
                if w30.splits_count[1] > 0 or w30.splits_count[2] > 0: t_leakage[30] += 1
                if w60.splits_count[1] > 0 or w60.splits_count[2] > 0: t_leakage[60] += 1
                if w300.splits_count[1] > 0 or w300.splits_count[2] > 0: t_leakage[300] += 1
                
                if p_split == 1: p_in_train += 1
                if gp_split == 1: gp_in_train += 1
                
            t60_feats = w60.get_feats()
            f_T1 = t60_feats[0]
            f_T2 = t60_feats[1]
            f_T3 = t60_feats[2]
            f_T4 = t60_feats[3]
            
            dist[f"{code}_{label}_T1_total"][f_T1] += 1
            dist[f"{code}_{label}_T2_proc"][f_T2[0]] += 1
            dist[f"{code}_{label}_T3_createproc"][f_T3[0]] += 1
            dist[f"{code}_{label}_T4_uniq"][f_T4] += 1
            
            tokens = flatten_tokens(grouped)
            s0 = get_sparse_signature(tokens, vocab)
            
            w5.add((ts, action, obj, code, actor_id, rec.get('objectID'), actor_img))
            w30.add((ts, action, obj, code, actor_id, rec.get('objectID'), actor_img))
            w60.add((ts, action, obj, code, actor_id, rec.get('objectID'), actor_img))
            w300.add((ts, action, obj, code, actor_id, rec.get('objectID'), actor_img))
            
            s1 = get_sig([s0, actor_img])
            s2 = get_sig([s1, parent_img])
            s3 = get_sig([s2, parent_img, actor_img])
            s4 = get_sig([s3, gp_img, parent_img, actor_img])
            
            t1_sig = get_sig([s0, f_T1])
            t2_sig = get_sig([s0, f_T2])
            t3_sig = get_sig([s0, f_T3])
            t4_sig = get_sig([s0, f_T4])
            t_combined = get_sig([s0, f_T1, f_T3])
            
            c3 = get_sig([s3, f_T1, f_T3])
            
            if label == 1:
                p_s['s0'].add(s0); p_s['s1'].add(s1); p_s['s2'].add(s2); p_s['s3'].add(s3); p_s['s4'].add(s4)
                p_s['t1'].add(t1_sig); p_s['t2'].add(t2_sig); p_s['t3'].add(t3_sig); p_s['t4'].add(t4_sig)
                p_s['t_combined'].add(t_combined); p_s['c3'].add(c3)
            else:
                n_s['s0'].add(s0); n_s['s1'].add(s1); n_s['s2'].add(s2); n_s['s3'].add(s3); n_s['s4'].add(s4)
                n_s['t1'].add(t1_sig); n_s['t2'].add(t2_sig); n_s['t3'].add(t3_sig); n_s['t4'].add(t4_sig)
                n_s['t_combined'].add(t_combined); n_s['c3'].add(c3)
                
    leakage_stats = {
        'test_events': test_events,
        't5_leakage': t_leakage[5],
        't30_leakage': t_leakage[30],
        't60_leakage': t_leakage[60],
        't300_leakage': t_leakage[300],
        'parent_in_train': p_in_train,
        'grandparent_in_train': gp_in_train
    }
    
    col = {}
    for k in p_s:
        if p_s[k]:
            col[k] = (len(p_s[k].intersection(n_s[k])), len(p_s[k]))
        else:
            col[k] = (0, 0)
        
    print(f"--- Finished processing {host} ---")
    return host, leakage_stats, dict(dist), col

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    vocab = load_vocab()
    
    manifest, _ = load_manifest(SPLIT_MANIFEST, 'host_random_split')
    entries = manifest['entries']
    split_dir = SPLIT_MANIFEST.parent
    
    total_leakage = {
        'test_events': 0, 't5_leakage': 0, 't30_leakage': 0, 
        't60_leakage': 0, 't300_leakage': 0, 'parent_in_train': 0, 'grandparent_in_train': 0
    }
    
    col_sums = {k: 0.0 for k in ['s0', 's1', 's2', 's3', 's4', 't1', 't2', 't3', 't4', 't_combined', 'c3']}
    col_weights = {k: 0 for k in ['s0', 's1', 's2', 's3', 's4', 't1', 't2', 't3', 't4', 't_combined', 'c3']}
    
    global_dist = defaultdict(lambda: Counter())

    import multiprocessing as mp
    
    args_list = [(h, entries, split_dir, vocab) for h in TARGET_HOSTS]
    
    with mp.Pool(processes=min(len(TARGET_HOSTS), mp.cpu_count())) as pool:
        results = pool.starmap(process_host, args_list)
        
    for res in results:
        host, leakage, host_dist, col = res
        
        for k in total_leakage:
            total_leakage[k] += leakage[k]
            
        for k in host_dist:
            global_dist[k].update(host_dist[k])
            
        for k in col:
            col_sums[k] += col[k][0]
            col_weights[k] += col[k][1]

    def get_percentiles(counter):
        if not counter:
            return {}
        total = sum(counter.values())
        items = sorted(counter.items())
        res = {'min': items[0][0], 'max': items[-1][0]}
        
        def find_p(target):
            curr = 0
            for val, count in items:
                curr += count
                if curr >= target:
                    return val
            return items[-1][0]
            
        res['p25'] = find_p(total * 0.25)
        res['median'] = find_p(total * 0.5)
        res['p75'] = find_p(total * 0.75)
        res['p95'] = find_p(total * 0.95)
        return res

    dist_stats = {}
    for k, v in global_dist.items():
        dist_stats[k] = get_percentiles(v)

    with open(OUTPUT_DIR / 'leakage_report.json', 'w') as f:
        if total_leakage['test_events'] > 0:
            for k in list(total_leakage.keys()):
                if k != 'test_events':
                    total_leakage[k + '_pct'] = round(total_leakage[k] / total_leakage['test_events'], 4)
        json.dump(total_leakage, f, indent=2)

    with open(OUTPUT_DIR / 'feature_distribution.json', 'w') as f:
        json.dump(dist_stats, f, indent=2)
        
    def avg_collision(key):
        return col_sums[key] / col_weights[key] if col_weights[key] > 0 else 0

    with open(OUTPUT_DIR / 'ablation_report.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Representation', 'Average Per-Host Collision Rate'])
        writer.writerow(['Current (S0)', avg_collision('s0')])
        writer.writerow(['+ Actor (S1)', avg_collision('s1')])
        writer.writerow(['+ Parent (S2)', avg_collision('s2')])
        writer.writerow(['+ Parent-Child (S3)', avg_collision('s3')])
        writer.writerow(['+ Grandparent (S4)', avg_collision('s4')])
        writer.writerow(['Temporal: Total (T1)', avg_collision('t1')])
        writer.writerow(['Temporal: Object Counts (T2)', avg_collision('t2')])
        writer.writerow(['Temporal: Action Counts (T3)', avg_collision('t3')])
        writer.writerow(['Temporal: Unique Entities (T4)', avg_collision('t4')])
        writer.writerow(['Temporal: T1+T3 (T_Combined)', avg_collision('t_combined')])
        writer.writerow(['Context: Lineage S3 + T_Combined (C3)', avg_collision('c3')])

if __name__ == '__main__':
    main()
