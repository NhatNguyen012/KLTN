import json
import csv
from pathlib import Path

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')
INPUT_RAW = PROJECT_ROOT / 'code/output/audits/mission4/raw_event_examples.jsonl'
OUT_JSONL = PROJECT_ROOT / 'code/output/audits/mission4/mixed_exact_semantic_comparison.jsonl'
OUT_CSV = PROJECT_ROOT / 'code/output/audits/mission4/ab_breakdown.csv'

def get_key_fields(obj_type, record):
    props = record.get('properties', {})
    if obj_type == 'PROCESS':
        return {
            'image_path': props.get('image_path', '').casefold(),
            'parent_image_path': props.get('parent_image_path', '').casefold(),
            'command_line': props.get('command_line', '').casefold()
        }
    elif obj_type == 'MODULE':
        return {
            'image_path': props.get('image_path', '').casefold(),
            'module_path': props.get('module_path', '').casefold()
        }
    elif obj_type == 'FILE':
        return {
            'image_path': props.get('image_path', '').casefold(),
            'file_path': props.get('file_path', '').casefold(),
            'new_path': props.get('new_path', '').casefold()
        }
    elif obj_type == 'SHELL':
        return {
            'payload': props.get('payload', '').casefold()
        }
    elif obj_type == 'REGISTRY':
        return {
            'image_path': props.get('image_path', '').casefold(),
            'key_path': props.get('key_path', '').casefold(),
            'value_name': props.get('value_name', '').casefold(),
            'value': props.get('value', '').casefold()
        }
    elif obj_type == 'TASK':
        return {
            'image_path': props.get('image_path', '').casefold(),
            'task_name': props.get('task_name', '').casefold(),
            'task_path': props.get('task_path', '').casefold(),
            'command': props.get('command', '').casefold()
        }
    else:
        # Fallback to comparing all properties
        return {k: str(v).casefold() for k, v in props.items()}

def is_equivalent(fields1, fields2):
    # Simply check if all keys have the same values
    return fields1 == fields2

def main():
    with open(INPUT_RAW) as f:
        lines = [json.loads(l) for l in f]

    results = []
    cat_counts = {'A': 0, 'B': 0, 'D': 0, 'UNRESOLVED': 0}
    field_diffs = [] # list of (Object, Field, ErrorType)

    with open(OUT_JSONL, 'w') as out_f:
        for item in lines:
            test_ev = item.get('test_raw_event')
            if not test_ev:
                continue
                
            b_cnt = item['benign_count_in_train']
            m_cnt = item['malicious_count_in_train']
            t_label = item['test_label']
            err_type = item['test_error_type']
            
            obj_type = test_ev.get('object', '').upper()
            test_fields = get_key_fields(obj_type, test_ev)
            
            # Determine category logic
            is_mixed = b_cnt > 0 and m_cnt > 0
            is_contradiction = (t_label == 0 and b_cnt > 0 and m_cnt == 0) or (t_label == 1 and m_cnt > 0 and b_cnt == 0)
            is_logical_ab = (t_label == 1 and b_cnt > 0 and m_cnt == 0) or (t_label == 0 and m_cnt > 0 and b_cnt == 0)
            
            matched_opposite = None
            diff_keys = set()
            category = 'UNRESOLVED'
            
            if is_contradiction:
                category = 'D'
            elif is_mixed or is_logical_ab:
                opposite_events = item['train_benign_events'] if t_label == 1 else item['train_malicious_events']
                
                if not opposite_events or not opposite_events[0]:
                    category = 'UNRESOLVED'
                else:
                    # Default to A if we have opposite events, since they might differ
                    category = 'A'
                    
                    # We will collect the fields that differ from the first opposite event
                    opp_fields = get_key_fields(obj_type, opposite_events[0])
                    matched_opposite = opp_fields
                    for k in test_fields:
                        if test_fields[k] != opp_fields.get(k):
                            diff_keys.add(k)
                            
                    for opp_ev in opposite_events:
                        if not opp_ev: continue
                        curr_opp_fields = get_key_fields(obj_type, opp_ev)
                        if is_equivalent(test_fields, curr_opp_fields):
                            category = 'B'
                            matched_opposite = curr_opp_fields
                            diff_keys = set() # No differences if there's a perfect match
                            break
                            
                    if category == 'A' and len(diff_keys) == 0:
                        # Safety check: if there are no differences but it wasn't caught by is_equivalent, 
                        # maybe there's a field present in opp_fields but missing in test_fields?
                        for k in opp_fields:
                            if opp_fields[k] != test_fields.get(k):
                                diff_keys.add(k)
                        if len(diff_keys) == 0:
                            category = 'B'
                            matched_opposite = opp_fields

            cat_counts[category] += 1
            if category == 'A':
                for k in diff_keys:
                    field_diffs.append((obj_type, k, err_type))
            
            res = {
                'source_id': item['test_error_id'],
                'test_label': t_label,
                'test_error_type': err_type,
                'object': obj_type,
                'train_label_distribution': {'benign': b_cnt, 'malicious': m_cnt},
                'test_fields': test_fields,
                'matched_opposite_fields': matched_opposite,
                'category': category,
                'diff_fields': list(diff_keys)
            }
            results.append(res)
            out_f.write(json.dumps(res) + '\n')

    # Aggregate field differences
    diff_counts = {}
    for obj, field, err in field_diffs:
        key = (obj, field, err)
        diff_counts[key] = diff_counts.get(key, 0) + 1
        
    FIELD_CSV = PROJECT_ROOT / 'code/output/audits/mission4/verified_field_loss_breakdown.csv'
    with open(FIELD_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Object', 'Field', 'Error_Type', 'Affected_Errors'])
        for (obj, field, err), count in sorted(diff_counts.items()):
            writer.writerow([obj, field, err, count])

    # Write CSV summary
    OUT_133 = PROJECT_ROOT / 'code/output/audits/mission4/exact_133_root_cause.csv'
    with open(OUT_133, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Error_ID', 'Test_Label', 'Error_Type', 'Object', 'Train_Benign', 'Train_Malicious', 'Category', 'Diff_Fields'])
        for r in results:
            writer.writerow([
                r['source_id'], r['test_label'], r['test_error_type'], r['object'], 
                r['train_label_distribution']['benign'], r['train_label_distribution']['malicious'], 
                r['category'], "|".join(r['diff_fields'])
            ])

    print(f"Total Exact Matches analyzed: {len(results)}")
    for cat, cnt in cat_counts.items():
        print(f"Category {cat}: {cnt}")

if __name__ == '__main__':
    main()
