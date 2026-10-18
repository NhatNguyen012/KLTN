#!/usr/bin/env python3
import json
import gzip
from collections import defaultdict
from pathlib import Path
import argparse
import sys

PROJECT_ROOT = Path('/mnt/SSD_Data/optc')

def get_raw_event(day, host, source_line):
    # Search in both malicious and benign directories
    for root_dir in [PROJECT_ROOT / 'host-malicious', PROJECT_ROOT / 'host-begnin']:
        for path in root_dir.rglob(f'*{host}*.json.gz'):
            if day in str(path):
                # Found the file
                with gzip.open(path, 'rt', encoding='utf-8') as f:
                    for i, line in enumerate(f, 1):
                        if i == source_line:
                            return json.loads(line)
    return None

def main():
    parser = argparse.ArgumentParser(description='Extract raw JSON for failed events from Kaggle test_errors.json')
    parser.add_argument('--test-errors', type=Path, required=True, help='Path to test_errors.json from Kaggle')
    parser.add_argument('--output-dir', type=Path, default=PROJECT_ROOT / 'code/output/audits', help='Output directory')
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(args.test_errors) as f:
        data = json.load(f)
        
    examples = data.get('examples', [])
    if not examples:
        print("No examples found in test_errors.json")
        sys.exit(0)
        
    audit_results = []
    
    print(f"Extracting raw JSON for {len(examples)} failed events...")
    
    # Group by file to avoid opening the same file multiple times
    by_file = defaultdict(list)
    for ex in examples:
        by_file[(ex['day'], ex['host'])].append(ex)
        
    for (day, host), events in by_file.items():
        # Sort by line number so we can do a single pass
        events.sort(key=lambda x: x['source_line'])
        line_to_event = {ex['source_line']: ex for ex in events}
        
        found = 0
        for root_dir in [PROJECT_ROOT / 'host-malicious', PROJECT_ROOT / 'host-begnin']:
            for path in root_dir.rglob(f'*{host}*.json.gz'):
                if day in str(path):
                    with gzip.open(path, 'rt', encoding='utf-8') as f:
                        for i, line in enumerate(f, 1):
                            if i in line_to_event:
                                ex = line_to_event[i]
                                raw = json.loads(line)
                                audit_results.append({
                                    'error_type': ex['error'],
                                    'score': ex['score'],
                                    'day': day,
                                    'host': host,
                                    'line': i,
                                    'raw_event': raw,
                                    'tokens': ex['tokens']
                                })
                                found += 1
                                if found == len(events):
                                    break
                if found == len(events):
                    break
            if found == len(events):
                break
                
    out_json = args.output_dir / 'failed_events_audit.json'
    with open(out_json, 'w') as f:
        json.dump(audit_results, f, indent=2)
        
    out_md = args.output_dir / 'failed_events_report.md'
    with open(out_md, 'w') as f:
        f.write("# Failed Events Audit Report\n\n")
        
        fns = [x for x in audit_results if x['error_type'] == 'FN']
        fps = [x for x in audit_results if x['error_type'] == 'FP']
        
        f.write(f"Total False Negatives (Missed Attacks): {len(fns)}\n")
        f.write(f"Total False Positives (False Alarms): {len(fps)}\n\n")
        
        for e_type, events in [('False Negatives', fns), ('False Positives', fps)]:
            f.write(f"## {e_type}\n\n")
            for ex in events:
                f.write(f"### {ex['host']} - {ex['day']} - Line {ex['line']}\n")
                f.write(f"**Score:** {ex['score']:.4f}\n\n")
                f.write("**Tokens seen by model:**\n")
                f.write("```json\n")
                f.write(json.dumps(ex['tokens'], indent=2) + "\n")
                f.write("```\n\n")
                f.write("**Raw Event Telemetry:**\n")
                f.write("```json\n")
                f.write(json.dumps(ex['raw_event'], indent=2) + "\n")
                f.write("```\n\n")
                f.write("---\n\n")
                
    print(f"Extraction complete! Saved to {out_json} and {out_md}")

if __name__ == '__main__':
    main()
