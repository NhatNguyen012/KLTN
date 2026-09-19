import json
found = 0
with open("code/output/audits/mission4/raw_event_examples.jsonl", "r") as f:
    for line in f:
        d = json.loads(line)
        cmd = d['test_raw_event']['properties'].get('command_line')
        if cmd:
            print(f"Error {found+1}: {d['test_error_type']} (True={d['test_label']}, Category={d.get('category')})")
            print("Raw:", cmd)
            print("Diff:", d.get('diff_fields', []))
            found += 1
        if found >= 5: break
