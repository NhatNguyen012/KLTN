import json
import gzip
from pathlib import Path
import sys

sys.path.insert(0, 'code/preprocess')
from ecar_tokenizer import classify_command_line

families_found = set()
family_examples = {}
malicious_examples = []
encoded_found = False

def process_file(p):
    global encoded_found
    print("Processing", p)
    try:
        with gzip.open(p, 'rt') as f:
            for i, line in enumerate(f):
                if i > 50000: break
                event = json.loads(line)
                props = event.get('properties', {})
                cmd = props.get('command_line')
                img = props.get('image_path', '')
                if cmd:
                    family = classify_command_line(cmd, img)
                    if family not in families_found:
                        families_found.add(family)
                        family_examples[family] = event
                    
                    if event.get('label', 1) == 1 and len(malicious_examples) < 3:
                        is_enc = '-enc' in cmd.lower() or '-encodedcommand' in cmd.lower()
                        if is_enc and not encoded_found:
                            encoded_found = True
                            malicious_examples.append(event)
                        elif not encoded_found and len(malicious_examples) < 2:
                            malicious_examples.append(event)
                        elif encoded_found:
                            if event not in malicious_examples:
                                malicious_examples.append(event)
    except Exception as e:
        pass

process_file(list(Path('host-malicious').rglob('*.json.gz'))[0])
process_file(list(Path('host-begnin').rglob('*.json.gz'))[0])

print("=== FAMILIES ===")
for f, ev in family_examples.items():
    print(f"[{f}] {ev.get('properties', {}).get('command_line')}")

print("\n=== MALICIOUS ===")
for ev in malicious_examples:
    print(f"{ev.get('properties', {}).get('command_line')}")
