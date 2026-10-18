import gzip
import json
import sys

file_path = sys.argv[1]
target_pid = int(sys.argv[2])

print(f"Tracing lineage for PID {target_pid} in {file_path}")

process_tree = {} # pid -> {ppid, image_path, command_line}

with gzip.open(file_path, 'rt') as f:
    for line in f:
        try:
            event = json.loads(line)
        except:
            continue
            
        if event.get('action') == 'START' and event.get('object') == 'PROCESS':
            pid = event.get('pid')
            process_tree[pid] = {
                'ppid': event.get('ppid'),
                'image_path': event.get('properties', {}).get('image_path', ''),
                'command_line': event.get('properties', {}).get('command_line', '')
            }

curr_pid = target_pid
lineage = []
while curr_pid in process_tree:
    info = process_tree[curr_pid]
    lineage.append(f"PID {curr_pid}: {info['image_path']} [{info['command_line']}]")
    if curr_pid == info['ppid'] or info['ppid'] == -1 or info['ppid'] == 0:
        break
    curr_pid = info['ppid']

if not lineage:
    print(f"Could not find START event for PID {target_pid} (process started before log began or missing)")
else:
    for l in reversed(lineage):
        print(" -> " + l)
