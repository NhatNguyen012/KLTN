"""Generate the isolated Event-node v5a Kaggle GPU training notebook."""
from __future__ import annotations

import json
from pathlib import Path

TARGET = Path(__file__).resolve().with_name('provenance_event_v5a_gpu.ipynb')


def cell(kind, source):
    result = dict(cell_type=kind, metadata={}, source=source.splitlines(keepends=True))
    if kind == 'code':
        result.update(execution_count=None, outputs=[])
    return result


SETUP = '''from pathlib import Path
import json, sys, tarfile

INPUT = Path('/kaggle/input')
WORK = Path('/kaggle/working/event-v5a-cache')

def valid_cache(path):
    manifest = path / 'manifest.json'
    if not manifest.is_file() or not (path / 'train_event_gpu.py').is_file():
        return False
    try:
        meta = json.loads(manifest.read_text())
    except (OSError, ValueError):
        return False
    return meta.get('format') == 'optc_event_ego_npz' and meta.get('schema') == 2 and meta.get('complete') is True

matches = sorted({p.parent for p in INPUT.glob('**/manifest.json') if valid_cache(p.parent)})
if len(matches) == 1:
    CACHE = matches[0]
elif not matches:
    archives = sorted(INPUT.glob('**/provenance-event-v5a-cache.tar'))
    if len(archives) != 1:
        raise RuntimeError(f'Attach exactly one Event v5a cache dataset; archives found: {len(archives)}')
    WORK.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archives[0], 'r') as tar:
        for member in tar:
            destination = (WORK / member.name).resolve()
            if not destination.is_relative_to(WORK.resolve()) or not member.isfile():
                raise ValueError(f'Unsafe cache archive member: {member.name}')
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, destination.open('wb') as target:
                while block := source.read(1 << 20):
                    target.write(block)
    CACHE = WORK
else:
    raise RuntimeError(f'Ambiguous Event v5a cache datasets: {matches}')

sys.path.insert(0, str(CACHE))
from event_ego_cache import load_manifest
_, meta = load_manifest(CACHE)
print('Event v5a cache:', CACHE)
print('Graph sample:', meta['splits'])
print('Node features:', len(meta['attributes']), 'Edge types:', meta['relations'])
import torch
print('PyTorch:', torch.__version__, 'CUDA:', torch.cuda.is_available())
if not torch.cuda.is_available():
    raise RuntimeError('Enable a Kaggle GPU accelerator before training Event v5a.')
'''

TRAIN = '''import subprocess
OUTPUT = Path('/kaggle/working/provenance-event-v5a-model')
EPOCHS = 30
BATCH_SIZE = 128
RESUME = False
command = [sys.executable, str(CACHE / 'train_event_gpu.py'), '--cache', str(CACHE),
           '--output', str(OUTPUT), '--epochs', str(EPOCHS), '--batch-size', str(BATCH_SIZE),
           '--device', 'cuda', '--evaluate-test']
if RESUME:
    command.append('--resume')
subprocess.run(command, check=True)
'''

EXPORT = '''import zipfile
metrics = json.loads((OUTPUT / 'metrics.json').read_text())
print(json.dumps(metrics, indent=2))
archive = Path('/kaggle/working/provenance_event_v5a_results.zip')
with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zip_out:
    for name in ('config.json', 'metrics.json', 'progress.json', 'model_numpy.npz', 'checkpoint.pt'):
        path = OUTPUT / name
        if path.is_file():
            zip_out.write(path, arcname=name)
    zip_out.write(CACHE / 'manifest.json', arcname='cache_manifest.json')
print('Download:', archive)
'''


def main():
    nb = dict(nbformat=4, nbformat_minor=5, metadata={'kernelspec': {
        'display_name': 'Python 3', 'language': 'python', 'name': 'python3'}},
        cells=[cell('markdown', '# Event-only v5a GraphSAGE training\n\n'
                    'Adds one target Event node (action/object) and two directed message-passing '
                    'edges to each frozen Process/Host ego graph. Same seed02 sampled rows as the '
                    'original graph cache. This trains a **new** checkpoint; the v4 model and '
                    'LightGBM remain unchanged. Validation selects the threshold before TEST.\n'),
               cell('code', SETUP), cell('code', TRAIN), cell('code', EXPORT)])
    TARGET.write_text(json.dumps(nb, ensure_ascii=False, indent=1)+'\n')
    print(TARGET)


if __name__ == '__main__':
    main()
