#!/usr/bin/env python3
"""Generate the parent-context LightGBM notebook; retain the historical cascade separately."""
import hashlib
import json
from pathlib import Path
from refresh_host_notebooks import notebook

CODE = Path(__file__).resolve().parents[2]
SPLIT = CODE/'output/host_ml_seed02/split/manifest.json'

def generate():
    split_sha = hashlib.sha256(SPLIT.read_bytes()).hexdigest()
    n = notebook('lgbm', 'kaggle', (CODE/'kaggle/host_training_runtime.py').read_text())
    n['cells'][0]['source'] = ['''# LightGBM — parent context, frozen seed02

TRAIN-only vocabulary includes event + actor/parent context; binary sparse shards.
No graph model or graph threshold is used. TRAIN sampling seed remains 1;
frozen split seed remains 02. Validation selects the F1 threshold; TEST uses that
frozen threshold on the full TEST partition. The previous 0.986933 F1 belongs to
the archived cascade experiment, not an expected score for this model.

Attach the new parent-context input archive (or extracted dataset). Never attach
baseline shards as substitutes. Output/sample directories are isolated by input identity.
Training runs on Kaggle, not during local preprocessing.

The historical notebook is preserved as `lgbm_graphsage_post_sweep_archived.ipynb`.
Parent context uses prior telemetry, including background events; UUIDs identify
state but are not vocabulary features. This frozen random-event split does not
establish generalization to unseen processes, hosts or campaigns.
''']
    setup = ''.join(n['cells'][1]['source'])
    setup = setup.replace("roots = [Path('/kaggle/input')] if Path('/kaggle/input').exists() else [Path.cwd() / 'code/output/host_ml_seed02/model_input']", "roots = ([Path('/kaggle/input'), Path('/kaggle/working/parent_context_input')] if Path('/kaggle/input').exists() else [Path.cwd() / 'ML/code/output/host_ml_parent_incoming_seed02/model_input'])")
    setup = setup.replace("candidate.get('format') == 'host_binary_delta_npz':", "candidate.get('format') == 'host_binary_delta_npz' and (candidate.get('context_policy') or {}).get('enabled'):")
    guard = f'''\n# Require the new experiment, even when OPTC_MANIFEST is explicitly supplied.
_input_meta = json.loads(MANIFEST.read_text())
if not (_input_meta.get('context_policy') or {{}}).get('incoming_enabled'):
    raise ValueError('Rebuild required: typed incoming context shards expected')
if not (_input_meta.get('context_policy') or {{}}).get('enabled'):
    raise ValueError('Parent-context shards required; baseline shards are not compatible')
if _input_meta.get('split_sha256') != {split_sha!r}:
    raise ValueError('Input is not the approved frozen seed02 split')
_experiment = 'parent-context-seed02-' + _input_meta['vocabulary_sha256'][:12]
OUTPUT_ROOT = OUTPUT_ROOT / _experiment
SAMPLE_DIR = OUTPUT_ROOT / 'train-neg30-sampling-seed01'
'''
    setup = setup.replace('sys.path.insert(0, str(MANIFEST.parent))', guard+'\nsys.path.insert(0, str(MANIFEST.parent))')
    n['cells'][1]['source'] = setup.splitlines(keepends=True)
    # An uploaded tar can be extracted once; the usual manifest discovery then works.
    unpack = '''# Optional portable archive input. Skip this cell when the dataset is extracted.
from pathlib import Path
import tarfile
archives = list(Path('/kaggle/input').rglob('host-input.tar')) if Path('/kaggle/input').exists() else []
if len(archives) == 1:
    target = Path('/kaggle/working/parent_context_input')
    if not (target/'manifest.json').exists():
        target.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archives[0]) as archive:
            members = archive.getmembers()
            for member in members:
                dest = (target/member.name).resolve()
                if not dest.is_relative_to(target.resolve()) or not (member.isfile() or member.isdir()):
                    raise ValueError('Unsafe archive member: ' + member.name)
            archive.extractall(target, members=members, filter='data')
elif len(archives) > 1:
    raise ValueError('Attach only the parent-context archive, or extract the intended dataset explicitly')
'''
    n['cells'].insert(1, dict(cell_type='code', metadata={}, execution_count=None, outputs=[], source=unpack.splitlines(keepends=True)))
    for cell in n['cells']:
        if cell['cell_type']=='code':
            compile(''.join(cell['source']), '<parent-context-notebook>', 'exec')
    return n

if __name__ == '__main__':
    (CODE/'kaggle/notebooks/lgbm.ipynb').write_text(json.dumps(generate(), indent=1)+'\n')
