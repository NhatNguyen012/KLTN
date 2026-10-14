"""Embed the reviewed fast evidence-veto audit into its Kaggle notebook."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "code/provenace_graph/model/evidence_veto_runtime.py"
TARGET = ROOT / "code/kaggle/notebooks/lgbm_v4_evidence_veto.ipynb"


def cell(kind, source):
    return dict(cell_type=kind, metadata={}, source=source.splitlines(keepends=True),
                **({"execution_count": None, "outputs": []} if kind == "code" else {}))


def main():
    setup = '''from pathlib import Path
import hashlib, json, sys, tarfile

INPUT = Path('/kaggle/input')
WORK = Path('/kaggle/working/evidence_veto_workspace')
WORK.mkdir(parents=True, exist_ok=True)

def unique_archive(name):
    matches = sorted(INPUT.glob('**/' + name))
    if len(matches) != 1:
        raise RuntimeError(f'Expected one {name} under /kaggle/input; found {len(matches)}')
    return matches[0]

def extract_safe(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:*') as tar:
        for member in tar:
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()) or not (member.isfile() or member.isdir()):
                raise ValueError(f'Unsafe archive member: {member.name}')
            if member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, target.open('wb') as dst:
                    while block := src.read(1 << 20):
                        dst.write(block)

def find_or_extract(marker, valid, archive_name, destination):
    # Kaggle datasets may already expose extracted archive contents. Prefer
    # those layouts, as the approved Host dataset does on the user's mount.
    extracted = sorted({p.parent for p in INPUT.glob('**/' + marker) if valid(p.parent)})
    if len(extracted) == 1:
        return extracted[0]
    if len(extracted) > 1:
        raise RuntimeError(f'Ambiguous extracted {marker}: {extracted}')
    archive = unique_archive(archive_name)
    extract_safe(archive, destination)
    if not valid(destination):
        raise ValueError(f'{archive_name} does not contain the expected {marker} layout')
    return destination

host = find_or_extract('manifest.json',
    lambda p: (p / 'assets/vocab.json').is_file() and (p / 'assets/split_manifest.json').is_file()
              and (p / 'volumes/ssd').is_dir(), 'host-input.tar', WORK / 'host')
bundle = find_or_extract('bundle_manifest.json',
    lambda p: (p / 'provenance/graph.sqlite').is_file()
              and (p / 'provenance/model_numpy.npz').is_file()
              and (p / 'code/cascade_runtime.py').is_file(),
    'provenance-cascade-bundle-v4.tar.gz', WORK / 'bundle')
extra = find_or_extract('package_manifest.json',
    lambda p: (p / 'previous/frozen_policy.json').is_file()
              and (p / 'cache/cache_manifest.json').is_file(),
    'v4-evidence-veto-input.tar.gz', WORK / 'evidence')
package = json.loads((extra / 'package_manifest.json').read_text())
if package['schema'] != 1:
    raise ValueError('Evidence input package schema mismatch')
for name, expected in package['files'].items():
    path = (extra / name).resolve()
    if not path.is_relative_to(extra.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f'Evidence input hash mismatch: {name}')
sys.path.insert(0, str(bundle / 'code'))
sys.path.insert(0, str(host))
print('Frozen inputs verified:', host, bundle, extra)
'''
    embedded = "runtime_source = " + repr(SOURCE.read_text()) + "\n"
    embedded += "runtime_path = WORK / 'evidence_veto_runtime.py'\n"
    embedded += "runtime_path.write_text(runtime_source)\n"
    embedded += "sys.path.insert(0, str(WORK))\n"
    embedded += "from evidence_veto_runtime import run\n"
    execute = '''output = Path('/kaggle/working/evidence_veto_v4_results')
result = run(host / 'manifest.json', bundle, extra / 'previous', extra / 'cache', output,
             volume_root_ssd=host / 'volumes/ssd')
print((output / 'summary.md').read_text())
'''
    package_cell = '''import zipfile
zip_path = Path('/kaggle/working/lgbm_v4_evidence_veto_results.zip')
with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    for path in sorted(output.iterdir()):
        if path.is_file():
            z.write(path, arcname=path.name)
print('Download:', zip_path)
'''
    nb = dict(nbformat=4, nbformat_minor=5, metadata={"kernelspec": {
        "display_name": "Python 3", "language": "python", "name": "python3"}},
        cells=[cell("markdown", "# LightGBM v4: evidence-gated GraphSAGE veto\n\n"
            "CPU-friendly audit of frozen conditional routing. It scores no full TEST shards "
            "and reconstructs only 27 validation + 49 TEST veto candidates. "
            "Validation freezes the gate before TEST labels are opened.\n"),
            cell("code", setup), cell("code", embedded), cell("code", execute),
            cell("code", package_cell)])
    TARGET.write_text(json.dumps(nb, indent=1, ensure_ascii=False) + "\n")
    print(TARGET)


if __name__ == "__main__":
    main()
