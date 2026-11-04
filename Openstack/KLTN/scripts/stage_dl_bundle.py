#!/usr/bin/env python3
"""Stage an eligible Network DL bundle and atomically switch the local pointer.

The script does not restart containers. The operator can inspect the staged
release before explicitly recreating ``dl-prep``.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import tempfile

from prepare_central import ROOT
from verify_model_bundle import verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bundle', type=Path)
    args = parser.parse_args()
    source = args.bundle.resolve()
    manifest = verify(source, branch='network_dl', require_eligible=True)
    model_root = ROOT / 'runtime/models/dl'
    releases = model_root / 'releases'
    releases.mkdir(parents=True, exist_ok=True)
    destination = releases / manifest['bundle_id']
    if destination.exists():
        verify(destination, branch='network_dl', require_eligible=True)
    else:
        with tempfile.TemporaryDirectory(prefix=manifest['bundle_id'] + '.', dir=releases) as temp:
            staging = Path(temp)
            shutil.copytree(source, staging, dirs_exist_ok=True)
            verify(staging, branch='network_dl', require_eligible=True)
            staging.rename(destination)
    link = model_root / 'current'
    temporary_link = model_root / '.current.next'
    if temporary_link.exists() or temporary_link.is_symlink():
        temporary_link.unlink()
    temporary_link.symlink_to(Path('releases') / manifest['bundle_id'], target_is_directory=True)
    temporary_link.replace(link)
    print(f"Staged {manifest['bundle_id']}. Inspect it, then explicitly recreate dl-prep.")


if __name__ == '__main__':
    main()
