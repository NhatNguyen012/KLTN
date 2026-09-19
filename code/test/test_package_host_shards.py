"""Portable packaging preserves every row and fails before publishing bad input."""
import ast
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from host_shards import FORMAT, SCHEMA, HostShardDataset, ShardBuffer, sha256
from pipeline_contract import PROJECT_ROOT

CODE = Path(__file__).resolve().parent
sys.path.insert(0, str(CODE/'kaggle'))
from package_host_shards import main, NOTEBOOKS, safe_name


def fixture(base):
    source = base / 'source'
    source.mkdir()
    assets = source / 'assets'
    assets.mkdir()
    (assets/'vocab.json').write_text(json.dumps({'a': 0, 'b': 1, 'c': 2}))
    vocab_sha = sha256(assets/'vocab.json')
    (assets/'vocab_metadata.json').write_text(json.dumps(
        dict(split_sha256='split-fixture', vocabulary_sha256=vocab_sha)))
    for name in ('host_shards.py', 'shard_metrics.py'):
        shutil.copyfile(CODE/name, source/name)
    roots = {name: str(base/name) for name in ('ssd', 'hdd', 'unused')}
    parts = []
    totals = {}
    for i, split in enumerate(('train', 'val', 'test')):
        buffer = ShardBuffer(3)
        buffer.append([0, 2], 0, 2)
        buffer.append([1], 1, 9)
        blob, meta = buffer.encode()
        volume = 'hdd' if i == 1 else 'ssd'
        part = dict(meta, split=split, source_id='source1', volume=volume,
                    path=f'{"a"*64}/{"b"*64}/{split}_000000.npz')
        target = Path(roots[volume])/part['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        parts.append(part)
        totals[split] = {key: meta[key] for key in ('rows', 'nnz', 'label_0', 'label_1', 'bytes')}
    manifest = dict(format=FORMAT, schema=SCHEMA, complete=True, vocab_size=3,
                    split_sha256='split-fixture', vocabulary_sha256=vocab_sha,
                    volumes=roots, sources=[dict(source_id='source1')], shards=parts,
                    assets_sha256={name: sha256(assets/name) for name in ('vocab.json', 'vocab_metadata.json')},
                    builder_sha256={'host_shards.py': sha256(source/'host_shards.py')}, splits=totals)
    (source/'manifest.json').write_text(json.dumps(manifest))
    (source/'checkpoints').mkdir()
    (source/'checkpoints/do-not-upload.json').write_text('{}')
    (Path(roots['ssd'])/'orphan.npz').write_bytes(b'do not upload')
    return source/'manifest.json'


class PackageTests(unittest.TestCase):
    def test_archive_roundtrip_and_notebook_setup_after_relocation(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base = Path(tmp)
            manifest = fixture(base)
            before = sha256(manifest)
            output = base/'upload'
            args = ['--manifest', str(manifest), '--output-dir', str(output), '--reserve-free-gib', '0']
            self.assertEqual(main(args+['--dry-run']), 0)
            self.assertFalse(output.exists())
            self.assertEqual(main(args), 0)
            report = json.loads((output/'package_report.json').read_text())
            self.assertEqual(report['checksum_checked_shards'], 3)
            self.assertEqual(report['archive_sha256'], sha256(output/'host-input.tar'))
            self.assertEqual(sha256(manifest), before)
            self.assertEqual(report['archive_format'], 'ustar')
            # Read raw headers without PAX/GNU extension support, as an upload
            # extractor might. Long shard paths must remain unique and exact.
            raw_names = []
            with (output/'host-input.tar').open('rb') as handle:
                while True:
                    block = handle.read(512)
                    if not block or block == bytes(512):
                        break
                    self.assertEqual(block[156:157], b'0')
                    name = block[:100].split(b'\0')[0].decode()
                    prefix = block[345:500].split(b'\0')[0].decode()
                    raw_names.append(f'{prefix}/{name}' if prefix else name)
                    size = int(block[124:136].strip(b'\0 '), 8)
                    handle.seek((size+511)//512*512, 1)
            self.assertEqual(len(raw_names), len(set(n.casefold() for n in raw_names)))
            with tarfile.open(output/'host-input.tar') as archive:
                self.assertEqual(raw_names, archive.getnames())
                self.assertFalse(any(m.pax_headers for m in archive))
            with self.assertRaisesRegex(ValueError, 'already exists'):
                main(args)
            self.assertEqual(report['archive_sha256'], sha256(output/'host-input.tar'))

            # Simulate Kaggle extracting the archive under an extra directory.
            mounted = base/'input/arbitrary-slug/host-input'
            with tarfile.open(output/'host-input.tar') as archive:
                members = archive.getmembers()
                self.assertTrue(all(m.isfile() for m in members))
                self.assertFalse(any('orphan' in m.name or 'checkpoints' in m.name for m in members))
                for member in members:
                    target = mounted/safe_name(member.name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
            self.assertEqual(sha256(mounted/'manifest.json'), before)
            # The original volume paths become inaccessible; relocation must work.
            (base/'ssd').rename(base/'old_ssd')
            (base/'hdd').rename(base/'old_hdd')
            for name in NOTEBOOKS:
                notebook = json.loads((mounted/name).read_text())
                cells = [''.join(cell['source']) for cell in notebook['cells'] if cell['cell_type'] == 'code']
                for cell in cells:
                    ast.parse(cell)
                setup = cells[0].replace("Path('/kaggle/input')", f'Path({str(base/"input")!r})')
                setup = setup.replace("Path('/kaggle/working')", f'Path({str(base/"working")!r})')
                scope = {}
                with patch.object(sys, 'path', list(sys.path)):
                    exec(compile(setup, name, 'exec'), scope)
                data = scope['data']
                self.assertEqual(data.manifest_path, (mounted/'manifest.json').resolve())
                for split in ('train', 'val', 'test'):
                    X, y = next(data.iter_batches(split))
                    self.assertEqual(X.toarray().tolist(), [[1, 0, 1], [0, 1, 0]])
                    self.assertEqual(y.tolist(), [0, 1])

    def test_corrupt_shard_never_publishes_package(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base = Path(tmp)
            manifest = fixture(base)
            data = HostShardDataset(manifest)
            path = data.path_for(data.meta['shards'][-1])
            payload = path.read_bytes()
            path.write_bytes(payload[:-1]+bytes([payload[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                main(['--manifest', str(manifest), '--output-dir', str(base/'upload'), '--reserve-free-gib', '0'])
            self.assertFalse((base/'upload').exists())
            self.assertFalse(list(base.glob('.upload.stage-*')))

    def test_output_guards_and_space_reserve(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            base = Path(tmp)
            manifest = fixture(base)
            for output in (manifest.parent/'upload', base/'ssd/upload', PROJECT_ROOT/'host-malicious/forbidden-upload'):
                with self.assertRaisesRegex(ValueError, 'outside source'):
                    main(['--manifest', str(manifest), '--output-dir', str(output)])
            with patch('package_host_shards.shutil.disk_usage') as usage:
                usage.return_value.free = 0
                with self.assertRaisesRegex(OSError, 'insufficient free space'):
                    main(['--manifest', str(manifest), '--output-dir', str(base/'upload')])
            self.assertFalse((base/'upload').exists())
            for unsafe in ('../escape.npz', '/absolute.npz', 'safe/../../escape.npz', 'a\\b'):
                with self.assertRaisesRegex(ValueError, 'unsafe archive'):
                    safe_name(unsafe)


if __name__ == '__main__':
    unittest.main()
