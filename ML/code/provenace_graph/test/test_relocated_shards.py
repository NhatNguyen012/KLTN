import tempfile
import unittest
from pathlib import Path

import numpy as np

from ML.code.provenace_graph.model.train import resolve_volume_roots,sampled_rows
from ML.code.provenace_graph.preprocess.common import sha
from ML.code.provenace_graph.preprocess.graph import connect


class RelocatedShardTests(unittest.TestCase):
    def test_discovers_volume_from_nested_manifest_relative_shard(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mounted-dataset'
            manifest = mount / 'manifest.json'
            relative = Path('source-id') / 'split-id' / 'train_000000.npz'
            shard = mount / 'payload' / 'ssd' / relative
            shard.parent.mkdir(parents=True)
            shard.touch()
            meta = {'volumes': {'ssd': '/old/machine/ssd'},
                    'shards': [{'volume': 'ssd', 'path': str(relative)}]}
            roots = resolve_volume_roots(manifest, meta)
            self.assertEqual(roots['ssd'], (mount / 'payload' / 'ssd').resolve())

    def test_prefers_standard_volume_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mounted-dataset'
            root = mount / 'volumes' / 'ssd'
            shard = root / 'id' / 'train.npz'
            shard.parent.mkdir(parents=True)
            shard.touch()
            meta = {'volumes': {'ssd': '/old/machine/ssd'},
                    'shards': [{'volume': 'ssd', 'path': 'id/train.npz'}]}
            roots = resolve_volume_roots(mount / 'manifest.json', meta)
            self.assertEqual(roots['ssd'], root.resolve())

    def test_unused_configured_volume_does_not_need_to_be_mounted(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mounted-dataset'
            root = mount / 'volumes' / 'ssd'
            shard = root / 'id' / 'train.npz'
            shard.parent.mkdir(parents=True)
            shard.touch()
            meta = {'volumes': {'ssd': '/old/machine/ssd', 'hdd': '/old/machine/hdd'},
                    'shards': [{'volume': 'ssd', 'path': 'id/train.npz'}]}
            roots = resolve_volume_roots(mount / 'manifest.json', meta)
            self.assertEqual(roots['ssd'], root.resolve())
            self.assertEqual(roots['hdd'], Path('/old/machine/hdd'))

    def test_sampled_rows_looks_up_only_reservoir_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);shards=[]
            for index,labels in enumerate(([0,1,0,1],[1,0,0,1])):
                path=root/f'shard-{index}.npz'
                np.savez_compressed(path,label=np.asarray(labels,dtype=np.uint8),
                                    source_line_delta=np.ones(len(labels),dtype='<u8'))
                shards.append(dict(split='train',volume='ssd',path=path.name,source_id=f's{index}',
                                   rows=len(labels),sha256=sha(path)))
            data=type('Dataset',(),{'meta':{'shards':shards},'path_for':lambda _,part:root/part['path']})()
            db=connect(root/'graph.sqlite')
            for part in shards:
                for line in range(1,part['rows']+1):
                    db.execute('INSERT INTO target VALUES (?,?,?,?,?,?)',(part['source_id'],line,'h','p',line,1))
            db.commit()
            selected,info=sampled_rows(data,db,'train',4,seed=7,balanced=True)
            self.assertEqual(len(selected),4)
            self.assertEqual(info['selected'],[2,2])
            self.assertEqual({row[3] for row in selected},{0,1})
            self.assertTrue(all(row[4] in {'s0','s1'} and 1<=row[5]<=4 for row in selected))
            db.close()


if __name__ == '__main__':
    unittest.main()
