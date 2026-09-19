#!/usr/bin/env python3
"""Build/resume the common TRAIN sample once, without fitting any model."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from host_training_runtime import TrainingDataset, cpu_budget, prepare_sample


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--rows',type=int,default=100_000_000)
    parser.add_argument('--workers',type=int,default=None)
    parser.add_argument('--max-nnz',type=int,default=1_800_000_000)
    args=parser.parse_args(argv)
    meta=json.loads(args.manifest.read_text())
    used={p['volume'] for p in meta['shards']}
    packaged=all((args.manifest.parent/'volumes'/key).is_dir() for key in used)
    roots={key:args.manifest.parent/'volumes'/key for key in meta['volumes']} if packaged else None
    data=TrainingDataset(args.manifest,roots)
    workers=min(4,cpu_budget()) if args.workers is None else cpu_budget(args.workers)
    prepare_sample(data,args.output_dir,target_rows=args.rows,seed=1,workers=workers,max_nnz=args.max_nnz)
    return 0


if __name__=='__main__':raise SystemExit(main())
