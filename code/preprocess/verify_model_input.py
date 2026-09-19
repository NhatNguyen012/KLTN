#!/usr/bin/env python3
"""Verify completed compressed model input without materializing a full split."""
import argparse
import json
from pathlib import Path
from host_shards import HostShardDataset,decode_shard,sha256


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--volume',action='append',default=[],metavar='ID=PATH',help='relocate a volume after copying/uploading')
    parser.add_argument('--decode',action='store_true',help='also reconstruct and validate each shard, one at a time')
    args=parser.parse_args(argv)
    roots={}
    for item in args.volume:
        key,sep,path=item.partition('=')
        if not sep or not path:raise ValueError('expected ID=PATH')
        roots[key]=path
    data=HostShardDataset(args.manifest,roots)
    for i,part in enumerate(data.meta['shards'],1):
        path=data.path_for(part)
        if args.decode:decode_shard(path,data.width,part)
        elif path.stat().st_size!=part['bytes'] or sha256(path)!=part['sha256']:raise ValueError(f'corrupt shard: {path}')
        if i%100==0:print(f'[{i}/{len(data.meta["shards"])}] verified',flush=True)
    print(json.dumps(dict(verified_shards=len(data.meta['shards']),split_sha256=data.meta['split_sha256'],
        splits=data.meta['splits'],consolidated_csr_GiB={s:data.csr_bytes(s)/2**30 for s in ('train','val','test')}),indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
