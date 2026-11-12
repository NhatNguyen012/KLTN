#!/usr/bin/env python3
"""Separate current-process training targets; never attached to graph features."""
import csv
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
import torch

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/'model')]
from research_paths import validate_output_dir


def main():
    root=validate_output_dir(DL/'output/process_graph_20261111');out=root/'process_supervision.pt'
    if out.exists():raise FileExistsError(out)
    source=DL/'output/research_20261111/raw_audit/positive_events.csv'
    with source.open() as f:positive={(r['source'],int(r['line'])):r for r in csv.DictReader(f)}
    data={};stats={}
    for split in ['train','val','test']:
        items=torch.load(root/'data'/f'{split}.pt',weights_only=False)
        counts=np.zeros(4,int);unknown=0;unassigned=0
        for item in items:
            n=item['features']['central_count'];keys=item['audit']['node_ids'][:n]
            targets=np.zeros((n,4),np.float32);mask=np.ones(n,bool);ambiguous=set()
            by_guid={guid:i for i,(host,guid) in enumerate(keys)}
            for ln in item['source_lines']:
                p=positive.get((item['source'],ln))
                if not p:continue
                i=by_guid.get(p['process_guid'])
                if i is None:unassigned+=1;continue
                if ln in item['targets']['uncertain_source_lines']:ambiguous.add(i);continue
                stage=int(p['stage'])
                if 1<=stage<=4:targets[i,stage-1]=1
            for i in ambiguous:
                if not targets[i].any():mask[i]=False
            if item['targets']['reason']=='invalid_s3_time_gate':mask[:]=False
            data[item['sample_id']]=dict(stage_target=targets,mask=mask)
            counts+=targets.sum(0).astype(int);unknown+=int(sum(~mask))
        stats[split]=dict(stage_positive_process_instances=counts.tolist(),masked_process_instances=unknown,unassigned_positive_events=unassigned)
    torch.save(data,out.with_suffix('.pt.tmp'));out.with_suffix('.pt.tmp').replace(out)
    (root/'process_supervision_metadata.json').write_text(json.dumps(dict(stats=stats,
        source_positive_events_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        data_identity_sha256=hashlib.sha256((root/'data/metadata.json').read_bytes()).hexdigest(),
        contract='Current-event actor annotations used as weak loss targets only; no ancestor/neighbor labels, unknowns masked, no changed features'),indent=2))
    print(json.dumps(stats,indent=2),flush=True)


if __name__=='__main__':main()
