#!/usr/bin/env python3
"""Fixed-weight input interventions for error explanation, never model selection.

Removing a feature group/event changes the input distribution; these are model
sensitivity measurements, not causal explanations of the real attack.
"""
import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import sys
import numpy as np
import torch

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/'model')]
from bilstm import BiLSTMBaseline
from dataset import PackedNetworkDataset,collate_sequence_batch
from train_provenance_context import ContextDataset,collate,forward
from research_paths import validate_output_dir


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--context-run',type=Path)
    ap.add_argument('--output-dir',type=Path,default=DL/'output/provenance_context_20261111/occlusion')
    args=ap.parse_args();out=validate_output_dir(args.output_dir);out.mkdir(parents=True,exist_ok=True)
    torch.set_num_threads(2)
    base=DL/'preprocess/output';data=DL/'output/provenance_context_20261111/data'
    maps=json.loads((base/'preprocessing/network_category_maps.json').read_text())
    cards=[maps['fields'][f]['size'] for f in ['app_family','proto','resp_port_class','image_dir_class']]
    names={v:k for k,v in maps['fields']['app_family']['mapping'].items()}
    with (DL/'output/research_20261111/audit/v5_test_errors.csv').open() as f:
        cases={r['sample_id'] for r in csv.DictReader(f) if r['error_type']!='correct'}
    if args.context_run:
        ck=torch.load(args.context_run/'best_model.pt',map_location='cpu',weights_only=False)
        model=BiLSTMBaseline(categorical_cardinalities=cards,num_stages=4,context_dim=ck['context_dim'])
        model.load_state_dict(ck['model_state_dict']);ds=ContextDataset(data,'test',ck['context_columns'])
        vocab=json.loads((data/'context_metadata.json').read_text())['vocabulary'];inverse={v:k for k,v in vocab.items()}
        rows=[];model.eval()
        for i,r in enumerate(ds.rows):
            if r['sample_id'] not in cases:continue
            b=collate([ds[i]])
            with torch.no_grad():original=float(forward(model,b)[0].sigmoid()[0])
            for prefix in ['event::','parent::','incoming::','filectx::']:
                indices=[j for j,col in enumerate(ck['context_columns']) if inverse[col].startswith(prefix)]
                altered=dict(b);altered['x_context']=b['x_context'].clone();altered['x_context'][:,:,indices]=0
                with torch.no_grad():p=float(forward(model,altered)[0].sigmoid()[0])
                rows.append(dict(sample_id=r['sample_id'],intervention='remove_'+prefix,original_probability=original,
                    intervened_probability=p,original_minus_intervened=original-p))
        name=args.context_run.name+'_group_occlusion.csv'
    else:
        model=BiLSTMBaseline(categorical_cardinalities=cards,num_stages=4)
        ck=torch.load(DL/'output/local_output/local_run_v5/best_model.pt',map_location='cpu',weights_only=False)
        model.load_state_dict(ck['model_state_dict']);model.eval();ds=PackedNetworkDataset(base,'test',cache_shards=10);rows=[]
        def probability(item):
            b=collate_sequence_batch([item])
            with torch.no_grad():return float(model(**{k:b[k] for k in ['x_cat','x_num','x_num_missing','x_bin','delta_t_log1p','lengths']}).sigmoid()[0])
        for i,r in enumerate(ds.rows):
            if r['sample_id'] not in cases:continue
            item=ds[i];p=probability(item)
            for app,n in Counter(item['x_cat'][:,0].tolist()).most_common(4):
                keep=item['x_cat'][:,0]!=app
                if not keep.any():continue
                altered=dict(item)
                for key in ['x_cat','x_num','x_num_missing','x_bin','delta_t_log1p']:altered[key]=item[key][keep].copy()
                altered['event_count']=int(keep.sum())
                relative_time=np.cumsum(np.expm1(item['delta_t_log1p'].astype(np.float64)))
                kept_time=relative_time[keep]
                altered['delta_t_log1p']=np.log1p(np.r_[0.,np.diff(kept_time)]).astype(np.float32)
                q=probability(altered)
                rows.append(dict(sample_id=r['sample_id'],intervention='drop_events_app='+names.get(app,str(app)),removed_events=n,
                    original_probability=p,intervened_probability=q,original_minus_intervened=p-q))
        name='v5_event_drop_sensitivity.csv'
    with (out/(name+'.tmp')).open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (out/(name+'.tmp')).replace(out/name)
    print(out/name,flush=True)


if __name__=='__main__':main()
