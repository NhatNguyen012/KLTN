#!/usr/bin/env python3
"""Paired DL context ablations with frozen sample/label/split identity.

none: original v5 inputs; event: intrinsic source/relation structure;
graph: intrinsic + strictly-past parent/incoming/file-writer context.
Each starts from the identical v5 checkpoint and considers epoch 0 for selection.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
import sys
import time
import numpy as np
import torch
from torch.utils.data import DataLoader
from sklearn.metrics import average_precision_score

MODEL=Path(__file__).resolve().parent
sys.path[:0]=[str(MODEL),str(MODEL.parent/'audit')]
from bilstm import BiLSTMBaseline
from dataset import PackedNetworkDataset,collate_sequence_batch
from decision_policy import select_binary_threshold,global_predictions
from research_paths import validate_output_dir
from audit_low_f1 import metrics


class ContextDataset(PackedNetworkDataset):
    def __init__(self,root,split,columns):
        super().__init__(root,split,cache_shards=10);self.columns=columns
    def __getitem__(self,index):
        item=super().__getitem__(index);r=self.rows[index];z=self._load_shard(r['shard_file']);idx=r['shard_sample_index']
        lo,hi=z['sample_offsets'][idx:idx+2]
        item['x_context']=z['x_context'][int(lo):int(hi),self.columns]
        return item


def collate(items):
    batch=collate_sequence_batch(items);c=items[0]['x_context'].shape[-1]
    context=torch.zeros(len(items),int(batch['lengths'].max()),c)
    for i,x in enumerate(items):context[i,:x['event_count']]=torch.from_numpy(x['x_context'].astype(np.float32))
    batch['x_context']=context;return batch


def forward(model,batch):
    return model(**{k:batch[k] for k in ['x_cat','x_num','x_num_missing','x_bin','delta_t_log1p','lengths','x_context']},return_stage_logits=True)


def predict(model,loader):
    model.eval();probs=[];logits=[];targets=[];ids=[]
    with torch.no_grad():
        for b in loader:
            p,s=forward(model,b);probs.extend(p.sigmoid().tolist());logits.extend(s.tolist())
            targets.extend(b['stages'].tolist());ids.extend(b['sample_ids'])
    return dict(probs=np.array(probs),logits=np.array(logits),stages=np.array(targets),ids=np.array(ids))


def score(a,threshold):
    pred=global_predictions(a['probs'],a['logits'],threshold)
    out=metrics(a['stages'],pred);out['average_precision']=float(average_precision_score(a['stages']>0,a['probs']))
    out['binary_threshold']=threshold;return out


def run(args,mode,seed):
    out=validate_output_dir(args.output_dir)/f'{mode}_seed{seed}'
    if out.exists():raise FileExistsError(out)
    out.mkdir(parents=True)
    meta=json.loads((args.data_dir/'context_metadata.json').read_text());vocab=meta['vocabulary']
    cols=sorted(v for k,v in vocab.items() if mode=='graph' or (mode=='event' and k.startswith('event::')))
    torch.manual_seed(seed);np.random.seed(seed);random.seed(seed)
    datasets={s:ContextDataset(args.data_dir,s,cols) for s in ['train','val','test']}
    loaders={s:DataLoader(ds,batch_size=args.batch_size,shuffle=False,collate_fn=collate) for s,ds in datasets.items()}
    maps=json.loads((args.data_dir/'preprocessing/network_category_maps.json').read_text())
    cards=[maps['fields'][f]['size'] for f in ['app_family','proto','resp_port_class','image_dir_class']]
    model=BiLSTMBaseline(categorical_cardinalities=cards,num_stages=4,context_dim=len(cols))
    checkpoint=torch.load(args.checkpoint,map_location='cpu',weights_only=False)['model_state_dict']
    state=model.state_dict();state.update(checkpoint);model.load_state_dict(state,strict=True)
    optimizer=torch.optim.AdamW([
        {'params':[p for n,p in model.named_parameters() if 'context_projection' not in n],'lr':args.lr},
        {'params':[p for n,p in model.named_parameters() if 'context_projection' in n],'lr':args.lr*3},
    ],weight_decay=1e-4)
    scheduler=torch.optim.lr_scheduler.CosineAnnealingLR(optimizer,args.epochs,eta_min=args.lr*.1)
    pools={k:[i for i,r in enumerate(datasets['train'].rows) if r['stage']==k] for k in range(1,5)}
    history=[];best=-1;selected_epoch=0;selected_threshold=0;selected_state=None
    for epoch in range(args.epochs+1):
        start=time.time()
        if epoch:
            torch.manual_seed(seed+epoch);rng=random.Random(seed+epoch);model.train()
            order=torch.randperm(len(datasets['train']),generator=torch.Generator().manual_seed(seed+epoch))
            for indices in order.split(args.batch_size):
                batch=collate([datasets['train'][int(i)] for i in indices]);optimizer.zero_grad()
                p,s=forward(model,batch)
                loss=torch.nn.functional.binary_cross_entropy_with_logits(p,batch['labels'])
                # Balanced stage-only supervision. Never add an all-positive binary loss.
                indices=[rng.choice(pool) for pool in pools.values() if pool for _ in range(2)]
                aux=collate([datasets['train'][i] for i in indices]);_,st=forward(model,aux)
                loss=loss+torch.nn.functional.cross_entropy(st,aux['stages']-1,label_smoothing=.05)
                loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),1.0);optimizer.step()
            scheduler.step()
        val=predict(model,loaders['val']);thr=select_binary_threshold(val['stages']>0,val['probs'],.02)
        m=score(val,thr);criterion=.5*m['binary_f1']+.5*m['attack_macro_f1']
        if criterion>best:
            best=criterion;selected_epoch=epoch;selected_threshold=thr
            selected_state={k:v.detach().clone() for k,v in model.state_dict().items()}
        history.append(dict(epoch=epoch,seconds=time.time()-start,val=m,selection_score=criterion))
        (out/'progress.json').write_text(json.dumps(history[-1],indent=2))
        print(mode,seed,epoch,'val_f1',round(m['binary_f1'],4),'attack_f1',round(m['attack_macro_f1'],4),'best',selected_epoch,flush=True)
    model.load_state_dict(selected_state)
    result=dict(mode=mode,seed=seed,epochs=args.epochs,best_epoch=selected_epoch,context_columns=cols,
        checkpoint_sha256=hashlib.sha256(args.checkpoint.read_bytes()).hexdigest(),
        source_context_metadata_sha256=hashlib.sha256((args.data_dir/'context_metadata.json').read_bytes()).hexdigest(),
        manifest_sha256=meta['manifest_sha256'],threshold=selected_threshold,history=history)
    torch.save(dict(model_state_dict=selected_state,context_columns=cols,context_dim=len(cols)),out/'best_model.pt.tmp')
    (out/'best_model.pt.tmp').replace(out/'best_model.pt')
    for split in ['val','test']:
        a=predict(model,loaders[split]);result[split]=score(a,selected_threshold)
        np.savez_compressed(out/f'{split}_predictions.npz',**a)
        pred=global_predictions(a['probs'],a['logits'],selected_threshold)
        with (out/f'{split}_predictions.csv').open('w') as f:
            w=csv.writer(f);w.writerow(['sample_id','true_stage','pred_stage','p_attack','error_type'])
            for sid,y,p,prob in zip(a['ids'],a['stages'],pred,a['probs']):
                error='FP' if y==0 and p>0 else 'FN' if y>0 and p==0 else 'stage_error' if y!=p else 'correct'
                w.writerow([sid,y,p,prob,error])
    (out/'result.json.tmp').write_text(json.dumps(result,indent=2));(out/'result.json.tmp').replace(out/'result.json')
    print('FINISHED',mode,seed,result['test'],flush=True)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--data-dir',type=Path,default=MODEL.parent/'output/provenance_context_20261111/data')
    ap.add_argument('--checkpoint',type=Path,default=MODEL.parent/'output/local_output/local_run_v5/best_model.pt')
    ap.add_argument('--output-dir',type=Path,default=MODEL.parent/'output/provenance_context_20261111/runs')
    ap.add_argument('--modes',nargs='+',choices=['none','event','graph'],default=['none','event','graph'])
    ap.add_argument('--seeds',nargs='+',type=int,default=[42,43])
    ap.add_argument('--epochs',type=int,default=10);ap.add_argument('--batch-size',type=int,default=32)
    ap.add_argument('--lr',type=float,default=1e-4);args=ap.parse_args();torch.set_num_threads(2)
    for seed in args.seeds:
        for mode in args.modes:run(args,mode,seed)


if __name__=='__main__':main()
