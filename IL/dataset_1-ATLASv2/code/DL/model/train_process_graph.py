#!/usr/bin/env python3
"""Four-way process/graph x original/reviewed supervision experiment.

Models train from scratch. Stage targets denote weak stage PRESENCE, not a
verified instantaneous attacker state. Calibration and selection use VAL only.
"""
import argparse
from functools import partial
import csv
import hashlib
import json
from pathlib import Path
import random
import sys
import time
import numpy as np
import torch
from sklearn.metrics import f1_score,average_precision_score,confusion_matrix
from torch.utils.data import DataLoader

MODEL=Path(__file__).resolve().parent
sys.path.insert(0,str(MODEL))
from process_graph import ProcessGraphMIL,collate_graphs
from decision_policy import select_binary_threshold
from research_paths import validate_output_dir


def predict(model,loader):
    model.eval();scores=[]
    with torch.no_grad():
        for batch in loader:scores.append(model(batch).sigmoid().numpy())
    return np.concatenate(scores)


def evaluate(items,scores,policy,threshold):
    mask=np.array([x['targets']['review_mask'] if policy=='reviewed' else True for x in items])
    y=np.array([x['original_label'] for x in items])[mask]
    stages=np.stack([x['targets']['reviewed_stages' if policy=='reviewed' else 'original_stages'] for x in items])[mask]
    p=scores[mask];pred=p.max(1)>=threshold;sp=p>=threshold
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return dict(samples=int(mask.sum()),positives=int(y.sum()),tp=int(tp),fp=int(fp),fn=int(fn),tn=int(tn),
        binary_f1=float(f1_score(y,pred,zero_division=0)),average_precision=float(average_precision_score(y,p.max(1))),
        fpr=float(fp/max(1,fp+tn)),stage_presence_macro_f1=float(f1_score(stages,sp,average='macro',zero_division=0)),
        stage_presence_micro_f1=float(f1_score(stages,sp,average='micro',zero_division=0)),
        stage_support=stages.sum(0).astype(int).tolist(),stage_recall=((sp*stages).sum(0)/np.maximum(1,stages.sum(0))).tolist())


def run(args,items,meta,mode,policy,seed):
    out=validate_output_dir(args.output_dir)/f'{mode}_{policy}_seed{seed}'
    if out.exists():raise FileExistsError(out)
    out.mkdir(parents=True)
    torch.manual_seed(seed);random.seed(seed);np.random.seed(seed)
    model=ProcessGraphMIL(len(meta['event_vocab']),len(meta['edge_vocab']),graph=mode=='graph')
    optimizer=torch.optim.AdamW(model.parameters(),lr=args.lr,weight_decay=.001)
    collate=partial(collate_graphs,policy=policy)
    loaders={s:DataLoader(rows,batch_size=args.batch_size,collate_fn=collate,shuffle=False) for s,rows in items.items()}
    valid=[x for x in items['train'] if policy=='original' or x['targets']['review_mask']]
    target=np.stack([x['targets'][policy+'_stages'] for x in valid]);counts=target.sum(0)
    weights=torch.tensor(np.sqrt((len(valid)-counts)/np.maximum(1,counts)).clip(1,10),dtype=torch.float32)
    mask=np.array([x['targets']['review_mask'] if policy=='reviewed' else True for x in items['val']])
    val_y=np.array([x['original_label'] for x in items['val']])[mask]
    best=-1;history=[];best_epoch=0;threshold=1.;best_state=None
    for epoch in range(args.epochs+1):
        start=time.time()
        if epoch:
            model.train();torch.manual_seed(seed+epoch)
            order=torch.randperm(len(items['train']),generator=torch.Generator().manual_seed(seed+epoch))
            for indices in order.split(args.batch_size):
                batch=collate([items['train'][int(i)] for i in indices]);keep=batch['target_mask']
                if not keep.any():continue
                optimizer.zero_grad()
                if args.process_supervision:
                    logits,process_logits=model(batch,return_process=True)
                else:logits=model(batch)
                binary_loss=torch.nn.functional.binary_cross_entropy_with_logits(logits.max(1).values[keep],batch['binary_target'][keep])
                stage_loss=torch.nn.functional.binary_cross_entropy_with_logits(logits[keep],batch['stage_target'][keep],pos_weight=weights)
                loss=binary_loss+.5*stage_loss
                if args.process_supervision:
                    pmask=batch['process_target_mask'] & batch['target_mask'][batch['owner']];ptarget=batch['process_stage_target']
                    values=torch.nn.functional.binary_cross_entropy_with_logits(process_logits,ptarget,reduction='none').mean(1)
                    positive=pmask & (ptarget.sum(1)>0);negative=pmask & ~positive
                    terms=[values[group].mean() for group in [positive,negative] if group.any()]
                    if terms:loss=loss+.5*torch.stack(terms).mean()
                loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
                optimizer.step()
        scores=predict(model,loaders['val']);thr=select_binary_threshold(val_y,scores[mask].max(1),.02)
        metrics=evaluate(items['val'],scores,policy,thr)
        criterion=.5*metrics['binary_f1']+.5*metrics['stage_presence_macro_f1']
        if criterion>best:
            best=criterion;best_epoch=epoch;threshold=thr;best_state={k:v.clone() for k,v in model.state_dict().items()}
            torch.save(dict(model_state_dict=best_state,epoch=epoch,threshold=thr),out/'best_model.pt.tmp')
            (out/'best_model.pt.tmp').replace(out/'best_model.pt')
        history.append(dict(epoch=epoch,seconds=time.time()-start,val=metrics,threshold=thr,selection=criterion))
        (out/'progress.json').write_text(json.dumps(history[-1],indent=2))
        print(mode,policy,seed,epoch,'VAL',round(metrics['binary_f1'],4),'stage',round(metrics['stage_presence_macro_f1'],4),'best',best_epoch,flush=True)
    model.load_state_dict(best_state)
    result=dict(mode=mode,policy=policy,seed=seed,best_epoch=best_epoch,threshold=threshold,history=history,
        config=vars(args).copy(),train_stage_counts=counts.tolist(),stage_pos_weights=weights.tolist(),
        identity_sha256=hashlib.sha256((args.data_dir/'metadata.json').read_bytes()).hexdigest(),
        task='binary detection and weak multi-label stage presence; not incremental source retention',
        process_supervision_sha256=hashlib.sha256(args.process_supervision.read_bytes()).hexdigest() if args.process_supervision else None)
    result['config']={k:str(v) if isinstance(v,Path) else v for k,v in result['config'].items()}
    for split in ['val','test']:
        scores=predict(model,loaders[split])
        # Same emitted decisions are shown on both cohorts. Threshold belongs to
        # the declared VAL policy, never a separately selected test subset.
        result[split]={p:evaluate(items[split],scores,p,threshold) for p in ['original','reviewed']}
        np.savez_compressed(out/f'{split}_scores.npz',scores=scores,sample_ids=np.array([x['sample_id'] for x in items[split]]))
        with (out/f'{split}_predictions.csv').open('w') as f:
            w=csv.writer(f);w.writerow(['sample_id','original_label','review_mask','attack_probability','predicted_binary','stage_probabilities','review_reason'])
            for item,p in zip(items[split],scores):w.writerow([item['sample_id'],item['original_label'],item['targets']['review_mask'],float(p.max()),int(p.max()>=threshold),'|'.join(map(str,p.tolist())),item['targets']['reason']])
    (out/'result.json.tmp').write_text(json.dumps(result,indent=2));(out/'result.json.tmp').replace(out/'result.json')
    print('FINISHED',mode,policy,seed,result['test'],flush=True)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--data-dir',type=Path,default=MODEL.parent/'output/process_graph_20261111/data')
    ap.add_argument('--output-dir',type=Path,default=MODEL.parent/'output/process_graph_20261111/runs')
    ap.add_argument('--modes',nargs='+',default=['process','graph'],choices=['process','graph'])
    ap.add_argument('--policies',nargs='+',default=['original','reviewed'],choices=['original','reviewed'])
    ap.add_argument('--seeds',nargs='+',type=int,default=[42,43]);ap.add_argument('--epochs',type=int,default=20)
    ap.add_argument('--batch-size',type=int,default=32);ap.add_argument('--lr',type=float,default=.001)
    ap.add_argument('--process-supervision',type=Path,default=None,help='Separate current-process weak targets, used only in training loss')
    args=ap.parse_args();torch.set_num_threads(2)
    meta=json.loads((args.data_dir/'metadata.json').read_text())
    items={s:torch.load(args.data_dir/f'{s}.pt',weights_only=False) for s in ['train','val','test']}
    if args.process_supervision:
        supervision=torch.load(args.process_supervision,weights_only=False)
        for rows in items.values():
            for item in rows:
                target=supervision[item['sample_id']]
                item['targets']['process_stage_target']=target['stage_target']
                item['targets']['process_target_mask']=target['mask']
    for seed in args.seeds:
        for policy in args.policies:
            for mode in args.modes:run(args,items,meta,mode,policy,seed)


if __name__=='__main__':main()
