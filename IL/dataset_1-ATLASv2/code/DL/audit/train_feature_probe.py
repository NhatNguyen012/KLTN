#!/usr/bin/env python3
"""Learned order-free feature probe: does the current task need recurrence?

Uses only existing encoded shard inputs. No GUID, scenario, label-derived feature,
or test-fitted transform. This is a diagnostic supervised target-domain MLP,
not an incremental-learning replacement and not evidence of source retention.
"""
import argparse
import json
from pathlib import Path
import sys
import numpy as np
import torch
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score

DL = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(DL / "model"), str(Path(__file__).resolve().parent)]
from dataset import PackedNetworkDataset
from decision_policy import select_binary_threshold, global_predictions
from research_paths import validate_output_dir
from audit_low_f1 import metrics


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=DL/"preprocess/output")
    ap.add_argument("--output-dir", type=Path, required=True)
    args=ap.parse_args(); out=validate_output_dir(args.output_dir);out.mkdir(parents=True,exist_ok=True)
    torch.set_num_threads(2)
    maps=json.loads((args.data_dir/"preprocessing/network_category_maps.json").read_text())
    cards=[maps['fields'][f]['size'] for f in ['app_family','proto','resp_port_class','image_dir_class']]
    data={}
    for split in ['train','val','test']:
        ds=PackedNetworkDataset(args.data_dir,split,cache_shards=10);xx=[];yy=[]
        for item in ds:
            parts=[]
            for col,n in enumerate(cards):
                c=np.bincount(item['x_cat'][:,col],minlength=n)
                parts.extend([c/len(item['x_cat']), (c>0).astype(float)])
            dt=item['delta_t_log1p']
            parts.extend([np.array([dt.mean(),dt.std(),dt.max(),np.log1p(len(dt)),item['x_bin'].mean()])])
            xx.append(np.concatenate(parts)); yy.append(item['stage'])
        data[split]=(np.array(xx,dtype=np.float32),np.array(yy))
    scaler=StandardScaler().fit(data['train'][0])
    for k,(x,y) in data.items():data[k]=(torch.tensor(scaler.transform(x),dtype=torch.float32),torch.tensor(y,dtype=torch.long))
    torch.save(dict(mean=scaler.mean_,scale=scaler.scale_,cards=cards),out/'train_only_transform.pt')
    results=[]
    for seed in [41,42,43]:
        torch.manual_seed(seed)
        model=torch.nn.Sequential(torch.nn.Linear(data['train'][0].shape[1],64),torch.nn.ReLU(),torch.nn.Dropout(.2),torch.nn.Linear(64,5))
        opt=torch.optim.AdamW(model.parameters(),lr=.001,weight_decay=.001)
        counts=torch.bincount(data['train'][1],minlength=5).float().clamp(min=1)
        weights=counts.rsqrt();weights/=weights.mean()
        best=-1;best_state=None;best_thr=None;best_epoch=None
        for epoch in range(1,61):
            model.train()
            for idx in torch.randperm(len(data['train'][0])).split(128):
                opt.zero_grad();loss=torch.nn.functional.cross_entropy(model(data['train'][0][idx]),data['train'][1][idx],weight=weights)
                loss.backward();opt.step()
            model.eval()
            with torch.no_grad():p=model(data['val'][0]).softmax(-1).numpy()
            y=data['val'][1].numpy();scores=1-p[:,0]
            thr=select_binary_threshold(y>0,scores,.02)
            pred=global_predictions(scores,p[:,1:],thr);m=metrics(y,pred)
            criterion=.5*m['binary_f1']+.5*m['attack_macro_f1']
            if criterion>best:
                best=criterion;best_state={k:v.clone() for k,v in model.state_dict().items()};best_thr=thr;best_epoch=epoch
        model.load_state_dict(best_state);model.eval();r=dict(seed=seed,epoch=best_epoch,threshold=best_thr)
        torch.save(best_state,out/f'mlp_seed{seed}.pt')
        for split in ['val','test']:
            with torch.no_grad():p=model(data[split][0]).softmax(-1).numpy()
            scores=1-p[:,0];y=data[split][1].numpy()
            r[split]=metrics(y,global_predictions(scores,p[:,1:],best_thr))
            r[split]['average_precision']=float(average_precision_score(y>0,scores))
            np.savez_compressed(out/f'seed{seed}_{split}_predictions.npz',stages=y,probs=scores,conditional_scores=p[:,1:])
        results.append(r);print(json.dumps(r),flush=True)
    tmp=out/'probe_results.json.tmp';tmp.write_text(json.dumps(dict(task='supervised target-domain order-free MLP diagnostic',data_dir=str(args.data_dir),results=results),indent=2));tmp.replace(out/'probe_results.json')


if __name__=='__main__':main()
