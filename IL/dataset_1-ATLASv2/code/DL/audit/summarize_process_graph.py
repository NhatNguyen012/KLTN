#!/usr/bin/env python3
"""Fixed-cohort reporting for process-graph and uncertainty-mask experiments."""
import argparse
import csv
import json
from pathlib import Path
import sys
import numpy as np
import torch
from sklearn.metrics import f1_score,average_precision_score

DL=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(DL/'model'),str(Path(__file__).resolve().parent)]
from research_paths import validate_output_dir
from decision_policy import select_binary_threshold
from audit_low_f1 import metrics


def main():
    root=validate_output_dir(DL/'output/process_graph_20261111')
    parser=argparse.ArgumentParser();parser.add_argument('--include-process-supervision',action='store_true');args=parser.parse_args()
    paths=sorted((root/'runs').glob('*/result.json'))
    if args.include_process_supervision:paths+=sorted((root/'runs_process_supervised').glob('*/result.json'))
    if len(paths)!=(10 if args.include_process_supervision else 8):raise RuntimeError('Expected all requested completed trials')
    items=torch.load(root/'data/test.pt',weights_only=False)
    labels=np.array([x['original_label'] for x in items]);legacy=np.array([x['original_stage'] for x in items])
    retained=np.array([x['targets']['review_mask'] for x in items]);table=[];details={}
    for path in paths:
        d=json.loads(path.read_text());rows=d['test'];r=dict(model=d['mode'],policy=d['policy'],process_supervision=bool(d['config'].get('process_supervision')),seed=d['seed'],epoch=d['best_epoch'],threshold=d['threshold'],
            validation_f1=d['val'][d['policy']]['binary_f1'],validation_stage_presence_f1=d['val'][d['policy']]['stage_presence_macro_f1'],
            original_f1=rows['original']['binary_f1'],original_tp=rows['original']['tp'],original_fp=rows['original']['fp'],original_fn=rows['original']['fn'],
            retained_f1=rows['reviewed']['binary_f1'],retained_tp=rows['reviewed']['tp'],retained_fp=rows['reviewed']['fp'],retained_fn=rows['reviewed']['fn'],
            original_ap=rows['original']['average_precision'],retained_ap=rows['reviewed']['average_precision'],
            retained_stage_presence_macro_f1=rows['reviewed']['stage_presence_macro_f1'])
        with np.load(path.parent/'test_scores.npz') as z:
            scores=z['scores'];assert np.array_equal(z['sample_ids'],[x['sample_id'] for x in items])
        active=scores.max(1)>=d['threshold'];stage_pred=np.where(active,scores.argmax(1)+1,0)
        diag=metrics(legacy,stage_pred)
        early=(legacy>0)&(legacy<4)
        r['legacy_stage_attack_macro_f1']=diag['attack_macro_f1']
        r['legacy_execution_binary_recall']=float(active[legacy==2].mean())
        r['legacy_execution_stage_recall']=float((scores[legacy==2,1]>=d['threshold']).mean())
        r['early_windows_detected']=int(sum(active&early))
        details[str(path.parent.relative_to(root))]=dict(original_legacy_stage=diag,
            legacy_execution_ids=[x['sample_id'] for x,k in zip(items,legacy) if k==2],
            legacy_execution_stage_scores=scores[legacy==2].tolist())
        table.append(r)
    prior=DL/'output/research_20261111/audit'
    with np.load(prior/'v5_val_predictions.npz') as z:
        threshold=select_binary_threshold(z['stages']>0,z['probs'],.02)
    with np.load(prior/'v5_test_predictions.npz') as z:
        assert np.array_equal(z['ids'],[x['sample_id'] for x in items]);p=z['probs']
    baseline={}
    for name,mask in [('original',np.ones(len(items),bool)),('retained',retained)]:
        yy=labels[mask];pred=p[mask]>=threshold
        baseline[name]=dict(f1=float(f1_score(yy,pred)),average_precision=float(average_precision_score(yy,p[mask])),
            tp=int(sum((yy==1)&pred)),fp=int(sum((yy==0)&pred)),fn=int(sum((yy==1)&~pred)))
    result=dict(trials=table,v5_reference=baseline,diagnostics=details,
        cohort_note='Original: 2369 windows/38 positive. Retained-evidence: 2356 windows/25 positive, excludes 13 uncertain positives; not verified gold or an untouched benchmark.',
        stage_note='Stage presence is a new weak multi-label task. It is not interchangeable with historical single-stage classification.')
    with (root/'comparison.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    (root/'comparison_summary.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(dict(trials=table,v5_reference=baseline),indent=2),flush=True)


if __name__=='__main__':main()
