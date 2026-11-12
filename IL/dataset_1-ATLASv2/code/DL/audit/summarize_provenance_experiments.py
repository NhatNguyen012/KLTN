#!/usr/bin/env python3
"""Summarize paired context trials without selecting using test outcomes."""
import csv
import json
from pathlib import Path
import sys
import os
import numpy as np

DL=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(DL/'model'))
from research_paths import validate_output_dir


def main():
    root=validate_output_dir(DL/'output/provenance_context_20261111')
    results=[json.loads(p.read_text()) for p in sorted((root/'runs').glob('*/result.json'))]
    if len(results)!=6:raise RuntimeError('Expected all six completed trials')
    table=[];changes=[]
    for r in results:
        table.append(dict(mode=r['mode'],seed=r['seed'],best_epoch=r['best_epoch'],threshold=r['threshold'],
            validation_f1=r['val']['binary_f1'],test_f1=r['test']['binary_f1'],test_ap=r['test']['average_precision'],
            attack_macro_f1=r['test']['attack_macro_f1'],tp=r['test']['tp'],fp=r['test']['fp'],fn=r['test']['fn']))
        if r['mode']=='none':continue
        with (root/f"runs/none_seed{r['seed']}/test_predictions.csv").open() as f:base={x['sample_id']:x for x in csv.DictReader(f)}
        with (root/f"runs/{r['mode']}_seed{r['seed']}/test_predictions.csv").open() as f:
            for x in csv.DictReader(f):
                b=base[x['sample_id']]
                if x['pred_stage']!=b['pred_stage']:
                    changes.append(dict(mode=r['mode'],seed=r['seed'],sample_id=x['sample_id'],true_stage=x['true_stage'],
                        before_stage=b['pred_stage'],after_stage=x['pred_stage'],before_probability=b['p_attack'],after_probability=x['p_attack'],
                        before_error=b['error_type'],after_error=x['error_type']))
    summary={}
    for mode in ['none','event','graph']:
        rs=[r for r in table if r['mode']==mode]
        summary[mode]={k:dict(mean=float(np.mean([r[k] for r in rs])),values=[r[k] for r in rs]) for k in ['test_f1','test_ap','attack_macro_f1','tp','fp','fn']}
    for name,rows in [('experiment_table.csv',table),('error_changes.csv',changes)]:
        with (root/name).open('w') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (root/'experiment_summary.json').write_text(json.dumps(dict(trials=table,by_mode=summary,changes=changes,
        interpretation='Two seeds, paired exploratory comparison on unchanged previously inspected test labels; no fresh generalization or source retention claim'),indent=2))
    os.environ.setdefault('MPLCONFIGDIR','/tmp/atlas_context_matplotlib')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,3,figsize=(12,3.5),dpi=180)
    for ax,metric,title in zip(axes,['test_f1','test_ap','attack_macro_f1'],['Binary F1','Average precision','Attack macro F1']):
        for seed in [42,43]:
            points=[next(r[metric] for r in table if r['mode']==mode and r['seed']==seed) for mode in ['none','event','graph']]
            ax.plot(range(3),points,'o-',label=f'seed {seed}')
        ax.set_xticks(range(3),['Original','Event','Graph context']);ax.set_title(title);ax.grid(alpha=.25);ax.set_ylim(bottom=0)
    axes[0].legend();fig.suptitle('Paired BiLSTM trials — identical samples, labels and initial checkpoint')
    fig.tight_layout();fig.savefig(root/'comparison.png');plt.close(fig)
    print(json.dumps(table,indent=2),flush=True)


if __name__=='__main__':main()
