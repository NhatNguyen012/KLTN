"""Read-only audit of saved Run-5 histograms and bounded diagnostic reservoirs."""
import json
from pathlib import Path
from collections import Counter
import numpy as np
ROOT=Path(__file__).resolve().parents[1]

def audit():
    root=ROOT/'output/kaggle_output/5'
    vocab=json.loads((root/'provenance/vocab_extended.json').read_text())
    inv={i:t for t,i in vocab.items()}
    with np.load(root/'results/incremental/validation-state.npz',allow_pickle=False) as d:
        vp,vn=d['positive'],d['negative']
    with np.load(root/'results/incremental/test-state.npz',allow_pickle=False) as d:
        tp,tn=d['positive'],d['negative'];state=json.loads(str(d['diagnostics']))
    vfp=vn[::-1].cumsum()[::-1]
    test_tp=tp[::-1].cumsum()[::-1];test_fp=tn[::-1].cumsum()[::-1]
    f1=2*test_tp/np.maximum(test_tp+test_fp+tp.sum(),1);best=int(f1.argmax())
    threshold=best/(len(tp)-1)
    points=[]
    for budget in [.005,.01]:
        i=int(np.flatnonzero(vfp<=budget*vn.sum())[0])
        points.append(dict(budget=budget,threshold=i/(len(vn)-1),test_tp=int(test_tp[i]),
                           test_fp=int(test_fp[i]),test_f1=float(f1[i])))
    errors={}
    for label,name,expected in [(0,'fp',int(test_fp[best])),(1,'fn',int(tp.sum()-test_tp[best]))]:
        rows=[r for r in state['extremes'][label] if (r['score']>=threshold)!=bool(label)]
        counts=Counter(inv[i] for r in rows for i in r['columns'])
        errors[name]=dict(rows=len(rows),histogram_expected=expected,
                          complete_at_this_threshold=len(rows)==expected,
                          token_counts=dict(counts.most_common()))
    return dict(test_oracle_threshold=threshold,test_oracle_f1=float(f1[best]),
                validation_calibrated_points=points,errors=errors,
                warning='Exploratory Test audit; error feature counts do not establish raw file paths or causation')

if __name__=='__main__':
    print(json.dumps(audit(),indent=2))
