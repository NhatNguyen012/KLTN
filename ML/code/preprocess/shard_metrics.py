"""Bounded-memory validation threshold selection and streamed test metrics.

Confusion metrics at a selected grid threshold are exact. Ranking metrics are
histogram approximations, explicitly reported as binned (not exact AP/AUC).
"""
import numpy as np


def evaluate_stream(dataset,split,predict,threshold=None,bins=10000):
    if split not in ('val','test') or bins<2:
        raise ValueError('expected validation/test and at least two bins')
    if split=='test' and threshold is None:
        raise ValueError('test requires a frozen validation threshold')
    if threshold is not None and not 0<=threshold<=1:
        raise ValueError('threshold outside [0,1]')
    positive=np.zeros(bins+1,dtype=np.int64);negative=np.zeros(bins+1,dtype=np.int64)
    tp=fp=fn=tn=0
    for X,y in dataset.iter_batches(split):
        p=np.asarray(predict(X)).reshape(-1)
        if len(p)!=len(y) or not np.all(np.isfinite(p)) or np.any((p<0)|(p>1)):
            raise ValueError('invalid probabilities')
        bucket=np.minimum((p*bins).astype(np.int64),bins)
        positive+=np.bincount(bucket[y==1],minlength=bins+1)
        negative+=np.bincount(bucket[y==0],minlength=bins+1)
        if threshold is not None:
            predicted=p>=threshold
            tp+=int(np.sum(predicted & (y==1)));fp+=int(np.sum(predicted & (y==0)))
            fn+=int(np.sum(~predicted & (y==1)));tn+=int(np.sum(~predicted & (y==0)))
    total_p=int(positive.sum());total_n=int(negative.sum())
    if not total_p or not total_n:raise ValueError('both classes required for evaluation')
    tps=positive[::-1].cumsum()[::-1];fps=negative[::-1].cumsum()[::-1]
    precisions=tps/np.maximum(tps+fps,1);recalls=tps/total_p
    if threshold is None:
        f1s=2*tps/np.maximum(2*tps+fps+(total_p-tps),1)
        best=int(np.argmax(f1s));threshold=best/bins
        tp=int(tps[best]);fp=int(fps[best]);fn=total_p-tp;tn=total_n-fp
    precision=tp/max(tp+fp,1);recall=tp/total_p
    pr_binned=float(np.sum(precisions*(positive/total_p)))
    roc_binned=float(np.sum(positive.astype(np.float64)*(negative.cumsum()-negative/2))/(total_p*total_n))
    return dict(split=split,rows=total_p+total_n,threshold=float(threshold),threshold_source='validation',
        precision=precision,recall=recall,f1=2*precision*recall/max(precision+recall,1e-30),
        fpr=fp/total_n,confusion=dict(tp=tp,fp=fp,fn=fn,tn=tn),
        pr_auc_binned=pr_binned,roc_auc_binned=roc_binned,ranking_bins=bins,
        note='Confusion metrics exact at threshold; ranking metrics approximate via score bins.')
