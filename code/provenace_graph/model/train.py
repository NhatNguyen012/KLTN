#!/usr/bin/env python3
"""Train a small standalone provenance GNN on frozen split labels (Kaggle).

No baseline semantic columns are consumed. Default training/evaluation caps are
explicit samples; use zero evaluation caps for full validation/test. No training
is started merely by importing this module.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import numpy as np

from ego import EgoGraphs,ATTRIBUTES,connect
from relational_sage import RelationalSAGE
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'preprocess'))
from common import BASELINE,DEFAULT_OUTPUT,CODE,safe,sha,atomic_json,digest
from host_shards import HostShardDataset


def rows(data,db,split):
    code={'train':1,'val':2,'test':3}[split]
    for part in data.meta['shards']:
        if part['split']!=split:continue
        path=data.path_for(part)
        if sha(path)!=part['sha256']:raise ValueError('baseline shard changed')
        with np.load(path,allow_pickle=False) as f:
            labels=f['label'];lines=np.cumsum(f['source_line_delta'],dtype=np.uint64)
        if len(labels)!=part['rows'] or len(lines)!=len(labels) or np.any(labels>1):raise ValueError('invalid row arrays')
        targets=db.execute('SELECT line,host,proc,t FROM target WHERE source=? AND split=? AND line>=? AND line<=? ORDER BY line',
                            (part['source_id'],code,int(lines[0]),int(lines[-1])))
        for line,label in zip(lines,labels):
            row=targets.fetchone()
            if row is None or row[0]!=int(line):raise ValueError('frozen graph/label alignment mismatch')
            yield (row[1],row[2],row[3],int(label),part['source_id'],int(line))
        if targets.fetchone() is not None:raise ValueError('extra target rows')


def sample(stream,limit,seed,balanced=False):
    rng=np.random.default_rng(seed);bins=[[],[]] if balanced else [[]];seen=[0]*len(bins)
    if balanced and limit<2:raise ValueError('balanced training limit must be at least two')
    caps=[limit//2,limit-limit//2] if balanced else [limit]
    for row in stream:
        group=row[3] if balanced else 0;seen[group]+=1;b=bins[group];cap=caps[group]
        if not cap or len(b)<cap:b.append(row)
        else:
            i=int(rng.integers(seen[group]))
            if i<cap:b[i]=row
    chosen=[r for b in bins for r in b]
    return chosen,dict(available=seen,selected=[len(b) for b in bins],seed=seed,balanced=balanced,limit=limit)


def metrics(y,p,threshold):
    y=np.asarray(y);pred=np.asarray(p)>=threshold
    tp=int(((y==1)&pred).sum());fp=int(((y==0)&pred).sum())
    fn=int(((y==1)&~pred).sum());tn=int(((y==0)&~pred).sum())
    precision=tp/max(tp+fp,1);recall=tp/max(tp+fn,1)
    # Exact grouped-score average precision; no tie-order artifact.
    order=np.argsort(-np.asarray(p),kind='stable');yy=y[order];pp=np.asarray(p)[order]
    ends=np.r_[np.flatnonzero(pp[:-1]!=pp[1:]),len(pp)-1]
    positives=np.cumsum(yy)[ends];increments=np.diff(np.r_[0,positives])
    ap=float(np.sum(increments*positives/(ends+1))/max(int(y.sum()),1))
    return dict(threshold=float(threshold),rows=len(y),precision=precision,recall=recall,
                f1=2*precision*recall/max(precision+recall,1e-15),fpr=fp/max(fp+tn,1),
                average_precision=ap,confusion=dict(tp=tp,fp=fp,fn=fn,tn=tn))


def choose_threshold(y,p):
    # Choose only from validation. Evaluate all distinct scores, grouped for ties.
    order=np.argsort(-p,kind='stable');yy=y[order];scores=p[order]
    ends=np.r_[np.flatnonzero(scores[:-1]!=scores[1:]),len(scores)-1]
    tp=np.cumsum(yy)[ends];fp=ends+1-tp;fn=yy.sum()-tp
    f1=2*tp/np.maximum(2*tp+fp+fn,1)
    best=int(np.argmax(f1))
    return float(scores[ends[best]])


def resolve_volume_roots(manifest_path, meta):
    """Find relocated shard volumes beside a Kaggle-mounted manifest.

    The baseline manifest records original absolute paths for provenance, but
    those paths are not portable. Prefer conventional package layouts, then
    infer each volume root from a shard's manifest-relative path.
    """
    parent=Path(manifest_path).resolve().parent
    search_roots=[parent]
    kaggle_input=Path('/kaggle/input')
    if kaggle_input.is_dir() and kaggle_input.resolve()!=parent:
        search_roots.append(kaggle_input.resolve())
    roots={}
    for volume,original in meta['volumes'].items():
        parts=[s for s in meta['shards'] if s['volume']==volume]
        if not parts:
            # Volume plans may include configured spillover locations that
            # received no shards. HostShardDataset won't access these roots.
            roots[volume]=Path(original).resolve()
            continue
        candidates=[parent/'volumes'/volume, parent/volume,
                    parent/'model_input'/'volumes'/volume]
        part=parts[0]
        root=next((p.resolve() for p in candidates
                   if p.is_dir() and part is not None and (p/part['path']).is_file()),None)
        if root is None:
            if part is not None:
                rel=Path(part['path'])
                # Search for this unique shard beneath the mounted dataset,
                # then strip its manifest-relative suffix to recover the root.
                for search_root in search_roots:
                    for found in search_root.rglob(rel.name):
                        found=found.resolve()
                        if found.name==rel.name and len(found.parts)>=len(rel.parts) and tuple(found.parts[-len(rel.parts):])==rel.parts:
                            root=found.parents[len(rel.parts)-1]
                            break
                    if root is not None: break
        if root is None:
            original=Path(original)
            if original.is_dir(): root=original.resolve()
        if root is None:
            raise FileNotFoundError(f"Could not locate relocated '{volume}' shard volume under {parent}; expected a file ending in {part['path'] if part else '<no shards>'}")
        roots[volume]=root
    return roots


def evaluate(model,encoder,selection):
    if not selection:raise ValueError('empty evaluation partition')
    labels=np.asarray([r[3] for r in selection],dtype=np.uint8)
    scores=np.asarray([model.predict(encoder.build(*r[:3]))['probability'] for r in selection])
    return labels,scores


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,default=BASELINE/'model_input/manifest.json')
    parser.add_argument('--graph',type=Path,default=DEFAULT_OUTPUT/'graph')
    parser.add_argument('--output',type=Path,default=DEFAULT_OUTPUT/'learned_model')
    parser.add_argument('--epochs',type=int,default=10);parser.add_argument('--train-limit',type=int,default=20000)
    parser.add_argument('--val-limit',type=int,default=5000);parser.add_argument('--test-limit',type=int,default=5000)
    parser.add_argument('--seed',type=int,default=1);parser.add_argument('--batch-size',type=int,default=32)
    parser.add_argument('--evaluate-test',action='store_true');parser.add_argument('--resume',action='store_true');args=parser.parse_args()
    if min(args.epochs,args.batch_size)<1 or args.train_limit<2 or min(args.val_limit,args.test_limit,args.seed)<0:
        raise ValueError('invalid training configuration')
    baseline=args.baseline.resolve();raw=json.loads(baseline.read_text())
    volumes=resolve_volume_roots(baseline,raw)
    data=HostShardDataset(baseline,volumes)
    graph=args.graph.resolve();meta=json.loads((graph/'manifest.json').read_text())
    if meta['config']['pilot']:raise ValueError('cannot train on prefix-limited pilot graph')
    if meta['config']['split_sha256']!=data.meta['split_sha256']:raise ValueError('split identity mismatch')
    # Packaging relocates the baseline manifest. Bind logical rows via source IDs,
    # split hash and original shard identities rather than its absolute volume paths.
    expected={s['source_id']:s['source'] for s in meta['config']['sources']}
    if any(expected.get(s['source_id'])!=s['source'] for s in data.meta['sources']):raise ValueError('source identity mismatch')
    if sha(graph/'graph.sqlite')!=meta['database_sha256']:raise ValueError('graph integrity mismatch')
    for name in ['graph.py','build_graph.py','common.py']:
        if sha(Path(__file__).resolve().parents[1]/'preprocess'/name)!=meta['config']['implementation'][name]:
            raise ValueError('graph scanner semantics changed')
    output=safe(args.output,[graph,baseline.parent,*data.roots.values()])
    config=dict(args={k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items() if k!='resume'},
                split_sha256=data.meta['split_sha256'],graph_sha256=meta['database_sha256'],
                model_source={p.name:sha(p) for p in Path(__file__).parent.glob('*.py')},attributes=ATTRIBUTES)
    if output.exists():
        if not args.resume or json.loads((output/'config.json').read_text())!=config:
            raise ValueError('existing output/config differs; use a new output or matching --resume')
    else:
        output.mkdir(parents=True);atomic_json(output/'config.json',config)
    db=connect(graph/'graph.sqlite',readonly=True);encoder=EgoGraphs(db);model=RelationalSAGE(len(ATTRIBUTES),seed=args.seed)
    try:
        train,selection=sample(rows(data,db,'train'),args.train_limit,args.seed,balanced=True)
        if len({r[3] for r in train})!=2:raise ValueError('training needs both classes')
        val,val_selection=sample(rows(data,db,'val'),args.val_limit,args.seed+1)
        atomic_json(output/'selection.json',dict(train=selection,val=val_selection,
                    training_row_identity_sha256=digest([(r[4],r[5],r[3]) for r in train])))
        rng=np.random.default_rng(args.seed);start_epoch=0
        if args.resume and (output/'progress.json').exists():
            previous=json.loads((output/'progress.json').read_text())
            checkpoint=output/previous['model_file']
            if sha(checkpoint)!=previous['model_sha256']:raise ValueError('checkpoint checksum mismatch')
            model=RelationalSAGE.load(checkpoint);start_epoch=previous['epoch'];rng.bit_generator.state=previous['rng_state']
        for epoch in range(start_epoch,args.epochs):
            permutation=rng.permutation(len(train));loss=0.;batches=0
            for start in range(0,len(train),args.batch_size):
                batch=[(encoder.build(*train[i][:3]),train[i][3]) for i in permutation[start:start+args.batch_size]]
                loss+=model.train_batch(batch);batches+=1
            filename=f'model-slot-{epoch%2}.npz'
            model.save(safe(output/'model.tmp'));os.replace(output/'model.tmp',output/filename)
            atomic_json(output/'progress.json',dict(epoch=epoch+1,loss=loss/max(batches,1),
                        model_file=filename,model_sha256=sha(output/filename),rng_state=rng.bit_generator.state))
            print(f'epoch={epoch+1} loss={loss/max(batches,1):.6f}',flush=True)
        y,p=evaluate(model,encoder,val);threshold=choose_threshold(y,p)
        report=dict(model='Two-layer relational mean GraphSAGE + linear neural head',parameters=model.parameter_count,
                    validation=metrics(y,p,threshold),validation_scope='full' if args.val_limit==0 else 'uniform sample',
                    calibration='Balanced sampled training scores are risk scores, not calibrated event probabilities.',
                    embedding_dimensions=dict(process=model.embedding,host=model.embedding),test=None)
        if args.evaluate_test:
            test,test_selection=sample(rows(data,db,'test'),args.test_limit,args.seed+2)
            yy,pp=evaluate(model,encoder,test);report['test']=metrics(yy,pp,threshold)
            report['test_scope']='full' if args.test_limit==0 else 'uniform sample';report['test_selection']=test_selection
        atomic_json(output/'metrics.json',report)
    finally:db.close()


if __name__=='__main__':main()
