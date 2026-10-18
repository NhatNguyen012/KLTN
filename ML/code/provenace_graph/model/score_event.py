#!/usr/bin/env python3
"""Score a process event with the learned graph model and expose its real subgraph."""
import argparse,json
from pathlib import Path
from ML.code.provenace_graph.model.ego import EgoGraphs,connect
from ML.code.provenace_graph.model.relational_sage import RelationalSAGE
from common import sha


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--graph',type=Path,required=True);p.add_argument('--model-dir',type=Path,required=True)
    p.add_argument('--source-id',required=True);p.add_argument('--source-line',type=int,required=True)
    a=p.parse_args();g=a.graph.resolve();modeldir=a.model_dir.resolve()
    config=json.loads((modeldir/'config.json').read_text());progress=json.loads((modeldir/'progress.json').read_text())
    if sha(g/'graph.sqlite')!=config['graph_sha256']:raise ValueError('graph identity differs from model')
    modelpath=modeldir/progress.get('model_file','model.npz')
    if sha(modelpath)!=progress['model_sha256']:raise ValueError('model checksum mismatch')
    model=RelationalSAGE.load(modelpath);db=connect(g/'graph.sqlite',readonly=True)
    try:
        row=db.execute('SELECT host,proc,t FROM target WHERE source=? AND line=?',(a.source_id,a.source_line)).fetchone()
        if row is None:raise ValueError('event not in graph target scope')
        graph=EgoGraphs(db).build(*row);score=model.predict(graph);importance=[]
        for edge in graph['edges']:
            if edge[2]!='creates':continue
            altered=dict(graph,edges=tuple(e for e in graph['edges'] if e!=edge))
            importance.append(dict(edge=edge,risk_change_when_removed=score['probability']-model.predict(altered)['probability']))
        result=dict(risk_score=score['probability'],process_embedding=score['process_embedding'].tolist(),
                    host_embedding=score['host_embedding'].tolist(),nodes=graph['node_keys'],edges=graph['edges'],
                    cutoff_us=graph['cutoff_us'],evidence=graph['evidence'],edge_ablation=importance,
                    note='Model sensitivity and observed ancestors, not proof of a true malicious root; balanced-training scores are not calibrated probabilities.')
        print(json.dumps(result,indent=2))
    finally:db.close()


if __name__=='__main__':main()
