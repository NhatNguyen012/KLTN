#!/usr/bin/env python3
"""Localize fixed-weight MIL alerts to central processes and inspect edge sensitivity."""
import argparse
import csv
import json
from pathlib import Path
import sys
import torch

DL=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(DL/'model'))
from process_graph import ProcessGraphMIL,collate_graphs
from research_paths import validate_output_dir


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--run',required=True)
    ap.add_argument('--runs-subdir',default='runs');args=ap.parse_args();root=validate_output_dir(DL/'output/process_graph_20261111')
    run=root/args.runs_subdir/args.run;result=json.loads((run/'result.json').read_text())
    meta=json.loads((root/'data/metadata.json').read_text());inverse={v:k for k,v in meta['edge_vocab'].items()}
    items=torch.load(root/'data/test.pt',weights_only=False)
    with (DL/'output/research_20261111/audit/v5_test_errors.csv').open() as f:
        cases={r['sample_id'] for r in csv.DictReader(f) if r['error_type']!='correct'}
    selected=[x for x in items if x['sample_id'] in cases]
    wanted={(x['source'],ln) for x in selected for ln in x['source_lines']};records={}
    with (DL/'output/provenance_context_20261111/data/event_provenance.jsonl').open() as f:
        for line in f:
            r=json.loads(line)
            if (r['source'],r['line']) in wanted:records[(r['source'],r['line'])]=r
    model=ProcessGraphMIL(len(meta['event_vocab']),len(meta['edge_vocab']),graph=result['mode']=='graph')
    model.load_state_dict(torch.load(run/'best_model.pt',weights_only=False)['model_state_dict']);model.eval();torch.set_num_threads(2)
    rows=[]
    for item in selected:
        batch=collate_graphs([item],result['policy'])
        with torch.no_grad():window,logits=model(batch,return_process=True)
        scores=window.sigmoid()[0];stage=int(scores.argmax());winner=int(logits[:,stage].argmax())
        host,guid=item['audit']['node_ids'][winner]
        evidence=[records[(item['source'],ln)]['event'] for ln in item['source_lines'] if
                  records[(item['source'],ln)]['event']['actor']==guid]
        row=dict(sample_id=item['sample_id'],original_label=item['original_label'],legacy_stage=item['original_stage'],
            review_mask=item['targets']['review_mask'],score=float(scores.max()),threshold=result['threshold'],
            predicted_binary=int(float(scores.max())>=result['threshold']),winning_stage=stage+1,
            winning_process_path=evidence[-1]['actor_path'],winning_process_guid=guid,
            source=item['source'],winning_source_lines='|'.join(str(e['line']) for e in evidence))
        for name in ['all_edges','parent_edges','incoming_edges']:
            kinds=[inverse[int(k)] for k in batch['edge_kind']]
            remove=[name=='all_edges' or (name=='parent_edges' and k.removesuffix('_reverse') in {'spawn','process_discovered'}) or
                    (name=='incoming_edges' and k.removesuffix('_reverse') in {'process_open','process_duplicate','thread_open','thread_duplicate','remote_thread_create','api_call','other_crossproc'}) for k in kinds]
            keep=~torch.tensor(remove,dtype=torch.bool);altered=dict(batch)
            altered['edge_index']=batch['edge_index'][:,keep];altered['edge_kind']=batch['edge_kind'][keep];altered['edge_age']=batch['edge_age'][keep]
            with torch.no_grad():row['score_without_'+name]=float(model(altered).sigmoid().max())
        rows.append(row)
    with (run/'case_explanations.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(run/'case_explanations.csv',flush=True)


if __name__=='__main__':main()
