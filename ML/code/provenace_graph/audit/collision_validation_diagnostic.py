"""Validation-only diagnostic for frozen v4 Host-vector collisions."""
from collections import defaultdict
import json
from pathlib import Path
import sys
import sqlite3
import hashlib

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / 'code/provenace_graph/model'), str(ROOT / 'code/preprocess')]
from collision_aware_runtime import key_for_row, score_map_from_audit, sha
from host_shards import HostShardDataset, decode_shard
from ego import ATTRIBUTES, EgoGraphs

OUT = ROOT / 'code/output/provenace_graph/collision_aware_v4_results'
MANIFEST = ROOT / 'code/output/provenace_graph/collision_aware_v4_local_host_input/manifest.json'
VOLUME = ROOT / 'code/output/host_ml_seed02/model_input/volumes/ssd'


def summarize(rows):
    y = np.fromiter((r['label'] for r in rows), dtype=np.int8)
    s = np.fromiter((r['graph_score'] for r in rows), dtype=np.float64)
    pred = s >= .95
    tp = int(np.sum(pred & (y == 1)))
    fp = int(np.sum(pred & (y == 0)))
    fn = int(np.sum(~pred & (y == 1)))
    tn = int(np.sum(~pred & (y == 0)))
    result = dict(n=len(rows), benign=int(np.sum(y == 0)), malicious=int(np.sum(y == 1)),
                  prevalence=float(np.mean(y)) if len(y) else None,
                  tp=tp, fp=fp, fn=fn, tn=tn,
                  precision=tp/(tp+fp) if tp+fp else None,
                  recall=tp/(tp+fn) if tp+fn else None,
                  fpr=fp/(fp+tn) if fp+tn else None,
                  roc_auc=float(roc_auc_score(y, s)) if len(set(y)) == 2 else None,
                  average_precision=float(average_precision_score(y, s)) if np.any(y) else None)
    for label, name in ((0, 'benign'), (1, 'malicious')):
        values = s[y == label]
        result[name + '_score'] = (dict(min=float(values.min()), p10=float(np.quantile(values, .1)),
                                         p25=float(np.quantile(values, .25)), median=float(np.median(values)),
                                         p75=float(np.quantile(values, .75)), p90=float(np.quantile(values, .9)),
                                         max=float(values.max()), at_least_95=int(np.sum(values >= .95)))
                                        if len(values) else None)
    return result


def main():
    identity = json.loads((OUT / 'config.json').read_text())
    if sha(MANIFEST) != identity['manifest_sha256']:
        raise ValueError('validation manifest identity mismatch')
    collisions = {bytes.fromhex(item['vector_key']) for line in (OUT / 'collision_registry.jsonl').open()
                  if (item := json.loads(line))['labels'] == [0, 1]}
    scores = score_map_from_audit(ROOT / 'code/output/provenace_graph/collision_aware_v4/local_score_map.json',
                                  identity['host_model_sha256'])
    data = HostShardDataset(MANIFEST, volume_roots={'ssd': VOLUME})
    rows = []
    for index, shard in enumerate(data.meta['shards']):
        if shard['split'] != 'val':
            continue
        x, labels, lines = decode_shard(data.path_for(shard), data.width, shard)
        cache = OUT / f'val-graph-{index:04d}.npz'
        receipt = json.loads(cache.with_suffix('.json').read_text())
        if sha(cache) != receipt['sha256'] or receipt['identity'] != identity or receipt['shard_sha256'] != shard['sha256']:
            raise ValueError(f'graph cache identity mismatch: {index}')
        with np.load(cache, allow_pickle=False) as content:
            graph = content['graph']
        if len(graph) != len(labels):
            raise ValueError('graph cache length mismatch')
        for row, label in enumerate(labels):
            key = key_for_row(x, row)
            if key not in collisions:
                continue
            score = float(graph[row])
            if not np.isfinite(score):
                raise ValueError(f'missing GraphSAGE score: {index}:{row}')
            ml = scores[key]
            band = 'low' if ml < .30 else 'middle' if ml < .96 else 'high'
            rows.append(dict(source_id=shard['source_id'], source_line=int(lines[row]),
                             vector_key=key.hex(), label=int(label), lgbm_score=ml,
                             graph_score=score, band=band))
        print(f'validation shard {index}: {len(rows)} collision events so far', flush=True)
    result = dict(scope='validation collision events only; registry labels from TRAIN only',
                  identity=identity, collision_vectors_in_train=len(collisions),
                  overall=summarize(rows),
                  bands={band: summarize([r for r in rows if r['band'] == band])
                         for band in ('low', 'middle', 'high')})
    groups = defaultdict(lambda: [[], []])
    for r in rows:
        groups[r['vector_key']][r['label']].append(r)
    paired = {key: group for key, group in groups.items() if all(group)}
    pair_stats = dict(vectors=len(paired), events=sum(len(a)+len(b) for a,b in paired.values()),
                      perfect_at_95=0, both_high_at_95=0, both_low_at_95=0,
                      mixed_at_95=0, positive_median_gap=0, nonpositive_median_gap=0,
                      concordant_pairs=0, tied_pairs=0, all_pairs=0)
    per_vector_concordance = []
    candidates = []
    for key, (benign, malicious) in paired.items():
        b = np.array([r['graph_score'] for r in benign])
        m = np.array([r['graph_score'] for r in malicious])
        bh, mh = np.any(b >= .95), np.any(m >= .95)
        bl, ml = np.any(b < .95), np.any(m < .95)
        category = ('perfect_at_95' if not bh and not ml else
                    'both_high_at_95' if bh and mh and not bl and not ml else
                    'both_low_at_95' if bl and ml and not bh and not mh else 'mixed_at_95')
        pair_stats[category] += 1
        pair_stats['positive_median_gap' if np.median(m) > np.median(b) else 'nonpositive_median_gap'] += 1
        sorted_b = np.sort(b)
        vector_concordant = 0
        vector_tied = 0
        for score in m:
            vector_concordant += int(np.searchsorted(sorted_b, score, side='left'))
            vector_tied += int(np.searchsorted(sorted_b, score, side='right') -
                               np.searchsorted(sorted_b, score, side='left'))
        pair_stats['concordant_pairs'] += vector_concordant
        pair_stats['tied_pairs'] += vector_tied
        pair_stats['all_pairs'] += len(b) * len(m)
        per_vector_concordance.append((vector_concordant+.5*vector_tied)/(len(b)*len(m)))
        b_low = min(benign, key=lambda r: r['graph_score'])
        b_high = max(benign, key=lambda r: r['graph_score'])
        m_low = min(malicious, key=lambda r: r['graph_score'])
        m_high = max(malicious, key=lambda r: r['graph_score'])
        examples = [(b_low, m_high), (b_high, m_low)]
        if examples:
            br, mr = max(examples, key=lambda pair: abs(pair[1]['graph_score'] - pair[0]['graph_score']))
            candidates.append(dict(category=category, vector_key=key,
                                   benign=br, malicious=mr, n_benign=len(b), n_malicious=len(m),
                                   median_gap=float(np.median(m)-np.median(b)),
                                   example_gap=mr['graph_score']-br['graph_score']))
    pair_stats['concordance'] = ((pair_stats['concordant_pairs']+.5*pair_stats['tied_pairs'])/
                                 pair_stats['all_pairs'] if pair_stats['all_pairs'] else None)
    pair_stats['macro_concordance'] = float(np.mean(per_vector_concordance))
    pair_stats['median_vector_concordance'] = float(np.median(per_vector_concordance))
    pair_stats['vectors_concordance_above_0_5'] = sum(v > .5 for v in per_vector_concordance)
    result['same_vector_opposite_label'] = pair_stats
    selected = []
    for category in ('perfect_at_95', 'both_high_at_95', 'both_low_at_95', 'mixed_at_95'):
        choices = [c for c in candidates if c['category'] == category]
        choices.sort(key=lambda c: (c['n_benign']+c['n_malicious'], abs(c['median_gap'])), reverse=True)
        selected.extend(choices[:3])
    vocab = json.loads((ROOT / 'code/output/host_ml_seed02/model_input/assets/vocab.json').read_text())
    inverse_vocab = {v: k for k, v in vocab.items()}
    for item in selected:
        columns = np.frombuffer(bytes.fromhex(item['vector_key']), dtype='<u4')
        item['host_feature_tokens'] = [inverse_vocab[int(column)] for column in columns]
    db_path = ROOT / 'code/output/provenace_graph/collision_aware_v4_local_bundle/provenance/graph.sqlite'
    db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    ego = EgoGraphs(db)
    try:
        for item in selected:
            for label in ('benign', 'malicious'):
                event = item[label]
                target = db.execute('SELECT host,proc,t,split FROM target WHERE source=? AND line=?',
                                    (event['source_id'], event['source_line'])).fetchone()
                if target is None or target[3] != 2:
                    raise ValueError('selected event missing from validation graph targets')
                graph = ego.build(*target[:3])
                root = graph['x'][graph['root']]
                encoded = graph['x'].tobytes() + repr(graph['edges']).encode()
                event['graph_context'] = dict(nodes=len(graph['node_keys']),
                                              process_nodes=sum(p is not None for _,p in graph['node_keys']),
                                              host_nodes=sum(p is None for _,p in graph['node_keys']),
                                              creates_edges=sum(e[2] == 'creates' for e in graph['edges']),
                                              communicates_edges=sum(e[2] == 'communicates' for e in graph['edges']),
                                              root_facts=[ATTRIBUTES[i] for i in np.flatnonzero(root) if i >= 6],
                                              flags=list(graph['flags']),
                                              encoding_sha256=hashlib.sha256(encoded).hexdigest())
            item['same_graph_encoding'] = (item['benign']['graph_context']['encoding_sha256'] ==
                                           item['malicious']['graph_context']['encoding_sha256'])
    finally:
        db.close()
    (OUT / 'validation_collision_diagnostic.json').write_text(json.dumps(result, indent=2))
    (OUT / 'validation_collision_pairs.jsonl').write_text(''.join(json.dumps(item)+'\n' for item in selected))
    print(json.dumps({k: v for k,v in result.items() if k != 'identity'}, indent=2))


if __name__ == '__main__':
    main()
