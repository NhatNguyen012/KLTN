#!/usr/bin/env python3
"""Error analysis of a step-2 (OpTC -> ATLASv2) IL run: which VAL/TEST windows are FN / FP at the val-selected threshold.
Usage: analyze_step2.py <run_dir> [--data dataset.pkl]"""
import argparse, copy, json, pickle, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import numpy as np, torch
HERE = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/optc_il"); sys.path.insert(0, str(HERE))
import train_il as T
from contract import FIELDS, load_optc_vocab
from il_model import ILBiLSTM, load_base
ap = argparse.ArgumentParser(); ap.add_argument("run"); ap.add_argument("--show", type=int, default=6); a = ap.parse_args()
run = Path(a.run); res = json.loads((run / "result.json").read_text()); args = argparse.Namespace(**res["args"])
dev = torch.device("cpu")
base, cfg, _ = load_base(dev); old_cards = cfg["categorical_cardinalities"]
blob = pickle.load(open(args.data, "rb")); meta = blob["meta"]; cat_fields = meta["cat_fields"]
drop = {f for f in args.drop_ctx.split(",") if f}; ctx_idx = [i for i, f in enumerate(cat_fields) if f not in drop]; n_cmd = meta["num_dim"] - 3
optc_vocab = load_optc_vocab(); cnt = {f: Counter() for f in FIELDS}; seen = set()
for s in blob["splits"]["train"]:
    for tr, ev in zip(s["trace"], s["optc_raw"]):
        key = (s["host"], tr[0], tr[1])
        if key in seen: continue
        seen.add(key)
        for f, v in zip(FIELDS, ev): cnt[f][v] += 1
ext, n_new = {}, []
for f, oc in zip(FIELDS, old_cards):
    m = dict(optc_vocab[f]); nxt = oc
    for v, c in sorted(cnt[f].items(), key=lambda x: (-x[1], x[0])):
        if v != "<MISSING>" and v not in m and c >= args.min_count: m[v] = nxt; nxt += 1
    ext[f] = m; n_new.append(nxt - oc)
A = T.atlas_samples(blob, args.label, ext, ctx_idx, n_cmd)
ctx_cards = [len(meta["vocab"][cat_fields[i]]) for i in ctx_idx]; n_ctx, cnd = len(ctx_idx), meta["num_dim"]
model = ILBiLSTM(copy.deepcopy(base), n_new, ctx_cards, cnd, hidden2=args.hidden2).to(dev)
model.load_state_dict(torch.load(run / "best.pt", map_location=dev)); model.eval()
thr = res["atlas"]["threshold_logit_val"]
f = lambda x: datetime.fromtimestamp(x / 1e6, tz=timezone.utc).strftime("%H:%M:%S")
def describe(s):
    src = s["src"]; tr = src["trace"]; ev = src[f"ev_y_{args.label}"]
    pos = [f"{t[1]}:{t[2]}>{t[3]}" for t, y in zip(tr, ev) if y == 1]
    allc = Counter(f"{t[1]}:{t[2]}" for t in tr)
    return f"{src['sample_id']} {f(src['start'])}-{f(src['end'])} n={len(tr)} pos_events={pos[:5]}{'...' if len(pos) > 5 else ''} | top actors {dict(allc.most_common(4))}"
print(f"RUN {run.name}: best ep {res['best_epoch']}, val threshold (logit) {thr:.2f}")
for split in ("val", "test"):
    d = A[split]; z = T.predict(model, d, dev, n_ctx, cnd); y = np.array([s["y"] for s in d])
    m = T.metrics(y, z, thr)
    print(f"\n[{split}] tp {m['tp']} fp {m['fp']} fn {m['fn']} F1 {m['f1']:.3f} AP {m.get('ap', float('nan')):.3f} | best-possible F1 on this split {T.best_threshold(y, z)[1]:.3f}")
    zs_pos = np.sort(z[y == 1]); zs_neg = np.sort(z[y == 0])[::-1]
    print(f"   positive logits: min {zs_pos[0]:.2f} p10 {np.percentile(zs_pos, 10):.2f} median {np.median(zs_pos):.2f} | top negative logits {np.round(zs_neg[:6], 2).tolist()}")
    fn = [i for i in np.flatnonzero((y == 1) & (z < thr))]; fp = [i for i in np.flatnonzero((y == 0) & (z >= thr))]
    by = lambda idx: dict(Counter(f"{d[i]['src']['scenario']}/{d[i]['src']['host'][-2:]}" for i in idx))
    print(f"   positives by scenario/host {by(np.flatnonzero(y == 1))}; FN by scenario/host {by(fn)}; FP by scenario/host {by(fp)}")
    for name, idx in (("FN", fn), ("FP", sorted(fp, key=lambda i: -z[i]))):
        for i in idx[:a.show]:
            print(f"   {name} z={z[i]:.2f}  {describe(d[i])[:330]}")
