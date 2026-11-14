#!/usr/bin/env python3
"""Inference cost of the final DL IL model (step 3, bag_freeze_replay2): rebuild it as train_il_step3_v2.main does,
load best.pt of a run, time predict() on SL700 / ATLASv2 / OpTC TEST on GPU and on CPU."""
import sys, time, json, copy, pickle, resource
from pathlib import Path
import numpy as np, torch
sys.path.insert(0, "/mnt/SSD_Data/optc/IL/dataset_2-AInception/code/DL")
import train_il_step3_v2 as M
S3, T = M.S3, M.T
run = Path(sys.argv[1])
D = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output")
S3.SL700_DATA = D / "sl700_windows_v3/dataset.pkl"; M.EV2 = D / "rootcause_20261113/events_v3"
dev = torch.device("cuda")
base, cfg, _ = M.load_base(dev)
old_cards = cfg["categorical_cardinalities"]
blob = pickle.load(open(S3.ATLAS_DATA, "rb")); meta = blob["meta"]; cat_fields = meta["cat_fields"]
ctx_idx = [i for i, f in enumerate(cat_fields) if f != "ip_scope"]; ctx_fields = [cat_fields[i] for i in ctx_idx]
n_cmd, cnd = meta["num_dim"] - 3, meta["num_dim"]
ext_atlas, n_new_atlas = S3.atlas_ext_vocab(blob, old_cards, 2)
model2 = M.ILBiLSTM(copy.deepcopy(base), n_new_atlas, [len(meta["vocab"][f]) for f in ctx_fields], cnd, hidden2=64).to(dev)
for e, k in zip(model2.embeddings, n_new_atlas): e.n_new_used = k > 0
sl = pickle.load(open(S3.SL700_DATA, "rb")); cnt_o, cnt_c = S3.sl700_counts(sl)
ext, n_new_sl = {}, []
for f, oc, k in zip(M.FIELDS, old_cards, n_new_atlas):
    ext[f], n = S3.extend(ext_atlas[f], cnt_o[f], oc + k, 2); n_new_sl.append(n)
ctx_vocab, ctx_new = {}, []
for f in ctx_fields:
    ctx_vocab[f], n = S3.extend(meta["vocab"][f], cnt_c[f], len(meta["vocab"][f]), 2, skip=()); ctx_new.append(n)
split_of = {s["sample_id"]: sp for sp, lst in sl["splits"].items() for s in lst}
ids, by_sample, n_tok = M.load_bags(["g_ev", "g_par", "g_ses"], 2, 64, split_of)
sl_te = S3.sl700_samples(sl, ext, ctx_vocab, ctx_fields, n_cmd, "test"); M.attach_bags(sl_te, ids, by_sample, 64)
at_te = T.atlas_samples(blob, "v9b", ext, ctx_idx, n_cmd)["test"]
rows = T.optc_rows(); op_te = T.load_optc([r for r in rows if r["split"] == "test"])
model = M.add_bag(S3.grow_model(model2, n_new_sl, ctx_new, 5).to(dev), n_tok, 32)
model.load_state_dict(torch.load(run / "best.pt", map_location=dev)); model.eval()
n_ctx = len(ctx_idx)
res = {"params_total": sum(p.numel() for p in model.parameters()), "best_pt_bytes": (run / "best.pt").stat().st_size}
for dname in ("cuda", "cpu"):
    d = torch.device(dname); model.to(d)
    if dname == "cpu": torch.set_num_threads(6)
    for name, data in (("sl700_test", sl_te), ("atlas_test", at_te), ("optc_test", op_te)):
        nev = int(sum(len(s["delta"]) for s in data))
        with torch.no_grad():
            S3.predict(model, data[:200], d, n_ctx, cnd)  # warm-up
            if dname == "cuda": torch.cuda.synchronize(); torch.cuda.reset_peak_memory_stats()
            t = time.perf_counter(); S3.predict(model, data, d, n_ctx, cnd)
            if dname == "cuda": torch.cuda.synchronize()
            dt = time.perf_counter() - t
        r = {"windows": len(data), "events": nev, "sec": round(dt, 3), "windows_per_s": round(len(data) / dt), "events_per_s": round(nev / dt),
             "ms_per_window": round(1000 * dt / len(data), 3)}
        if dname == "cuda": r["peak_gpu_alloc_MiB"] = round(torch.cuda.max_memory_allocated() / 2**20, 1)
        res[f"{dname}:{name}"] = r; print(dname, name, r, flush=True)
res["max_rss_MiB"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
(Path(sys.argv[2])).write_text(json.dumps(res, indent=1)); print(json.dumps(res))
