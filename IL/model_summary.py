#!/usr/bin/env python3
"""Human-readable summary of the two final IL models (after OpTC -> ATLASv2 -> SL700).

  DL: ILBiLSTM (+ Linux token bag) rebuilt from a step-3 best.pt (shapes are read from the checkpoint, the
      state dict is loaded with strict=True) and printed with torchinfo.summary.
  ML: the three LightGBM boosters of the residual chain  z = 0.8*(0.8*z_OpTC + z_ATLASv2) + z_SL700.

Usage: PYTHONPATH=<dir with torchinfo> python3 model_summary.py --dl <step3 run dir> --step2 <step2 run dir> \
           --ml-step3 <ml step3 run dir> --ml-atlas <.../lgbm-kaggle> [--ml-vocab <vocab_sl700.json>]
       [--batch 1 --events 512 --bag-k 64]   size of the example input used for the shape columns
"""
import argparse, json, sys
from pathlib import Path

import torch
import torch.nn as nn

IL = Path(__file__).resolve().parent
sys.path.insert(0, str(IL / "dataset_1-ATLASv2/code/DL/optc_il"))
sys.path.insert(0, str(IL / "dataset_2-AInception/code/DL"))
from il_model import ILBiLSTM, load_base  # noqa: E402


def build_from_checkpoint(sd):
    base, cfg, _ = load_base("cpu")
    n_emb = len(base.embeddings)
    n_new = [sd[f"embeddings.{i}.new.weight"].shape[0] for i in range(n_emb)]
    ctx = [tuple(sd[k].shape) for k in sorted((k for k in sd if k.startswith("ctx_embs.")), key=lambda k: int(k.split(".")[1]))]
    has_bag = "bag_emb.weight" in sd
    bag_dim = sd["bag_emb.weight"].shape[1] if has_bag else 0
    cin = sd["ctx_proj.0.weight"].shape[1]
    ctx_num = cin - sum(d for _, d in ctx) - bag_dim
    m = ILBiLSTM(base, n_new, [r for r, _ in ctx], ctx_num, hidden2=sd["lstm2.weight_hh_l0"].shape[1])
    for i, e in enumerate(m.embeddings):                         # grown embedding tables keep the old dim
        e.old = nn.Embedding(*sd[f"embeddings.{i}.old.weight"].shape); e.n_old = e.old.num_embeddings
        e.new = nn.Embedding(*sd[f"embeddings.{i}.new.weight"].shape)
    m.ctx_embs = nn.ModuleList(nn.Embedding(r, d, padding_idx=0) for r, d in ctx)
    m.ctx_proj[0] = nn.Linear(cin, sd["ctx_proj.0.weight"].shape[0])
    m.stage_head[-1] = nn.Linear(sd["stage_head.2.weight"].shape[1], sd["stage_head.2.weight"].shape[0])
    if has_bag:
        from train_il_step3_v2 import ILBiLSTMBag
        m.__class__ = ILBiLSTMBag
        m.bag_emb = nn.EmbeddingBag(*sd["bag_emb.weight"].shape, mode="mean", padding_idx=0)
    m.load_state_dict(sd, strict=True)
    return m.eval(), base, dict(n_new=n_new, ctx=ctx, ctx_num=ctx_num, has_bag=has_bag)


def dl_summary(run, step2, B=1, T=512, K=64):
    import torchinfo
    sd = torch.load(Path(run) / "best.pt", map_location="cpu")
    m, base, info = build_from_checkpoint(sd)
    n_emb = len(m.embeddings)
    d_delta = m.event_encoder[0].in_features - sum(e.old.embedding_dim for e in m.embeddings) - 1
    inp = dict(x_cat=torch.ones(B, T, n_emb, dtype=torch.long), delta=torch.zeros(B, T, d_delta),
               ctx_cat=torch.ones(B, T, len(info["ctx"]), dtype=torch.long), ctx_num=torch.zeros(B, T, info["ctx_num"]),
               has_ctx=torch.ones(B), lengths=torch.full((B,), T, dtype=torch.long))
    if info["has_bag"]:
        inp["bag"] = torch.ones(B, T, K, dtype=torch.long)
    print("=" * 100)
    print(f"DL model after OpTC -> ATLASv2 -> SL700: {run}")
    print(f"(input: {B} window x {T} events = the maximum window length used in training/testing"
          + (f", up to {K} Linux tokens per event)" if info["has_bag"] else ")"))
    print("=" * 100)
    print(torchinfo.summary(m, input_data=inp, depth=3, verbose=0,
                            col_names=("input_size", "output_size", "num_params", "trainable"), row_settings=("var_names",)))
    n = lambda mod: sum(p.numel() for p in mod.parameters())
    n_sd = lambda d: sum(v.numel() for v in d.values())
    rows = [("Task 0  OpTC base BiLSTM (embeddings, event encoder, BiLSTM, classifier)", n(base))]
    if step2 and (Path(step2) / "best.pt").exists():
        s2 = n_sd(torch.load(Path(step2) / "best.pt", map_location="cpu"))
        rows.append(("Task 1  + ATLASv2: new token rows, host-context branch, 2nd BiLSTM, event/stage heads, gate", s2 - rows[0][1]))
        rows.append(("Task 2  + SL700: new token/context rows, 5th stage class, Linux token bag", n(m) - s2))
    rows.append(("Total", n(m)))
    print("\nParameters added at each incremental step")
    for name, v in rows:
        print(f"  {name:<95s} {v:>10,d}")
    g = m.groups()
    print("\nParameter groups (the final model is fine-tuned with all groups trainable from epoch 1, with replay of old domains)")
    for k, ps in g.items():
        print(f"  {k:<9s} {sum(p.numel() for p in ps):>10,d} parameters in {len(ps)} tensors")
    print("""
Data flow of one window (T events).  [old] = from the OpTC model, [T1] = added at ATLASv2, [T2] = added at SL700
  x_cat (4 token ids per event) --> embeddings: id < old size ? old row [old] : new row [T1/T2]      (B,T,33)
  concat with 1 zero column + delta-time                                                             (B,T,35)
  --> event_encoder [old]                                                              event         (B,T,64)
  ctx_cat (10 host-context ids) --> ctx_embs [T1], ctx_num, bag of Linux tokens --> bag_emb [T2]
  --> ctx_proj [T1], last Linear zero-initialised                                      ctx           (B,T,64)
  event = event + ctx * has_ctx          (has_ctx = 0 for OpTC windows: they go through the old path only)
  --> lstm  BiLSTM [old] --> per-event states (B,T,128) and final states (B,128)
        final states --> classifier [old] --> z_old   (window logit of the OpTC model)
        per-event states --> lstm2 BiLSTM [T1] --> event_head [T1] --> one attack logit per event    (B,T)
                                               --> stage_head [T1, 5th class T2] --> attack stage    (B,T,5)
  window logit  z = z_old + gate * max over events(event logit)        gate [T1] starts at 0
  => at the start of each incremental step the extended model outputs exactly the previous model
     (checked numerically before training: init_equivalence_max_abs in result.json).""")
    res = Path(run) / "result.json"
    if res.exists():
        rr = json.loads(res.read_text()); ar = rr["args"]
        print("\nTraining settings of this step (args in result.json)")
        print("  " + ", ".join(f"{k}={ar[k]}" for k in sorted(ar) if k not in ("out", "sl700_data", "events_dir") and ar[k] not in (None, "")))
        print(f"  best epoch {rr['best_epoch']}; output equal to the step-2 model before training up to {rr['init_equivalence_max_abs']}")
    if res.exists():
        a = json.loads(res.read_text())["after"]
        print("\nTest results of this checkpoint (threshold chosen on validation)")
        for name, d in (("SL700", a["sl700"]["test"]), ("ATLASv2", a["atlas"]["test"]), ("OpTC", a["optc"]["test_at_base_thr"])):
            print(f"  {name:<8s} F1 {d['f1']:.3f}  P {d['precision']:.3f}  R {d['recall']:.3f}  (tp {d['tp']}  fp {d['fp']}  fn {d['fn']})")


def booster_stats(path, names=None):
    import lightgbm as lgb
    import numpy as np
    b = lgb.Booster(model_file=str(path))
    df = b.trees_to_dataframe()
    leaves = df[df.split_feature.isna()]
    per_tree = leaves.groupby("tree_index").size()
    depth = df.groupby("tree_index").node_depth.max()
    imp = b.feature_importance("gain")
    names = names or {i: n for i, n in enumerate(b.feature_name())}
    top = [(names.get(i, f"Column_{i}"), imp[i] / imp.sum()) for i in np.argsort(-imp)[:10] if imp[i] > 0]
    pr = b.params
    return dict(trees=b.num_trees(), features=b.num_feature(), used_features=int((b.feature_importance("split") > 0).sum()),
                leaves_total=int(len(leaves)), leaves_per_tree=float(per_tree.mean()), max_depth=int(depth.max()),
                mean_depth=float(depth.mean()), top_gain=top,
                params={k: pr.get(k) for k in ("objective", "learning_rate", "num_leaves", "min_data_in_leaf", "lambda_l2", "scale_pos_weight")})


def print_tree(path, names, tree=0, max_depth=3):
    import lightgbm as lgb
    df = lgb.Booster(model_file=str(path)).trees_to_dataframe()
    df = df[df.tree_index == tree].set_index("node_index")
    def walk(n, d):
        r = df.loc[n]; pad = "    " + "  " * d
        if r.split_feature is None or r.split_feature != r.split_feature:
            print(f"{pad}leaf value {r.value:+.4f}  ({int(r['count'])} rows)"); return
        col = int(str(r.split_feature).replace("Column_", "")); tok = names.get(col, r.split_feature) if names else r.split_feature
        if d >= max_depth:
            print(f"{pad}... subtree on [{tok}] ({int(r['count'])} rows)"); return
        print(f"{pad}[{tok}] absent:"); walk(r.left_child, d + 1)
        print(f"{pad}[{tok}] present:"); walk(r.right_child, d + 1)
    walk(df.index[0], 0)


def ml_summary(step3_run, atlas_run, vocab=None):
    names = {i: t for t, i in json.loads(Path(vocab).read_text()).items()} if vocab else None
    ml1 = IL / "dataset_1-ATLASv2/code/ML"
    latest = json.loads((Path(atlas_run) / "incremental/model/latest.json").read_text())
    parts = [("Task 0  OpTC base booster", ml1 / "pretrained_optc_model/model-slot-0.txt", 0.8 * 0.8),
             ("Task 1  ATLASv2 residual booster", Path(atlas_run) / "incremental/model" / latest["path"], 0.8),
             ("Task 2  SL700 residual booster", Path(step3_run) / "model.txt", 1.0)]
    print("\n" + "=" * 100)
    print(f"ML model after OpTC -> ATLASv2 -> SL700 (LightGBM, binary logistic): {step3_run}")
    print("z(x) = 0.8 * (0.8 * z_OpTC(x[:w0]) + z_ATLASv2(x[:w1])) + z_SL700(x);  p = sigmoid(z);  old boosters are frozen")
    print("=" * 100)
    print(f"{'stage':<36s}{'weight':>7s}{'trees':>7s}{'features':>10s}{'used':>7s}{'leaves':>9s}{'leaves/tree':>12s}{'depth mean/max':>16s}")
    tot_t = tot_l = 0
    tops = []
    for name, p, w in parts:
        s = booster_stats(p, names); tot_t += s["trees"]; tot_l += s["leaves_total"]; tops.append((name, s["top_gain"], s["params"]))
        print(f"{name:<36s}{w:>7.2f}{s['trees']:>7d}{s['features']:>10,d}{s['used_features']:>7,d}{s['leaves_total']:>9,d}"
              f"{s['leaves_per_tree']:>12.1f}{s['mean_depth']:>10.1f} /{s['max_depth']:>3d}")
    print(f"{'Total':<36s}{'':>7s}{tot_t:>7d}{'':>10s}{'':>7s}{tot_l:>9,d}")
    print("\nInput: one row per event, multi-hot vector of tokens (1 = the token occurs in the event). The vocabulary only grows:")
    print("  columns of an older task keep their index, so an old booster reads the first w columns of the new vector.")
    print("\nHyper-parameters")
    for name, _, pr in tops:
        print(f"  {name}: " + ", ".join(f"{k}={v}" for k, v in pr.items() if v is not None))
    print("\nMost important features by gain (share of the total gain of that booster)")
    for name, t, _ in tops:
        print(f"  {name}")
        for tok, g in t:
            print(f"    {g:>6.1%}  {tok}")
    print("\nExample: first tree of the SL700 booster, top 3 levels (features are 0/1, so a split = token absent / present)")
    print_tree(parts[2][1], names)
    res = Path(step3_run) / "result.json"
    if res.exists():
        r = json.loads(res.read_text())
        f = lambda d: f"F1 {d['f1']:.3f}  P {d['precision']:.3f}  R {d['recall']:.3f}  (tp {d['tp']}  fp {d['fp']}  fn {d['fn']})"
        i = r["info"]; ar = r["args"]
        print(f"""
Training of the SL700 booster (step 3)
  unit of prediction: one event (one row); labels are per event
  rows: SL700 train {i['sl700_rows']:,d} ({i['sl700_pos']:,d} attack), negatives capped at {ar['neg_per_pos']}:1
  replay OpTC: {i['replay_optc'][0]:,d} attack + {i['replay_optc'][1]:,d} benign;  replay ATLASv2: {i['replay_atlas'][0]:,d} attack + {i['replay_atlas'][1]:,d} benign
  init score (the booster learns the residual): 0.8*z1 for SL700 rows and replay negatives, {ar['rep_pos_alpha']}*z1 for replay positives,
      z1 = 0.8*z_OpTC + z_ATLASv2 = frozen model of the previous step
  hard negatives (benign rows the previous model scores > 0.5): {i['hard_negatives']:,d} rows, weight 5
  threshold: maximum F1 on SL700 validation; thresholds of ATLASv2 and OpTC are frozen from their own steps""")
        print("\nTest results, per event (each test set scored once)")
        print(f"  SL700 zero-shot, before step 3   {f(r['sl700_zero_shot_task1']['test'])}")
        print(f"  SL700 after step 3               {f(r['sl700']['test'])}")
        print(f"  ATLASv2 before step 3            {f(r['before_step3']['atlas_test'])}")
        print(f"  ATLASv2 after step 3             {f(r['after_step3']['atlas_test'])}")
        print(f"  OpTC before step 3               {f(r['before_step3']['optc_test'])}")
        print(f"  OpTC after step 3                {f(r['after_step3']['optc_test'])}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dl"); ap.add_argument("--step2"); ap.add_argument("--ml-step3"); ap.add_argument("--ml-atlas")
    ap.add_argument("--ml-vocab", help="token -> column json, to print token names instead of column indices")
    ap.add_argument("--batch", type=int, default=1); ap.add_argument("--events", type=int, default=512); ap.add_argument("--bag-k", type=int, default=64)
    a = ap.parse_args()
    if a.dl:
        dl_summary(a.dl, a.step2, a.batch, a.events, a.bag_k)
    if a.ml_step3:
        ml_summary(a.ml_step3, a.ml_atlas, a.ml_vocab)
