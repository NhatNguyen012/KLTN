#!/usr/bin/env python3
"""IL step 3, v2 input: OpTC -> ATLASv2 -> AInception SL700 with Linux (Base-OpTC-style) event tokens and causal
parent / login-session (incoming) context.

Same model, data, split, schedule, replay and selection as train_il_step3.py; one addition for SL700 events:
a bag of Linux tokens per event (events_v2 from code/rootcause/build_sl700_events_v2.py: command line, auth record,
uid/auid, file path class, actor/parent/grandparent context, login-session context), vocabulary from SL700 TRAIN
events (min count 2, <UNK> = 1, pad = 0), embedded with a mean EmbeddingBag and concatenated to the host-context
input. The new input columns of the context projection start at zero, so the grown model still reproduces the
step-2 model on OpTC, ATLASv2 and SL700 at initialisation (asserted). OpTC / ATLASv2 windows have empty bags.
"""
from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import pickle
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train_il_step3 as S3  # noqa: E402
from train_il_step3 import T, FIELDS, ILBiLSTM, load_base  # noqa: E402

EV2 = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/rootcause_20261113/events_v2")
SEP = "\x1f"


# ------------------------------------------------------------------ model: + bag branch
class ILBiLSTMBag(ILBiLSTM):
    def forward(self, x_cat, delta, ctx_cat, ctx_num, has_ctx, lengths, bag=None):
        B, T_, _ = x_cat.shape
        parts = [emb(x_cat[..., i]) for i, emb in enumerate(self.embeddings)]
        x_bin = torch.zeros(B, T_, 1, device=x_cat.device)
        event = self.event_encoder(torch.cat(parts + [x_bin, delta], -1))
        c = [e(ctx_cat[..., i]) for i, e in enumerate(self.ctx_embs)] + [ctx_num]
        bv = self.bag_emb(bag.reshape(B * T_, -1)).reshape(B, T_, -1)
        event = event + self.ctx_proj(torch.cat(c + [bv], -1)) * has_ctx[:, None, None]
        packed = pack_padded_sequence(event, lengths.cpu(), batch_first=True, enforce_sorted=False)
        out, (h_n, _) = self.lstm(packed)
        z_old = self.classifier(torch.cat([h_n[-2], h_n[-1]], -1)).squeeze(-1)
        h2, _ = self.lstm2(out)
        h2, _ = pad_packed_sequence(h2, batch_first=True, total_length=T_)
        mask = torch.arange(T_, device=x_cat.device)[None] < lengths[:, None]
        ev = self.event_head(h2).squeeze(-1).masked_fill(~mask, -1e4)
        z = z_old + self.gate * ev.max(1).values
        return z, z_old, ev, self.stage_head(h2), mask


def add_bag(model, n_tok, dim):
    model.__class__ = ILBiLSTMBag
    dev = model.gate.device
    model.bag_emb = nn.EmbeddingBag(n_tok, dim, mode="mean", padding_idx=0).to(dev)
    lin = model.ctx_proj[0]
    nl = nn.Linear(lin.in_features + dim, lin.out_features).to(dev)
    with torch.no_grad():
        nl.weight.zero_(); nl.weight[:, :lin.in_features] = lin.weight; nl.bias.copy_(lin.bias)
    model.ctx_proj[0] = nl
    return model


# ------------------------------------------------------------------ data
def load_bags(groups, min_count, kmax, split_of):
    """split_of: sample_id -> split of the SL700 windows dataset in use (the bag vocabulary comes from its TRAIN windows)"""
    ev = pd.read_parquet(EV2 / "events.parquet", columns=["gid", "run", "kind"] + list(groups))
    W = pickle.load(open(EV2 / "windows.pkl", "rb"))
    cols = [ev[g].values for g in groups]
    toks = [sorted({t for part in row for t in (part.split(SEP) if part else ())}) for row in zip(*cols)]
    train_gid = set()
    for w in W:
        if split_of[w["sample_id"]] == "train":
            train_gid.update(w["idx"].tolist())
    cnt = Counter(t for g in train_gid for t in toks[g])
    keep = [t for t, c in sorted(cnt.items(), key=lambda x: (-x[1], x[0])) if c >= min_count]
    vocab = {t: i + 2 for i, t in enumerate(keep)}
    ids = []
    for row in toks:
        r = sorted({vocab.get(t, 1) for t in row})[:kmax]
        ids.append(np.asarray(r, np.int32))
    by_sample = {w["sample_id"]: w["idx"] for w in W}
    return ids, by_sample, len(vocab) + 2


def attach_bags(samples, ids, by_sample, kmax):
    for s in samples:
        idx = by_sample[s["id"]]
        assert len(idx) == len(s["delta"]), s["id"]
        b = np.zeros((len(idx), max(1, max(len(ids[g]) for g in idx))), np.int32)
        for j, g in enumerate(idx):
            r = ids[g]; b[j, :len(r)] = r
        s["bag"] = b


def collate(batch, device, n_ctx, cnd):
    inp, y, evy, evst, dom = S3_collate(batch, device, n_ctx, cnd)
    B = len(batch); L = max(len(s["delta"]) for s in batch)
    K = max((s["bag"].shape[1] for s in batch if "bag" in s), default=1)
    bag = np.zeros((B, L, K), np.int64)
    for i, s in enumerate(batch):
        if "bag" in s:
            n, w = s["bag"].shape
            bag[i, :n, :w] = s["bag"]
    inp["bag"] = torch.from_numpy(bag).to(device)
    return inp, y, evy, evst, dom


S3_collate = S3.collate
S3.collate = collate  # S3.predict / S3.evaluate resolve collate at call time


def main():
    global EV2
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--init", default="step2", choices=["step2", "random"])
    ap.add_argument("--step2-run", default="freeze_replay")
    ap.add_argument("--schedule", default="freeze", choices=["freeze", "full"])
    ap.add_argument("--epochs-a", type=int, default=4)
    ap.add_argument("--epochs-b", type=int, default=8)
    ap.add_argument("--epochs-c", type=int, default=8)
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--lr-a", type=float, default=1e-3)
    ap.add_argument("--lr", type=float, default=5e-4)
    ap.add_argument("--mult-body", type=float, default=0.2)
    ap.add_argument("--mult-emb", type=float, default=0.05)
    ap.add_argument("--wd", type=float, default=1e-4)
    ap.add_argument("--bs", type=int, default=64)
    ap.add_argument("--aux", type=float, default=0.5)
    ap.add_argument("--stage-w", type=float, default=0.5)
    ap.add_argument("--replay-optc", type=int, default=1)
    ap.add_argument("--replay-atlas", type=int, default=1)
    ap.add_argument("--rp-optc-pos", type=int, default=150)
    ap.add_argument("--rp-optc-neg", type=int, default=450)
    ap.add_argument("--rp-atlas-pos", type=int, default=100)
    ap.add_argument("--rp-atlas-neg", type=int, default=400)
    ap.add_argument("--optc-val-neg", type=int, default=4000)
    ap.add_argument("--select", default="all", choices=["all", "sl700"])
    ap.add_argument("--min-count", type=int, default=2)
    ap.add_argument("--bag-groups", default="g_ev,g_par,g_ses", help="token groups of events_v2 (add g_scope for login/connection address scope)")
    ap.add_argument("--bag-dim", type=int, default=32)
    ap.add_argument("--bag-max", type=int, default=64)
    ap.add_argument("--sl700-data", default=str(S3.SL700_DATA), help="windows dataset (sl700_windows_v1 = relabel_v2, sl700_windows_v3 = relabel_v3)")
    ap.add_argument("--events-dir", default=str(EV2), help="events_v2 (relabel_v2) or events_v3 (relabel_v3) with the same windows")
    a = ap.parse_args()
    S3.SL700_DATA, EV2 = Path(a.sl700_data), Path(a.events_dir)
    use_bag = a.bag_groups not in ("", "none")
    if not use_bag:
        S3.collate = S3_collate

    out = Path(a.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"output dir not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    t0 = time.time()

    # ---- rebuild the step-2 model exactly (as train_il_step3)
    base, cfg, base_thr_prob = load_base(dev)
    old_cards = cfg["categorical_cardinalities"]
    blob = pickle.load(open(S3.ATLAS_DATA, "rb"))
    meta = blob["meta"]; cat_fields = meta["cat_fields"]
    ctx_idx = [i for i, f in enumerate(cat_fields) if f != "ip_scope"]
    ctx_fields = [cat_fields[i] for i in ctx_idx]
    n_cmd, cnd = meta["num_dim"] - 3, meta["num_dim"]
    ext_atlas, n_new_atlas = S3.atlas_ext_vocab(blob, old_cards, a.min_count)
    ctx_cards_atlas = [len(meta["vocab"][f]) for f in ctx_fields]
    body = copy.deepcopy(base)
    if a.init == "random":
        for mod in body.modules():
            if hasattr(mod, "reset_parameters") and mod is not body:
                mod.reset_parameters()
    model2 = ILBiLSTM(body, n_new_atlas, ctx_cards_atlas, cnd, hidden2=64).to(dev)
    for e, k in zip(model2.embeddings, n_new_atlas):
        e.n_new_used = k > 0
    if a.init == "step2":
        model2.load_state_dict(torch.load(S3.STEP2 / f"{a.step2_run}_s{a.seed}" / "best.pt", map_location=dev), strict=True)

    # ---- SL700 vocabulary extension (TRAIN only) + Linux token bags
    sl = pickle.load(open(S3.SL700_DATA, "rb"))
    cnt_o, cnt_c = S3.sl700_counts(sl)
    ext, n_new_sl = {}, []
    for f, oc, k in zip(FIELDS, old_cards, n_new_atlas):
        ext[f], n = S3.extend(ext_atlas[f], cnt_o[f], oc + k, a.min_count); n_new_sl.append(n)
    ctx_vocab, ctx_new = {}, []
    for f in ctx_fields:
        ctx_vocab[f], n = S3.extend(meta["vocab"][f], cnt_c[f], len(meta["vocab"][f]), a.min_count, skip=())
        ctx_new.append(n)
    groups = [g for g in a.bag_groups.split(",") if g] if use_bag else []
    split_of = {s["sample_id"]: sp for sp, lst in sl["splits"].items() for s in lst}
    bag_ids, by_sample, n_tok = load_bags(groups, a.min_count, a.bag_max, split_of) if use_bag else (None, None, 0)
    print("SL700 new ids: contract", dict(zip(FIELDS, n_new_sl)), "| context", dict(zip(ctx_fields, ctx_new)),
          f"| bag groups {groups} vocab {n_tok}", flush=True)

    A = T.atlas_samples(blob, "v9b", ext, ctx_idx, n_cmd)
    at_tr, at_va, at_te = A["train"], A["val"], A["test"]
    S = {sp: S3.sl700_samples(sl, ext, ctx_vocab, ctx_fields, n_cmd, sp) for sp in ("train", "val", "test")}
    if use_bag:
        for lst in S.values():
            attach_bags(lst, bag_ids, by_sample, a.bag_max)
    sl_tr, sl_va, sl_te = S["train"], S["val"], S["test"]
    rows = T.optc_rows(); rng = np.random.default_rng(a.seed)
    tr_pos = [r for r in rows if r["split"] == "train" and r["label"] == "1"]
    tr_neg = [r for r in rows if r["split"] == "train" and r["label"] == "0"]
    pool = T.load_optc(tr_pos + [tr_neg[i] for i in rng.choice(len(tr_neg), 8000, replace=False)])
    op_pos = [s for s in pool if s["y"] == 1]; op_neg = [s for s in pool if s["y"] == 0]
    v_rows = [r for r in rows if r["split"] == "val"]
    v_pos = [r for r in v_rows if r["label"] == "1"]; v_neg = [r for r in v_rows if r["label"] == "0"]
    op_vsel = T.load_optc(v_pos + [v_neg[i] for i in rng.choice(len(v_neg), a.optc_val_neg, replace=False)])
    print(f"SL700 train/val/test {len(sl_tr)}/{len(sl_va)}/{len(sl_te)} | ATLASv2 {len(at_tr)}/{len(at_va)}/{len(at_te)}  [{time.time() - t0:.0f}s]", flush=True)

    # ---- grow (+ bag branch) and check equivalence with the step-2 model
    model = S3.grow_model(copy.deepcopy(model2), n_new_sl, ctx_new, 5).to(dev)
    if use_bag:
        model = add_bag(model, n_tok, a.bag_dim)
    n_ctx = len(ctx_idx)
    A2 = T.atlas_samples(blob, "v9b", ext_atlas, ctx_idx, n_cmd)
    step2_ctx = {f: meta["vocab"][f] for f in ctx_fields}
    sl_va2 = S3.sl700_samples(sl, ext_atlas, step2_ctx, ctx_fields, n_cmd, "val")

    def pred2(d):  # step-2 model on samples without bags
        return S3.predict(_Plain(model2) if use_bag else model2, d, dev, n_ctx, cnd)
    d_o = np.abs(S3.predict(model, op_vsel[:512], dev, n_ctx, cnd) - pred2(op_vsel[:512])).max()
    d_a = np.abs(S3.predict(model, at_va[:256], dev, n_ctx, cnd) - pred2(A2["val"][:256])).max()
    d_s = np.abs(S3.predict(model, sl_va[:256], dev, n_ctx, cnd) - pred2(sl_va2[:256])).max()
    print(f"init equivalence max|z_step3v2 - z_step2|: OpTC {d_o:.2e} ATLASv2 {d_a:.2e} SL700 {d_s:.2e}", flush=True)
    if a.init == "step2":
        assert max(d_o, d_a, d_s) < 1e-4, "grown model does not reproduce the step-2 model"

    op_val = T.load_optc(v_rows); op_te = T.load_optc([r for r in rows if r["split"] == "test"])
    del model2, A2, sl_va2

    # ---- training (identical loop to train_il_step3)
    y_sv, y_av, y_ov = (np.array([s["y"] for s in d]) for d in (sl_va, at_va, op_vsel))
    pw = {}
    for name, d in (("sl700", sl_tr), ("atlas", at_tr)):
        npos = sum(s["y"] for s in d); pw[name] = math.sqrt((len(d) - npos) / max(1, npos))
    evs = np.concatenate([s["evy"] for s in sl_tr] + ([s["evy"] for s in at_tr] if a.replay_atlas else []))
    epw = torch.tensor(math.sqrt((evs == 0).sum() / max(1, (evs == 1).sum())), device=dev)
    sts = np.concatenate([s["evst"] for s in sl_tr] + ([s["evst"] for s in at_tr] if a.replay_atlas else []))
    stc = np.array([(sts == k).sum() for k in range(1, 6)], float)
    stage_cw = torch.tensor(np.where(stc > 0, np.sqrt(stc.sum() / np.maximum(stc, 1) / (stc > 0).sum()), 0.0), dtype=torch.float32, device=dev)
    at_pos = [s for s in at_tr if s["y"] == 1]; at_neg = [s for s in at_tr if s["y"] == 0]
    n_ep = a.epochs if a.schedule == "full" else a.epochs_a + a.epochs_b + a.epochs_c
    hist, best, cur, opt = [], (-1.0, 0, None), None, None
    for ep in range(1, n_ep + 1):
        stn = S3.stage_of(ep, a)
        if stn != cur:
            g = model.groups()
            plan = ({"new": a.lr, "old_body": a.lr, "old_emb": a.lr} if stn == "FULL" else {"new": a.lr_a} if stn == "A" else
                    {"new": a.lr, "old_body": a.lr * a.mult_body} if stn == "B" else
                    {"new": a.lr, "old_body": a.lr * a.mult_body, "old_emb": a.lr * a.mult_emb})
            for n_, ps in g.items():
                for p in ps:
                    p.requires_grad = n_ in plan
            opt = torch.optim.AdamW([{"params": g[n_], "lr": lr} for n_, lr in plan.items() if g[n_]], weight_decay=a.wd)
            cur = stn
        model.train(); te0 = time.time()
        epoch = list(sl_tr)
        if a.replay_atlas:
            epoch += random.sample(at_pos, min(a.rp_atlas_pos, len(at_pos))) + random.sample(at_neg, a.rp_atlas_neg)
        if a.replay_optc:
            epoch += random.sample(op_pos, min(a.rp_optc_pos, len(op_pos))) + random.sample(op_neg, a.rp_optc_neg)
        random.shuffle(epoch)
        tot = defaultdict(float)
        for i in range(0, len(epoch), a.bs):
            batch = epoch[i:i + a.bs]
            inp, y, evy, evst, dom = (collate if use_bag else S3_collate)(batch, dev, n_ctx, cnd)
            z, _, ev, st, mask = model(**inp)
            wpos = torch.where(dom == 2, torch.full_like(y, pw["sl700"]), torch.where(dom == 1, torch.full_like(y, pw["atlas"]), torch.ones_like(y)))
            w = torch.where(y > 0, wpos, torch.ones_like(y))
            loss = (F.binary_cross_entropy_with_logits(z, y, reduction="none") * w).sum() / w.sum(); tot["bce"] += loss.item()
            m = evy >= 0
            if a.aux > 0 and m.any():
                l2 = F.binary_cross_entropy_with_logits(ev[m], evy[m], pos_weight=epw); loss = loss + a.aux * l2; tot["ev"] += l2.item()
            ms = evst > 0
            if a.stage_w > 0 and ms.any():
                l3 = F.cross_entropy(st[ms], evst[ms] - 1, weight=stage_cw); loss = loss + a.stage_w * l3; tot["stage_ce"] += l3.item()
            opt.zero_grad(); loss.backward()
            nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.0)
            opt.step()
        zs = S3.predict(model, sl_va, dev, n_ctx, cnd); za = S3.predict(model, at_va, dev, n_ctx, cnd); zo = S3.predict(model, op_vsel, dev, n_ctx, cnd)
        ss, sa, so = T.val_score(y_sv, zs), T.val_score(y_av, za), T.val_score(y_ov, zo)
        rec = {"epoch": ep, "stage": stn, **{k: round(v, 3) for k, v in tot.items()}, "sec": round(time.time() - te0, 1),
               "val_sl700": round(ss, 4), "val_atlas": round(sa, 4), "val_optc": round(so, 4), "gate": round(float(model.gate.item()), 3),
               "score": (ss + sa + so) / 3 if a.select == "all" else ss}
        hist.append(rec); print(json.dumps(rec), flush=True)
        if rec["score"] > best[0]:
            best = (rec["score"], ep, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()})

    model.load_state_dict(best[2]); torch.save(best[2], out / "best.pt")
    sets = {"sl_va": sl_va, "sl_te": sl_te, "at_va": at_va, "at_te": at_te, "op_val": op_val, "op_te": op_te}
    after = S3.evaluate(model, dev, n_ctx, cnd, sets, base_thr_prob)
    zt = after.pop("_sl700_test_logits")
    zv = S3.predict(model, sl_va, dev, n_ctx, cnd)
    res = {"args": vars(a), "best_epoch": best[1], "best_stage": S3.stage_of(best[1], a), "bag_vocab": n_tok,
           "init_equivalence_max_abs": {"optc": float(d_o), "atlas": float(d_a), "sl700": float(d_s)}, "after": after,
           "elapsed_sec": round(time.time() - t0)}
    (out / "result.json").write_text(json.dumps(res, indent=2, default=float))
    (out / "history.json").write_text(json.dumps(hist, indent=1))
    for name, d, z in (("test", sl_te, zt), ("val", sl_va, zv)):
        with open(out / f"sl700_{name}_predictions.csv", "w", newline="") as fh:
            wr = csv.writer(fh); wr.writerow(["sample_id", "y", "logit", "pred", "stages"])
            for s, zz in zip(d, z):
                wr.writerow([s["id"], s["y"], f"{zz:.5f}", int(zz >= after["sl700"]["threshold_logit_val"]), "|".join(map(str, s["stages"]))])
    f = lambda d: f"F1 {d['f1']:.4f} AP {d.get('ap', 0):.3f} (tp {d['tp']} fp {d['fp']} fn {d['fn']})"
    print("RESULT best_epoch", best[1], "\nSL700 TEST", f(after["sl700"]["test"]), "| stage", json.dumps(after["sl700"]["stage"]["summary"]),
          "\nATLASv2 TEST", f(after["atlas"]["test"]), "| stage presence %.3f" % (after["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0),
          "\nOpTC TEST@base_thr", f(after["optc"]["test_at_base_thr"]), flush=True)


class _Plain(nn.Module):
    """Step-2 model called with the v2 collate (drops the bag argument)."""

    def __init__(self, m):
        super().__init__()
        self.m = m
        self.stage_head = m.stage_head

    def forward(self, bag=None, **kw):
        return self.m(**kw)


if __name__ == "__main__":
    main()
