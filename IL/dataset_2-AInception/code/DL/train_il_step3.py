#!/usr/bin/env python3
"""IL step 3: OpTC -> ATLASv2 -> AInception SL700 (Linux auditd) with the optc_il BiLSTM.

Start: the step-2 model (IL/dataset_1-ATLASv2/code/DL/output/optc_il_20261112/runs/freeze_replay_s<seed>/best.pt),
rebuilt exactly (same vocabulary extension and context vocabulary) and loaded strictly. New for SL700:
  * OpTC-contract vocabulary extended again (ATLASv2 ids unchanged, SL700 TRAIN tokens appended, rows = copy of <UNK>);
  * host-context vocabularies extended the same way (rows = copy of the context <UNK>);
  * stage head 4 -> 5 classes (1 IC, 2 ED, 3 LM, 4 EX as ATLASv2; 5 Impact new), old rows copied, new row zero
    weight and a low bias.
At initialisation the window logit equals the step-2 model's on OpTC, ATLASv2 and SL700 inputs (asserted).
Training: freezing schedule A (non-OpTC-base parts) -> B (+ OpTC encoder/LSTM/classifier) -> C (+ OpTC embedding rows)
or full fine-tuning; replay of real OpTC TRAIN windows and/or real ATLASv2 TRAIN windows.
Selection (epoch, thresholds) on VALIDATION only: SL700 val (run a_c), ATLASv2 val, OpTC val.
TEST scored once: SL700 test (run f_a), ATLASv2 test, OpTC test, for the step-2 model ("before") and the result.
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
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, f1_score

OPTC_IL = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/optc_il")
sys.path.insert(0, str(OPTC_IL))
import train_il as T  # noqa: E402  (load_optc, optc_rows, atlas_samples, metrics, best_threshold, val_score, ...)
from contract import FIELDS, load_optc_vocab  # noqa: E402
from il_model import ILBiLSTM, load_base  # noqa: E402

ATLAS_DATA = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/output/bilstm_v9_20261112/dataset_v9b_stage_optc.pkl")
STEP2 = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL/output/optc_il_20261112/runs")
SL700_DATA = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/sl700_windows_v1/dataset.pkl")
STAGES = ["initial_compromise", "execution_discovery", "lateral_movement", "exfiltration", "impact"]
CTX_DOMS = ("atlas", "sl700")


# ------------------------------------------------------------------ vocabularies
def atlas_ext_vocab(blob, old_cards, min_count=2):
    """Exactly the step-2 extension (train_il.main)."""
    optc_vocab = load_optc_vocab()
    cnt = {f: Counter() for f in FIELDS}; seen = set()
    for s in blob["splits"]["train"]:
        for tr, ev in zip(s["trace"], s["optc_raw"]):
            key = (s["host"], tr[0], tr[1])
            if key in seen:
                continue
            seen.add(key)
            for f, v in zip(FIELDS, ev):
                cnt[f][v] += 1
    ext, n_new = {}, []
    for f, oc in zip(FIELDS, old_cards):
        m = dict(optc_vocab[f]); nxt = oc
        for v, c in sorted(cnt[f].items(), key=lambda x: (-x[1], x[0])):
            if v != "<MISSING>" and v not in m and c >= min_count:
                m[v] = nxt; nxt += 1
        ext[f] = m; n_new.append(nxt - oc)
    return ext, n_new


def sl700_counts(sl):
    cnt_o = {f: Counter() for f in FIELDS}; cnt_c = defaultdict(Counter); seen = set()
    cat_fields = sl["meta"]["cat_fields"]
    for s in sl["splits"]["train"]:
        for tr, ev, tok in zip(s["trace"], s["optc_raw"], s["tok_raw"]):
            key = (s["host"], s["run"], tr[0], tr[1])
            if key in seen:
                continue
            seen.add(key)
            for f, v in zip(FIELDS, ev):
                cnt_o[f][v] += 1
            for f, v in zip(cat_fields, tok):
                cnt_c[f][v] += 1
    return cnt_o, cnt_c


def extend(vocab, counts, start, min_count=2, skip=("<MISSING>",)):
    m = dict(vocab); nxt = start
    for v, c in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
        if v not in skip and v not in m and c >= min_count:
            m[v] = nxt; nxt += 1
    return m, nxt - start


# ------------------------------------------------------------------ model surgery
def grow_model(model, n_new_sl, ctx_new, n_stage=5):
    """Append SL700 rows to the OpTC-contract and context embeddings (copies of <UNK>), stage head 4 -> n_stage."""
    for emb, k in zip(model.embeddings, n_new_sl):
        if k == 0:
            continue
        n_have = emb.new.num_embeddings if emb.n_new_used else 0
        w = emb.new.weight.detach()[:n_have] if n_have else emb.new.weight.detach()[:0]
        unk = emb.old.weight.detach()[0:1]
        new = nn.Embedding(n_have + k, emb.old.embedding_dim).to(w.device)
        with torch.no_grad():
            new.weight.copy_(torch.cat([w, unk.expand(k, -1)], 0))
        emb.new = new; emb.n_new_used = True
    for j, k in enumerate(ctx_new):
        if k == 0:
            continue
        old = model.ctx_embs[j]
        new = nn.Embedding(old.num_embeddings + k, old.embedding_dim, padding_idx=0).to(old.weight.device)
        with torch.no_grad():
            new.weight.copy_(torch.cat([old.weight.detach(), old.weight.detach()[1:2].expand(k, -1)], 0))
        model.ctx_embs[j] = new
    last = model.stage_head[-1]
    if last.out_features < n_stage:
        nl = nn.Linear(last.in_features, n_stage).to(last.weight.device)
        with torch.no_grad():
            nl.weight.zero_(); nl.bias.fill_(float(last.bias.min()) - 3.0)
            nl.weight[:last.out_features] = last.weight; nl.bias[:last.out_features] = last.bias
        model.stage_head[-1] = nl
    return model


# ------------------------------------------------------------------ data
def sl700_samples(sl, ext, ctx_vocab, ctx_fields, n_cmd, split):
    cat_fields = sl["meta"]["cat_fields"]
    pos = [cat_fields.index(f) for f in ctx_fields]
    out = []
    for s in sl["splits"][split]:
        ids = np.array([[1 if v == "<MISSING>" else ext[f].get(v, 0) for f, v in zip(FIELDS, ev)] for ev in s["optc_raw"]], dtype=np.int64)
        cc = np.array([[ctx_vocab[f].get(tok[p], 1) for f, p in zip(ctx_fields, pos)] for tok in s["tok_raw"]], dtype=np.int64)
        out.append({"dom": "sl700", "id": s["sample_id"], "x_cat": ids, "delta": s["num"][:, n_cmd].astype(np.float32),
                    "ctx_cat": cc, "ctx_num": s["num"].astype(np.float32), "y": int(s["y"]),
                    "evy": s["ev_y"].astype(np.float32), "evst": s["ev_stage"].astype(np.int64),
                    "stages": s["stages"], "stage_last": s["stage_last"]})
    return out


def collate(batch, device, n_ctx, cnd):
    B = len(batch); L = max(len(s["delta"]) for s in batch)
    x = np.zeros((B, L, len(FIELDS)), np.int64); d = np.zeros((B, L, 1), np.float32)
    cc = np.zeros((B, L, n_ctx), np.int64); cn = np.zeros((B, L, cnd), np.float32)
    evy = np.full((B, L), -1, np.float32); evst = np.zeros((B, L), np.int64)
    has = np.zeros(B, np.float32); y = np.zeros(B, np.float32); dom = np.zeros(B, np.int64)
    for i, s in enumerate(batch):
        n = len(s["delta"])
        x[i, :n] = s["x_cat"]; d[i, :n, 0] = s["delta"]; y[i] = s["y"]
        dom[i] = {"optc": 0, "atlas": 1, "sl700": 2}[s["dom"]]
        if s["dom"] in CTX_DOMS:
            cc[i, :n] = s["ctx_cat"]; cn[i, :n] = s["ctx_num"]; has[i] = 1.0
            evy[i, :n] = s["evy"]; evst[i, :n] = s["evst"]
    t = lambda a: torch.from_numpy(a).to(device)
    return dict(x_cat=t(x), delta=t(d), ctx_cat=t(cc), ctx_num=t(cn), has_ctx=t(has),
                lengths=torch.tensor([len(s["delta"]) for s in batch], device=device)), t(y), t(evy), t(evst), t(dom)


@torch.no_grad()
def predict(model, data, device, n_ctx, cnd, bs=96, with_events=False):
    model.eval()
    K = model.stage_head[-1].out_features
    z = np.zeros(len(data), np.float32); pres = np.zeros((len(data), K), np.float32); last = np.zeros(len(data), np.int64)
    order = np.argsort([len(s["delta"]) for s in data])
    for i in range(0, len(data), bs):
        idx = order[i:i + bs]
        inp, *_ = collate([data[j] for j in idx], device, n_ctx, cnd)
        zz, _, ev, st, mask = model(**inp)
        z[idx] = zz.float().cpu().numpy()
        if with_events:
            joint = (F.logsigmoid(ev)[..., None] + F.log_softmax(st, -1)).masked_fill(~mask[..., None], -1e4)
            alert = (ev >= 0) & mask
            ar = torch.arange(ev.size(1), device=ev.device)[None].expand_as(ev)
            li = torch.where(alert, ar, torch.full_like(ar, -1)).max(1).values
            sk = joint.max(1).values
            lp = torch.where(li >= 0, st.argmax(-1).gather(1, li.clamp(min=0)[:, None]).squeeze(1), sk.argmax(-1))
            pres[idx] = sk.cpu().numpy(); last[idx] = (lp + 1).cpu().numpy()
    return (z, pres, last) if with_events else z


def stage_eval(va, te, pv, pt, lt, val_pos, test_pos, stage_ids, get):
    """get(sample) -> (set of stage ids present, last stage id). stage_ids: classes that exist in this domain."""
    K = pv.shape[1]
    res, taus = {}, {}
    for k in stage_ids:
        if k > K:
            continue
        yk = np.array([k in get(s)[0] for s in va])
        taus[k] = T.best_threshold(yk, np.where(val_pos, pv[:, k - 1], -1e4))[0] if yk.sum() else float("inf")
    for k in stage_ids:
        if k > K:
            continue
        yk = np.array([k in get(s)[0] for s in te])
        pk = test_pos & (pt[:, k - 1] >= taus[k])
        tp = int((pk & yk).sum()); fp = int((pk & ~yk).sum()); fn = int((~pk & yk).sum())
        res[STAGES[k - 1]] = dict(support=int(yk.sum()), tp=tp, fp=fp, fn=fn, f1=2 * tp / max(1, 2 * tp + fp + fn), val_tau=taus[k])
    y_last = np.array([get(s)[1] for s in te]); p_last = np.where(test_pos, lt, 0)
    f1s = f1_score(y_last, p_last, labels=stage_ids, average=None, zero_division=0)
    supp = [int((y_last == k).sum()) for k in stage_ids]
    tpw = (y_last > 0) & test_pos
    sup = [v for v in res.values() if v["support"] > 0]
    return {"presence": res,
            "last_stage": {"per_stage_f1": {STAGES[k - 1]: float(f) for k, f in zip(stage_ids, f1s)}, "support": dict(zip(map(str, stage_ids), supp)),
                           "confusion_true_rows": {str(a): [int(((y_last == a) & (p_last == b)).sum()) for b in range(K + 1)] for a in [0] + list(stage_ids)}},
            "summary": {"presence_macro_f1_supported": float(np.mean([v["f1"] for v in sup])) if sup else None,
                        "last_stage_macro_f1_supported": float(np.mean([f for f, n in zip(f1s, supp) if n > 0])) if any(supp) else None,
                        "last_stage_acc_on_detected_attacks": float((p_last[tpw] == y_last[tpw]).mean()) if tpw.any() else None}}


def atlas_get(label):
    return lambda s: (set(s["src"][f"stages_{label}"]), s["src"][f"stage_last_{label}"])


def sl_get(s):
    return set(s["stages"]), s["stage_last"]


def evaluate(model, dev, n_ctx, cnd, sets, base_thr_prob, label="v9b"):
    """Thresholds from VAL, then TEST once. sets: dict with sl_va, sl_te, at_va, at_te, op_val, op_te."""
    out = {}
    y = lambda d: np.array([s["y"] for s in d])
    zv, pv, _ = predict(model, sets["sl_va"], dev, n_ctx, cnd, with_events=True)
    zt, pt, lt = predict(model, sets["sl_te"], dev, n_ctx, cnd, with_events=True)
    thr = T.best_threshold(y(sets["sl_va"]), zv)[0]
    out["sl700"] = {"threshold_logit_val": thr, "val": T.metrics(y(sets["sl_va"]), zv, thr), "test": T.metrics(y(sets["sl_te"]), zt, thr),
                    "stage": stage_eval(sets["sl_va"], sets["sl_te"], pv, pt, lt, zv >= thr, zt >= thr, [1, 2, 5], sl_get)}
    out["_sl700_test_logits"] = zt
    zv, pv, _ = predict(model, sets["at_va"], dev, n_ctx, cnd, with_events=True)
    zt, pt, lt = predict(model, sets["at_te"], dev, n_ctx, cnd, with_events=True)
    thr = T.best_threshold(y(sets["at_va"]), zv)[0]
    out["atlas"] = {"threshold_logit_val": thr, "val": T.metrics(y(sets["at_va"]), zv, thr), "test": T.metrics(y(sets["at_te"]), zt, thr),
                    "stage": stage_eval(sets["at_va"], sets["at_te"], pv, pt, lt, zv >= thr, zt >= thr, [1, 2, 3, 4], atlas_get(label))}
    zov = predict(model, sets["op_val"], dev, n_ctx, cnd); thr_o = T.best_threshold(y(sets["op_val"]), zov)[0]
    zot = predict(model, sets["op_te"], dev, n_ctx, cnd)
    out["optc"] = {"test_at_base_thr": T.metrics(y(sets["op_te"]), T.fp16_prob(zot), base_thr_prob),
                   "test_at_optc_val_thr": T.metrics(y(sets["op_te"]), zot, thr_o), "optc_val_threshold_logit": thr_o}
    return out


# ------------------------------------------------------------------ schedule (as step 2)
def stage_of(ep, args):
    if args.schedule == "full":
        return "FULL"
    return "A" if ep <= args.epochs_a else ("B" if ep <= args.epochs_a + args.epochs_b else "C")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--init", default="step2", choices=["step2", "random"],
                    help="step2: the OpTC->ATLASv2 model of the same seed; random: same architecture, no prior knowledge")
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
    ap.add_argument("--select", default="all", choices=["all", "sl700"],
                    help="all: mean val score of SL700, ATLASv2, OpTC; sl700: SL700 val only (no old-domain data used)")
    ap.add_argument("--drop-sl-fields", default="", help="ablation: comma list of OpTC-contract fields set to <UNK> for SL700 (e.g. app_family)")
    ap.add_argument("--min-count", type=int, default=2)
    a = ap.parse_args()

    out = Path(a.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"output dir not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    t0 = time.time()

    # ---- rebuild the step-2 model exactly
    base, cfg, base_thr_prob = load_base(dev)
    old_cards = cfg["categorical_cardinalities"]
    blob = pickle.load(open(ATLAS_DATA, "rb"))
    meta = blob["meta"]; cat_fields = meta["cat_fields"]
    ctx_idx = [i for i, f in enumerate(cat_fields) if f != "ip_scope"]
    ctx_fields = [cat_fields[i] for i in ctx_idx]
    n_cmd, cnd = meta["num_dim"] - 3, meta["num_dim"]
    ext_atlas, n_new_atlas = atlas_ext_vocab(blob, old_cards, a.min_count)
    ctx_cards_atlas = [len(meta["vocab"][f]) for f in ctx_fields]
    body = copy.deepcopy(base)
    if a.init == "random":                       # same architecture, no OpTC/ATLASv2 knowledge (transfer baseline)
        for mod in body.modules():
            if hasattr(mod, "reset_parameters") and mod is not body:
                mod.reset_parameters()
    model2 = ILBiLSTM(body, n_new_atlas, ctx_cards_atlas, cnd, hidden2=64).to(dev)
    for e, k in zip(model2.embeddings, n_new_atlas):
        e.n_new_used = k > 0
    if a.init == "step2":
        sd = torch.load(STEP2 / f"{a.step2_run}_s{a.seed}" / "best.pt", map_location=dev)
        model2.load_state_dict(sd, strict=True)
    print("step-2 model rebuilt:", "loaded" if a.init == "step2" else "random", "| ATLASv2 new ids", dict(zip(FIELDS, n_new_atlas)), flush=True)

    # ---- SL700 vocabulary extension (TRAIN only)
    sl = pickle.load(open(SL700_DATA, "rb"))
    cnt_o, cnt_c = sl700_counts(sl)
    ext, n_new_sl = {}, []
    for f, oc, k in zip(FIELDS, old_cards, n_new_atlas):
        ext[f], n = extend(ext_atlas[f], cnt_o[f], oc + k, a.min_count); n_new_sl.append(n)
    ctx_vocab, ctx_new = {}, []
    for f in ctx_fields:
        ctx_vocab[f], n = extend(meta["vocab"][f], cnt_c[f], len(meta["vocab"][f]), a.min_count, skip=())
        ctx_new.append(n)
    print("SL700 new ids: contract", dict(zip(FIELDS, n_new_sl)), "| context", dict(zip(ctx_fields, ctx_new)), flush=True)

    # ---- data
    A = T.atlas_samples(blob, "v9b", ext, ctx_idx, n_cmd)
    at_tr, at_va, at_te = A["train"], A["val"], A["test"]
    S = {sp: sl700_samples(sl, ext, ctx_vocab, ctx_fields, n_cmd, sp) for sp in ("train", "val", "test")}
    if a.drop_sl_fields:   # ablation: hide the listed contract fields of SL700 events behind <UNK>
        cols = [FIELDS.index(f) for f in a.drop_sl_fields.split(",") if f]
        for lst in S.values():
            for s in lst:
                s["x_cat"][:, cols] = 0
    sl_tr, sl_va, sl_te = S["train"], S["val"], S["test"]
    rows = T.optc_rows(); rng = np.random.default_rng(a.seed)
    tr_pos = [r for r in rows if r["split"] == "train" and r["label"] == "1"]
    tr_neg = [r for r in rows if r["split"] == "train" and r["label"] == "0"]
    pool = T.load_optc(tr_pos + [tr_neg[i] for i in rng.choice(len(tr_neg), 8000, replace=False)])
    op_pos = [s for s in pool if s["y"] == 1]; op_neg = [s for s in pool if s["y"] == 0]
    v_rows = [r for r in rows if r["split"] == "val"]
    v_pos = [r for r in v_rows if r["label"] == "1"]; v_neg = [r for r in v_rows if r["label"] == "0"]
    op_vsel = T.load_optc(v_pos + [v_neg[i] for i in rng.choice(len(v_neg), a.optc_val_neg, replace=False)])
    print(f"SL700 train/val/test {len(sl_tr)}/{len(sl_va)}/{len(sl_te)} pos {sum(s['y'] for s in sl_tr)}/{sum(s['y'] for s in sl_va)}/{sum(s['y'] for s in sl_te)}"
          f" | ATLASv2 {len(at_tr)}/{len(at_va)}/{len(at_te)} | OpTC pool {len(op_pos)}+{len(op_neg)}  [{time.time() - t0:.0f}s]", flush=True)

    # ---- grow and check equivalence with the step-2 model
    model = grow_model(copy.deepcopy(model2), n_new_sl, ctx_new, 5).to(dev)
    n_ctx = len(ctx_idx)
    A2 = T.atlas_samples(blob, "v9b", ext_atlas, ctx_idx, n_cmd)  # the same ATLASv2 windows encoded with the step-2 vocabulary
    sl_va2 = sl700_samples(sl, ext_atlas, {f: meta["vocab"][f] for f in ctx_fields}, ctx_fields, n_cmd, "val")
    if a.drop_sl_fields:
        for s in sl_va2:
            s["x_cat"][:, cols] = 0
    d_o = np.abs(predict(model, op_vsel[:512], dev, n_ctx, cnd) - predict(model2, op_vsel[:512], dev, n_ctx, cnd)).max()
    d_a = np.abs(predict(model, at_va[:256], dev, n_ctx, cnd) - predict(model2, A2["val"][:256], dev, n_ctx, cnd)).max()
    d_s = np.abs(predict(model, sl_va[:256], dev, n_ctx, cnd) - predict(model2, sl_va2[:256], dev, n_ctx, cnd)).max()
    print(f"init equivalence max|z_step3 - z_step2|: OpTC {d_o:.2e} ATLASv2 {d_a:.2e} SL700 {d_s:.2e}", flush=True)
    if a.init == "step2":
        assert max(d_o, d_a, d_s) < 1e-4, "grown model does not reproduce the step-2 model"

    # ---- 'before' = the step-2 model (thresholds from its own VAL), scored on all TEST sets
    op_val = T.load_optc(v_rows); op_te = T.load_optc([r for r in rows if r["split"] == "test"])
    sets2 = {"sl_va": sl_va2, "sl_te": sl700_samples(sl, ext_atlas, {f: meta["vocab"][f] for f in ctx_fields}, ctx_fields, n_cmd, "test"),
             "at_va": A2["val"], "at_te": A2["test"], "op_val": op_val, "op_te": op_te}
    if a.drop_sl_fields:
        for s in sets2["sl_te"]:
            s["x_cat"][:, cols] = 0
    before = evaluate(model2, dev, n_ctx, cnd, sets2, base_thr_prob)
    before.pop("_sl700_test_logits")
    del model2, sets2, A2

    # ---- training
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
        stn = stage_of(ep, a)
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
            print(f"--- stage {stn}: trainable {({n_: sum(p.numel() for p in g[n_]) for n_ in plan})}", flush=True)
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
            inp, y, evy, evst, dom = collate(batch, dev, n_ctx, cnd)
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
        zs = predict(model, sl_va, dev, n_ctx, cnd); za = predict(model, at_va, dev, n_ctx, cnd); zo = predict(model, op_vsel, dev, n_ctx, cnd)
        ss, sa, so = T.val_score(y_sv, zs), T.val_score(y_av, za), T.val_score(y_ov, zo)
        rec = {"epoch": ep, "stage": stn, **{k: round(v, 3) for k, v in tot.items()}, "sec": round(time.time() - te0, 1),
               "val_sl700": round(ss, 4), "val_atlas": round(sa, 4), "val_optc": round(so, 4), "gate": round(float(model.gate.item()), 3),
               "score": (ss + sa + so) / 3 if a.select == "all" else ss}
        hist.append(rec); print(json.dumps(rec), flush=True)
        if rec["score"] > best[0]:
            best = (rec["score"], ep, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()})

    model.load_state_dict(best[2]); torch.save(best[2], out / "best.pt")
    sets = {"sl_va": sl_va, "sl_te": sl_te, "at_va": at_va, "at_te": at_te, "op_val": op_val, "op_te": op_te}
    after = evaluate(model, dev, n_ctx, cnd, sets, base_thr_prob)
    zt = after.pop("_sl700_test_logits")
    res = {"args": vars(a), "best_epoch": best[1], "best_stage": stage_of(best[1], a),
           "vocab_new_ids_sl700": {"contract": dict(zip(FIELDS, n_new_sl)), "context": dict(zip(ctx_fields, ctx_new))},
           "init_equivalence_max_abs": {"optc": float(d_o), "atlas": float(d_a), "sl700": float(d_s)},
           "before_step2_model": before, "after": after,
           "bwt": {"atlas_test_f1": after["atlas"]["test"]["f1"] - before["atlas"]["test"]["f1"],
                   "atlas_stage_presence_macro": (after["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0) -
                                                 (before["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0),
                   "optc_test_f1_at_base_thr": after["optc"]["test_at_base_thr"]["f1"] - before["optc"]["test_at_base_thr"]["f1"]},
           "elapsed_sec": round(time.time() - t0)}
    (out / "result.json").write_text(json.dumps(res, indent=2, default=float))
    (out / "history.json").write_text(json.dumps(hist, indent=1))
    with open(out / "sl700_test_predictions.csv", "w", newline="") as fh:
        wr = csv.writer(fh); wr.writerow(["sample_id", "y", "logit", "pred", "stages"])
        for s, z in zip(sl_te, zt):
            wr.writerow([s["id"], s["y"], f"{z:.5f}", int(z >= after["sl700"]["threshold_logit_val"]), "|".join(map(str, s["stages"]))])
    f = lambda d: f"F1 {d['f1']:.4f} (tp {d['tp']} fp {d['fp']} fn {d['fn']})"
    print("RESULT best_epoch", best[1], res["best_stage"],
          "\nSL700 TEST  before", f(before["sl700"]["test"]), "| after", f(after["sl700"]["test"]),
          "| stage after", json.dumps(after["sl700"]["stage"]["summary"]),
          "\nATLASv2 TEST before", f(before["atlas"]["test"]), "| after", f(after["atlas"]["test"]),
          "| stage presence before/after %.3f / %.3f" % (before["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0,
                                                         after["atlas"]["stage"]["summary"]["presence_macro_f1_supported"] or 0),
          "\nOpTC TEST@base_thr before", f(before["optc"]["test_at_base_thr"]), "| after", f(after["optc"]["test_at_base_thr"]), flush=True)


if __name__ == "__main__":
    main()
