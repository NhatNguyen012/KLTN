#!/usr/bin/env python3
"""Incremental learning OpTC -> ATLASv2 for the OpTC Network-DL BiLSTM.

Start: the OpTC subsetB BiLSTM (pretrained_optc_model, identical to
DL/05_models/v2_subsetB/bilstm). Learn ATLASv2 (binary detection + attack
stage) without forgetting OpTC:
  * vocabulary extension (OpTC ids unchanged; new ATLASv2 tokens appended);
  * new host-context branch, second BiLSTM layer, event head and stage head
    (il_model.py), all initialised so the extended model == base model;
  * freezing schedule  A: new parts only -> B: + old encoder/LSTM/classifier
    (lower lr) -> C: + old embedding rows (lowest lr)   (--schedule freeze),
    or plain fine-tuning of everything from epoch 1      (--schedule full);
  * replay of REAL OpTC TRAIN windows (DL/02_artifacts/22_v2_pipeline/S4_shards,
    read-only), optional LwF distillation to the frozen base logits.
Selection (epoch, thresholds) uses VALIDATION only (ATLASv2 val + OpTC val);
TEST (ATLASv2 S4/M6 + day 4, OpTC test) is scored once at the end.
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
from sklearn.metrics import average_precision_score, f1_score, precision_recall_curve, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import FIELDS, SHARD_CAT_IDX, load_optc_vocab  # noqa: E402
from il_model import ILBiLSTM, load_base  # noqa: E402

OPTC_ROOT = Path("/mnt/SSD_Data/optc/DL/02_artifacts/22_v2_pipeline/S4_shards")
STAGES = ["initial_compromise", "execution_discovery", "lateral_movement", "exfiltration"]


# ------------------------------------------------------------------ data
def load_optc(rows):
    """rows: list of dicts from samples.csv -> list of samples (x_cat uint16 [L,4], delta f32 [L])."""
    by_shard = defaultdict(list)
    for r in rows:
        by_shard[r["shard_file"]].append(r)
    out = []
    for shard, rs in by_shard.items():
        with np.load(OPTC_ROOT / shard, allow_pickle=False) as z:
            xc, dt, off, lab = z["x_cat"], z["delta_t_log1p"], z["sample_offsets"], z["sample_labels"]
            for r in rs:
                i = int(r["shard_sample_index"]); a, b = int(off[i]), int(off[i + 1])
                assert int(lab[i]) == int(r["label"])
                out.append({"dom": "optc", "id": r["sample_id"], "x_cat": xc[a:b][:, SHARD_CAT_IDX].copy(),
                            "delta": dt[a:b].astype(np.float32), "y": int(r["label"])})
    return out


def optc_rows():
    with open(OPTC_ROOT / "data" / "samples.csv", newline="") as fh:
        return list(csv.DictReader(fh))


def atlas_samples(blob, label, ext, ctx_idx, n_cmd):
    out = {}
    for split, lst in blob["splits"].items():
        res = []
        for s in lst:
            ids = np.array([[1 if v == "<MISSING>" else ext[f].get(v, 0) for f, v in zip(FIELDS, ev)]
                            for ev in s["optc_raw"]], dtype=np.int64)
            res.append({"dom": "atlas", "id": s["sample_id"], "x_cat": ids, "delta": s["num"][:, n_cmd].astype(np.float32),
                        "ctx_cat": s["cat"][:, ctx_idx], "ctx_num": s["num"].astype(np.float32),
                        "y": int(s[f"y_{label}"]), "evy": s[f"ev_y_{label}"].astype(np.float32),
                        "evst": s[f"ev_stage_{label}"].astype(np.int64), "src": s})
        out[split] = res
    return out


def collate(batch, device, n_ctx, ctx_num_dim):
    B = len(batch); L = max(len(s["delta"]) for s in batch)
    x = np.zeros((B, L, len(FIELDS)), np.int64); d = np.zeros((B, L, 1), np.float32)
    cc = np.zeros((B, L, n_ctx), np.int64); cn = np.zeros((B, L, ctx_num_dim), np.float32)
    evy = np.full((B, L), -1, np.float32); evst = np.zeros((B, L), np.int64)
    has = np.zeros(B, np.float32); y = np.zeros(B, np.float32); isopt = np.zeros(B, bool)
    for i, s in enumerate(batch):
        n = len(s["delta"])
        x[i, :n] = s["x_cat"]; d[i, :n, 0] = s["delta"]; y[i] = s["y"]
        if s["dom"] == "atlas":
            cc[i, :n] = s["ctx_cat"]; cn[i, :n] = s["ctx_num"]; has[i] = 1.0
            evy[i, :n] = s["evy"]; evst[i, :n] = s["evst"]
        else:
            isopt[i] = True
    t = lambda a: torch.from_numpy(a).to(device)
    return dict(x_cat=t(x), delta=t(d), ctx_cat=t(cc), ctx_num=t(cn), has_ctx=t(has),
                lengths=torch.tensor([len(s["delta"]) for s in batch], device=device)), t(y), t(evy), t(evst), t(isopt)


@torch.no_grad()
def predict(model, data, device, n_ctx, cnd, bs=128, with_events=False):
    model.eval()
    zs, evs, sts, ms = [], [], [], []
    order = np.argsort([len(s["delta"]) for s in data])  # length-sorted batches for speed
    for i in range(0, len(data), bs):
        idx = order[i:i + bs]
        inp, *_ = collate([data[j] for j in idx], device, n_ctx, cnd)
        z, _, ev, st, mask = model(**inp)
        zs.append((idx, z.float().cpu().numpy()))
        if with_events:
            joint = (F.logsigmoid(ev)[..., None] + F.log_softmax(st, -1)).masked_fill(~mask[..., None], -1e4)
            alert = (ev >= 0) & mask
            ar = torch.arange(ev.size(1), device=ev.device)[None].expand_as(ev)
            last_idx = torch.where(alert, ar, torch.full_like(ar, -1)).max(1).values
            s_k = joint.max(1).values
            lp = torch.where(last_idx >= 0, st.argmax(-1).gather(1, last_idx.clamp(min=0)[:, None]).squeeze(1), s_k.argmax(-1))
            evs.append((idx, s_k.cpu().numpy(), (lp + 1).cpu().numpy()))
    z = np.zeros(len(data), np.float32)
    for idx, v in zs:
        z[idx] = v
    if not with_events:
        return z
    pres = np.zeros((len(data), 4), np.float32); last = np.zeros(len(data), np.int64)
    for idx, a, b in evs:
        pres[idx] = a; last[idx] = b
    return z, pres, last


@torch.no_grad()
def predict_base(base, data, device, bs=128):
    base.eval()
    z = np.zeros(len(data), np.float32)
    order = np.argsort([len(s["delta"]) for s in data])
    for i in range(0, len(data), bs):
        idx = order[i:i + bs]
        batch = [data[j] for j in idx]
        B = len(batch); L = max(len(s["delta"]) for s in batch)
        x = np.zeros((B, L, 4), np.int64); d = np.zeros((B, L, 1), np.float32)
        for k, s in enumerate(batch):
            n = len(s["delta"]); xi = s["x_cat"].astype(np.int64)
            xi = np.where(xi >= np.array(base_cards(base))[None], 0, xi)  # unseen ids -> <UNK>, as the base model sees them
            x[k, :n] = xi; d[k, :n, 0] = s["delta"]
        t = lambda a: torch.from_numpy(a).to(device)
        out = base(x_cat=t(x), x_num=torch.zeros(B, L, 0, device=device), x_num_missing=torch.zeros(B, L, 0, device=device),
                   x_bin=torch.zeros(B, L, 1, device=device), delta_t_log1p=t(d),
                   lengths=torch.tensor([len(s["delta"]) for s in batch], device=device))
        z[idx] = out.float().cpu().numpy()
    return z


def base_cards(base):
    return [e.num_embeddings for e in base.embeddings]


# ------------------------------------------------------------------ metrics
def fp16_prob(z):
    return torch.sigmoid(torch.from_numpy(np.asarray(z, np.float32)).half()).float().numpy()


def best_threshold(y, p):
    if y.sum() == 0:
        return float(np.max(p) + 1.0), 0.0
    prec, rec, thr = precision_recall_curve(y, p)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-12, None)
    i = int(np.nanargmax(f1[:-1]))
    s = np.unique(p); j = np.searchsorted(s, thr[i])
    lo = s[j - 1] if j > 0 else thr[i] - 1.0
    return float((lo + thr[i]) / 2), float(f1[i])


def metrics(y, score, t):
    pred = score >= t
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    pr = tp / max(1, tp + fp); rc = tp / max(1, tp + fn)
    out = dict(threshold=float(t), tp=tp, fp=fp, fn=fn, tn=int(len(y) - tp - fp - fn), precision=pr, recall=rc,
               f1=2 * pr * rc / max(1e-12, pr + rc))
    if 0 < y.sum() < len(y):
        out["ap"] = float(average_precision_score(y, score)); out["roc_auc"] = float(roc_auc_score(y, score))
    return out


def val_score(y, z):
    if y.sum() == 0:
        return 0.0
    return (float(average_precision_score(y, z)) + best_threshold(y, z)[1]) / 2


def stage_eval(va, te, pv, pt, lt, val_pos, test_pos, label):
    taus = []
    for k in range(4):
        yk = np.array([(k + 1) in s["src"][f"stages_{label}"] for s in va])
        taus.append(best_threshold(yk, np.where(val_pos, pv[:, k], -1e4))[0] if yk.sum() else float("inf"))
    per = {}
    for k, name in enumerate(STAGES):
        yk = np.array([(k + 1) in s["src"][f"stages_{label}"] for s in te])
        pk = test_pos & (pt[:, k] >= taus[k])
        tp = int((pk & yk).sum()); fp = int((pk & ~yk).sum()); fn = int((~pk & yk).sum())
        per[name] = dict(support=int(yk.sum()), tp=tp, fp=fp, fn=fn, f1=2 * tp / max(1, 2 * tp + fp + fn), val_tau=taus[k])
    y_last = np.array([s["src"][f"stage_last_{label}"] for s in te]); p_last = np.where(test_pos, lt, 0)
    f1s = f1_score(y_last, p_last, labels=[1, 2, 3, 4], average=None, zero_division=0)
    supp = [int((y_last == k).sum()) for k in (1, 2, 3, 4)]
    tpw = (y_last > 0) & test_pos
    sup = [v for v in per.values() if v["support"] > 0]
    return {"presence": per,
            "last_stage": {"per_stage_f1": dict(zip(STAGES, map(float, f1s))), "support": supp,
                           "confusion_true_rows_0to4": [[int(((y_last == a) & (p_last == b)).sum()) for b in range(5)] for a in range(5)]},
            "test_summary": {"presence_macro_f1_supported": float(np.mean([v["f1"] for v in sup])),
                             "last_stage_macro_f1_supported": float(np.mean([f for f, n in zip(f1s, supp) if n > 0])),
                             "last_stage_acc_on_detected_attacks": float((p_last[tpw] == y_last[tpw]).mean()) if tpw.any() else None}}


# ------------------------------------------------------------------ schedule
def stage_of(ep, args):
    if args.schedule == "full":
        return "FULL"
    if ep <= args.epochs_a:
        return "A"
    if ep <= args.epochs_a + args.epochs_b:
        return "B"
    return "C"


def make_optimizer(model, stage, args):
    g = model.groups()
    if stage == "FULL":
        plan = {"new": args.lr, "old_body": args.lr, "old_emb": args.lr}
    elif stage == "A":
        plan = {"new": args.lr_a}
    elif stage == "B":
        plan = {"new": args.lr, "old_body": args.lr * args.mult_body}
    else:
        plan = {"new": args.lr, "old_body": args.lr * args.mult_body, "old_emb": args.lr * args.mult_emb}
    for name, ps in g.items():
        for p in ps:
            p.requires_grad = name in plan
    groups = [{"params": g[n], "lr": lr} for n, lr in plan.items() if g[n]]
    return torch.optim.AdamW(groups, weight_decay=args.wd), {n: sum(p.numel() for p in g[n]) for n in plan}


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="dataset_v9b_stage_optc.pkl from bilstm_v9/build_dataset.py")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="v9b", choices=["legacy", "v9", "v9b"])
    ap.add_argument("--schedule", default="freeze", choices=["freeze", "full"])
    ap.add_argument("--epochs-a", type=int, default=4)
    ap.add_argument("--epochs-b", type=int, default=8)
    ap.add_argument("--epochs-c", type=int, default=8)
    ap.add_argument("--epochs", type=int, default=20, help="only for --schedule full")
    ap.add_argument("--lr-a", type=float, default=1e-3)
    ap.add_argument("--lr", type=float, default=5e-4)
    ap.add_argument("--mult-body", type=float, default=0.2)
    ap.add_argument("--mult-emb", type=float, default=0.05)
    ap.add_argument("--wd", type=float, default=1e-4)
    ap.add_argument("--bs", type=int, default=64)
    ap.add_argument("--aux", type=float, default=0.5)
    ap.add_argument("--stage-w", type=float, default=0.5)
    ap.add_argument("--replay", type=int, default=1)
    ap.add_argument("--replay-pos", type=int, default=150, help="OpTC TRAIN positives drawn per epoch (of 401)")
    ap.add_argument("--replay-neg", type=int, default=450, help="OpTC TRAIN negatives drawn per epoch")
    ap.add_argument("--replay-neg-pool", type=int, default=8000)
    ap.add_argument("--lwf", type=float, default=0.0, help="MSE weight to frozen base logits on replayed OpTC")
    ap.add_argument("--optc-val-neg", type=int, default=4000, help="OpTC VAL negatives used for per-epoch selection")
    ap.add_argument("--drop-ctx", default="ip_scope")
    ap.add_argument("--min-count", type=int, default=2)
    ap.add_argument("--hidden2", type=int, default=64)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--init", default="optc", choices=["optc", "random"],
                    help="random: same architecture, base weights re-initialised (no OpTC knowledge) - transfer baseline")
    ap.add_argument("--select", default="both", choices=["both", "atlas"],
                    help="epoch selection: mean of ATLASv2-val and OpTC-val scores, or ATLASv2-val only (no OpTC data used at all)")
    args = ap.parse_args()

    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"output dir not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    random.seed(args.seed); np.random.seed(args.seed); torch.manual_seed(args.seed)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    t0 = time.time()

    base, cfg, base_thr_prob = load_base(dev)
    if args.init == "random":
        for mod in base.modules():
            if hasattr(mod, "reset_parameters") and mod is not base:
                mod.reset_parameters()
    old_cards = cfg["categorical_cardinalities"]

    # ---- ATLASv2 + vocabulary extension (TRAIN only)
    blob = pickle.load(open(args.data, "rb"))
    meta = blob["meta"]; cat_fields = meta["cat_fields"]
    drop = {f for f in args.drop_ctx.split(",") if f}
    ctx_idx = [i for i, f in enumerate(cat_fields) if f not in drop]
    n_cmd = meta["num_dim"] - 3
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
            if v != "<MISSING>" and v not in m and c >= args.min_count:
                m[v] = nxt; nxt += 1
        ext[f] = m; n_new.append(nxt - oc)
    print("vocab extension (new ids per field):", dict(zip(FIELDS, n_new)), flush=True)
    A = atlas_samples(blob, args.label, ext, ctx_idx, n_cmd)
    tr, va, te = A["train"], A["val"], A["test"]
    ctx_cards = [len(meta["vocab"][cat_fields[i]]) for i in ctx_idx]
    n_ctx, cnd = len(ctx_idx), meta["num_dim"]

    # ---- OpTC (real shards, read-only)
    rows = optc_rows()
    rng = np.random.default_rng(args.seed)
    tr_pos = [r for r in rows if r["split"] == "train" and r["label"] == "1"]
    tr_neg = [r for r in rows if r["split"] == "train" and r["label"] == "0"]
    pool = load_optc(tr_pos + [tr_neg[i] for i in rng.choice(len(tr_neg), args.replay_neg_pool, replace=False)])
    rep_pos = [s for s in pool if s["y"] == 1]; rep_neg = [s for s in pool if s["y"] == 0]
    v_rows = [r for r in rows if r["split"] == "val"]
    v_pos = [r for r in v_rows if r["label"] == "1"]; v_neg = [r for r in v_rows if r["label"] == "0"]
    optc_vsel = load_optc(v_pos + [v_neg[i] for i in rng.choice(len(v_neg), args.optc_val_neg, replace=False)])
    print(f"ATLASv2 windows train/val/test {len(tr)}/{len(va)}/{len(te)} (pos {sum(s['y'] for s in tr)}/{sum(s['y'] for s in va)}/{sum(s['y'] for s in te)}); "
          f"OpTC replay pool {len(rep_pos)} pos + {len(rep_neg)} neg; OpTC val-sel {len(optc_vsel)}  [{time.time() - t0:.0f}s]", flush=True)

    # ---- extended model == base model at init (numerical check)
    model = ILBiLSTM(copy.deepcopy(base), n_new, ctx_cards, cnd, hidden2=args.hidden2).to(dev)
    chk_o = optc_vsel[:512]; chk_a = va[:256]
    d1 = np.abs(predict(model, chk_o, dev, n_ctx, cnd) - predict_base(base, chk_o, dev)).max()
    d2 = np.abs(predict(model, chk_a, dev, n_ctx, cnd) - predict_base(base, chk_a, dev)).max()
    print(f"init equivalence max|z_ext - z_base|: OpTC {d1:.2e}  ATLASv2 {d2:.2e}", flush=True)
    assert d1 < 1e-4 and d2 < 1e-4, "extended model does not reproduce the base model"

    y_va = np.array([s["y"] for s in va]); y_ov = np.array([s["y"] for s in optc_vsel])
    pos = [s for s in tr if s["y"] == 1]; neg = [s for s in tr if s["y"] == 0]
    pw_a = math.sqrt(len(neg) / max(1, len(pos)))
    ev_all = np.concatenate([s["evy"] for s in tr])
    epw = torch.tensor(math.sqrt((ev_all == 0).sum() / max(1, (ev_all == 1).sum())), device=dev)
    st_all = np.concatenate([s["evst"] for s in tr]); st_cnt = np.array([(st_all == k).sum() for k in (1, 2, 3, 4)], float)
    stage_cw = torch.tensor(np.sqrt(st_cnt.sum() / np.maximum(st_cnt, 1) / 4), dtype=torch.float32, device=dev)
    n_ep = args.epochs if args.schedule == "full" else args.epochs_a + args.epochs_b + args.epochs_c

    hist, best, cur_stage, opt = [], (-1.0, 0, None), None, None
    for ep in range(1, n_ep + 1):
        st_name = stage_of(ep, args)
        if st_name != cur_stage:
            opt, ntr = make_optimizer(model, st_name, args); cur_stage = st_name
            print(f"--- stage {st_name}: trainable {ntr}", flush=True)
        model.train(); te0 = time.time()
        epoch = list(tr)
        if args.replay:
            epoch += random.sample(rep_pos, min(args.replay_pos, len(rep_pos))) + random.sample(rep_neg, args.replay_neg)
        random.shuffle(epoch)
        tot = defaultdict(float)
        for i in range(0, len(epoch), args.bs):
            batch = epoch[i:i + args.bs]
            inp, y, evy, evst, isopt = collate(batch, dev, n_ctx, cnd)
            z, z_old, ev, st, mask = model(**inp)
            w = torch.where(isopt, torch.ones_like(y), torch.where(y > 0, torch.full_like(y, pw_a), torch.ones_like(y)))
            loss = (F.binary_cross_entropy_with_logits(z, y, reduction="none") * w).sum() / w.sum()
            tot["bce"] += loss.item()
            m = evy >= 0
            if args.aux > 0 and m.any():
                l2 = F.binary_cross_entropy_with_logits(ev[m], evy[m], pos_weight=epw); loss = loss + args.aux * l2; tot["ev"] += l2.item()
            ms = evst > 0
            if args.stage_w > 0 and ms.any():
                l3 = F.cross_entropy(st[ms], evst[ms] - 1, weight=stage_cw); loss = loss + args.stage_w * l3; tot["stage_ce"] += l3.item()
            if args.lwf > 0 and isopt.any():
                with torch.no_grad():
                    zb = torch.from_numpy(predict_base(base, [b for b, o in zip(batch, isopt.tolist()) if o], dev)).to(dev)
                l4 = F.mse_loss(z[isopt], zb); loss = loss + args.lwf * l4; tot["lwf"] += l4.item()
            opt.zero_grad(); loss.backward()
            nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.0)
            opt.step()
        za = predict(model, va, dev, n_ctx, cnd); zo = predict(model, optc_vsel, dev, n_ctx, cnd)
        sa, so = val_score(y_va, za), val_score(y_ov, zo)
        f1o_base = metrics(y_ov, fp16_prob(zo), base_thr_prob)["f1"]
        rec = {"epoch": ep, "stage": st_name, **{k: round(v, 3) for k, v in tot.items()}, "sec": round(time.time() - te0, 1),
               "val_atlas_ap": float(average_precision_score(y_va, za)), "val_atlas_f1": best_threshold(y_va, za)[1],
               "val_optc_ap": float(average_precision_score(y_ov, zo)), "val_optc_f1_at_base_thr": f1o_base,
               "gate": float(model.gate.item()), "score": (sa + so) / 2 if args.select == "both" else sa}
        hist.append(rec); print(json.dumps(rec), flush=True)
        if rec["score"] > best[0]:
            best = (rec["score"], ep, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()})

    model.load_state_dict(best[2]); torch.save(best[2], out / "best.pt")
    # ---- thresholds on VALIDATION
    za, pva, _ = predict(model, va, dev, n_ctx, cnd, with_events=True)
    thr_a = best_threshold(y_va, za)[0]
    optc_val = load_optc(v_rows); y_ovf = np.array([s["y"] for s in optc_val])
    zof = predict(model, optc_val, dev, n_ctx, cnd); thr_o = best_threshold(y_ovf, zof)[0]
    # ---- TEST, once
    zt, ptt, ltt = predict(model, te, dev, n_ctx, cnd, with_events=True)
    res = {"args": vars(args), "best_epoch": best[1], "best_stage": stage_of(best[1], args), "vocab_new_ids": dict(zip(FIELDS, n_new)),
           "init_equivalence_max_abs": {"optc": float(d1), "atlas": float(d2)},
           "atlas": {"threshold_logit_val": thr_a, "val": metrics(y_va, za, thr_a)}}
    for lab in ("v9b", "v9", "legacy"):
        res["atlas"][f"test_{lab}_labels"] = metrics(np.array([s["src"][f"y_{lab}"] for s in te]), zt, thr_a)
    res["atlas"]["stage"] = stage_eval(va, te, pva, ptt, ltt, za >= thr_a, zt >= thr_a, args.label)
    optc_test = load_optc([r for r in rows if r["split"] == "test"]); y_ot = np.array([s["y"] for s in optc_test])
    zb_t = predict_base(base, optc_test, dev); zi_t = predict(model, optc_test, dev, n_ctx, cnd)
    res["optc_test"] = {
        "before_base_model_at_base_thr": metrics(y_ot, fp16_prob(zb_t), base_thr_prob),
        "after_at_base_thr": metrics(y_ot, fp16_prob(zi_t), base_thr_prob),
        "after_at_optc_val_thr": metrics(y_ot, zi_t, thr_o),
        "after_at_atlas_val_thr": metrics(y_ot, zi_t, thr_a),
        "base_threshold_prob": base_thr_prob, "optc_val_threshold_logit": thr_o}
    res["bwt_f1_at_base_thr"] = res["optc_test"]["after_at_base_thr"]["f1"] - res["optc_test"]["before_base_model_at_base_thr"]["f1"]
    res["elapsed_sec"] = round(time.time() - t0)
    (out / "result.json").write_text(json.dumps(res, indent=2))
    (out / "history.json").write_text(json.dumps(hist, indent=1))
    with open(out / "atlas_test_predictions.csv", "w", newline="") as fh:
        wr = csv.writer(fh); wr.writerow(["sample_id", f"y_{args.label}", "logit", "pred", "stages"])
        for s, z in zip(te, zt):
            wr.writerow([s["id"], s["y"], f"{z:.5f}", int(z >= thr_a), "|".join(map(str, s["src"][f"stages_{args.label}"]))])
    o = res["optc_test"]; a = res["atlas"]
    print("RESULT best_epoch", best[1], res["best_stage"],
          "\nATLASv2 TEST(v9b) F1 %.4f  (tp %d fp %d fn %d)" % (a["test_v9b_labels"]["f1"], a["test_v9b_labels"]["tp"], a["test_v9b_labels"]["fp"], a["test_v9b_labels"]["fn"]),
          "\nATLASv2 stage", json.dumps(a["stage"]["test_summary"]),
          "\nOpTC TEST F1 before %.4f  after@base_thr %.4f  after@optc_val_thr %.4f  after@atlas_thr %.4f" % (
              o["before_base_model_at_base_thr"]["f1"], o["after_at_base_thr"]["f1"], o["after_at_optc_val_thr"]["f1"], o["after_at_atlas_val_thr"]["f1"]),
          flush=True)


if __name__ == "__main__":
    main()
