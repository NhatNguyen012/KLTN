#!/usr/bin/env python3
"""Step 3 of the v9 pipeline: train a single BiLSTM window detector.

Model: per-field embeddings + cmdline/time features -> event encoder ->
2-layer BiLSTM -> (a) per-event head (auxiliary event supervision) and
(b) attention + max pooled window head. Checkpoint, scoring head and threshold
are selected on VALIDATION only; TEST is evaluated once at the end.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import pickle
import random
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence


def emb_dim(card: int) -> int:
    return int(min(24, max(4, round(2 * math.sqrt(card)))))


class BiLSTMDetector(nn.Module):
    def __init__(self, cards, num_dim, d_event=128, hidden=128, layers=2, dropout=0.25, token_dropout=0.1):
        super().__init__()
        self.embs = nn.ModuleList(nn.Embedding(c, emb_dim(c), padding_idx=0) for c in cards)
        in_dim = sum(e.embedding_dim for e in self.embs) + num_dim
        self.token_dropout = token_dropout
        self.encoder = nn.Sequential(nn.Linear(in_dim, d_event), nn.LayerNorm(d_event), nn.GELU(), nn.Dropout(dropout))
        self.lstm = nn.LSTM(d_event, hidden, num_layers=layers, batch_first=True, bidirectional=True,
                            dropout=dropout if layers > 1 else 0.0)
        H = 2 * hidden
        self.event_head = nn.Sequential(nn.Linear(H, hidden), nn.GELU(), nn.Linear(hidden, 1))
        self.att = nn.Sequential(nn.Linear(H, hidden), nn.Tanh(), nn.Linear(hidden, 1, bias=False))
        self.window_head = nn.Sequential(nn.LayerNorm(2 * H), nn.Linear(2 * H, hidden), nn.GELU(),
                                         nn.Dropout(dropout), nn.Linear(hidden, 1))
        # Per-event attack-stage head (1..4 -> 0..3); trained only on positive events.
        self.stage_head = nn.Sequential(nn.Linear(H, hidden), nn.GELU(), nn.Linear(hidden, 4))

    def forward(self, cat, num, lengths):
        if self.training and self.token_dropout > 0:
            drop = (torch.rand(cat.shape, device=cat.device) < self.token_dropout) & (cat > 0)
            cat = cat.masked_fill(drop, 1)  # -> <UNK>
        x = torch.cat([e(cat[..., i]) for i, e in enumerate(self.embs)] + [num], -1)
        x = self.encoder(x)
        packed = pack_padded_sequence(x, lengths.cpu(), batch_first=True, enforce_sorted=False)
        h, _ = self.lstm(packed)
        h, _ = pad_packed_sequence(h, batch_first=True, total_length=cat.size(1))
        mask = torch.arange(cat.size(1), device=cat.device)[None] < lengths[:, None]
        ev_logit = self.event_head(h).squeeze(-1).masked_fill(~mask, -1e4)
        a = self.att(h).squeeze(-1).masked_fill(~mask, -1e4)
        h_att = torch.bmm(F.softmax(a, -1).unsqueeze(1), h).squeeze(1)
        h_max = h.masked_fill(~mask[..., None], -1e4).max(1).values
        win_logit = self.window_head(torch.cat([h_att, h_max], -1)).squeeze(-1)
        return win_logit, ev_logit, mask, self.stage_head(h)


def collate(batch, device):
    L = max(len(s["cat"]) for s in batch)
    B = len(batch)
    F_ = batch[0]["cat"].shape[1]
    N = batch[0]["num"].shape[1]
    cat = np.zeros((B, L, F_), np.int64)
    num = np.zeros((B, L, N), np.float32)
    evy = np.full((B, L), -1, np.float32)
    evst = np.zeros((B, L), np.int64)
    for i, s in enumerate(batch):
        n = len(s["cat"])
        cat[i, :n] = s["cat"]
        num[i, :n] = s["num"]
        evy[i, :n] = s["_evy"]
        evst[i, :n] = s["_evst"]
    t = lambda a: torch.from_numpy(a).to(device)
    return (t(cat), t(num), torch.tensor([len(s["cat"]) for s in batch], device=device),
            torch.tensor([s["_y"] for s in batch], dtype=torch.float32, device=device), t(evy), t(evst))


def prepare(samples, label, use_extra):
    out = []
    for s in samples:
        keep = np.ones(len(s["cat"]), bool) if use_extra else ~s["is_extra"]
        d = dict(s)
        d["cat"], d["num"] = s["cat"][keep], s["num"][keep]
        d["_evy"] = s[f"ev_y_{label}"][keep].astype(np.float32)
        d["_y"] = s[f"y_{label}"]
        st = s.get(f"ev_stage_{label}")
        d["_evst"] = st[keep].astype(np.int64) if st is not None else np.zeros(int(keep.sum()), np.int64)
        out.append(d)
    return out


@torch.no_grad()
def predict(model, data, device, bs=128):
    model.eval()
    win, mil = [], []
    for i in range(0, len(data), bs):
        cat, num, lens, _, _, _ = collate(data[i:i + bs], device)
        w, e, _, _ = model(cat, num, lens)
        win.append(w.float().cpu())  # logits: no float32 sigmoid saturation
        mil.append(e.max(1).values.float().cpu())
    return torch.cat(win).numpy(), torch.cat(mil).numpy()


def best_threshold(y, p):
    """Exact F1-maximising threshold over all distinct scores (midpoint)."""
    if y.sum() == 0:
        return 1.0, 0.0
    prec, rec, thr = precision_recall_curve(y, p)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-12, None)
    i = int(np.nanargmax(f1[:-1]))
    s = np.unique(p)
    j = np.searchsorted(s, thr[i])
    lo = s[j - 1] if j > 0 else thr[i] - 1.0
    return float((lo + thr[i]) / 2), float(f1[i])


def metrics(y, p, t):
    pred = p >= t
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    prec = tp / max(1, tp + fp); rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-12, prec + rec)
    out = dict(tp=tp, fp=fp, fn=fn, tn=int(len(y) - tp - fp - fn), precision=prec, recall=rec, f1=f1,
               fpr=fp / max(1, int((y == 0).sum())))
    if 0 < y.sum() < len(y):
        out["ap"] = float(average_precision_score(y, p)); out["roc_auc"] = float(roc_auc_score(y, p))
    return out


@torch.no_grad()
def stage_scores(model, data, device, ev_thr, bs=128):
    """Per window: presence score s_k = max_t [log p_attack(t) + log q_k(t)] and
    'last stage' = stage argmax at the last event whose attack logit >= ev_thr
    (fallback: argmax_k s_k)."""
    model.eval()
    pres, last = [], []
    for i in range(0, len(data), bs):
        cat, num, lens, _, _, _ = collate(data[i:i + bs], device)
        _, e, mask, st = model(cat, num, lens)
        joint = F.logsigmoid(e)[..., None] + F.log_softmax(st, -1)
        joint = joint.masked_fill(~mask[..., None], -1e4)
        s_k = joint.max(1).values
        pres.append(s_k.cpu())
        alert = (e >= ev_thr) & mask
        idx = torch.arange(e.size(1), device=e.device)[None].expand_as(e)
        last_idx = torch.where(alert, idx, torch.full_like(idx, -1)).max(1).values
        st_arg = st.argmax(-1)
        lp = torch.where(last_idx >= 0, st_arg.gather(1, last_idx.clamp(min=0)[:, None]).squeeze(1), s_k.argmax(-1))
        last.append((lp + 1).cpu())
    return torch.cat(pres).numpy(), torch.cat(last).numpy()


def stage_eval(model, va, te, device, label, val_pos, test_pos, ev_thr):
    """Two stage tasks, both on ALL windows (benign false alarms count as errors):
    presence (multi-label, which stages occur in the window) and last-stage
    (5-class incl. benign; the historical single-label target)."""
    from sklearn.metrics import f1_score, precision_recall_fscore_support
    out = {}
    pv, _ = stage_scores(model, va, device, ev_thr)
    pt, lt = stage_scores(model, te, device, ev_thr)
    taus = []
    for k in range(4):
        yk = np.array([(k + 1) in s[f"stages_{label}"] for s in va])
        sk = np.where(val_pos, pv[:, k], -1e4)
        taus.append(best_threshold(yk, sk)[0] if yk.sum() else float("inf"))
    per = {}
    for k, name in enumerate(["initial_compromise", "execution_discovery", "lateral_movement", "exfiltration"]):
        yk = np.array([(k + 1) in s[f"stages_{label}"] for s in te])
        pk = test_pos & (pt[:, k] >= taus[k])
        tp = int((pk & yk).sum()); fp = int((pk & ~yk).sum()); fn = int((~pk & yk).sum())
        f1 = 2 * tp / max(1, 2 * tp + fp + fn)
        per[name] = dict(support=int(yk.sum()), tp=tp, fp=fp, fn=fn, f1=f1, val_tau=taus[k])
    out["presence"] = per
    sup = [v for v in per.values() if v["support"] > 0]
    y_last = np.array([s[f"stage_last_{label}"] for s in te])
    p_last = np.where(test_pos, lt, 0)
    labs = [1, 2, 3, 4]
    f1s = f1_score(y_last, p_last, labels=labs, average=None, zero_division=0)
    supp = [int((y_last == k).sum()) for k in labs]
    out["last_stage"] = {
        "per_stage_f1": dict(zip(["initial_compromise", "execution_discovery", "lateral_movement", "exfiltration"], map(float, f1s))),
        "support": supp,
        "predicted": [int((p_last == k).sum()) for k in labs],
        "confusion_true_rows_0to4": [[int(((y_last == a) & (p_last == b)).sum()) for b in range(5)] for a in range(5)],
    }
    tpw = (y_last > 0) & test_pos
    out["test_summary"] = {
        "presence_macro_f1_supported": float(np.mean([v["f1"] for v in sup])),
        "presence_macro_f1_fixed4": float(np.mean([v["f1"] for v in per.values()])),
        "last_stage_macro_f1_supported": float(np.mean([f for f, n in zip(f1s, supp) if n > 0])),
        "last_stage_macro_f1_fixed4": float(np.mean(f1s)),
        "last_stage_acc_on_detected_attacks": float((p_last[tpw] == y_last[tpw]).mean()) if tpw.any() else None,
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", choices=["legacy", "v9", "v9b"], default="v9")
    ap.add_argument("--use-extra", type=int, default=1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--bs", type=int, default=64)
    ap.add_argument("--aux", type=float, default=0.5)
    ap.add_argument("--hidden", type=int, default=128)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--dropout", type=float, default=0.25)
    ap.add_argument("--token-dropout", type=float, default=0.1)
    ap.add_argument("--wd", type=float, default=1e-4)
    ap.add_argument("--select", choices=["best", "swa"], default="best",
                    help="best: val-selected epoch; swa: uniform weight average of epochs >= --swa-start (no epoch selection)")
    ap.add_argument("--swa-start", type=int, default=0, help="default: second half of training")
    ap.add_argument("--drop-fields", default="", help="comma list of categorical fields to blank (ablation)")
    ap.add_argument("--drop-cmd", type=int, default=0, help="zero the command-line flag features (ablation)")
    ap.add_argument("--stage-w", type=float, default=0.0, help="weight of per-event stage CE (0 = no stage head training)")
    ap.add_argument("--neg-ratio", type=float, default=0, help="if >0 subsample train negatives per epoch to ratio*pos")
    args = ap.parse_args()

    random.seed(args.seed); np.random.seed(args.seed); torch.manual_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    blob = pickle.load(open(args.data, "rb"))
    meta = blob["meta"]
    tr = prepare(blob["splits"]["train"], args.label, args.use_extra)
    va = prepare(blob["splits"]["val"], args.label, args.use_extra)
    te = prepare(blob["splits"]["test"], args.label, args.use_extra)
    drop_idx = [meta["cat_fields"].index(f) for f in args.drop_fields.split(",") if f]
    n_cmd = meta["num_dim"] - 3  # last 3 numeric columns are dt, rel-time, is_filemod
    for d in (tr, va, te):
        for smp in d:
            if drop_idx:
                smp["cat"] = smp["cat"].copy(); smp["cat"][:, drop_idx] = 1
            if args.drop_cmd:
                smp["num"] = smp["num"].copy(); smp["num"][:, :n_cmd] = 0.0
    cards = [len(meta["vocab"][f]) for f in meta["cat_fields"]]
    model = BiLSTMDetector(cards, meta["num_dim"], hidden=args.hidden, layers=args.layers,
                           dropout=args.dropout, token_dropout=args.token_dropout).to(device)
    pos = [s for s in tr if s["_y"] == 1]; neg = [s for s in tr if s["_y"] == 0]
    pw = torch.tensor(math.sqrt(len(neg) / max(1, len(pos))), device=device)
    ev_all = np.concatenate([s["_evy"] for s in tr]); ev_pos = (ev_all == 1).sum(); ev_neg = (ev_all == 0).sum()
    epw = torch.tensor(math.sqrt(ev_neg / max(1, ev_pos)), device=device)
    st_all = np.concatenate([s["_evst"] for s in tr]); st_cnt = np.array([(st_all == k).sum() for k in (1, 2, 3, 4)], float)
    stage_cw = torch.tensor(np.sqrt(st_cnt.sum() / np.maximum(st_cnt, 1) / 4), dtype=torch.float32, device=device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.wd)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=args.lr, total_steps=args.epochs * math.ceil(len(tr) / args.bs) + 10)
    yv = np.array([s["_y"] for s in va])
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    print(f"device={device} train pos={len(pos)} neg={len(neg)} pos_weight={pw.item():.2f} ev_pw={epw.item():.2f} "
          f"params={sum(p.numel() for p in model.parameters()):,}", flush=True)

    best = (-1, -1); hist = []
    swa_start = args.swa_start or args.epochs // 2 + 1
    swa = torch.optim.swa_utils.AveragedModel(model) if args.select == "swa" else None
    for ep in range(1, args.epochs + 1):
        model.train(); t0 = time.time()
        epoch = pos + (random.sample(neg, min(len(neg), int(args.neg_ratio * len(pos)))) if args.neg_ratio > 0 else neg)
        random.shuffle(epoch)
        tot = 0.0
        for i in range(0, len(epoch), args.bs):
            cat, num, lens, y, evy, evst = collate(epoch[i:i + args.bs], device)
            w, e, mask, st = model(cat, num, lens)
            loss = F.binary_cross_entropy_with_logits(w, y, pos_weight=pw)
            m = evy >= 0
            if args.aux > 0 and m.any():
                loss = loss + args.aux * F.binary_cross_entropy_with_logits(e[m], evy[m], pos_weight=epw)
            ms = evst > 0
            if args.stage_w > 0 and ms.any():
                loss = loss + args.stage_w * F.cross_entropy(st[ms], evst[ms] - 1, weight=stage_cw)
            opt.zero_grad(); loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); tot += loss.item()
        pw_, pm_ = predict(model, va, device)
        rec = {"epoch": ep, "loss": tot, "sec": round(time.time() - t0, 1)}
        for name, p in (("win", pw_), ("mil", pm_)):
            t, f1 = best_threshold(yv, p)
            rec[f"val_{name}_ap"] = float(average_precision_score(yv, p)); rec[f"val_{name}_f1"] = f1
        if swa is not None and ep >= swa_start:
            swa.update_parameters(model)
        hist.append(rec)
        score = max((rec["val_win_ap"] + rec["val_win_f1"]) / 2, (rec["val_mil_ap"] + rec["val_mil_f1"]) / 2)
        if score > best[0]:
            best = (score, ep); torch.save(model.state_dict(), out / "best.pt")
        print(json.dumps(rec), flush=True)

    if swa is not None:
        model.load_state_dict(swa.module.state_dict())
        torch.save(model.state_dict(), out / "swa.pt")
        best = (None, f"swa{swa_start}-{args.epochs}")
    else:
        model.load_state_dict(torch.load(out / "best.pt", map_location=device))
    pv_win, pv_mil = predict(model, va, device)
    heads = {}
    for name, p in (("win", pv_win), ("mil", pv_mil)):
        t, f1 = best_threshold(yv, p)
        heads[name] = ((float(average_precision_score(yv, p)) + f1) / 2, t)
    head = max(heads, key=lambda k: heads[k][0]); thr = heads[head][1]
    pt_win, pt_mil = predict(model, te, device)
    pt = pt_win if head == "win" else pt_mil
    pv = pv_win if head == "win" else pv_mil
    res = {"args": vars(args), "best_epoch": best[1], "head": head, "threshold": thr,
           "val": metrics(yv, pv, thr)}
    yt_v9 = np.array([s["y_v9"] for s in te]); yt_leg = np.array([s["y_legacy"] for s in te])
    res["test_v9_labels"] = metrics(yt_v9, pt, thr)
    res["test_legacy_labels"] = metrics(yt_leg, pt, thr)
    if "y_v9b" in te[0]:
        res["test_v9b_labels"] = metrics(np.array([s["y_v9b"] for s in te]), pt, thr)
    keep = ~((yt_leg == 1) & (yt_v9 == 0))  # drop windows whose only evidence is benign-observed seed endpoints
    res["test_legacy_minus_portal_only"] = metrics(yt_leg[keep], pt[keep], thr)
    if args.stage_w > 0:
        ev_thr = thr if head == "mil" else 0.0
        res["stage"] = stage_eval(model, va, te, device, args.label, pv >= thr, pt >= thr, ev_thr)
        print("STAGE", json.dumps(res["stage"]["test_summary"]), flush=True)
    (out / "result.json").write_text(json.dumps(res, indent=2))
    (out / "history.json").write_text(json.dumps(hist, indent=1))
    with open(out / "test_predictions.csv", "w", newline="") as fh:
        wr = csv.writer(fh); wr.writerow(["sample_id", "y_v9", "y_v9b", "y_legacy", "score", "pred", "stages"])
        for s, p in zip(te, pt):
            wr.writerow([s["sample_id"], s["y_v9"], s.get("y_v9b", ""), s["y_legacy"], f"{p:.6f}", int(p >= thr), "|".join(map(str, s["stages"]))])
    print("RESULT", json.dumps({k: res[k] for k in ("best_epoch", "head", "threshold")}),
          "\nVAL ", json.dumps(res["val"]), "\nTEST(v9) ", json.dumps(res["test_v9_labels"]),
          "\nTEST(legacy) ", json.dumps(res["test_legacy_labels"]),
          "\nTEST(v9b) ", json.dumps(res.get("test_v9b_labels")), flush=True)


if __name__ == "__main__":
    main()
