#!/usr/bin/env python3
"""S36c - Fine-tune / Incremental Learning OpTC -> ATLASv2 (STEP 48), mo hinh B (BiLSTM hoac Mixed-Type). Chay tren Kaggle; chay thu CPU duoc.

Khac s14_ft_train.py (STEP 30):
  - co VAL (cua so vb == 0 trong cac fold con lai) de chon checkpoint (VAL PR-AUC + 0.1 * F1 tot nhat) va nguong (F1 toi da tren VAL, giua cao nguyen). TEST chi tinh MOT lan.
  - mo dan (gradual unfreezing) theo STEP 44: A (hang embedding moi + dau phan loai) -> B1 (+ encoder su kien) -> B2 (+ tang chuoi) -> C (+ embedding cu, lr nho);
    moi giai doan dung toi da N epoch, dung som theo VAL, nap lai checkpoint tot nhat cua giai doan truoc khi mo tiep.
  - replay OpTC that (STEP 30) tron vao moi epoch; khong so sanh "truoc fine-tune"; chi bao ma tran nham lan TRAIN, VAL, TEST (ATLASv2) va OpTC TEST.
  - kiem tra tuong duong khoi tao: mo hinh mo rong (chua train) cho logit giong mo hinh goc khi id moi duoc doi thanh <UNK>.
Tai su dung ham tu s14_ft_train.py (cung thu muc)."""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).parent))
import s14_ft_train as T  # noqa: E402


# nguong goc 1.0 (Mixed-Type) la nguong tren xac suat fp16 (sigmoid lam tron thanh 1.0 khi logit > ~8.3): doi sang logit bang cach chan 1 - 2^-12


def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))


def group_of(name):
    if name.startswith("classifier."):
        return "head"
    if name.startswith("embeddings.") or name.startswith("event_encoder.cat_embeddings."):
        return "emb"
    if name.startswith("event_encoder."):
        return "enc"
    return "seq"  # lstm.*, temporal_blocks.*, temporal_norm.*, position_embedding.*


def conf_at(y, lg, thr_logit):
    pred = (lg >= thr_logit).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"threshold_logit": round(float(thr_logit), 5), "threshold_prob": round(float(sigmoid(thr_logit)), 6), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4)}


def best_threshold(y, lg):
    """F1 toi da tren VAL; neu co cao nguyen (nhieu nguong cho F1 bang nhau) lay diem giua cao nguyen (theo logit)."""
    u = np.unique(lg)
    if len(u) == 1:
        return float(u[0]) + 1e-6
    cand = np.r_[u[0] - 1.0, (u[:-1] + u[1:]) / 2.0, u[-1] + 1.0]
    f1 = np.array([conf_at(y, lg, t)["f1"] for t in cand])
    top = np.flatnonzero(f1 >= f1.max() - 1e-12)
    runs = np.split(top, np.flatnonzero(np.diff(top) > 1) + 1)
    run = max(runs, key=len)
    return float((cand[run[0]] + cand[run[-1]]) / 2.0)


def summarize(df, thr_logit):
    y, lg = df.label.to_numpy(), df.logit.to_numpy()
    out = {"n": int(len(df)), "positives": int(y.sum()), "confusion": conf_at(y, lg, thr_logit)}
    if 0 < y.sum() < len(y):
        out["pr_auc"] = round(float(average_precision_score(y, lg)), 4)
        out["roc_auc"] = round(float(roc_auc_score(y, lg)), 4)
    return out


def equivalence_check(model_ext, base_sd, cfg, old_cards, kind, samples, dev, code_dir, bs):
    base = T.build_model(kind, cfg, old_cards, code_dir)
    base.load_state_dict(base_sd)
    base.to(dev)
    mapped = []
    for s in samples:
        x = s["x_cat"].copy()
        for j, c in enumerate(old_cards):
            x[:, j] = np.where(x[:, j] >= c, 0, x[:, j])
        mapped.append({**s, "x_cat": x})
    a = T.predict(model_ext, kind, samples, dev, bs).logit.to_numpy()
    b = T.predict(base, kind, mapped, dev, bs).logit.to_numpy()
    return float(np.abs(a - b).max())


def stage_plan(args):
    lb = args.lr_b_bilstm if args.model == "bilstm" else args.lr_b_mixed
    return [  # (ten, so epoch toi da, lr co so, nhom hoat dong, he so lr theo nhom)
        ("A", args.epochs_a, args.lr_a, ("head", "emb"), {"head": 1.0, "emb": 1.0}),
        ("B1", args.epochs_b, lb, ("head", "emb", "enc"), {"head": 1.0, "emb": 1.0, "enc": 1.0}),
        ("B2", args.epochs_b, lb, ("head", "emb", "enc", "seq"), {"head": 1.0, "emb": 1.0, "enc": 1.0, "seq": 0.5}),
        ("C", args.epochs_b, lb, ("head", "emb", "enc", "seq"), {"head": 0.5, "emb": 0.1, "enc": 0.5, "seq": 0.25}),
    ]


def set_requires_grad(model, active, mask_old_emb, old_rows):
    handles = []
    for name, p in model.named_parameters():
        g = group_of(name)
        p.requires_grad = g in active
        if g == "emb" and p.requires_grad and mask_old_emb:
            mask = torch.zeros(p.shape[0], 1, device=p.device)
            mask[old_rows[name]:] = 1.0
            handles.append(p.register_hook(lambda gr, m=mask: gr * m))
    return handles


def run_fold(args, k, ctx):
    dev = ctx["device"]
    kind = args.model
    ft = Path(args.ft_root)
    fold_dir = ft / f"fold{k}"
    spec = json.load(open(fold_dir / "spec_ext.json", encoding="utf-8"))
    cards = [max(e["id"] for e in spec["categorical"]["fields"][f]["vocab"]) + 1 for f in T.CAT_NAMES]
    cfg, old_cards = ctx["cfg"], ctx["cfg"]["categorical_cardinalities"]
    print(f"[fold {k}] cardinalities cu {old_cards} -> mo rong {cards}", flush=True)
    T.seed_everything(args.seed + k)
    model = T.build_model(kind, cfg, cards, args.code_dir)
    old_rows = T.transfer_weights(model, ctx["base_sd"], old_cards, kind)
    model.to(dev)
    folds = pd.read_csv(ft / "folds.csv")
    sm = pd.read_csv(fold_dir / "atlasv2/data/samples.csv")[["sample_id", "shard_file", "shard_sample_index"]]
    rows = sm.merge(folds[["sample_id", "fold", "vb", "label", "scenario", "kind", "hostname"]], on="sample_id")
    assert len(rows) == len(sm) == len(folds)
    rows["root"] = str(fold_dir / "atlasv2")
    rows["role"] = np.where(rows.fold == k, "test", np.where(rows.vb == 0, "val", "train"))
    samples = T.materialize(rows)
    sel = {r: [i for i in range(len(rows)) if rows.role.iat[i] == r] for r in ("train", "val", "test")}
    train_new = [samples[i] for i in sel["train"]]
    val_s = [samples[i] for i in sel["val"]]
    test_s = [samples[i] for i in sel["test"]]
    npos = lambda L: sum(s["label"] for s in L)
    print(f"[fold {k}] train {len(train_new)} (duong {npos(train_new)}) | val {len(val_s)} (duong {npos(val_s)}) | test {len(test_s)} (duong {npos(test_s)})", flush=True)
    worst = equivalence_check(model, ctx["base_sd"], cfg, old_cards, kind, test_s[:200], dev, args.code_dir, args.eval_batch)
    print(f"[fold {k}] kiem tra tuong duong khoi tao: chenh logit lon nhat {worst:.6f}", flush=True)
    if worst > args.equiv_tol:
        raise RuntimeError(f"mo hinh mo rong chua train KHONG tuong duong mo hinh goc (chenh {worst:.5f} > {args.equiv_tol})")
    result = {"fold": k, "cardinalities_old": old_cards, "cardinalities_ext": cards, "equivalence_max_logit_diff": worst, "added_tokens": spec["extension"]["added"],
              "sizes": {r: {"n": len(sel[r]), "positives": npos([samples[i] for i in sel[r]])} for r in sel}, "history": []}
    rep = ctx["replay"]
    rep_pos = [s for s in rep if s["label"] == 1]
    rep_neg = [s for s in rep if s["label"] == 0]
    n_pos = npos(train_new) + args.replay_pos
    n_neg = len(train_new) - npos(train_new) + (args.replay_per_epoch - args.replay_pos)
    crit = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(n_neg / max(n_pos, 1), dtype=torch.float32, device=dev))
    amp = dev.type == "cuda" and not args.no_amp
    scaler = torch.amp.GradScaler("cuda", enabled=amp)
    rng = np.random.default_rng(args.seed * 1000 + k)
    best = {"score": -1.0, "state": None, "stage": None, "epoch": 0}
    ep_global = 0
    for stage, max_ep, lr, active, mult in stage_plan(args):
        handles = set_requires_grad(model, active, mask_old_emb=(stage != "C"), old_rows=old_rows)
        groups = []
        for g in active:
            ps = [p for n, p in model.named_parameters() if group_of(n) == g and p.requires_grad]
            if ps:
                groups.append({"params": ps, "lr": lr * mult[g], "weight_decay": 0.0 if g == "emb" else args.weight_decay})
        opt = torch.optim.AdamW(groups)
        ntr = sum(p.numel() for gp in groups for p in gp["params"])
        print(f"[fold {k}] giai doan {stage}: toi da {max_ep} epoch, lr co so {lr}, nhom {list(active)}, tham so co the hoc {ntr:,}", flush=True)
        stage_best, bad_ep = -1.0, 0
        for ep in range(max_ep):
            ep_global += 1
            draw = [rep_pos[i] for i in rng.permutation(len(rep_pos))[:args.replay_pos]] + [rep_neg[i] for i in rng.permutation(len(rep_neg))[:args.replay_per_epoch - args.replay_pos]]
            epoch_samples = train_new + draw
            order = rng.permutation(len(epoch_samples))
            model.train()
            tot, nb, t0 = 0.0, 0, time.time()
            params = [p for gp in groups for p in gp["params"]]
            for i in range(0, len(order), args.batch_size):
                b = T.collate([epoch_samples[j] for j in order[i:i + args.batch_size]])
                opt.zero_grad(set_to_none=True)
                with torch.autocast(device_type=dev.type, dtype=torch.float16, enabled=amp):
                    loss = crit(T.forward(model, kind, b, dev).float(), b["labels"].to(dev))
                scaler.scale(loss).backward()
                scaler.unscale_(opt)
                torch.nn.utils.clip_grad_norm_(params, args.grad_clip)
                scaler.step(opt)
                scaler.update()
                tot += float(loss.item())
                nb += 1
            vdf = T.predict(model, kind, val_s, dev, args.eval_batch)
            vy, vl = vdf.label.to_numpy(), vdf.logit.to_numpy()
            vpr = float(average_precision_score(vy, vl)) if 0 < vy.sum() < len(vy) else 0.0
            vthr = best_threshold(vy, vl)
            vf1 = conf_at(vy, vl, vthr)["f1"]
            score = vpr + 0.1 * vf1
            result["history"].append({"stage": stage, "epoch": ep_global, "train_loss": round(tot / max(nb, 1), 5), "val_pr_auc": round(vpr, 4), "val_f1": vf1, "val_score": round(score, 4),
                                      "seconds": round(time.time() - t0, 1)})
            print(f"[fold {k}] {stage} epoch {ep_global}: loss {tot / max(nb, 1):.5f} | VAL PR-AUC {vpr:.4f} F1 {vf1:.4f} ({time.time() - t0:.0f}s)", flush=True)
            if score > best["score"] + 1e-6:
                best = {"score": score, "state": {n: v.detach().cpu().clone() for n, v in model.state_dict().items()}, "stage": stage, "epoch": ep_global}
            if score > stage_best + 1e-6:
                stage_best, bad_ep = score, 0
            else:
                bad_ep += 1
                if bad_ep >= args.patience:
                    print(f"[fold {k}] giai doan {stage}: dung som (khong cai thien VAL {args.patience} epoch)", flush=True)
                    break
        for h in handles:
            h.remove()
        model.load_state_dict(best["state"])  # mo tiep tu checkpoint tot nhat tren VAL
    print(f"[fold {k}] checkpoint tot nhat: giai doan {best['stage']}, epoch {best['epoch']}, VAL score {best['score']:.4f}", flush=True)
    model.load_state_dict(best["state"])
    # ngưỡng chọn trên VAL, đánh giá một lần
    vdf = T.predict(model, kind, val_s, dev, args.eval_batch)
    thr_logit = best_threshold(vdf.label.to_numpy(), vdf.logit.to_numpy())
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    allp = []
    for role in ("train", "val", "test"):
        df = T.predict(model, kind, [samples[i] for i in sel[role]], dev, args.eval_batch)
        meta = rows.iloc[sel[role]][["scenario", "kind", "hostname"]].reset_index(drop=True)
        df = pd.concat([df, meta], axis=1)
        df["role"] = role
        df["fold"] = k
        allp.append(df)
        result[f"atlasv2_{role}"] = summarize(df, thr_logit)
    pd.concat(allp).to_csv(out / f"predictions_{kind}_fold{k}_atlasv2.csv", index=False)
    result.update({"selected_on": "VAL (ATLASv2)", "threshold_logit": thr_logit, "threshold_prob": float(sigmoid(thr_logit)), "best_stage": best["stage"], "best_epoch": best["epoch"]})
    te = allp[2]
    result["atlasv2_test_by_scenario"] = {sc: {"n": int(len(g)), "positives": int(g.label.sum()), "predicted_positive": int((g.logit >= thr_logit).sum()),
                                               "tp": int(((g.label == 1) & (g.logit >= thr_logit)).sum())} for sc, g in te.groupby("scenario")}
    torch.save({"model_state_dict": model.state_dict(), "cardinalities": cards, "fold": k, "threshold_logit": thr_logit}, out / f"model_{kind}_fold{k}.pt")
    if args.optc_eval != "none":
        res = T.eval_optc(model, kind, args, ctx, {"x": 0.5}, k)
        df = pd.read_csv(out / f"predictions_{kind}_fold{k}_optc_test.csv")
        result["optc_test"] = {"n": int(len(df)), "positives": int(df.label.sum()), "at_val_threshold": conf_at(df.label.to_numpy(), df.logit.to_numpy(), thr_logit),
                               "at_optc_base_threshold": conf_at(df.label.to_numpy(), df.logit.to_numpy(), float(np.log(min(ctx["thr"], 1 - 2.0 ** -12) / (1 - min(ctx["thr"], 1 - 2.0 ** -12))))),
                               "pr_auc": round(float(average_precision_score(df.label, df.logit)), 4), "roc_auc": round(float(roc_auc_score(df.label, df.logit)), 4)}
    json.dump(result, open(out / f"result_{kind}_fold{k}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[fold {k}] xong. TEST ATLASv2:", json.dumps(result["atlasv2_test"]["confusion"], ensure_ascii=False), flush=True)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["bilstm", "mixed"], required=True)
    ap.add_argument("--ft-root", required=True)
    ap.add_argument("--optc-root", required=True)
    ap.add_argument("--code-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--folds", default="0,1,2")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epochs-a", type=int, default=8)
    ap.add_argument("--epochs-b", type=int, default=10)
    ap.add_argument("--patience", type=int, default=3)
    ap.add_argument("--lr-a", type=float, default=1e-3)
    ap.add_argument("--lr-b-bilstm", type=float, default=3e-4)
    ap.add_argument("--lr-b-mixed", type=float, default=1e-4)
    ap.add_argument("--weight-decay", type=float, default=1e-4)
    ap.add_argument("--grad-clip", type=float, default=1.0)
    ap.add_argument("--replay-per-epoch", type=int, default=600)
    ap.add_argument("--replay-pos", type=int, default=150)
    ap.add_argument("--batch-size", type=int, default=0)
    ap.add_argument("--eval-batch", type=int, default=0)
    ap.add_argument("--equiv-tol", type=float, default=0.02)
    ap.add_argument("--optc-eval", choices=["test", "none"], default="test")
    ap.add_argument("--max-optc-test", type=int, default=0, help="chi de chay thu: gioi han so mau am OpTC TEST")
    ap.add_argument("--no-amp", action="store_true")
    ap.add_argument("--cpu", action="store_true")
    args = ap.parse_args()
    args.batch_size = args.batch_size or (32 if args.model == "bilstm" else 16)
    args.eval_batch = args.eval_batch or (128 if args.model == "bilstm" else 32)
    dev = torch.device("cpu" if args.cpu or not torch.cuda.is_available() else "cuda")
    ft = Path(args.ft_root)
    man = json.load(open(ft / "ft_manifest.json", encoding="utf-8"))
    base = ft / "base_models" / args.model
    cfg = json.load(open(base / "config.json", encoding="utf-8"))
    thr = float(json.load(open(base / "threshold.json", encoding="utf-8"))["threshold"])
    ck = torch.load(base / "best_model.pt", map_location="cpu", weights_only=False)
    Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    print(f"[init] mo hinh {args.model}, thiet bi {dev}, nguong VAL OpTC goc {thr}, thu muc ra {args.out_dir}", flush=True)
    optc_manifest = pd.read_csv(Path(args.optc_root) / "split/network_sample_manifest.csv")
    rr = pd.read_csv(ft / "replay_R.csv")
    rr["root"] = str(Path(args.optc_root))
    t0 = time.time()
    replay = T.materialize(rr)
    print(f"[init] replay OpTC that: {len(replay)} mau (duong {sum(s['label'] for s in replay)}) nap trong {time.time() - t0:.0f}s", flush=True)
    ctx = {"device": dev, "cfg": cfg, "base_sd": ck["model_state_dict"], "thr": thr, "domains": man["domains"], "replay": replay, "optc_manifest": optc_manifest}
    results = [run_fold(args, k, ctx) for k in [int(x) for x in args.folds.split(",")]]
    json.dump({"model": args.model, "args": vars(args), "folds": [r["fold"] for r in results]}, open(Path(args.out_dir) / f"run_{args.model}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", flush=True)


if __name__ == "__main__":
    main()
