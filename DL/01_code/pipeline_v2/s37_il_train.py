#!/usr/bin/env python3
"""S37c - IL OpTC -> nhieu mien moi (ATLASv2 + THEIA, STEP 49) cho mo hinh B (BiLSTM hoac Mixed-Type). Chay tren Kaggle; chay thu CPU duoc.

Giong s36_il_train.py (mo dan A -> B1 -> B2 -> C, replay OpTC that, VAL de chon checkpoint/nguong, TEST mot lan) nhung:
  - doc nhieu mien tu ft_manifest.json (domains); TRAIN/VAL/TEST gop moi mien; checkpoint va nguong chon tren VAL GOP; bao cao them theo tung mien o cung nguong gop.
  - khong so sanh "truoc fine-tune"; chi ma tran nham lan TRAIN, VAL, TEST (tung mien va gop) va OpTC TEST.
Tai su dung ham tu s14_ft_train.py va s36_il_train.py (cung thu muc)."""
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
import s36_il_train as S  # noqa: E402


def run_fold(args, k, ctx):
    dev, kind = ctx["device"], args.model
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
    parts = []
    for ds in ctx["domains"]:
        sm = pd.read_csv(fold_dir / ds / "data/samples.csv")[["sample_id", "shard_file", "shard_sample_index"]]
        m = sm.merge(folds[folds.dataset == ds][["sample_id", "fold", "vb", "label", "scenario", "kind", "hostname"]], on="sample_id")
        assert len(m) == len(sm) == (folds.dataset == ds).sum(), ds
        m["root"] = str(fold_dir / ds)
        m["dataset"] = ds
        parts.append(m)
    rows = pd.concat(parts, ignore_index=True)
    rows["role"] = np.where(rows.fold == k, "test", np.where(rows.vb == 0, "val", "train"))
    samples = T.materialize(rows)
    sel = {r: [i for i in range(len(rows)) if rows.role.iat[i] == r] for r in ("train", "val", "test")}
    train_new = [samples[i] for i in sel["train"]]
    val_s = [samples[i] for i in sel["val"]]
    test_s = [samples[i] for i in sel["test"]]
    npos = lambda L: sum(s["label"] for s in L)
    for ds in ctx["domains"]:
        c = {r: (int(((rows.role == r) & (rows.dataset == ds)).sum()), int(rows[(rows.role == r) & (rows.dataset == ds)].label.sum())) for r in sel}
        print(f"[fold {k}] {ds}: train {c['train']} | val {c['val']} | test {c['test']}  (mau, duong)", flush=True)
    worst = S.equivalence_check(model, ctx["base_sd"], cfg, old_cards, kind, test_s[:200], dev, args.code_dir, args.eval_batch)
    print(f"[fold {k}] kiem tra tuong duong khoi tao: chenh logit lon nhat {worst:.6f}", flush=True)
    if worst > args.equiv_tol:
        raise RuntimeError(f"mo hinh mo rong chua train KHONG tuong duong mo hinh goc (chenh {worst:.5f} > {args.equiv_tol})")
    result = {"fold": k, "domains": ctx["domains"], "cardinalities_old": old_cards, "cardinalities_ext": cards, "equivalence_max_logit_diff": worst, "added_tokens": spec["extension"]["added"],
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
    for stage, max_ep, lr, active, mult in S.stage_plan(args):
        handles = S.set_requires_grad(model, active, mask_old_emb=(stage != "C"), old_rows=old_rows)
        groups = []
        for g in active:
            ps = [p for n, p in model.named_parameters() if S.group_of(n) == g and p.requires_grad]
            if ps:
                groups.append({"params": ps, "lr": lr * mult[g], "weight_decay": 0.0 if g == "emb" else args.weight_decay})
        opt = torch.optim.AdamW(groups)
        print(f"[fold {k}] giai doan {stage}: toi da {max_ep} epoch, lr co so {lr}, nhom {list(active)}, tham so co the hoc {sum(p.numel() for gp in groups for p in gp['params']):,}", flush=True)
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
            vf1 = S.conf_at(vy, vl, S.best_threshold(vy, vl))["f1"]
            score = vpr + 0.1 * vf1
            result["history"].append({"stage": stage, "epoch": ep_global, "train_loss": round(tot / max(nb, 1), 5), "val_pr_auc": round(vpr, 4), "val_f1": vf1, "val_score": round(score, 4),
                                      "seconds": round(time.time() - t0, 1)})
            print(f"[fold {k}] {stage} epoch {ep_global}: loss {tot / max(nb, 1):.5f} | VAL gop PR-AUC {vpr:.4f} F1 {vf1:.4f} ({time.time() - t0:.0f}s)", flush=True)
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
        model.load_state_dict(best["state"])
    print(f"[fold {k}] checkpoint tot nhat: giai doan {best['stage']}, epoch {best['epoch']}, VAL score {best['score']:.4f}", flush=True)
    model.load_state_dict(best["state"])
    vdf = T.predict(model, kind, val_s, dev, args.eval_batch)
    thr_logit = S.best_threshold(vdf.label.to_numpy(), vdf.logit.to_numpy())
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    allp = []
    for role in ("train", "val", "test"):
        df = T.predict(model, kind, [samples[i] for i in sel[role]], dev, args.eval_batch)
        meta = rows.iloc[sel[role]][["dataset", "scenario", "kind", "hostname"]].reset_index(drop=True)
        df = pd.concat([df, meta], axis=1)
        df["role"], df["fold"] = role, k
        allp.append(df)
        result[f"new_{role}"] = S.summarize(df, thr_logit)
        result[f"new_{role}_by_domain"] = {ds: S.summarize(df[df.dataset == ds], thr_logit) for ds in ctx["domains"]}
    pd.concat(allp).to_csv(out / f"predictions_{kind}_fold{k}_newdomains.csv", index=False)
    result.update({"selected_on": "VAL gop (ATLASv2 + THEIA)", "threshold_logit": thr_logit, "threshold_prob": float(S.sigmoid(thr_logit)), "best_stage": best["stage"], "best_epoch": best["epoch"]})
    te = allp[2]
    result["test_by_scenario"] = {f"{ds}/{sc}": {"n": int(len(g)), "positives": int(g.label.sum()), "predicted_positive": int((g.logit >= thr_logit).sum()), "tp": int(((g.label == 1) & (g.logit >= thr_logit)).sum())}
                                  for (ds, sc), g in te.groupby(["dataset", "scenario"])}
    torch.save({"model_state_dict": model.state_dict(), "cardinalities": cards, "fold": k, "threshold_logit": thr_logit}, out / f"model_{kind}_fold{k}.pt")
    if args.optc_eval != "none":
        T.eval_optc(model, kind, args, ctx, {"x": 0.5}, k)
        df = pd.read_csv(out / f"predictions_{kind}_fold{k}_optc_test.csv")
        base_logit = float(np.log(min(ctx["thr"], 1 - 2.0 ** -12) / (1 - min(ctx["thr"], 1 - 2.0 ** -12))))
        result["optc_test"] = {"n": int(len(df)), "positives": int(df.label.sum()), "at_val_threshold": S.conf_at(df.label.to_numpy(), df.logit.to_numpy(), thr_logit),
                               "at_optc_base_threshold": S.conf_at(df.label.to_numpy(), df.logit.to_numpy(), base_logit),
                               "pr_auc": round(float(average_precision_score(df.label, df.logit)), 4), "roc_auc": round(float(roc_auc_score(df.label, df.logit)), 4)}
    json.dump(result, open(out / f"result_{kind}_fold{k}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[fold {k}] xong. TEST gop:", json.dumps(result["new_test"]["confusion"], ensure_ascii=False), flush=True)
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
    ap.add_argument("--max-optc-test", type=int, default=0)
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
    print(f"[init] mo hinh {args.model}, thiet bi {dev}, mien {man['domains']}, nguong VAL OpTC goc {thr}", flush=True)
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
