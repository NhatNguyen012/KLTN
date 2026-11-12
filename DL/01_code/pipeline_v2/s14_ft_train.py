#!/usr/bin/env python3
"""S14b - Fine-tune mô hình B (BiLSTM hoặc Mixed-Type) trên hai miền Windows (skrghosh, FiveDirections) với từ điển mở rộng và replay OpTC (STEP 30). Chạy trên Kaggle; chạy thử CPU được.

Mỗi fold k:
  1. dựng mô hình với bảng embedding mở rộng (hàng mới = bản sao hàng <UNK>); các tham số khác copy từ mô hình gốc; kiến trúc không đổi.
  2. KIỂM TRA BẮT BUỘC: trước khi train, logit trên mẫu test của fold phải trùng dự đoán zero-shot tham chiếu (STEP 26, 29) trong dung sai; không qua thì dừng.
  3. giai đoạn A: chỉ học hàng embedding mới + đầu phân loại; giai đoạn B: mở khóa toàn bộ, lr nhỏ. Mỗi epoch = toàn bộ mẫu TRAIN của hai miền (fold != k) + một lần rút mới từ tập replay OpTC.
  4. đánh giá MỘT lần: mẫu test của fold (hai miền) và OpTC TEST (tuỳ chọn); ngưỡng cố định: ngưỡng VAL OpTC của mô hình gốc và 0.5. Không chọn ngưỡng, epoch hay siêu tham số theo dữ liệu mới.
Đầu vào mô hình: 4 category (app_family, proto, resp_port_class, image_dir_class) + delta_t_log1p; numeric rỗng; x_bin = 0 (giống bản B)."""
import argparse
import importlib.util
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score, roc_auc_score

CAT_IDX = [0, 1, 4, 5]  # app_family, proto, resp_port_class, image_dir_class trong x_cat 7 cột của shards
CAT_NAMES = ["app_family", "proto", "resp_port_class", "image_dir_class"]
EMB_PREFIX = {"bilstm": "embeddings.", "mixed": "event_encoder.cat_embeddings."}


def load_module(path, name):
    sys.path.insert(0, str(Path(path).parent))  # 05b_train_bilstm.py import network_dl_dataset_v1_1 cùng thư mục
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- dữ liệu
def read_shard(path):
    with np.load(path, allow_pickle=False) as z:
        return {k: z[k] for k in ("x_cat", "delta_t_log1p", "sample_offsets")}


def sample_from(arrs, i, label, sid):
    off = arrs["sample_offsets"]
    a, b = int(off[i]), int(off[i + 1])
    return {"x_cat": arrs["x_cat"][a:b][:, CAT_IDX].astype(np.int64), "delta": arrs["delta_t_log1p"][a:b].astype(np.float32), "label": int(label), "sample_id": sid}


def materialize(rows):
    """rows: DataFrame có cột root, shard_file, shard_sample_index, label, sample_id -> list sample (giữ thứ tự rows)."""
    out = [None] * len(rows)
    rows = rows.reset_index(drop=True)
    for (root, shard), g in rows.groupby(["root", "shard_file"], sort=False):
        arrs = read_shard(Path(root) / shard)
        for pos, r in zip(g.index, g.itertuples()):
            out[pos] = sample_from(arrs, int(r.shard_sample_index), r.label, r.sample_id)
    return out


def collate(batch):
    lengths = torch.tensor([len(s["delta"]) for s in batch], dtype=torch.long)
    T, B = int(lengths.max()), len(batch)
    x_cat = torch.zeros(B, T, len(CAT_IDX), dtype=torch.long)
    delta = torch.zeros(B, T, 1)
    mask = torch.zeros(B, T, dtype=torch.bool)
    for i, s in enumerate(batch):
        t = len(s["delta"])
        x_cat[i, :t] = torch.from_numpy(s["x_cat"])
        delta[i, :t, 0] = torch.from_numpy(s["delta"])
        mask[i, :t] = True
    return {"x_cat": x_cat, "x_num": torch.zeros(B, T, 0), "x_num_missing": torch.zeros(B, T, 0), "x_bin": torch.zeros(B, T, 1), "delta_t_log1p": delta, "mask": mask,
            "lengths": lengths, "labels": torch.tensor([s["label"] for s in batch], dtype=torch.float32), "sample_ids": [s["sample_id"] for s in batch]}


def forward(model, kind, b, device):
    kw = {k: b[k].to(device) for k in ("x_cat", "x_num", "x_num_missing", "x_bin", "delta_t_log1p")}
    if kind == "bilstm":
        return model(lengths=b["lengths"], **kw)
    return model(attention_mask=b["mask"].to(device), **kw)


@torch.no_grad()
def predict(model, kind, samples, device, bs):
    model.eval()
    logit, labels, ids = [], [], []
    for i in range(0, len(samples), bs):
        b = collate(samples[i:i + bs])
        logit.append(forward(model, kind, b, device).float().cpu().numpy())
        labels.append(b["labels"].numpy())
        ids += b["sample_ids"]
    logit = np.concatenate(logit) if logit else np.zeros(0)
    prob = torch.sigmoid(torch.from_numpy(logit).half()).float().numpy()  # giống mô phỏng fp16 ở STEP 26
    return pd.DataFrame({"sample_id": ids, "label": (np.concatenate(labels) if labels else np.zeros(0)).astype(int), "logit": logit, "probability": prob})


def metrics_at(y, p, thr):
    pred = (p >= thr).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"threshold": float(thr), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4)}


def summarize(df, thresholds):
    y, p, lg = df.label.to_numpy(), df.probability.to_numpy(), df.logit.to_numpy()
    out = {"n": int(len(df)), "positives": int(y.sum()), "at": {name: metrics_at(y, p, t) for name, t in thresholds.items()}}
    if 0 < y.sum() < len(y):
        out["pr_auc"] = round(float(average_precision_score(y, lg)), 4)
        out["roc_auc"] = round(float(roc_auc_score(y, lg)), 4)
    return out


# ---------------------------------------------------------------- mô hình
def build_model(kind, cfg, cards, code_dir):
    if kind == "bilstm":
        m = load_module(Path(code_dir) / "05b_train_bilstm.py", "train_bilstm")
        base_dims = [m.embedding_dim(c) for c in cfg["categorical_cardinalities"]]  # giữ nguyên chiều embedding của mô hình gốc dù số hàng tăng (hàm gốc suy chiều từ số hàng)
        it = iter(base_dims)
        m.embedding_dim = lambda c: next(it)
        return m.BiLSTMBaseline(categorical_cardinalities=cards, numerical_dim=0, event_dim=cfg["event_dim"], hidden_dim=cfg["hidden_dim"], lstm_layers=cfg["lstm_layers"], dropout=cfg["dropout"])
    m = load_module(Path(code_dir) / "mixed_type_attention_model.py", "mixed_model")
    return m.MixedTypeSelfAttentionClassifier(m.MixedTypeModelConfig(categorical_cardinalities=cards, numerical_dim=0, binary_dim=1, max_events=cfg["max_events"], d_model=cfg["d_model"],
                                                                      num_heads=cfg["num_heads"], feature_layers=cfg["feature_layers"], temporal_layers=cfg["temporal_layers"], ff_dim=cfg["ff_dim"],
                                                                      dropout=cfg["dropout"]))


def transfer_weights(model, base_sd, old_cards, kind):
    """Copy tham số gốc; hàng embedding mới = bản sao hàng <UNK> (id 0). Trả về {tên tham số embedding: số hàng cũ}."""
    sd = model.state_dict()
    new_sd, old_rows = {}, {}
    for key, tensor in sd.items():
        if key not in base_sd:
            raise KeyError(f"tham số {key} không có trong mô hình gốc")
        base = base_sd[key]
        if key.startswith(EMB_PREFIX[kind]) and key.endswith(".weight"):
            idx = int(key[len(EMB_PREFIX[kind]):].split(".")[0])
            assert base.shape[1] == tensor.shape[1], f"chiều embedding đổi ở {key}: {tuple(base.shape)} -> {tuple(tensor.shape)}"
            assert base.shape[0] == old_cards[idx] and tensor.shape[0] >= base.shape[0]
            w = tensor.clone()
            w[:base.shape[0]] = base
            w[base.shape[0]:] = base[0:1]
            new_sd[key] = w
            old_rows[key] = base.shape[0]
        else:
            assert base.shape == tensor.shape, (key, base.shape, tensor.shape)
            new_sd[key] = base
    model.load_state_dict(new_sd)
    return old_rows


def set_stage(model, kind, stage, old_rows):
    """A: chỉ hàng embedding mới và đầu phân loại. B: tất cả. Trả về danh sách hook cần gỡ."""
    handles = []
    for name, p in model.named_parameters():
        if stage == "B":
            p.requires_grad = True
        elif name in old_rows:
            p.requires_grad = True
            mask = torch.zeros(p.shape[0], 1, device=p.device)
            mask[old_rows[name]:] = 1.0
            handles.append(p.register_hook(lambda g, m=mask: g * m))
        else:
            p.requires_grad = name.startswith("classifier.")
    return handles


def seed_everything(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ---------------------------------------------------------------- chạy một fold
def run_fold(args, k, ctx):
    dev = ctx["device"]
    kind = args.model
    ft = Path(args.ft_root)
    fold_dir = ft / f"fold{k}"
    spec = json.load(open(fold_dir / "spec_ext.json", encoding="utf-8"))
    cards = [max(e["id"] for e in spec["categorical"]["fields"][f]["vocab"]) + 1 for f in CAT_NAMES]
    cfg, old_cards = ctx["cfg"], ctx["cfg"]["categorical_cardinalities"]
    print(f"[fold {k}] cardinalities cũ {old_cards} -> mở rộng {cards}", flush=True)
    seed_everything(args.seed + k)
    model = build_model(kind, cfg, cards, args.code_dir)
    old_rows = transfer_weights(model, ctx["base_sd"], old_cards, kind)
    model.to(dev)
    # dữ liệu hai miền
    folds = pd.read_csv(ft / "folds.csv")
    rows = []
    for ds in ctx["domains"]:
        sm = pd.read_csv(fold_dir / ds / "data/samples.csv")[["sample_id", "shard_file", "shard_sample_index"]]
        m = sm.merge(folds[folds.dataset == ds][["sample_id", "fold", "label"]], on="sample_id")
        m["root"] = str(fold_dir / ds)
        m["dataset"] = ds
        rows.append(m)
    rows = pd.concat(rows, ignore_index=True)
    samples = materialize(rows)
    tr_idx = [i for i in range(len(rows)) if rows.fold.iat[i] != k]
    te_idx = [i for i in range(len(rows)) if rows.fold.iat[i] == k]
    train_new = [samples[i] for i in tr_idx]
    test_samples = [samples[i] for i in te_idx]
    print(f"[fold {k}] train {len(train_new)} mẫu (dương {sum(s['label'] for s in train_new)}), test {len(test_samples)} (dương {sum(s['label'] for s in test_samples)})", flush=True)
    thr = {"optc_val_threshold": ctx["thr"], "0.5": 0.5}
    # kiểm tra khớp zero-shot
    pre = predict(model, kind, test_samples, dev, args.eval_batch)
    pre["dataset"] = rows.dataset.iloc[te_idx].to_numpy()
    worst = 0.0
    for ds in ctx["domains"]:
        ref = pd.read_csv(ft / "ref_zeroshot" / f"predictions_{ds}_{kind}.csv")[["sample_id", "logit"]].rename(columns={"logit": "ref_logit"})
        m = pre[pre.dataset == ds].merge(ref, on="sample_id")
        assert len(m) == (pre.dataset == ds).sum(), f"thiếu mẫu tham chiếu {ds}"
        d = float((m.logit - m.ref_logit).abs().max())
        worst = max(worst, d)
        print(f"[fold {k}] khớp zero-shot {ds}: chênh logit lớn nhất {d:.5f} trên {len(m)} mẫu", flush=True)
    if worst > args.equiv_tol:
        raise RuntimeError(f"mô hình mở rộng chưa train KHÔNG khớp zero-shot (chênh {worst:.5f} > {args.equiv_tol}); dừng")
    result = {"fold": k, "cardinalities_old": old_cards, "cardinalities_ext": cards, "equivalence_max_logit_diff": worst,
              "zero_shot_on_test": summarize(pre, thr), "added_tokens": spec["extension"]["added"], "history": []}
    # replay
    rep = ctx["replay"]
    rep_pos = [s for s in rep if s["label"] == 1]
    rep_neg = [s for s in rep if s["label"] == 0]
    n_pos = sum(s["label"] for s in train_new) + args.replay_pos
    n_neg = len(train_new) - sum(s["label"] for s in train_new) + (args.replay_per_epoch - args.replay_pos)
    pos_weight = torch.tensor(n_neg / max(n_pos, 1), dtype=torch.float32, device=dev)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    amp = dev.type == "cuda" and not args.no_amp
    scaler = torch.amp.GradScaler("cuda", enabled=amp)
    rng = np.random.default_rng(args.seed * 1000 + k)
    ep_global = 0
    for stage, epochs, lr, wd in (("A", args.epochs_a, args.lr_a, 0.0), ("B", args.epochs_b, args.lr_b_bilstm if kind == "bilstm" else args.lr_b_mixed, args.weight_decay)):
        handles = set_stage(model, kind, stage, old_rows)
        params = [p for p in model.parameters() if p.requires_grad]
        opt = torch.optim.AdamW(params, lr=lr, weight_decay=wd)
        print(f"[fold {k}] giai đoạn {stage}: {epochs} epoch, lr {lr}, tham số học {sum(p.numel() for p in params):,}", flush=True)
        for ep in range(epochs):
            ep_global += 1
            draw = [rep_pos[i] for i in rng.permutation(len(rep_pos))[:args.replay_pos]] + [rep_neg[i] for i in rng.permutation(len(rep_neg))[:args.replay_per_epoch - args.replay_pos]]
            epoch_samples = train_new + draw
            order = rng.permutation(len(epoch_samples))
            model.train()
            tot, nb, t0 = 0.0, 0, time.time()
            for i in range(0, len(order), args.batch_size):
                b = collate([epoch_samples[j] for j in order[i:i + args.batch_size]])
                opt.zero_grad(set_to_none=True)
                with torch.autocast(device_type=dev.type, dtype=torch.float16, enabled=amp):
                    loss = crit(forward(model, kind, b, dev).float(), b["labels"].to(dev))
                scaler.scale(loss).backward()
                scaler.unscale_(opt)
                torch.nn.utils.clip_grad_norm_(params, args.grad_clip)
                scaler.step(opt)
                scaler.update()
                tot += float(loss.item())
                nb += 1
            result["history"].append({"stage": stage, "epoch": ep_global, "train_loss": round(tot / max(nb, 1), 5), "seconds": round(time.time() - t0, 1)})
            print(f"[fold {k}] {stage} epoch {ep_global}: loss {tot / max(nb, 1):.5f} ({time.time() - t0:.0f}s)", flush=True)
        for h in handles:
            h.remove()
    # đánh giá một lần
    post = predict(model, kind, test_samples, dev, args.eval_batch)
    post["dataset"] = rows.dataset.iloc[te_idx].to_numpy()
    post["fold"] = k
    result["after_on_test"] = summarize(post, thr)
    result["after_on_test_by_dataset"] = {ds: summarize(post[post.dataset == ds], thr) for ds in ctx["domains"]}
    result["before_on_test_by_dataset"] = {ds: summarize(pre[pre.dataset == ds], thr) for ds in ctx["domains"]}
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    post.to_csv(out / f"predictions_{kind}_fold{k}_newdomains.csv", index=False)
    torch.save({"model_state_dict": model.state_dict(), "cardinalities": cards, "fold": k}, out / f"model_{kind}_fold{k}.pt")
    if args.optc_eval != "none":
        result["optc_test"] = eval_optc(model, kind, args, ctx, thr, k)
    json.dump(result, open(out / f"result_{kind}_fold{k}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[fold {k}] xong; test sau fine-tune:", json.dumps(result["after_on_test"]["at"], ensure_ascii=False), flush=True)
    return result


def eval_optc(model, kind, args, ctx, thr, k):
    """OpTC TEST (đọc streaming theo shard); với mô hình mở rộng id cũ < 61 nên dùng nguyên shards OpTC."""
    t0 = time.time()
    man = ctx["optc_manifest"]
    te = man[man.split == "test"]
    if args.max_optc_test:
        te = pd.concat([te[te.label == 1], te[te.label == 0].head(args.max_optc_test)])
    root = Path(args.optc_root)
    frames = []
    for shard, g in te.groupby("shard_file", sort=False):
        arrs = read_shard(root / shard)
        samples = [sample_from(arrs, int(r.shard_sample_index), r.label, r.sample_id) for r in g.itertuples()]
        frames.append(predict(model, kind, samples, ctx["device"], args.eval_batch))
    df = pd.concat(frames, ignore_index=True)
    df.to_csv(Path(args.out_dir) / f"predictions_{kind}_fold{k}_optc_test.csv", index=False)
    res = summarize(df, thr)
    res["seconds"] = round(time.time() - t0)
    print(f"[fold {k}] OpTC TEST: {json.dumps(res['at'], ensure_ascii=False)} ({res['seconds']}s)", flush=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["bilstm", "mixed"], required=True)
    ap.add_argument("--ft-root", required=True, help="gói v3_ft_kaggle_upload (có ft_manifest.json)")
    ap.add_argument("--optc-root", required=True, help="gốc dataset OpTC v2 (split/, shards/)")
    ap.add_argument("--code-dir", required=True, help="thư mục chứa 05b_train_bilstm.py và mixed_type_attention_model.py")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--folds", default="0,1,2")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epochs-a", type=int, default=3)
    ap.add_argument("--epochs-b", type=int, default=3)
    ap.add_argument("--lr-a", type=float, default=1e-3)
    ap.add_argument("--lr-b-bilstm", type=float, default=1e-4)
    ap.add_argument("--lr-b-mixed", type=float, default=3e-5)
    ap.add_argument("--weight-decay", type=float, default=1e-4)
    ap.add_argument("--grad-clip", type=float, default=1.0)
    ap.add_argument("--replay-per-epoch", type=int, default=600)
    ap.add_argument("--replay-pos", type=int, default=150)
    ap.add_argument("--batch-size", type=int, default=0, help="0 = mặc định theo mô hình (BiLSTM 32, Mixed 16)")
    ap.add_argument("--eval-batch", type=int, default=0)
    ap.add_argument("--equiv-tol", type=float, default=0.02)
    ap.add_argument("--optc-eval", choices=["test", "none"], default="test")
    ap.add_argument("--max-optc-test", type=int, default=0, help="chỉ để chạy thử: giới hạn số mẫu âm OpTC TEST")
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
    print(f"[init] mô hình {args.model}, thiết bị {dev}, ngưỡng VAL OpTC {thr}, thư mục ra {args.out_dir}", flush=True)
    optc_manifest = pd.read_csv(Path(args.optc_root) / "split/network_sample_manifest.csv")
    # tập replay (đọc một lần)
    rr = pd.read_csv(ft / "replay_R.csv")
    rr["root"] = str(Path(args.optc_root))
    t0 = time.time()
    replay = materialize(rr)
    print(f"[init] replay R: {len(replay)} mẫu (dương {sum(s['label'] for s in replay)}) nạp trong {time.time() - t0:.0f}s", flush=True)
    ctx = {"device": dev, "cfg": cfg, "base_sd": ck["model_state_dict"], "thr": thr, "domains": man["domains"], "replay": replay, "optc_manifest": optc_manifest}
    results = []
    for k in [int(x) for x in args.folds.split(",")]:
        results.append(run_fold(args, k, ctx))
    json.dump({"model": args.model, "args": vars(args), "folds": [r["fold"] for r in results]}, open(Path(args.out_dir) / f"run_{args.model}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", flush=True)


if __name__ == "__main__":
    main()
