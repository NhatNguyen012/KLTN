#!/usr/bin/env python3
"""S15 - Chẩn đoán CHỈ TRÊN TRAIN (STEP 34): cho mô hình B học lâu hơn / lr cao hơn trên TRAIN của một fold, xem có fit được các mẫu dương TRAIN không.

Phân biệt (a) "đầu vào không đủ tách" với (b) "huấn luyện quá ngắn / lr quá nhỏ" của STEP 33. Không đọc mẫu test của fold, không đánh giá OpTC TEST, không chọn gì theo dữ liệu đó.
Mô hình khởi tạo giống s14_ft_train (mô hình gốc + từ điển mở rộng của fold, hàng mới = bản sao <UNK>), mở khóa toàn bộ tham số ngay từ đầu.
Input : 03_datasets/v3_ft_kaggle_upload (folds, fold<k>, base_models, replay_R.csv), 03_datasets/v2_network_dl_kaggle_upload (shards OpTC cho replay, nếu --replay), mã mô hình trích từ notebook subsetB
Output: --out-dir/diag_<model>_fold<k>_<tag>.json (đường cong theo epoch) và .csv (xác suất cuối từng mẫu TRAIN)
Cách dùng: python s15_train_diag.py --model bilstm --fold 0 --epochs 60 --lr 1e-3 --replay 0 --tag e60"""
import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score, roc_auc_score

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
import s14_ft_train as T  # noqa: E402

ROOT = Path("D:/UIT/KLTNv2")
FT = ROOT / "03_datasets/v3_ft_kaggle_upload"


def fit_stats(pr, thr):
    y, p, lg = pr.label.to_numpy(), pr.probability.to_numpy(), pr.logit.to_numpy()
    out = {}
    for name, t in (("0.5", 0.5), ("optc_val", thr)):
        pred = p >= t
        out[name] = {"tp": int((pred & (y == 1)).sum()), "fp": int((pred & (y == 0)).sum())}
    out["roc_auc"] = round(float(roc_auc_score(y, lg)), 4)
    out["pr_auc"] = round(float(average_precision_score(y, lg)), 4)
    out["median_prob_pos"] = round(float(np.median(p[y == 1])), 4)
    out["median_prob_neg"] = round(float(np.median(p[y == 0])), 5)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["bilstm", "mixed"], required=True)
    ap.add_argument("--fold", type=int, default=0)
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--lr", type=float, required=True)
    ap.add_argument("--weight-decay", type=float, default=1e-4)
    ap.add_argument("--replay", type=int, default=0, help="số mẫu replay OpTC mỗi epoch (0 = không dùng); nếu >0, một phần tư là dương")
    ap.add_argument("--eval-every", type=int, default=5)
    ap.add_argument("--batch-size", type=int, default=0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-epoch-seconds", type=float, default=0, help="dừng nếu một epoch quá lâu (chỉ để chạy thử)")
    ap.add_argument("--tag", default="diag")
    ap.add_argument("--out-dir", default=str(ROOT / "02_artifacts/34_train_diag_v1/runs"))
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--ft-root", default=str(FT))
    ap.add_argument("--optc-root", default=str(ROOT / "03_datasets/v2_network_dl_kaggle_upload"), help="gốc dataset OpTC v2 (chỉ cần khi --replay > 0)")
    ap.add_argument("--code-dir", default="", help="thư mục chứa 05b_train_bilstm.py / mixed_type_attention_model.py (Kaggle); để trống = trích từ notebook subsetB (local)")
    ap.add_argument("--cpu", action="store_true")
    args = ap.parse_args()
    if args.threads:
        torch.set_num_threads(args.threads)
    kind, k = args.model, args.fold
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    bs = args.batch_size or (32 if kind == "bilstm" else 16)
    dev = torch.device("cpu" if args.cpu or not torch.cuda.is_available() else "cuda")
    FTR = Path(args.ft_root)
    if args.code_dir:
        code = Path(args.code_dir)
    else:  # mã mô hình trích từ notebook B, như s14_collect
        from s8_notebooks_subset import extract_files
        code = Path(tempfile.mkdtemp(prefix="s15_code_"))
        nbname = "06e_BiLSTM_Kaggle_v2_subsetB.ipynb" if kind == "bilstm" else "07e_Mixed_Type_Kaggle_v2_subsetB.ipynb"
        d, _ = extract_files(json.load(open(ROOT / "04_notebooks" / nbname, encoding="utf-8")), "c")
        for p in d.iterdir():
            (code / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    base = FTR / "base_models" / kind
    cfg = json.load(open(base / "config.json", encoding="utf-8"))
    thr = float(json.load(open(base / "threshold.json", encoding="utf-8"))["threshold"])
    ck = torch.load(base / "best_model.pt", map_location="cpu", weights_only=False)
    spec = json.load(open(FTR / f"fold{k}/spec_ext.json", encoding="utf-8"))
    cards = [max(e["id"] for e in spec["categorical"]["fields"][f]["vocab"]) + 1 for f in T.CAT_NAMES]
    T.seed_everything(args.seed + k)
    model = T.build_model(kind, cfg, cards, code)
    T.transfer_weights(model, ck["model_state_dict"], cfg["categorical_cardinalities"], kind)
    # TRAIN của fold (fold != k); KHÔNG nạp mẫu test của fold
    folds = pd.read_csv(FTR / "folds.csv")
    rows = []
    for ds in ("skrghosh", "fivedirections"):
        sm = pd.read_csv(FTR / f"fold{k}/{ds}/data/samples.csv")[["sample_id", "shard_file", "shard_sample_index"]]
        m = sm.merge(folds[folds.dataset == ds][["sample_id", "fold", "label"]], on="sample_id")
        m["root"] = str(FTR / f"fold{k}/{ds}")
        m["dataset"] = ds
        rows.append(m)
    rows = pd.concat(rows, ignore_index=True)
    rows = rows[rows.fold != k].reset_index(drop=True)
    train = T.materialize(rows)
    n_pos = sum(s["label"] for s in train)
    print(f"[diag] {kind} fold {k}: TRAIN {len(train)} mẫu (dương {n_pos}), lr {args.lr}, epoch {args.epochs}, replay {args.replay}, batch {bs}, threads {torch.get_num_threads()}", flush=True)
    rep_pos = rep_neg = []
    if args.replay:
        rr = pd.read_csv(FTR / "replay_R.csv")
        rr["root"] = args.optc_root
        rep = T.materialize(rr)
        rep_pos = [s for s in rep if s["label"] == 1]
        rep_neg = [s for s in rep if s["label"] == 0]
    rp = args.replay // 4
    npos = n_pos + (rp if args.replay else 0)
    nneg = len(train) - n_pos + ((args.replay - rp) if args.replay else 0)
    model.to(dev)
    crit = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(nneg / max(npos, 1), dtype=torch.float32, device=dev))
    for p in model.parameters():
        p.requires_grad = True
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    rng = np.random.default_rng(args.seed * 1000 + k)
    curve = []
    t_all = time.time()
    for ep in range(1, args.epochs + 1):
        draw = []
        if args.replay:
            draw = [rep_pos[i] for i in rng.permutation(len(rep_pos))[:rp]] + [rep_neg[i] for i in rng.permutation(len(rep_neg))[:args.replay - rp]]
        es = train + draw
        order = rng.permutation(len(es))
        model.train()
        tot, nb, t0 = 0.0, 0, time.time()
        for i in range(0, len(order), bs):
            b = T.collate([es[j] for j in order[i:i + bs]])
            opt.zero_grad(set_to_none=True)
            loss = crit(T.forward(model, kind, b, dev).float(), b["labels"].to(dev))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            tot += float(loss.item())
            nb += 1
        rec = {"epoch": ep, "train_loss": round(tot / nb, 5), "seconds": round(time.time() - t0, 1)}
        if ep % args.eval_every == 0 or ep == 1 or ep == args.epochs:
            pr = T.predict(model, kind, train, dev, 64)
            rec["fit"] = fit_stats(pr, thr)
            print(f"[diag] ep {ep}: loss {rec['train_loss']:.4f} ({rec['seconds']}s) TP@0.5 {rec['fit']['0.5']['tp']}/{n_pos} FP@0.5 {rec['fit']['0.5']['fp']} ROC {rec['fit']['roc_auc']} PR {rec['fit']['pr_auc']}", flush=True)
        else:
            print(f"[diag] ep {ep}: loss {rec['train_loss']:.4f} ({rec['seconds']}s)", flush=True)
        curve.append(rec)
        if args.max_epoch_seconds and rec["seconds"] > args.max_epoch_seconds:
            print("[diag] dừng: epoch quá lâu", flush=True)
            break
    pr = T.predict(model, kind, train, dev, 64)
    pr["dataset"] = rows.dataset.to_numpy()
    pr.to_csv(out / f"diag_{kind}_fold{k}_{args.tag}.csv", index=False)
    res = {"model": kind, "fold": k, "args": vars(args), "train_samples": len(train), "train_positives": n_pos, "optc_threshold": thr, "total_seconds": round(time.time() - t_all), "curve": curve, "final_fit": fit_stats(pr, thr)}
    json.dump(res, open(out / f"diag_{kind}_fold{k}_{args.tag}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", json.dumps(res["final_fit"], ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
