#!/usr/bin/env python3
"""STEP 17d - fusion với điểm host THẬT (LightGBM/XGBoost huấn luyện lại theo split host-disjoint) + điểm network (Mixed-Type bỏ app_family, seed_1).

Quy tắc: cách gộp event -> cửa sổ (max / p99 / tỉ lệ event vượt ngưỡng) chọn trên VAL theo F1 của host-only; ngưỡng/trọng số chọn trên VAL;
TEST chạy đúng một lần. Đánh giá trên các cửa sổ của eval_windows_seed1.csv (cả hai nhánh cùng tập cửa sổ).
Hai loại nhãn: y_net (nhãn mạng của pipeline) và y_host (có event độc hại theo A New Hope).
"""
import importlib.util
import json
import sys

import numpy as np
import pandas as pd

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/17_host_retrain_v1"
spec = importlib.util.spec_from_file_location("f12c", R + "/01_code/pipeline/12c_fusion_baseline.py")
f12 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f12)


def agg_score(df, how):
    if how == "max":
        return df["max_prob"].to_numpy()
    if how == "p99":
        return df["p99_prob"].to_numpy()
    if how == "frac":
        return (df["n_above_thr"] / df["n_events_scored"].clip(lower=1)).to_numpy()
    raise ValueError(how)


def main():
    hs = pd.read_csv(OUT + "/window_scores_host.csv")
    fu = pd.read_csv(R + "/02_artifacts/14_readable_pipeline_v1/S9_fusion_inputs/window_fusion_table_seed1.csv")
    fu = fu.rename(columns={"window_start_epoch_utc": "window_start_epoch_utc"})
    base = fu[["hostname", "window_start_epoch_utc", "split", "p_net", "has_net", "y_net", "y_host"]]
    results = {}
    for model in sorted(hs["model"].unique()):
        h = hs[hs["model"] == model]
        x = base.merge(h[["hostname", "window_start_epoch_utc", "max_prob", "p99_prob", "mean_prob", "n_above_thr", "n_events_scored", "n_label1"]],
                       on=["hostname", "window_start_epoch_utc"], how="inner")
        x["p_net_f"] = x["p_net"].fillna(0.0)
        v, t = x[x["split"] == "val"], x[x["split"] == "test"]
        res = {"n_windows": {"val": int(len(v)), "test": int(len(t))}}
        for tgt in ("y_net", "y_host"):
            yv, yt = v[tgt].to_numpy(), t[tgt].to_numpy()
            best = None
            for how in ("max", "p99", "frac"):
                sv = agg_score(v, how)
                thr, f = f12.best_thr(yv, sv)
                if best is None or f > best[2]:
                    best = (how, thr, f)
            how = best[0]
            sv, st = agg_score(v, how), agg_score(t, how)
            r = {"val_pos": int(yv.sum()), "test_pos": int(yt.sum()), "host_aggregator": how}
            thn, _ = f12.best_thr(yv, v["p_net_f"].to_numpy())
            r["net_only"] = {"thr": thn, **f12.prf(yt, (t["p_net_f"].to_numpy() >= thn).astype(int))}
            thh, _ = f12.best_thr(yv, sv)
            r["host_only"] = {"thr": thh, **f12.prf(yt, (st >= thh).astype(int))}
            r["OR"] = {"thr_net": thn, "thr_host": thh, **f12.prf(yt, ((t["p_net_f"].to_numpy() >= thn) | (st >= thh)).astype(int))}
            bw, bf, bt = 0.5, -1, 0
            for w_ in np.linspace(0, 1, 11):
                s = w_ * v["p_net_f"].to_numpy() + (1 - w_) * sv
                tt, f = f12.best_thr(yv, s)
                if f > bf + 1e-12:
                    bw, bf, bt = w_, f, tt
            s_t = bw * t["p_net_f"].to_numpy() + (1 - bw) * st
            r["average"] = {"w_net": float(bw), "thr": bt, **f12.prf(yt, (s_t >= bt).astype(int))}
            Xv = np.c_[f12.logit(v["p_net_f"].to_numpy()), f12.logit(sv), 1 - v["has_net"].to_numpy()]
            Xt = np.c_[f12.logit(t["p_net_f"].to_numpy()), f12.logit(st), 1 - t["has_net"].to_numpy()]
            mu, sd = Xv.mean(0), Xv.std(0) + 1e-9
            w = f12.fit_lr((Xv - mu) / sd, yv)
            pv, pt = f12.pred_lr((Xv - mu) / sd, w), f12.pred_lr((Xt - mu) / sd, w)
            thr, _ = f12.best_thr(yv, pv)
            r["stacking"] = {"thr": thr, "coef": [round(float(c), 3) for c in w], **f12.prf(yt, (pt >= thr).astype(int))}
            res[tgt] = r
        results[model] = res
        x.to_csv(f"{OUT}/fusion_table_{model}.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    json.dump(results, open(OUT + "/fusion_results_host_model.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    for m, res in results.items():
        for tgt in ("y_net", "y_host"):
            r = res[tgt]
            print(f"\n== host model {m} | nhãn {tgt} | val_pos {r['val_pos']} test_pos {r['test_pos']} | gộp event->cửa sổ: {r['host_aggregator']}")
            for k in ("net_only", "host_only", "OR", "average", "stacking"):
                v = r[k]
                print(f"  {k:9s} tp={v['tp']:3d} fp={v['fp']:4d} fn={v['fn']:3d} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f}")


if __name__ == "__main__":
    main()
