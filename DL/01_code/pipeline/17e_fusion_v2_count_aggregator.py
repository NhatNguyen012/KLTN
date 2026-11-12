#!/usr/bin/env python3
"""STEP 17e - fusion v2: thêm cách gộp event -> cửa sổ "count" (số event vượt ngưỡng) vào danh sách chọn trên VAL.

v1 = {max, p99, frac} (đúng như 17d). v2 = {max, p99, frac, count}. Cùng dữ liệu, cùng quy trình chọn trên VAL
(F1 của host-only theo từng nhãn), cùng ngưỡng/trọng số chọn trên VAL.
LƯU Ý: TEST đã được mở một lần ở 17d; chạy này là lần mở THỨ HAI (thăm dò, không phải kết quả chốt).
Không đọc dữ liệu thô; chỉ dùng window_scores_host.csv và bảng fusion S9. Không sửa artifact cũ.
"""
import importlib.util
import json

import numpy as np
import pandas as pd

R = "D:/UIT/KLTNv2"
SRC = R + "/02_artifacts/17_host_retrain_v1"
OUT = R + "/02_artifacts/17e_fusion_v2_count_v1"
spec = importlib.util.spec_from_file_location("f12c", R + "/01_code/pipeline/12c_fusion_baseline.py")
f12 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f12)

V1 = ("max", "p99", "frac")
V2 = ("max", "p99", "frac", "count")


def raw_score(df, how):
    if how == "max":
        return df["max_prob"].to_numpy()
    if how == "p99":
        return df["p99_prob"].to_numpy()
    if how == "frac":
        return (df["n_above_thr"] / df["n_events_scored"].clip(lower=1)).to_numpy()
    if how == "count":
        return df["n_above_thr"].to_numpy(dtype=float)
    raise ValueError(how)


def unit_scale(how, sv, s):
    """Đưa điểm về [0,1] cho average/stacking; chỉ dùng thống kê của VAL (count -> log1p / log1p(max VAL))."""
    if how == "count":
        return np.clip(np.log1p(s) / max(np.log1p(sv.max()), 1e-9), 0, 1)
    return s


def run_variant(x, hows):
    v, t = x[x["split"] == "val"], x[x["split"] == "test"]
    res = {"n_windows": {"val": int(len(v)), "test": int(len(t))}}
    for tgt in ("y_net", "y_host"):
        yv, yt = v[tgt].to_numpy(), t[tgt].to_numpy()
        per = {}
        for how in hows:
            thr, f = f12.best_thr(yv, raw_score(v, how))
            per[how] = {"val_thr": thr, "val_f1": round(f, 4)}
        how = max(hows, key=lambda h: (per[h]["val_f1"], -hows.index(h)))  # hoà -> giữ thứ tự khai báo
        sv_raw, st_raw = raw_score(v, how), raw_score(t, how)
        r = {"val_pos": int(yv.sum()), "test_pos": int(yt.sum()), "host_aggregator": how, "val_f1_by_aggregator": per}
        pv, pt = v["p_net_f"].to_numpy(), t["p_net_f"].to_numpy()
        thn, _ = f12.best_thr(yv, pv)
        r["net_only"] = {"thr": thn, **f12.prf(yt, (pt >= thn).astype(int))}
        thh, _ = f12.best_thr(yv, sv_raw)
        hv = (st_raw >= thh).astype(int)
        r["host_only"] = {"thr": thh, **f12.prf(yt, hv)}
        r["OR"] = {"thr_net": thn, "thr_host": thh, **f12.prf(yt, ((pt >= thn) | (st_raw >= thh)).astype(int))}
        sv, st = unit_scale(how, sv_raw, sv_raw), unit_scale(how, sv_raw, st_raw)
        bw, bf, bt = 0.5, -1, 0
        for w_ in np.linspace(0, 1, 11):
            tt, f = f12.best_thr(yv, w_ * pv + (1 - w_) * sv)
            if f > bf + 1e-12:
                bw, bf, bt = w_, f, tt
        r["average"] = {"w_net": float(bw), "thr": bt, **f12.prf(yt, ((bw * pt + (1 - bw) * st) >= bt).astype(int))}
        if how == "count":
            hfv, hft = np.log1p(sv_raw), np.log1p(st_raw)
        else:
            hfv, hft = f12.logit(sv), f12.logit(st)
        Xv = np.c_[f12.logit(pv), hfv, 1 - v["has_net"].to_numpy()]
        Xt = np.c_[f12.logit(pt), hft, 1 - t["has_net"].to_numpy()]
        mu, sd = Xv.mean(0), Xv.std(0) + 1e-9
        w = f12.fit_lr((Xv - mu) / sd, yv)
        qv, qt = f12.pred_lr((Xv - mu) / sd, w), f12.pred_lr((Xt - mu) / sd, w)
        thr, _ = f12.best_thr(yv, qv)
        r["stacking"] = {"thr": thr, "coef": [round(float(c), 3) for c in w], **f12.prf(yt, (qt >= thr).astype(int))}
        res[tgt] = r
    return res


def sc3_detail(x, res_v2, model):
    """Bảng cửa sổ của sysclient0051 (TEST): điểm theo từng cách gộp + dự đoán host-only của v1 và v2 (nhãn y_net)."""
    t = x[(x["split"] == "test") & (x["hostname"] == "sysclient0051")].copy()
    r1, r2 = res_v2["v1"]["y_net"], res_v2["v2"]["y_net"]
    t["frac"] = raw_score(t, "frac")
    t["count"] = raw_score(t, "count")
    t["pred_v1"] = (raw_score(t, r1["host_aggregator"]) >= r1["host_only"]["thr"]).astype(int)
    t["pred_v2"] = (raw_score(t, r2["host_aggregator"]) >= r2["host_only"]["thr"]).astype(int)
    t["window_start_edt"] = (pd.to_datetime(t["window_start_epoch_utc"], unit="s") - pd.Timedelta(hours=4)).dt.strftime("%Y-%m-%d %H:%M")
    t["model"] = model
    cols = ["model", "hostname", "window_start_edt", "window_start_epoch_utc", "y_net", "y_host", "n_events_scored", "max_prob", "p99_prob",
            "n_above_thr", "frac", "n_label1", "p_net", "pred_v1", "pred_v2"]
    return t[cols].sort_values("window_start_epoch_utc")


def main():
    import os
    os.makedirs(OUT, exist_ok=True)
    hs = pd.read_csv(SRC + "/window_scores_host.csv")
    fu = pd.read_csv(R + "/02_artifacts/14_readable_pipeline_v1/S9_fusion_inputs/window_fusion_table_seed1.csv")
    base = fu[["hostname", "window_start_epoch_utc", "split", "p_net", "has_net", "y_net", "y_host"]]
    allres, sc3, dist, oracle = {}, [], [], []
    for model in sorted(hs["model"].unique()):
        h = hs[hs["model"] == model]
        x = base.merge(h[["hostname", "window_start_epoch_utc", "max_prob", "p99_prob", "mean_prob", "n_above_thr", "n_events_scored", "n_label1"]],
                       on=["hostname", "window_start_epoch_utc"], how="inner")
        x["p_net_f"] = x["p_net"].fillna(0.0)
        res = {"v1": run_variant(x, V1), "v2": run_variant(x, V2)}
        allres[model] = res
        # CHẨN ĐOÁN "oracle": quét ngưỡng count trực tiếp trên TEST (KHÔNG dùng để chọn ngưỡng, chỉ để biết count có tách được không)
        te, va = x[x["split"] == "test"], x[x["split"] == "val"]
        for tgt in ("y_net", "y_host"):
            for thr in (1, 10, 50, 100, 150, 200, 250, 300, 400, 500):
                sc3_t = te[te["hostname"] == "sysclient0051"]
                sc3_hit = int(((sc3_t["n_above_thr"] >= thr) & (sc3_t[tgt] == 1)).sum())
                oracle.append({"model": model, "target": tgt, "count_thr": thr, "sc3_0051_pos": int(sc3_t[tgt].sum()), "sc3_0051_tp": sc3_hit,
                               "test": f12.prf(te[tgt].to_numpy(), (te["n_above_thr"].to_numpy() >= thr).astype(int)),
                               "val": f12.prf(va[tgt].to_numpy(), (va["n_above_thr"].to_numpy() >= thr).astype(int))})
        sc3.append(sc3_detail(x, res, model))
        # phân bố count theo nhóm (VAL/TEST x y_host) để thấy count có tách được không
        x["count"] = raw_score(x, "count")
        for (sp, yh), g in x.groupby(["split", "y_host"]):
            q = g["count"].quantile([0.5, 0.9, 0.99]).to_list()
            dist.append({"model": model, "split": sp, "y_host": int(yh), "n": len(g), "count_p50": q[0], "count_p90": q[1], "count_p99": q[2], "count_max": g["count"].max()})
    json.dump(allres, open(OUT + "/fusion_results_v1_vs_v2.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    pd.concat(sc3).to_csv(OUT + "/sc3_sysclient0051_windows.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    pd.DataFrame(dist).to_csv(OUT + "/count_distribution.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    rows = []
    for m, res in allres.items():
        for ver in ("v1", "v2"):
            for tgt in ("y_net", "y_host"):
                r = res[ver][tgt]
                print(f"\n== {m} | {ver} | {tgt} | val_pos {r['val_pos']} test_pos {r['test_pos']} | gộp: {r['host_aggregator']} | VAL F1 theo cách gộp: "
                      + ", ".join(f"{k}={v['val_f1']}" for k, v in r["val_f1_by_aggregator"].items()))
                for k in ("net_only", "host_only", "OR", "average", "stacking"):
                    v = r[k]
                    print(f"  {k:9s} tp={v['tp']:3d} fp={v['fp']:3d} fn={v['fn']:3d} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f}")
                    rows.append({"model": m, "version": ver, "target": tgt, "aggregator": r["host_aggregator"], "method": k,
                                 **{c: v[c] for c in ("tp", "fp", "fn", "precision", "recall", "f1")}})
    pd.DataFrame(rows).to_csv(OUT + "/fusion_v1_vs_v2_table.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print("\n== SC3 sysclient0051 (TEST), nhãn y_net, host-only")
    print(pd.concat(sc3).drop(columns=["window_start_epoch_utc", "hostname"]).to_string(index=False))
    print("\n== phân bố count")
    print(pd.DataFrame(dist).to_string(index=False))
    od = pd.DataFrame([{"model": o["model"], "target": o["target"], "count_thr": o["count_thr"], "sc3_0051_pos": o["sc3_0051_pos"],
                        "sc3_0051_tp": o["sc3_0051_tp"], **{f"test_{k}": o["test"][k] for k in ("tp", "fp", "fn", "f1")},
                        **{f"val_{k}": o["val"][k] for k in ("tp", "fp", "fn", "f1")}} for o in oracle])
    od.to_csv(OUT + "/count_threshold_sweep_DIAGNOSTIC.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    print("\n== quét ngưỡng count (CHẨN ĐOÁN, không dùng chọn ngưỡng)")
    print(od.to_string(index=False))


if __name__ == "__main__":
    main()
