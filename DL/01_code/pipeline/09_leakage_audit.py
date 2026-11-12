"""
STEP 09 — Leakage / shortcut audit cho Network DL (host split, network-dl-v1.1-15m).

READ-ONLY: script không sửa bất kỳ artifact cũ nào. Nó chỉ đọc lại
manifest / shards / predictions / joined parquet và ghi bằng chứng
vào --out-dir (mặc định 02_artifacts/09_leakage_audit_v1).

Các nhóm kiểm tra (xem STEP_09_LEAKAGE_AUDIT.md):
  A. Split integrity: host overlap, duplicate sample key, phân bố positive theo host/ngày.
  B. Recompute metric từ *_predictions.csv + recall theo từng host.
  C. Rule baseline: "window có >= 1 event app_family == powershell.exe" (quét TOÀN BỘ shards).
  D. Metadata-only baseline: HistGradientBoosting trên 4 số nguyên
     (event_count, app_node_count, remote_node_count, chunk_index), threshold chọn trên VAL.
  E. Near-duplicate: TEST positive windows so với TRAIN positive windows.
  F. Joined parquet: label x app_family, C2 destination (resp_h:resp_p) của positive events theo split.

Chạy (Windows, môi trường local đã có pandas/numpy/scikit-learn/pyarrow):
  python 09_leakage_audit.py --project-root D:\\UIT\\KLTNv2
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

CAT = ["app_family", "proto", "service", "conn_state", "resp_port_class"]
NUM = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
SPLITS = ("train", "val", "test")


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


# --------------------------------------------------------------------------- A
def check_split(man: pd.DataFrame) -> dict:
    hosts = {s: set(man.loc[man.split == s, "hostname"]) for s in SPLITS}
    pos = man[man.label == 1]
    return {
        "host_overlap": {
            "train_test": len(hosts["train"] & hosts["test"]),
            "train_val": len(hosts["train"] & hosts["val"]),
            "val_test": len(hosts["val"] & hosts["test"]),
        },
        "duplicate_host_window_chunk": int(man.duplicated(["hostname", "window_start_epoch", "chunk_index"]).sum()),
        "per_split": {
            s: {
                "samples": int((man.split == s).sum()),
                "positive_samples": int(((man.split == s) & (man.label == 1)).sum()),
                "hosts": len(hosts[s]),
                "positive_hosts": int(pos.loc[pos.split == s, "hostname"].nunique()),
            }
            for s in SPLITS
        },
        "positive_samples_by_split_host": {
            s: pos.loc[pos.split == s].groupby("hostname").size().sort_values(ascending=False).to_dict()
            for s in SPLITS
        },
        "samples_by_date_split_label": pd.crosstab(man.date, [man.split, man.label]).to_dict(),
    }


# --------------------------------------------------------------------------- B
def check_models(project: Path, man: pd.DataFrame, model_dirs: list[str]) -> dict:
    out = {}
    for name in model_dirs:
        d = project / name
        if not (d / "threshold.json").exists():
            continue
        thr = json.loads((d / "threshold.json").read_text(encoding="utf-8"))["threshold"]
        res = {"threshold_from_val": thr}
        for sp in ("val", "test"):
            p = pd.read_csv(d / f"{sp}_predictions.csv", float_precision="round_trip")
            p = p.merge(man[["sample_id", "hostname"]], on="sample_id", how="left")
            yp = p.probability >= thr
            tp = int((yp & (p.label == 1)).sum()); fp = int((yp & (p.label == 0)).sum())
            fn = int((~yp & (p.label == 1)).sum())
            per_host = (
                p[p.label == 1]
                .assign(hit=yp[p.label == 1])
                .groupby("hostname")
                .agg(positives=("hit", "size"), detected=("hit", "sum"))
            )
            res[sp] = {"tp": tp, "fp": fp, "fn": fn, **prf(tp, fp, fn),
                       "per_host": per_host.astype(int).to_dict(orient="index")}
        out[name] = res
    return out


# --------------------------------------------------------------------------- C
def rule_powershell(ds_root: Path, man: pd.DataFrame, ps_id: int) -> dict:
    """Quét cột app_family của mọi shard; không cần load x_num."""
    flags = []
    for shard in sorted((ds_root / "shards").glob("*/*/*.npz")):
        rel = shard.relative_to(ds_root).as_posix()
        with np.load(shard, allow_pickle=False) as z:
            app = z["x_cat"][:, 0]
            off = z["sample_offsets"]
        hit = np.add.reduceat((app == ps_id).astype(np.int64), off[:-1]) if len(app) else np.array([])
        # reduceat trên sample rỗng không xảy ra vì event_count >= 1
        flags.append(pd.DataFrame({"shard_file": rel, "shard_sample_index": np.arange(len(off) - 1), "ps_events": hit}))
    f = pd.concat(flags, ignore_index=True)
    m = man.merge(f, on=["shard_file", "shard_sample_index"], how="left")
    if m.ps_events.isna().any():
        raise RuntimeError("Manifest có sample không tìm thấy trong shards")
    out = {"total_powershell_events": int(m.ps_events.sum()),
           "powershell_events_in_negative_samples": int(m.loc[m.label == 0, "ps_events"].sum())}
    for sp in SPLITS:
        s = m[m.split == sp]; yp = s.ps_events > 0
        tp = int((yp & (s.label == 1)).sum()); fp = int((yp & (s.label == 0)).sum()); fn = int((~yp & (s.label == 1)).sum())
        tn = int((~yp & (s.label == 0)).sum())
        out[sp] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, **prf(tp, fp, fn)}
    return out


# --------------------------------------------------------------------------- D
def metadata_baseline(man: pd.DataFrame) -> dict:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score

    feats = ["event_count", "app_node_count", "remote_node_count", "chunk_index"]
    tr, va, te = (man[man.split == s] for s in SPLITS)
    clf = HistGradientBoostingClassifier(max_iter=200, random_state=0, class_weight="balanced").fit(tr[feats], tr.label)
    pv = clf.predict_proba(va[feats])[:, 1]; pt = clf.predict_proba(te[feats])[:, 1]
    pr, rc, th = precision_recall_curve(va.label, pv)
    f1 = np.divide(2 * pr * rc, pr + rc, out=np.zeros_like(pr), where=(pr + rc) > 0)
    thr = float(th[int(np.nanargmax(f1[:-1]))])
    yp = pt >= thr
    tp = int((yp & (te.label == 1)).sum()); fp = int((yp & (te.label == 0)).sum()); fn = int((~yp & (te.label == 1)).sum())
    return {"features": feats, "threshold_from_val": thr, "test": {"tp": tp, "fp": fp, "fn": fn, **prf(tp, fp, fn),
            "pr_auc": round(float(average_precision_score(te.label, pt)), 4),
            "roc_auc": round(float(roc_auc_score(te.label, pt)), 4)}}


# --------------------------------------------------------------------------- E
def load_events(ds_root: Path, man: pd.DataFrame, shard_files: list[str]) -> pd.DataFrame:
    parts = []
    for rel in shard_files:
        with np.load(ds_root / rel, allow_pickle=False) as z:
            off = z["sample_offsets"]; n = len(off) - 1
            d = pd.DataFrame(z["x_cat"].astype(np.int64), columns=CAT)
            for i, c in enumerate(NUM):
                d[c] = z["x_num"][:, i]
            d["dt"] = z["delta_t_log1p"]
        d["shard_file"] = rel
        d["shard_sample_index"] = np.repeat(np.arange(n), np.diff(off))
        parts.append(d)
    ev = pd.concat(parts, ignore_index=True)
    return ev.merge(man[["shard_file", "shard_sample_index", "sample_id", "split", "hostname", "label"]],
                    on=["shard_file", "shard_sample_index"], how="left")


def near_duplicates(ds_root: Path, man: pd.DataFrame, ps_id: int, ff_id: int) -> dict:
    files = sorted(man.loc[man.label == 1, "shard_file"].unique())
    ev = load_events(ds_root, man, files)

    # Event signature: categorical + numeric (z) làm tròn 0.05
    q = np.round(ev[NUM].to_numpy() / 0.05).astype(np.int64)
    mat = np.concatenate([ev[CAT].to_numpy(np.int64), q], axis=1)
    h = np.zeros(len(ev), dtype=np.uint64)
    for k in range(mat.shape[1]):
        h = h * np.uint64(1000003) + (mat[:, k].astype(np.uint64) + np.uint64(7919))
    ev["sig"] = h
    trpos = set(ev.loc[(ev.split == "train") & (ev.label == 1), "sig"].tolist())
    trneg = set(ev.loc[(ev.split == "train") & (ev.label == 0), "sig"].tolist())
    ev_match = {}
    for sp in ("val", "test"):
        e = ev[(ev.split == sp) & (ev.label == 1)]
        ev_match[sp] = {"events_in_positive_windows": int(len(e)),
                        "share_signature_in_train_positive": round(float(e.sig.isin(trpos).mean()), 4),
                        "share_signature_in_train_negative": round(float(e.sig.isin(trneg).mean()), 4)}

    # Window-level aggregate + nearest neighbour
    ev["ps"] = (ev.app_family == ps_id).astype(float)
    ev["ff"] = (ev.app_family == ff_id).astype(float)
    for k, (col, v) in {"svc_ssl": ("service", 2), "svc_http": ("service", 3), "p443": ("resp_port_class", 2),
                        "p80": ("resp_port_class", 3), "p8080": ("resp_port_class", 4), "preg": ("resp_port_class", 5)}.items():
        ev[k] = (ev[col] == v).astype(float)
    cols = NUM + ["dt", "ps", "ff", "svc_ssl", "svc_http", "p443", "p80", "p8080", "preg"]
    g = ev.groupby("sample_id")
    S = g[cols].mean()
    S["dt_std"] = g["dt"].std(ddof=0)
    S["logn"] = np.log1p(g.size())
    S = S.join(g[["split", "label", "hostname"]].first())
    feat = cols + ["dt_std", "logn"]
    X = S[feat].to_numpy(float)
    Xz = (X - X.mean(0)) / (X.std(0) + 1e-9)
    idx = lambda sp, lab: np.where((S.split == sp) & (S.label == lab))[0]
    trp, trn, tep = idx("train", 1), idx("train", 0), idx("test", 1)
    rows = []
    for i in tep:
        dp = np.sqrt(((Xz[trp] - Xz[i]) ** 2).sum(1)); dn = np.sqrt(((Xz[trn] - Xz[i]) ** 2).sum(1))
        rows.append((S.hostname.iloc[i], float(dp.min()), S.hostname.iloc[trp[dp.argmin()]], float(dn.min())))
    r = pd.DataFrame(rows, columns=["host", "d_train_pos", "nn_train_host", "d_train_neg"])
    rng = np.random.default_rng(0)
    a, b = rng.choice(trn, 2000), rng.choice(trn, 2000)
    ref = float(np.median(np.sqrt(((Xz[a] - Xz[b]) ** 2).sum(1))))

    P = S[S.label == 1]
    Zp = ((P[feat] - S[feat].mean()) / (S[feat].std() + 1e-9)).round(0).astype(int).astype(str)
    tmpl = Zp.agg("|".join, axis=1)
    train_t = set(tmpl[P.split == "train"])
    return {
        "event_signature_match": ev_match,
        "window_nn_by_test_host": r.groupby("host").agg(
            windows=("d_train_pos", "size"),
            median_dist_nearest_train_pos=("d_train_pos", "median"),
            median_dist_nearest_train_neg=("d_train_neg", "median"),
            nearest_train_pos_host=("nn_train_host", lambda x: x.value_counts().index[0]),
        ).round(4).to_dict(orient="index"),
        "reference_median_dist_two_random_train_negatives": round(ref, 4),
        "share_test_pos_nearer_to_train_pos_than_train_neg": round(float((r.d_train_pos < r.d_train_neg).mean()), 4),
        "templates": {
            "positive_windows_total": int(len(P)),
            "largest_template_size": int(tmpl.value_counts().iloc[0]),
            **{f"{sp}_windows_with_template_seen_in_train": int(tmpl[P.split == sp].isin(train_t).sum()) for sp in ("val", "test")},
            **{f"{sp}_positive_windows": int((P.split == sp).sum()) for sp in ("val", "test")},
        },
    }


# --------------------------------------------------------------------------- F
def joined_checks(joined_root: Path) -> dict:
    import pyarrow.dataset as pds

    dset = pds.dataset(str(joined_root), format="parquet", partitioning="hive")
    cols = ["split", "hostname", "label", "app_family", "resp_h", "resp_p"]
    flt = (pds.field("label") == 1) | (pds.field("app_family") == "powershell.exe")
    df = dset.to_table(columns=cols, filter=flt).to_pandas()
    return joined_summary(df)


def joined_summary(df: pd.DataFrame) -> dict:
    df = df[df.split.astype(str).isin(SPLITS)].copy()
    df["split"] = df.split.astype(str)
    pos = df[df.label == 1]
    ps = df[df.app_family == "powershell.exe"]
    dst = pos.assign(dst=pos.resp_h.astype(str) + ":" + pos.resp_p.astype(str))
    tab = pd.crosstab(dst.dst, dst.split)
    train_dst = set(dst.loc[dst.split == "train", "dst"])
    return {
        "positive_events": int(len(pos)),
        "powershell_events": int(len(ps)),
        "powershell_events_label1": int((ps.label == 1).sum()),
        "positive_events_by_app_top": pos.app_family.value_counts().head(10).to_dict(),
        "positive_event_destinations_by_split": tab.to_dict(orient="index"),
        "share_test_positive_events_to_dst_seen_in_train_positive": round(
            float(dst.loc[dst.split == "test", "dst"].isin(train_dst).mean()), 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", default=r"D:\UIT\KLTNv2")
    ap.add_argument("--dataset-root", default=None, help="mặc định <root>/03_datasets/network_dl_v1_1_15m")
    ap.add_argument("--joined-root", default=None, help="mặc định <root>/02_artifacts/02_network_joined_v1/joined")
    ap.add_argument("--model-dirs", nargs="*", default=["05_models/06_bilstm_baseline_v1", "05_models/07_mixed_type_attention_v1"])
    ap.add_argument("--out-dir", default=None, help="mặc định <root>/02_artifacts/09_leakage_audit_v1")
    ap.add_argument("--skip-joined", action="store_true")
    args = ap.parse_args()

    root = Path(args.project_root)
    ds_root = Path(args.dataset_root) if args.dataset_root else root / "03_datasets" / "network_dl_v1_1_15m"
    joined = Path(args.joined_root) if args.joined_root else root / "02_artifacts" / "02_network_joined_v1" / "joined"
    out = Path(args.out_dir) if args.out_dir else root / "02_artifacts" / "09_leakage_audit_v1"
    out.mkdir(parents=True, exist_ok=True)

    maps = json.loads((ds_root / "preprocessing" / "network_category_maps.json").read_text(encoding="utf-8"))
    app_map = maps["fields"]["app_family"]["mapping"]
    ps_id, ff_id = int(app_map["powershell.exe"]), int(app_map["firefox.exe"])

    man = pd.read_csv(ds_root / "split" / "network_sample_manifest.csv")
    ev = {"script": "step09-leakage-audit-v1.0", "dataset_root": str(ds_root)}

    print("[A] split integrity"); ev["A_split"] = check_split(man)
    print("[B] model metrics recompute"); ev["B_models"] = check_models(root, man, args.model_dirs)
    print("[C] powershell rule (scan all shards)"); ev["C_rule_powershell"] = rule_powershell(ds_root, man, ps_id)
    print("[D] metadata-only baseline"); ev["D_metadata_baseline"] = metadata_baseline(man)
    print("[E] near-duplicate analysis"); ev["E_near_duplicates"] = near_duplicates(ds_root, man, ps_id, ff_id)
    if not args.skip_joined:
        print("[F] joined parquet checks"); ev["F_joined"] = joined_checks(joined)

    (out / "audit_evidence.json").write_text(json.dumps(ev, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(json.dumps({k: ev[k] for k in ("C_rule_powershell", "D_metadata_baseline")}, indent=2, default=str))
    print(f"[OUTPUT] {out / 'audit_evidence.json'}")


if __name__ == "__main__":
    main()
