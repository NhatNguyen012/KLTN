#!/usr/bin/env python3
"""Build the deployable bundles of the final IL models (OpTC -> ATLASv2 -> AInception SL700) with real parity evidence.

  host-ml  fused LightGBM (endpoint): z = 0.64 z_OpTC + 0.8 z_ATLASv2 + z_SL700 in one booster (lgbm_fuse.py), vocabulary
           token -> column of the main config (ecar_lx: SL700 address-scope columns dropped), per-domain thresholds.
  host-dl  IL BiLSTM (central): seed chosen on VALIDATION, vocabularies rebuilt exactly as the trainer built them,
           state dict, per-domain logit thresholds.
Parity is computed, never assumed:
  * fused booster == the training composition (SL700 TEST rows), max |dz|;
  * linux-audit host-ml: raw SL700 TEST-run audit.log lines -> serving featurizer (online grouping) vs the training
    matrix rows (test.npz) -> identical columns and scores;
  * windows-cbc host-ml: ATLASv2 CBC-EDR TEST file -> serving featurizer vs the ATLASv2 training tokenizer;
  * host-dl: SL700 TEST-run events -> serving window builder vs the training windows (events, encodings, logits) and
    the trainer's logged VAL logits.
Fixtures (raw inputs + expected outputs) go into each bundle so the runtimes can self-test before serving.
Bundles are written to a NEW directory under runtime/releases (never overwritten).

Usage: build_il_bundles.py --out-root runtime/releases [--only ml|dl] [--tag 20261114]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pickle
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
WS = Path("/mnt/SSD_Data/optc")
sys.path.insert(0, str(ROOT / "serving"))
sys.path.insert(0, str(ROOT / "scripts"))
from lgbm_fuse import fuse  # noqa: E402

IL1, IL2 = WS / "IL/dataset_1-ATLASv2", WS / "IL/dataset_2-AInception"
ML1 = IL1 / "code/ML"
OPTC_MODEL = ML1 / "pretrained_optc_model/model-slot-0.txt"
ATLAS_MODEL_DIR = ML1 / "output/v9b_20261112/run_v9b/atlasv2-incremental-2e4a6239dc94/lgbm-kaggle/incremental/model"
SL_RUN = IL2 / "output/ml_il_step3_20261113/runs/incA05_ecar_lx_s1"
SL_DATA = IL2 / "output/ml_il_step3_20261113/data"
ATLAS_VOCAB = ML1 / "preprocess/output/assets/vocab_extended.json"
DL_RUNS = IL2 / "output/il_step3v3_20261113/runs"
RAW_SL700 = WS / "DATASET/AInception/extracted"
W_OPTC, W_ATLAS, ALPHA = 10317, 12365, 0.8
TH_ATLAS = 0.94073


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def jdump(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n")


def artifacts(root: Path) -> dict:
    return {str(p.relative_to(root)): {"sha256": sha256(p), "bytes": p.stat().st_size}
            for p in sorted(root.rglob("*")) if p.is_file() and p.name != "manifest.json"}


def vendored_provenance() -> dict:
    return json.loads((ROOT / "serving/kltn_features/_vendor/PROVENANCE.json").read_text())


def runtime_code_hashes() -> dict:
    base = ROOT / "serving"
    return {str(p.relative_to(base)): sha256(p) for p in sorted((base / "kltn_features").rglob("*.py"))}


# ============================================================================================== host ML
def deploy_vocab():
    """Token -> model column: ATLASv2 prefix (12,365) + SL700 columns of groups ecar and lx in their original order
    (train_ml_il_step3.select_columns); lx_scope columns are not model inputs."""
    voc = json.loads((SL_DATA / "vocab_sl700.json").read_text())
    groups = {int(c): g for c, g in json.loads((SL_DATA / "columns.json").read_text()).items()}
    keep = list(range(W_ATLAS)) + sorted(c for c, g in groups.items() if g in ("ecar", "lx"))
    remap = {c: i for i, c in enumerate(keep)}
    vocab = {t: remap[c] for t, c in voc.items() if c in remap}
    return vocab, np.asarray(keep, np.int64)


def load_npz(path):
    from scipy import sparse
    z = np.load(path)
    return sparse.csr_matrix((z["data"], z["indices"], z["indptr"]), shape=tuple(z["shape"])), z["labels"]


def research_z(bo, ba, bs, X):
    return ALPHA * (ALPHA * bo.predict(X[:, :W_OPTC], raw_score=True) + ba.predict(X[:, :W_ATLAS], raw_score=True)) + \
        bs.predict(X, raw_score=True)


def lo_cut(run: str) -> int:
    """relabel_v2.run_sl700 keeps events from 3 h before the first AttackMate action."""
    am = next((RAW_SL700 / f"SL700_{run}/run_{run}").glob("*_labeled/*/gather/attacker/logs/attackmate.json"))
    from datetime import datetime as _dt
    starts = []
    for line in open(am):
        if line.strip():
            s = json.loads(line)["start-datetime"].replace("Z", "+00:00").replace(" ", "T")
            d = _dt.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            starts.append(int(d.timestamp() * 1_000_000))
    return min(starts) - 3 * 3600 * 1_000_000


def raw_audit_lines(run: str, host: str, lo: int):
    from kltn_features._vendor.ainception_adapters import _HDR
    path = next((RAW_SL700 / f"SL700_{run}/run_{run}").glob(f"attack_{run}/mnt/attack_{run}/gather/{host}/logs/log/audit/audit.log"))
    with open(path, errors="replace") as fh:
        for line in fh:
            m = _HDR.match(line.strip())
            if m and int(m.group(2)) * 1_000_000 + int(m.group(3).ljust(3, "0")[:3]) * 1000 >= lo:
                yield line


def linux_parity(vocab, keep, fused, bo, ba, bs):
    """Serving featurizer on raw TEST-run lines vs the training matrix rows of the same events."""
    import pandas as pd
    from kltn_features.host_ml import HostFeaturizer
    X, y = load_npz(SL_DATA / "test.npz")
    meta = pd.read_parquet(SL_DATA / "meta_test.parquet")
    Xk = X[:, keep].tocsr()
    run = meta.run.iloc[0]
    lo = lo_cut(run)
    out = {"run": run, "hosts": {}, "rows_training": int(len(meta))}
    fixture = None
    mism_total = matched_total = 0
    max_dz = 0.0
    for host, hm in meta.groupby("host"):
        fz = HostFeaturizer("linux-audit", vocab, host)
        rows = []
        for i, line in enumerate(raw_audit_lines(run, host, lo)):
            rows += fz.feed(line, ref=i)
        rows += fz.flush()
        by_key = {}
        for r in rows:
            by_key.setdefault((r.ts, r.event["line"], r.kind), r)
        idx = hm.index.to_numpy()
        cols_serv, missing, mism = [], 0, 0
        for i, (ts, line, kind) in zip(idx, zip(hm.ts, hm.line, hm.kind)):
            r = by_key.get((int(ts), int(line), kind))
            if r is None:
                missing += 1
                cols_serv.append(None)
                continue
            c = fz.columns(r)
            cols_serv.append(c)
            if c != sorted(Xk[i].indices.tolist()):
                mism += 1
        ok = [j for j, c in enumerate(cols_serv) if c is not None]
        from scipy import sparse
        Xs = sparse.csr_matrix((np.ones(sum(len(cols_serv[j]) for j in ok), np.float32),
                                np.concatenate([np.asarray(cols_serv[j], np.int64) for j in ok]) if ok else np.zeros(0, np.int64),
                                np.cumsum([0] + [len(cols_serv[j]) for j in ok])), shape=(len(ok), Xk.shape[1]))
        z_serv = fused.predict(Xs, raw_score=True)
        z_train = research_z(bo, ba, bs, Xk[idx[ok]])
        dz = float(np.abs(z_serv - z_train).max()) if ok else 0.0
        max_dz = max(max_dz, dz)
        mism_total += mism + missing
        matched_total += len(ok)
        out["hosts"][host] = {"training_rows": int(len(hm)), "serving_rows": len(rows), "matched": len(ok),
                              "missing_in_serving": missing, "column_mismatch": mism, "max_abs_dz": dz,
                              "attack_rows": int(hm.y.sum())}
        if fixture is None and hm.y.sum() > 0:
            # fixture: the raw lines around the first attack row (+ the 2 h before it for context) of this host
            t_att = int(hm[hm.y == 1].ts.min())
            lines = [ln for ln in raw_audit_lines(run, host, t_att - 600 * 1_000_000)
                     if _line_ts(ln) <= t_att + 300 * 1_000_000][-6000:]
            fixture = {"host": host, "lines": lines}
    out["rows_matched"] = matched_total
    out["rows_mismatched_or_missing"] = mism_total
    out["max_abs_dz"] = max_dz
    out["passed"] = mism_total == 0 and max_dz < 1e-6
    return out, fixture


def _line_ts(line: str) -> int:
    from kltn_features._vendor.ainception_adapters import _HDR
    m = _HDR.match(line.strip())
    return int(m.group(2)) * 1_000_000 + int(m.group(3).ljust(3, "0")[:3]) * 1000 if m else -1


def fixture_expectations(domain, vocab, fused, inputs, host):
    from kltn_features.host_ml import HostFeaturizer
    fz = HostFeaturizer(domain, vocab, host)
    rows = []
    for i, x in enumerate(inputs):
        rows += fz.feed(x, ref=i)
    rows += fz.flush()
    if not rows:
        return []
    X = fz.matrix(rows)
    z = fused.predict(X, raw_score=True)
    return [{"ts": r.ts, "kind": r.kind, "refs": r.refs, "columns": X[k].indices.tolist(), "raw_score": float(z[k])}
            for k, r in enumerate(rows)]


def windows_cbc_parity(vocab, fused, n_events=40000):
    """ATLASv2 CBC TEST scenario: serving featurizer (windows-cbc) vs the ATLASv2 training tokenizer."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("research_build_host_shards", ML1 / "preprocess/build_host_shards.py")
    B = importlib.util.module_from_spec(spec)          # research module; its own sys.path setup resolves ML.code.*
    spec.loader.exec_module(B)
    from preprocess.cbc_adapter import CBCAdapter
    from preprocess.label_refiner import LabelRefiner
    from preprocess.split_config import TEST_SCENARIOS
    from kltn_features.host_ml import HostFeaturizer
    reapr = WS / "DATASET/ATLASv2_staged/reapr-ground-truth/atlasv2"
    data = IL1 / "output/raw_cbc/atlasv2/data"
    files = sorted(p for p in data.rglob("*.jsonl") if "cbc-edr" in str(p) and "alerts" not in str(p)
                   and any(p.stem.endswith("-" + s) for s in TEST_SCENARIOS))
    f = files[0]
    sc = f.stem.split("-")[-1]
    adapter = CBCAdapter(LabelRefiner(reapr))
    events = sorted(adapter.stream_file(f, sc), key=lambda e: e.timestamp)[:n_events]
    atlas_vocab = json.loads(ATLAS_VOCAB.read_text())
    optc_set = {t for t, c in atlas_vocab.items() if c < W_OPTC}
    sess = B.FileSessionIndex()
    fz = HostFeaturizer("windows-cbc", vocab, "atlas")
    n_rows = tok_mismatch = ext_hits = 0
    research_cols, serving_rows = [], []
    for ev in events:
        sess.add_event(ev)
        r = fz.feed_canonical(ev)
        if ev.event_type == "FLOW_START":
            assert r is None
            continue
        rec = B.canonical_ecar_record(ev, sess)
        toks = B.flatten_tokens(B.tokenize_record(rec)[0]) + B.extract_domain_shift_tokens(ev, sess, optc_set)
        if r is None:
            tok_mismatch += 1
            continue
        n_rows += 1
        if toks != r.tokens:
            tok_mismatch += 1
        research_cols.append(sorted({atlas_vocab[t] for t in toks if t in atlas_vocab}))
        serving_rows.append(r)
    X = fz.matrix(serving_rows)
    ext = np.asarray([(X[k].indices >= W_ATLAS).any() for k in range(X.shape[0])])
    ext_hits = int(ext.sum())
    from scipy import sparse
    Xr = sparse.csr_matrix((np.ones(sum(map(len, research_cols)), np.float32),
                            np.concatenate([np.asarray(c, np.int64) for c in research_cols]),
                            np.cumsum([0] + [len(c) for c in research_cols])), shape=X.shape)
    z_s, z_r = fused.predict(X, raw_score=True), fused.predict(Xr, raw_score=True)
    same_cols = int(sum(1 for k in range(X.shape[0]) if X[k].indices.tolist() == Xr[k].indices.tolist()))
    p_s, p_r = 1 / (1 + np.exp(-z_s)), 1 / (1 + np.exp(-z_r))
    out = {"file": str(f.relative_to(IL1)), "events": len(events), "rows": n_rows, "token_mismatch": tok_mismatch,
           "rows_identical_columns": same_cols,
           "rows_activating_sl700_extension_columns": ext_hits,
           "max_abs_dz_vs_atlas_vocab_only": float(np.abs(z_s - z_r).max()) if n_rows else 0.0,
           "decision_flips_at_atlas_threshold": int(((p_s >= TH_ATLAS) != (p_r >= TH_ATLAS)).sum()),
           "note": "serving uses the full extended vocabulary; the ATLASv2 shards were built with the 12,365-token "
                   "vocabulary, so rows that hit SL700-extension columns differ by construction (reported, not hidden)"}
    out["passed"] = tok_mismatch == 0 and n_rows > 0
    sample = [ev for ev in events[:2500]]
    fixture = [{k: getattr(ev, k) for k in ev.__dataclass_fields__} for ev in sample]
    return out, fixture


def build_ml(out: Path, tag: str):
    import lightgbm as lgb
    t0 = time.time()
    latest = json.loads((ATLAS_MODEL_DIR / "latest.json").read_text())
    assert latest["complete"] and latest["identity"]["base_margin_alpha"] == ALPHA
    atlas_model = ATLAS_MODEL_DIR / latest["path"]
    sl_model = SL_RUN / "model.txt"
    res = json.loads((SL_RUN / "result.json").read_text())
    assert res["args"]["config"] == "ecar_lx" and res["args"]["mode"] == "inc"
    bo, ba, bs = (lgb.Booster(model_file=str(p)) for p in (OPTC_MODEL, atlas_model, sl_model))
    weights = {"optc": ALPHA * ALPHA, "atlasv2": ALPHA, "sl700": 1.0}
    text = fuse([(OPTC_MODEL.read_text(), weights["optc"]), (atlas_model.read_text(), weights["atlasv2"]),
                 (sl_model.read_text(), weights["sl700"])])
    (out / "model").mkdir(parents=True)
    lgb.Booster(model_str=text).save_model(str(out / "model/model.txt"))
    fused = lgb.Booster(model_file=str(out / "model/model.txt"))
    vocab, keep = deploy_vocab()
    assert len(vocab) == fused.num_feature() == bs.num_feature() == 21487
    jdump(out / "preprocess/vocab.json", vocab)
    # (1) fused == training composition on SL700 TEST rows
    X, y = load_npz(SL_DATA / "test.npz")
    Xk = X[:, keep].tocsr()
    z_f, z_r = fused.predict(Xk, raw_score=True), research_z(bo, ba, bs, Xk)
    th_lin = float(res["sl700"]["test"]["threshold"])
    p = 1 / (1 + np.exp(-z_f))
    conf = {"tp": int(((p >= th_lin) & (y == 1)).sum()), "fp": int(((p >= th_lin) & (y == 0)).sum()),
            "fn": int(((p < th_lin) & (y == 1)).sum())}
    fusion_check = {"rows": int(X.shape[0]), "max_abs_dz": float(np.abs(z_f - z_r).max()), "sl700_test_at_val_threshold": conf,
                    "reproduces_published_confusion": conf == {k: res["sl700"]["test"][k] for k in ("tp", "fp", "fn")}}
    print("fusion check", fusion_check, flush=True)
    # (2) linux-audit streaming parity on raw audit.log of the TEST run
    lin, lin_fix = linux_parity(vocab, keep, fused, bo, ba, bs)
    print("linux parity", {k: v for k, v in lin.items() if k != "hosts"}, flush=True)
    # (3) windows-cbc parity on an ATLASv2 TEST file
    win, win_fix = windows_cbc_parity(vocab, fused)
    print("windows-cbc parity", win, flush=True)
    # fixtures for runtime self-tests
    lin_exp = fixture_expectations("linux-audit", vocab, fused, lin_fix["lines"], lin_fix["host"])
    jdump(out / "evidence/fixture_linux_audit.json", {"domain": "linux-audit", "host": lin_fix["host"],
                                                      "inputs": lin_fix["lines"], "expected": lin_exp})
    from kltn_features._vendor.common_schema import CanonicalEvent
    from kltn_features.host_ml import HostFeaturizer
    fz = HostFeaturizer("windows-cbc", vocab, "atlas")
    rows = [r for r in (fz.feed_canonical(CanonicalEvent(**d)) for d in win_fix) if r is not None]
    Xw = fz.matrix(rows)
    zw = fused.predict(Xw, raw_score=True)
    jdump(out / "evidence/fixture_windows_cbc.json", {"domain": "windows-cbc", "inputs": win_fix,
          "expected": [{"ts": r.ts, "kind": r.kind, "columns": Xw[k].indices.tolist(), "raw_score": float(zw[k])}
                       for k, r in enumerate(rows)]})
    after = res["after_step3"]
    domains = {
        "linux-audit": {"validation": "validated", "threshold": th_lin,
                        "threshold_source": "SL700 VALIDATION run a_c (max F1), frozen before TEST",
                        "telemetry": "auditd with the bfuzzy/auditd-attack rule set (41d8a13) = SL700 collection",
                        "offline_test": {"sl700_event_f1": res["sl700"]["test"]["f1"], "precision": res["sl700"]["test"]["precision"],
                                         "recall": res["sl700"]["test"]["recall"],
                                         "sl700_window_f1": res["sl700"]["window_level_test"]["f1"]}},
        "windows-sysmon": {"validation": "shadow_unvalidated", "threshold": TH_ATLAS,
                           "threshold_source": "ATLASv2 VALIDATION (IL step 2, CBC-EDR telemetry)",
                           "telemetry": "Sysmon mapped to CBC-EDR semantics (kltn_features/sysmon.py); never evaluated on labelled Sysmon",
                           "offline_test": {"atlasv2_cbc_event_f1_after_step3": after["atlas_test"]["f1"],
                                            "optc_ecar_event_f1_after_step3": after["optc_test"]["f1"]}},
        "windows-cbc": {"validation": "validated", "threshold": TH_ATLAS,
                        "threshold_source": "ATLASv2 VALIDATION (IL step 2)",
                        "offline_test": {"atlasv2_cbc_event_f1_after_step3": after["atlas_test"]["f1"]}},
    }
    parity = {"fusion": fusion_check, "linux_audit_stream": lin, "windows_cbc": win,
              "passed": bool(fusion_check["max_abs_dz"] < 1e-9 and fusion_check["reproduces_published_confusion"]
                             and lin["passed"] and win["passed"]),
              "verified_at": datetime.now(timezone.utc).isoformat()}
    jdump(out / "evidence/parity.json", parity)
    jdump(out / "evidence/training_results.json", {"sl700_step3": res, "fusion_weights": weights})
    manifest = {
        "schema_version": "bundle.v2", "bundle_id": f"host-ml-il3-{tag}", "branch": "host_ml",
        "algorithm": "lightgbm", "created_at": datetime.now(timezone.utc).isoformat(),
        "lineage": [{"step": 1, "domain": "OpTC eCAR", "model": str(OPTC_MODEL.relative_to(WS)), "sha256": sha256(OPTC_MODEL)},
                    {"step": 2, "domain": "ATLASv2 CBC-EDR", "model": str(atlas_model.relative_to(WS)), "sha256": sha256(atlas_model)},
                    {"step": 3, "domain": "AInception SL700 auditd", "model": str(sl_model.relative_to(WS)), "sha256": sha256(sl_model)}],
        "model": {"path": "model/model.txt", "num_trees": fused.num_trees(), "num_feature": fused.num_feature(),
                  "composition": "z = 0.64*z_OpTC(x[:, :10317]) + 0.8*z_ATLASv2(x[:, :12365]) + z_SL700(x)",
                  "fusion_weights": weights, "output": "sigmoid(raw score)"},
        "feature_contract": {"representation": "binary token presence", "width": len(vocab), "vocab": "preprocess/vocab.json",
                             "optc_base_width": W_OPTC, "atlasv2_width": W_ATLAS, "featurizer": "kltn_features.host_ml",
                             "unknown_tokens": "dropped from the vector, counted as OOV (drift / vocabulary extension)"},
        "domains": domains,
        "supported_domains": sorted(domains),
        "domain_validation": "validated",
        "policy": {"select_threshold": 0.5, "positive_class": 1,
                   "note": "per-domain decision thresholds in domains.*.threshold; events scoring >= select_threshold "
                           "are forwarded with evidence (selected logs)"},
        "runtime_code_sha256": runtime_code_hashes(), "vendored": vendored_provenance(),
        "parity": {"passed": parity["passed"], "evidence": "evidence/parity.json",
                   "fixtures": ["evidence/fixture_linux_audit.json", "evidence/fixture_windows_cbc.json"],
                   "verified_at": parity["verified_at"]},
    }
    manifest["activation"] = {"eligible": parity["passed"], "blockers": [] if parity["passed"] else ["parity_failed"]}
    manifest["artifacts"] = artifacts(out)
    jdump(out / "manifest.json", manifest)
    print(f"host-ml bundle {out} parity={parity['passed']} [{time.time() - t0:.0f}s]", flush=True)
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-root", default=str(ROOT / "runtime/releases"))
    ap.add_argument("--tag", default=datetime.now(timezone.utc).strftime("%Y%m%d"))
    ap.add_argument("--only", choices=["ml", "dl"], default=None)
    a = ap.parse_args()
    root = Path(a.out_root)
    for kind, fn in (("ml", build_ml), ("dl", None)):
        if a.only and a.only != kind:
            continue
        if fn is None:
            import build_dl_bundle
            fn = build_dl_bundle.build_dl
        out = root / (f"host-ml-il3-{a.tag}" if kind == "ml" else f"host-dl-il3-{a.tag}")
        if out.exists():
            raise SystemExit(f"{out} exists; bundles are immutable (use another --tag)")
        tmp = out.with_name(out.name + ".building")
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)
        fn(tmp, a.tag)
        tmp.rename(out)


if __name__ == "__main__":
    main()
