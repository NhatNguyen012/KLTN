"""Host-ML incremental step N on SOC-verified lab data (same recipe as IL step 3, OpTC -> ATLASv2 -> SL700):

1. featurize the exported events with the deployed featurizer (state replayed per host in time order);
2. vocabulary extension: tokens of TRAIN rows absent from the vocabulary, count >= 2, appended after the existing
   columns (old ids never move, so every older booster keeps reading the same columns);
3. residual booster: init score = 0.8 * z_current(x), trained on the new-domain rows + replay (SL700, ATLASv2, OpTC
   rows) with hard-negative weights, 300 rounds, the step-3 hyper-parameters;
4. new-domain threshold on VALIDATION; TEST reported once; old domains re-scored on their VALIDATION sets at their
   frozen thresholds (forgetting gate: F1 drop <= 0.02);
5. fused candidate = 0.8 * current fused + residual (one booster), equivalence asserted on rows.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy import sparse
from scipy.special import expit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "serving"))
sys.path.insert(0, str(ROOT / "scripts"))
from build_il_bundles import (SL_DATA, artifacts, deploy_vocab, fixture_expectations, jdump, load_npz,  # noqa: E402
                              runtime_code_hashes, vendored_provenance)
from lgbm_fuse import fuse  # noqa: E402

ALPHA, HARD_W, MIN_COUNT, ROUNDS, FORGET_TOL = 0.8, 5.0, 2, 300, 0.02
ML3 = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/code/ML")


def research():
    sys.path.insert(0, str(ML3))
    sys.path.insert(0, "/mnt/SSD_Data/optc")
    import train_ml_il_step3 as M
    spec = importlib.util.spec_from_file_location("eval_old_val", ML3 / "eval_old_val.py")
    E = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(E)
    return M, E


def featurize(domain: str, vocab: dict, events: list[dict]):
    from kltn_features.host_ml import HostFeaturizer
    rows, by_host = [], {}
    for ev in events:                                   # export is ordered by host, time
        fz = by_host.setdefault(ev["host"], HostFeaturizer(domain, vocab, ev["host"]))
        for r in fz.feed_event(ev["event"], ref=ev["key"]):
            rows.append((r.tokens, ev["y"], ev["split"], ev["key"]))
    return rows


def matrix(token_rows, vocab, width):
    indptr, indices = [0], []
    for toks in token_rows:
        indices += sorted({vocab[t] for t in toks if t in vocab})
        indptr.append(len(indices))
    return sparse.csr_matrix((np.ones(len(indices), np.float32), np.asarray(indices, np.int64), np.asarray(indptr, np.int64)),
                             shape=(len(token_rows), width))


def f1_at(y, p, t):
    pred = p >= t
    tp, fp, fn = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum()), int((~pred & (y == 1)).sum())
    return {"threshold": float(t), "tp": tp, "fp": fp, "fn": fn, "f1": 2 * tp / max(1, 2 * tp + fp + fn)}


def run(parent: Path, domain: str, data: dict, out: Path, tag: str, threads: int = 10) -> dict:
    import lightgbm as lgb
    M, E = research()
    t0 = time.time()
    pm = json.loads((parent / "manifest.json").read_text())
    vocab = json.loads((parent / "preprocess/vocab.json").read_text())
    W0 = len(vocab)
    cur = lgb.Booster(model_file=str(parent / pm["model"]["path"]))
    rows = featurize(domain, vocab, data["events"])
    lab = [r for r in rows if r[1] in (0, 1)]
    cnt = Counter(t for toks, y, sp, _ in lab if sp == "train" for t in set(toks) if t not in vocab)
    new = [t for t, c in sorted(cnt.items(), key=lambda x: (-x[1], x[0])) if c >= MIN_COUNT]
    ext = dict(vocab)
    for t in new:
        ext[t] = len(ext)
    W1 = len(ext)
    split = {sp: [r for r in lab if r[2] == sp] for sp in ("train", "val", "test")}
    X = {sp: matrix([r[0] for r in v], ext, W1) for sp, v in split.items()}
    y = {sp: np.asarray([r[1] for r in v], np.int8) for sp, v in split.items()}
    zc = {sp: cur.predict(X[sp][:, :W0], raw_score=True, num_threads=threads) for sp in X}
    # replay: SL700 rows (model column space) + ATLASv2 + OpTC
    rng = np.random.default_rng(1)
    _, keep = deploy_vocab()
    Xs, ys = load_npz(SL_DATA / "train.npz")
    Xs = Xs[:, keep].tocsr()
    i_s = np.r_[rng.choice(np.flatnonzero(ys == 1), min(12500, int(ys.sum())), replace=False),
                rng.choice(np.flatnonzero(ys == 0), 25000, replace=False)]
    Xa, ya = M.load_shards(M.ATLAS_MANIFEST, "train", M.W_ATLAS)
    i_a = np.r_[np.flatnonzero(ya == 1), rng.choice(np.flatnonzero(ya == 0), 35000, replace=False)]
    Xo, yo = M.load_npz(M.OPTC_REPLAY)
    i_o = np.r_[rng.choice(np.flatnonzero(yo == 1), 12500, replace=False), rng.choice(np.flatnonzero(yo == 0), 25000, replace=False)]
    Xr = sparse.vstack([M.width(Xs[i_s], W1), M.width(Xa[i_a], W1), M.width(Xo[i_o], W1)], format="csr")
    yr = np.r_[ys[i_s], ya[i_a], yo[i_o]].astype(np.int8)
    zr = cur.predict(Xr[:, :W0], raw_score=True, num_threads=threads)
    X_fit = sparse.vstack([X["train"], Xr], format="csr")
    y_fit = np.r_[y["train"], yr]
    z_fit = np.r_[zc["train"], zr]
    w = np.where((y_fit == 0) & (expit(z_fit) > 0.5), HARD_W, 1.0).astype(np.float32)
    spw = float((y["train"] == 0).sum() / max(1, (y["train"] == 1).sum()))
    params = dict(objective="binary", metric="None", num_leaves=31, learning_rate=0.03, seed=1, num_threads=threads,
                  verbosity=-1, force_col_wise=True, deterministic=True, scale_pos_weight=spw, max_delta_step=2.0, reg_lambda=5.0)
    res = lgb.train(params, lgb.Dataset(X_fit, label=y_fit, init_score=ALPHA * z_fit, weight=w, params=params), num_boost_round=ROUNDS)
    z_new = {sp: ALPHA * zc[sp] + res.predict(X[sp], raw_score=True, num_threads=threads) for sp in X}
    thr = float(M.best_thr(y["val"], expit(z_new["val"]))[0])
    th_before = float(pm["domains"].get(domain, {}).get("threshold", 0.5))
    new_domain = {"rows": {sp: int(len(y[sp])) for sp in y}, "attack": {sp: int(y[sp].sum()) for sp in y},
                  "new_tokens": len(new), "width": W1,
                  "before": {"test": f1_at(y["test"], expit(zc["test"]), th_before)},
                  "after": {"val": f1_at(y["val"], expit(z_new["val"]), thr), "test": f1_at(y["test"], expit(z_new["test"]), thr)}}
    # forgetting gate on the old domains' VALIDATION sets (frozen thresholds)
    old = {}
    Xv, yv = load_npz(SL_DATA / "val.npz")
    sets = {"sl700_val": (Xv[:, keep].tocsr(), yv, pm["domains"]["linux-audit"]["threshold"]),
            "atlasv2_val": (*M.load_shards(M.ATLAS_MANIFEST, "val", M.W_ATLAS), M.TH_ATLAS),
            "optc_val": (*E.load_optc_val(), M.TH_OPTC)}
    for name, (Xo_, yo_, th) in sets.items():
        Xp = M.width(Xo_, W1)
        zb = cur.predict(Xp[:, :W0], raw_score=True, num_threads=threads)
        za = ALPHA * zb + res.predict(Xp, raw_score=True, num_threads=threads)
        old[name] = {"before": f1_at(yo_, expit(zb), th)["f1"], "after": f1_at(yo_, expit(za), th)["f1"]}
    forgetting_ok = all(v["before"] - v["after"] <= FORGET_TOL for v in old.values())
    improves = new_domain["after"]["test"]["f1"] >= new_domain["before"]["test"]["f1"]
    # fused candidate and its equivalence
    (out / "model").mkdir(parents=True)
    text = fuse([((parent / pm["model"]["path"]).read_text(), ALPHA), (res.model_to_string(), 1.0)])
    lgb.Booster(model_str=text).save_model(str(out / "model/model.txt"))
    fused = lgb.Booster(model_file=str(out / "model/model.txt"))
    dz = float(np.abs(fused.predict(X["val"], raw_score=True, num_threads=threads) - z_new["val"]).max()) if len(y["val"]) else 0.0
    jdump(out / "preprocess/vocab.json", ext)
    # fixtures: same inputs as the parent, expectations recomputed with the candidate
    for fx_name in ("fixture_linux_audit.json", "fixture_windows_cbc.json"):
        fx = json.loads((parent / "evidence" / fx_name).read_text())
        if fx["domain"] == "linux-audit":
            fx["expected"] = fixture_expectations("linux-audit", ext, fused, fx["inputs"], fx.get("host", "fixture"))
        else:
            from kltn_features._vendor.common_schema import CanonicalEvent
            from kltn_features.host_ml import HostFeaturizer
            fz = HostFeaturizer("windows-cbc", ext, "fixture")
            rs = [r for r in (fz.feed_canonical(CanonicalEvent(**d)) for d in fx["inputs"]) if r is not None]
            Xf = fz.matrix(rs)
            zf = fused.predict(Xf, raw_score=True)
            fx["expected"] = [{"ts": r.ts, "kind": r.kind, "columns": Xf[k].indices.tolist(), "raw_score": float(zf[k])}
                              for k, r in enumerate(rs)]
        jdump(out / "evidence" / fx_name, fx)
    passed = dz < 1e-6
    blockers = [b for b, ok in (("parity", passed), ("forgetting", forgetting_ok), ("no_improvement_on_new_domain", improves)) if not ok]
    metrics = {"new_domain": new_domain, "old_domains_val": old, "fusion_equivalence_max_abs_dz": dz,
               "elapsed_s": round(time.time() - t0)}
    jdump(out / "evidence/il_step.json", metrics)
    jdump(out / "evidence/parity.json", {"fusion_equivalence_max_abs_dz": dz, "passed": passed,
                                         "verified_at": datetime.now(timezone.utc).isoformat()})
    domains = json.loads(json.dumps(pm["domains"]))
    d = domains.setdefault(domain, {})
    d.update(threshold=thr, threshold_source=f"lab VALIDATION incidents ({tag})",
             validation="validated", offline_test={"lab_event_f1": new_domain["after"]["test"]["f1"]})
    manifest = dict(pm)
    manifest.update(bundle_id=f"host-ml-il{len(pm['lineage']) + 1}-{tag}", created_at=datetime.now(timezone.utc).isoformat(),
                    parent_bundle_id=pm["bundle_id"],
                    lineage=pm["lineage"] + [{"step": len(pm["lineage"]) + 1, "domain": f"lab {domain}", "tag": tag}],
                    model={**pm["model"], "num_trees": fused.num_trees(), "num_feature": fused.num_feature(),
                           "composition": f"z = 0.8 * z_parent({pm['bundle_id']}) + z_step(x)"},
                    feature_contract={**pm["feature_contract"], "width": W1}, domains=domains,
                    runtime_code_sha256=runtime_code_hashes(), vendored=vendored_provenance(),
                    parity={"passed": passed, "evidence": "evidence/parity.json",
                            "fixtures": ["evidence/fixture_linux_audit.json", "evidence/fixture_windows_cbc.json"],
                            "verified_at": datetime.now(timezone.utc).isoformat()},
                    activation={"eligible": not blockers, "blockers": blockers})
    manifest.pop("artifacts", None)
    manifest["artifacts"] = artifacts(out)
    jdump(out / "manifest.json", manifest)
    return {"bundle_id": manifest["bundle_id"], "eligible": not blockers, "blockers": blockers, "metrics": metrics}
