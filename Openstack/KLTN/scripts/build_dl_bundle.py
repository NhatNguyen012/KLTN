"""host-dl bundle of the final IL BiLSTM (IL/dataset_2-AInception/code/DL/train_il_step3_v2.py, config bag_freeze_replay2).

* seed: the run whose best epoch has the highest VALIDATION score (mean F1 of SL700 / ATLASv2 / OpTC VAL), no TEST;
* vocabularies rebuilt with the trainer's own functions (asserted identical to the ids the trainer used);
* runtime model = vendored classes sized from the checkpoint (kltn_features.dl_stream.build_model), checked against
  the research model and against the trainer's logged VAL logits;
* streaming parity: raw TEST-run audit.log lines -> AuditStream -> LinuxDLState -> Windower -> encode, compared window
  by window with the training dataset (events, raw tokens, numeric features, bag ids, logits); ATLASv2 CBC TEST
  records -> windows_record -> Windower, compared with the ATLASv2 training windows.
Called by build_il_bundles.py.
"""
from __future__ import annotations

import copy
import csv
import json
import pickle
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from build_il_bundles import (IL1, IL2, WS, artifacts, jdump, lo_cut, raw_audit_lines, runtime_code_hashes,
                              vendored_provenance)

DL_RUNS = IL2 / "output/il_step3v3_20261113/runs"
CONFIG = "bag_freeze_replay2"
SEEDS = (42, 43, 44)
ATLAS_EVENTS = IL1 / "code/DL/output/bilstm_v9_20261112/events"


def choose_seed():
    rows = []
    for s in SEEDS:
        hist = json.loads((DL_RUNS / f"{CONFIG}_s{s}/history.json").read_text())
        best = max(hist, key=lambda h: h["score"])
        rows.append({"seed": s, "best_epoch": best["epoch"], "val_score_mean3": best["score"],
                     "val_sl700": best["val_sl700"], "val_atlas": best["val_atlas"], "val_optc": best["val_optc"]})
    pick = max(rows, key=lambda r: (r["val_score_mean3"], -r["seed"]))
    return pick, rows


def research_setup(seed: int, args: dict):
    """train_il_step3_v2.main up to the grown model, with the run's own arguments."""
    sys.path.insert(0, str(IL2 / "code/DL"))
    import train_il_step3 as S3
    import train_il_step3_v2 as V2
    from train_il_step3 import FIELDS, ILBiLSTM, load_base
    S3.SL700_DATA = Path(args["sl700_data"].replace("dataset_3-AInception", "dataset_2-AInception"))
    V2.EV2 = Path(args["events_dir"].replace("dataset_3-AInception", "dataset_2-AInception"))
    base, cfg, _thr = load_base("cpu")
    old_cards = cfg["categorical_cardinalities"]
    blob = pickle.load(open(S3.ATLAS_DATA, "rb"))
    meta = blob["meta"]
    cat_fields = meta["cat_fields"]
    ctx_idx = [i for i, f in enumerate(cat_fields) if f != "ip_scope"]
    ctx_fields = [cat_fields[i] for i in ctx_idx]
    n_cmd, cnd = meta["num_dim"] - 3, meta["num_dim"]
    mc = args["min_count"]
    ext_atlas, n_new_atlas = S3.atlas_ext_vocab(blob, old_cards, mc)
    ctx_cards_atlas = [len(meta["vocab"][f]) for f in ctx_fields]
    model2 = ILBiLSTM(copy.deepcopy(base), n_new_atlas, ctx_cards_atlas, cnd, hidden2=64)
    for e, k in zip(model2.embeddings, n_new_atlas):
        e.n_new_used = k > 0
    sl = pickle.load(open(S3.SL700_DATA, "rb"))
    cnt_o, cnt_c = S3.sl700_counts(sl)
    ext, n_new_sl = {}, []
    for f, oc, k in zip(FIELDS, old_cards, n_new_atlas):
        ext[f], n = S3.extend(ext_atlas[f], cnt_o[f], oc + k, mc)
        n_new_sl.append(n)
    ctx_vocab, ctx_new = {}, []
    for f in ctx_fields:
        ctx_vocab[f], n = S3.extend(meta["vocab"][f], cnt_c[f], len(meta["vocab"][f]), mc, skip=())
        ctx_new.append(n)
    groups = [g for g in args["bag_groups"].split(",") if g]
    split_of = {s["sample_id"]: sp for sp, lst in sl["splits"].items() for s in lst}
    bag_ids, by_sample, n_tok = V2.load_bags(groups, mc, args["bag_max"], split_of)
    bag_vocab = rebuild_bag_vocab(V2, groups, mc, split_of)
    assert len(bag_vocab) + 2 == n_tok
    model = S3.grow_model(copy.deepcopy(model2), n_new_sl, ctx_new, 5)
    model = V2.add_bag(model, n_tok, args["bag_dim"])
    sd = __import__("torch").load(DL_RUNS / f"{CONFIG}_s{seed}/best.pt", map_location="cpu")
    model.load_state_dict(sd, strict=True)
    model.eval()
    return dict(S3=S3, V2=V2, model=model, sd=sd, cfg=cfg, blob=blob, meta=meta, sl=sl, ext=ext, ctx_fields=ctx_fields,
                ctx_idx=ctx_idx, ctx_vocab=ctx_vocab, bag_vocab=bag_vocab, bag_ids=bag_ids, by_sample=by_sample,
                n_cmd=n_cmd, cnd=cnd, groups=groups, cat_fields=cat_fields)


def rebuild_bag_vocab(V2, groups, min_count, split_of):
    """train_il_step3_v2.load_bags, returning the token -> id dict (identical statements)."""
    import pandas as pd
    ev = pd.read_parquet(V2.EV2 / "events.parquet", columns=["gid", "run", "kind"] + list(groups))
    W = pickle.load(open(V2.EV2 / "windows.pkl", "rb"))
    cols = [ev[g].values for g in groups]
    toks = [sorted({t for part in row for t in (part.split(V2.SEP) if part else ())}) for row in zip(*cols)]
    train_gid = set()
    for w in W:
        if split_of[w["sample_id"]] == "train":
            train_gid.update(w["idx"].tolist())
    cnt = Counter(t for g in train_gid for t in toks[g])
    keep = [t for t, c in sorted(cnt.items(), key=lambda x: (-x[1], x[0])) if c >= min_count]
    return {t: i + 2 for i, t in enumerate(keep)}


def live_event(r: dict) -> dict:
    return r


def training_order(run: str, host: str):
    """build_sl700_windows.build_run event order: run-level pandas sort_values("ts") (quicksort, not stable), then the
    host group. Ties (same millisecond) end up in an arbitrary but reproducible order."""
    import pandas as pd
    from kltn_features._vendor.dl_sl700_events import EXTRA_KINDS, LABEL_KINDS
    run_df = pd.read_parquet(IL2 / f"output/relabel_v3/SL700_{run}/events.parquet",
                             columns=["ts", "line", "host", "kind", "pid", "ppid", "image", "cmd", "tpath", "rip", "rport",
                                      "outbound", "user", "syscall", "y", "stage"])
    df = run_df[run_df.kind.isin(LABEL_KINDS + EXTRA_KINDS)].sort_values("ts")
    h = df[df.host == host]
    return {(int(t), int(l)): i for i, (t, l) in enumerate(zip(h.ts, h.line))}


def linux_stream_parity(R, vocab_rt, model_rt, run_args):
    """Raw TEST-run audit lines -> serving window builder, compared with the training windows of the same run, twice:
    (a) records re-ordered like the training builder (exactness of every input), (b) serving order (ts, serial)."""
    from kltn_features.auditd_stream import AuditStream
    from kltn_features.dl_stream import LinuxDLState, Windower, encode, predict
    test = {s["sample_id"]: s for s in R["sl"]["splits"]["test"]}
    run = next(iter(test.values()))["run"]
    lo = lo_cut(run)
    hosts = sorted({s["host"] for s in test.values()})
    ref_pred = {}
    with open(DL_RUNS / f"{CONFIG}_s{run_args['seed']}/sl700_test_predictions.csv") as fh:
        for row in csv.DictReader(fh):
            ref_pred[row["sample_id"]] = float(row["logit"])
    res = {}
    keep = None
    for mode in ("training_order", "serving_order"):
        found, mism = {}, Counter()
        samples, sids = [], []
        for host in hosts:
            st, wd, a = LinuxDLState(), Windower(origin_us=None), AuditStream(host)
            events = []
            for line in raw_audit_lines(run, host, lo):
                events += a.feed(line)
            events += a.flush()
            recs = st.records(events)
            if mode == "training_order":
                order = training_order(run, host)
                recs = sorted(recs, key=lambda r: order[(r["ts"], r["line"])])
            wd.add(recs)
            for w, ci, start, end, evs in wd.ready(None, final=True):
                sid = f"{host}_{run}_w{w:04d}_c{ci:02d}"
                ref = test.get(sid)
                if ref is None:
                    mism["extra_window"] += 1
                    continue
                enc = encode(evs)
                found[sid] = True
                if enc["tok_raw"] != ref["tok_raw"]:
                    mism["tok_raw"] += 1
                if enc["optc_raw"] != ref["optc_raw"]:
                    mism["optc_raw"] += 1
                if enc["num"].shape != ref["num"].shape or not np.allclose(enc["num"], ref["num"], atol=1e-6):
                    mism["num"] += 1
                s = vocab_rt.sample(enc, with_bag=True)
                ref_bag = [sorted(R["bag_ids"][g].tolist()) for g in R["by_sample"][sid]]
                if [sorted(int(v) for v in row if v > 0) for row in s["bag"]] != [[v for v in r if v > 0] for r in ref_bag]:
                    mism["bag"] += 1
                samples.append(s)
                sids.append(sid)
        preds = predict(model_rt, samples)
        z = np.asarray([p["z"] for p in preds])
        zr = np.asarray([ref_pred[sid] for sid in sids])
        y = np.asarray([test[sid]["y"] for sid in sids])
        thr = run_args["threshold"]
        f1 = lambda zz: _f1(y, zz >= thr)
        res[mode] = {"training_windows": len(test), "serving_windows_matched": len(found),
                     "missing": len(test) - len(found), "mismatch": dict(mism),
                     "max_abs_dlogit_vs_logged": float(np.abs(z - zr).max()) if len(z) else None,
                     "decision_flips_at_val_threshold": int(((z >= thr) != (zr >= thr)).sum()),
                     "test_f1_at_val_threshold": f1(z), "test_f1_logged": f1(zr)}
        if mode == "serving_order":
            keep = (samples[:48], sids[:48], preds[:48])
    ex = res["training_order"]
    res["passed"] = (ex["missing"] == 0 and not ex["mismatch"] and ex["decision_flips_at_val_threshold"] == 0
                     and ex["max_abs_dlogit_vs_logged"] < 0.05)
    res["note"] = ("training ordered same-millisecond events with an unstable pandas sort; serving orders them by audit "
                   "serial. (a) proves every input matches when the training order is reproduced; (b) is what the "
                   "deployed model sees, reported with its TEST F1.")
    return res, *keep


def _f1(y, pred):
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    return round(2 * tp / max(1, 2 * tp + fp + fn), 4)


def atlas_stream_parity(R, vocab_rt, model_rt):
    """ATLASv2 CBC TEST windows: serving builder on the cached CBC records vs the training windows."""
    from kltn_features.dl_stream import Windower, encode, predict, windows_record
    S3 = R["S3"]
    blob = R["blob"]
    test = {s["sample_id"]: s for s in blob["splits"]["test"]}
    files = sorted({sid.rsplit("_w", 1)[0] for sid in test})
    found, mism = set(), Counter()
    samples, sids = [], []
    meta_vocab = R["meta"]["vocab"]
    ctx_from_meta = 0
    for stem_key in files:
        host, sc = stem_key.split("_", 1)
        cands = [p for p in ATLAS_EVENTS.glob("*.pkl") if p.stem.endswith("-" + sc)]
        recs = None
        for p in cands:
            d = pickle.load(open(p, "rb"))
            if d["records"] and d["records"][0]["host"] == host:
                recs = d["records"]
                break
        if recs is None:
            mism["file_not_found"] += 1
            continue
        recs = sorted(recs, key=lambda r: r["ts"])
        wd = Windower(origin_us=None)
        wd.add([windows_record(r) for r in recs])
        for w, ci, start, end, evs in wd.ready(None, final=True):
            sid = f"{host}_{sc}_w{w:04d}_c{ci:02d}"
            if sid not in test:
                continue
            ref = test[sid]
            enc = encode(evs)
            found.add(sid)
            if enc["optc_raw"] != ref["optc_raw"]:
                mism["optc_raw"] += 1
            if not np.allclose(enc["num"], ref["num"], atol=1e-6):
                mism["num"] += 1
            ref_cat = ref["cat"]
            mine = np.array([[meta_vocab[f].get(tok[j], 1) for j, f in enumerate(R["cat_fields"])] for tok in enc["tok_raw"]])
            if mine.shape != ref_cat.shape or (mine != ref_cat).any():
                mism["cat_ids_meta_vocab"] += 1
            s = vocab_rt.sample(enc, with_bag=False)
            if (s["ctx_cat"] != ref_cat[:, R["ctx_idx"]]).any():
                ctx_from_meta += 1        # tokens that the SL700 step added to the context vocabulary
            samples.append(s)
            sids.append(sid)
    preds = predict(model_rt, samples)
    # research logits with the research input recipe (context ids from the ATLASv2 vocabulary, as evaluated)
    A = __import__("train_il").atlas_samples(blob, "v9b", R["ext"], R["ctx_idx"], R["n_cmd"])
    by = {s["id"]: s for s in A["test"]}
    zr = S3.predict(R["model"], [by[sid] for sid in sids], "cpu", len(R["ctx_idx"]), R["cnd"])
    dz = np.abs(np.asarray([p["z"] for p in preds]) - zr)
    out = {"training_windows": len(test), "serving_windows_matched": len(found), "missing": len(test) - len(found),
           "mismatch": dict(mism), "windows_with_ctx_ids_from_sl700_extension": ctx_from_meta,
           "max_abs_dlogit_vs_research_recipe": float(dz.max()) if len(dz) else None}
    out["passed"] = (len(found) == len(test) and not mism)
    return out, samples[:32], sids[:32], preds[:32]


def build_dl(out: Path, tag: str):
    import torch
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "serving"))
    from kltn_features.dl_stream import DLVocab, build_model, predict
    t0 = time.time()
    pick, seeds = choose_seed()
    seed = pick["seed"]
    res = json.loads((DL_RUNS / f"{CONFIG}_s{seed}/result.json").read_text())
    args = res["args"]
    print("seed", seed, "by VAL", seeds, flush=True)
    R = research_setup(seed, args)
    sd = {k: v.detach().cpu().clone() for k, v in R["sd"].items()}
    base_cfg = R["cfg"]
    config = {"base_cardinalities": base_cfg["categorical_cardinalities"], "event_dim": base_cfg["event_dim"],
              "hidden_dim": base_cfg["hidden_dim"], "lstm_layers": base_cfg["lstm_layers"], "dropout": base_cfg["dropout"],
              "hidden2": 64, "num_dim": R["cnd"], "ctx_fields": R["ctx_fields"]}
    vocab_blob = {"fields": list(__import__("train_il_step3").FIELDS), "ext": R["ext"], "cat_fields": R["cat_fields"],
                  "ctx_fields": R["ctx_fields"], "ctx_vocab": R["ctx_vocab"], "bag_vocab": R["bag_vocab"],
                  "bag_groups": R["groups"], "bag_max": args["bag_max"], "num_dim": R["cnd"],
                  "min_count": args["min_count"]}
    (out / "model").mkdir(parents=True)
    torch.save(sd, out / "model/weights.pt")
    jdump(out / "model/config.json", config)
    jdump(out / "preprocess/vocab.json", vocab_blob)
    # runtime model from the bundle files only
    sd_rt = torch.load(out / "model/weights.pt", map_location="cpu", weights_only=True)
    model_rt = build_model(sd_rt, json.loads((out / "model/config.json").read_text()))
    vocab_rt = DLVocab(json.loads((out / "preprocess/vocab.json").read_text()))
    # (1) runtime model == research model == trainer's logged VAL logits (SL700 VAL, a_c)
    S3, V2 = R["S3"], R["V2"]
    sl_va = S3.sl700_samples(R["sl"], R["ext"], R["ctx_vocab"], R["ctx_fields"], R["n_cmd"], "val")
    V2.attach_bags(sl_va, R["bag_ids"], R["by_sample"], args["bag_max"])
    z_res = S3.predict(R["model"], sl_va, "cpu", len(R["ctx_idx"]), R["cnd"])
    rt_samples = [{"x_cat": s["x_cat"], "delta": s["delta"], "ctx_cat": s["ctx_cat"], "ctx_num": s["ctx_num"], "bag": s["bag"]} for s in sl_va]
    z_rt = np.asarray([p["z"] for p in predict(model_rt, rt_samples)])
    logged = {}
    with open(DL_RUNS / f"{CONFIG}_s{seed}/sl700_val_predictions.csv") as fh:
        for row in csv.DictReader(fh):
            logged[row["sample_id"]] = float(row["logit"])
    z_log = np.asarray([logged[s["id"]] for s in sl_va])
    thr_v = float(res["after"]["sl700"]["threshold_logit_val"])
    model_check = {"val_windows": len(sl_va), "max_abs_runtime_vs_research": float(np.abs(z_rt - z_res).max()),
                   "max_abs_research_vs_logged": float(np.abs(z_res - z_log).max()),
                   "decision_flips_vs_logged": int(((z_rt >= thr_v) != (z_log >= thr_v)).sum()),
                   "note": "logged logits come from the GPU (cuDNN) run, the bundle runs on CPU"}
    print("model check", model_check, flush=True)
    thr_lin = float(res["after"]["sl700"]["threshold_logit_val"])
    thr_win = float(res["after"]["atlas"]["threshold_logit_val"])
    lin, lin_s, lin_ids, lin_p = linux_stream_parity(R, vocab_rt, model_rt, {"seed": seed, "threshold": thr_lin})
    print("linux stream parity", lin, flush=True)
    sys.path.insert(0, str(IL1 / "code/DL/optc_il"))
    win, win_s, win_ids, win_p = atlas_stream_parity(R, vocab_rt, model_rt)
    print("atlas stream parity", win, flush=True)
    to_list = lambda s: {k: v.tolist() for k, v in s.items()}
    jdump(out / "evidence/fixture_windows.json", {
        "linux-audit": [{"sample_id": i, "inputs": to_list(s), "z": p["z"]} for s, i, p in zip(lin_s, lin_ids, lin_p)],
        "windows-cbc": [{"sample_id": i, "inputs": to_list(s), "z": p["z"]} for s, i, p in zip(win_s, win_ids, win_p)]})
    after = res["after"]
    domains = {
        "linux-audit": {"validation": "validated", "threshold_logit": thr_lin, "with_bag": True,
                        "threshold_source": "SL700 VALIDATION run a_c (max F1)",
                        "offline": {"val_f1": after["sl700"]["val"]["f1"], "test_f1": after["sl700"]["test"]["f1"],
                                    "test_stage": after["sl700"]["stage"]["summary"]}},
        "windows-sysmon": {"validation": "shadow_unvalidated", "threshold_logit": thr_win, "with_bag": False,
                           "threshold_source": "ATLASv2 VALIDATION (CBC-EDR)",
                           "offline": {"atlasv2_val_f1": after["atlas"]["val"]["f1"], "atlasv2_test_f1": after["atlas"]["test"]["f1"]},
                           "note": "Sysmon mapped to CBC-EDR semantics; never evaluated on labelled Sysmon"},
        "windows-cbc": {"validation": "validated", "threshold_logit": thr_win, "with_bag": False,
                        "threshold_source": "ATLASv2 VALIDATION (CBC-EDR)",
                        "offline": {"atlasv2_val_f1": after["atlas"]["val"]["f1"], "atlasv2_test_f1": after["atlas"]["test"]["f1"]}},
    }
    parity = {"model": model_check, "linux_audit_stream": lin, "windows_cbc_stream": win,
              "passed": bool(model_check["max_abs_runtime_vs_research"] < 1e-4 and model_check["max_abs_research_vs_logged"] < 0.05
                             and model_check["decision_flips_vs_logged"] == 0 and lin["passed"] and win["passed"]),
              "verified_at": datetime.now(timezone.utc).isoformat()}
    jdump(out / "evidence/parity.json", parity)
    jdump(out / "evidence/training_results.json", {"seed_selection": {"picked": pick, "candidates": seeds}, "result": res})
    manifest = {
        "schema_version": "bundle.v2", "bundle_id": f"host-dl-il3-{tag}", "branch": "host_dl", "algorithm": "il-bilstm",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "lineage": [{"step": 1, "domain": "OpTC network-DL subsetB (base BiLSTM)"},
                    {"step": 2, "domain": "ATLASv2 CBC-EDR", "run": "optc_il_20261112/runs/freeze_replay_s%d" % seed},
                    {"step": 3, "domain": "AInception SL700 auditd", "run": f"il_step3v3_20261113/runs/{CONFIG}_s{seed}"}],
        "model": {"weights": "model/weights.pt", "config": "model/config.json", "seed": seed,
                  "output": "window logit z = z_old + gate * max_t event_logit; per-event logits; 5-way stage head",
                  "stages": {"1": "initial_compromise", "2": "execution_discovery", "3": "lateral_movement",
                             "4": "exfiltration", "5": "impact"}},
        "window": {"seconds": 180, "stride_seconds": 30, "max_label_events": 512, "min_label_events": 2},
        "feature_contract": {"vocab": "preprocess/vocab.json", "builder": "kltn_features.dl_stream"},
        "domains": domains, "supported_domains": sorted(domains), "domain_validation": "validated",
        "runtime_code_sha256": runtime_code_hashes(), "vendored": vendored_provenance(),
        "parity": {"passed": parity["passed"], "evidence": "evidence/parity.json",
                   "fixtures": ["evidence/fixture_windows.json"], "verified_at": parity["verified_at"]},
    }
    manifest["activation"] = {"eligible": parity["passed"], "blockers": [] if parity["passed"] else ["parity_failed"]}
    manifest["artifacts"] = artifacts(out)
    jdump(out / "manifest.json", manifest)
    print(f"host-dl bundle {out} parity={parity['passed']} [{time.time() - t0:.0f}s]", flush=True)
    return manifest
