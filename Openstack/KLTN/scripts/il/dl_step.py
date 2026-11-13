"""Host-DL incremental step N on SOC-verified lab data (same recipe as IL step 3 of the BiLSTM):

1. windows of the new domain with the serving builder (kltn_features.dl_stream), event labels from SOC verification
   (attack / benign / unknown -> masked), window label = any attack event, split by the export's incident cut points;
2. vocabulary extension (OpTC-contract values, host-context values, Linux bag tokens) from TRAIN windows, count >= 2,
   appended after the existing ids; new embedding rows start as copies of <UNK>, so the grown model equals the parent
   model at initialisation (asserted);
3. freezing schedule A (new parts) -> B (+ old body x0.2) -> C (+ old embeddings x0.05) with replay of SL700,
   ATLASv2 and OpTC TRAIN windows each epoch; epoch selection on the mean VALIDATION F1 over all domains;
4. new-domain threshold on VALIDATION, TEST once; old domains at their frozen thresholds (forgetting gate 0.02).
"""
from __future__ import annotations

import copy
import json
import math
import pickle
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "serving"))
sys.path.insert(0, str(ROOT / "scripts"))
from build_il_bundles import artifacts, jdump, runtime_code_hashes, vendored_provenance  # noqa: E402

IL1 = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2")
IL2 = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception")
SL700 = IL2 / "output/sl700_windows_v3/dataset.pkl"
EV3 = IL2 / "output/rootcause_20261113/events_v3"
EPOCHS = tuple(int(x) for x in __import__("os").environ.get("KLTN_IL_EPOCHS", "4,8,8").split(","))
FORGET_TOL = 0.02


def windows_of(domain, events, vocab):
    from kltn_features.dl_stream import LinuxDLState, Windower, encode, windows_record
    from kltn_features.sysmon import to_dl_record
    by_host, out = {}, []
    for ev in events:
        by_host.setdefault(ev["host"], []).append(ev)
    for host, evs in by_host.items():
        lab = {ev["key"]: (ev["y"], ev["split"]) for ev in evs}
        if domain == "linux-audit":
            recs = LinuxDLState().records([dict(e["event"], ref=e["key"]) for e in evs])
        else:
            recs = []
            for e in evs:
                r = to_dl_record(e["event"], line=e["event"].get("record_id") or 0)
                if r is not None:
                    r["ref"] = e["key"]
                    recs.append(windows_record(r))
        wd = Windower(origin_us=0)
        wd.add(recs)
        for w, ci, start, end, chunk in wd.ready(None, final=True):
            enc = encode(chunk)
            ys = [lab.get(c["ref"], (-1, "train"))[0] if c["is_label"] else -1 for c in chunk]
            split = lab.get(chunk[0]["ref"], (0, "train"))[1]
            out.append({"enc": enc, "ev_y": np.asarray(ys, np.float32), "y": int(any(v == 1 for v in ys)), "split": split})
    return out


def f1_at(y, z, t):
    pred = z >= t
    tp, fp, fn = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum()), int((~pred & (y == 1)).sum())
    return 2 * tp / max(1, 2 * tp + fp + fn)


def best_thr(y, z):
    best = (-1, 0.0)
    for t in np.unique(z):
        best = max(best, (f1_at(y, z, t), float(t)))
    return best[1]


def grow(model, vocab, new_counts):
    """Append rows for new ids (copies of <UNK>); return the extended vocabulary blob."""
    import torch
    import torch.nn as nn
    v = copy.deepcopy(vocab)
    with torch.no_grad():
        for i, f in enumerate(v["fields"]):
            add = [t for t, c in sorted(new_counts["ext"][f].items(), key=lambda x: (-x[1], x[0])) if c >= 2 and t not in v["ext"][f]]
            if not add:
                continue
            emb = model.embeddings[i]
            base = emb.n_old + emb.new.num_embeddings
            for k, t in enumerate(add):
                v["ext"][f][t] = base + k
            w = torch.cat([emb.new.weight, emb.old.weight[0:1].expand(len(add), -1)], 0)
            emb.new = nn.Embedding.from_pretrained(w.clone(), freeze=False)
        for j, f in enumerate(v["ctx_fields"]):
            add = [t for t, c in sorted(new_counts["ctx"][f].items(), key=lambda x: (-x[1], x[0])) if c >= 2 and t not in v["ctx_vocab"][f]]
            if not add:
                continue
            old = model.ctx_embs[j]
            for k, t in enumerate(add):
                v["ctx_vocab"][f][t] = old.num_embeddings + k
            w = torch.cat([old.weight, old.weight[1:2].expand(len(add), -1)], 0)
            model.ctx_embs[j] = nn.Embedding.from_pretrained(w.clone(), freeze=False, padding_idx=0)
        add = [t for t, c in sorted(new_counts["bag"].items(), key=lambda x: (-x[1], x[0])) if c >= 2 and t not in v["bag_vocab"]]
        if add and hasattr(model, "bag_emb"):
            old = model.bag_emb
            for k, t in enumerate(add):
                v["bag_vocab"][t] = old.num_embeddings + k
            w = torch.cat([old.weight, old.weight[1:2].expand(len(add), -1)], 0)
            model.bag_emb = nn.EmbeddingBag.from_pretrained(w.clone(), freeze=False, mode="mean", padding_idx=0)
    return v


def replay_sets(vocab_rt, n_cmd):
    """SL700 / ATLASv2 / OpTC windows as runtime samples (labels attached)."""
    import pandas as pd
    sys.path.insert(0, str(IL2 / "code/DL"))
    sys.path.insert(0, str(IL1 / "code/DL/optc_il"))
    import train_il as T
    import train_il_step3 as S3
    from kltn_features._vendor.dl_bag_groups import SEP
    sl = pickle.load(open(SL700, "rb"))
    ev = pd.read_parquet(EV3 / "events.parquet", columns=["gid", "g_ev", "g_par", "g_ses"])
    toks = {g: [t for part in (a, b, c) for t in (part.split(SEP) if part else ())] for g, a, b, c in
            zip(ev.gid, ev.g_ev, ev.g_par, ev.g_ses)}
    W = {w["sample_id"]: w["idx"] for w in pickle.load(open(EV3 / "windows.pkl", "rb"))}
    out = {}
    for sp in ("train", "val"):
        lst = []
        for s in sl["splits"][sp]:
            enc = {"tok_raw": s["tok_raw"], "optc_raw": s["optc_raw"], "num": s["num"], "bag_raw": [toks[g] for g in W[s["sample_id"]]]}
            x = vocab_rt.sample(enc, with_bag=True)
            x.update(y=int(s["y"]), ev_y=s["ev_y"].astype(np.float32), dom="sl700")
            lst.append(x)
        out[f"sl700_{sp}"] = lst
    blob = pickle.load(open(S3.ATLAS_DATA, "rb"))
    ctx_idx = [i for i, f in enumerate(blob["meta"]["cat_fields"]) if f != "ip_scope"]
    for sp in ("train", "val"):
        lst = []
        for s in blob["splits"][sp]:
            ids = np.array([[1 if v == "<MISSING>" else vocab_rt.ext[f].get(v, 0) for f, v in zip(vocab_rt.fields, e)]
                            for e in s["optc_raw"]], dtype=np.int64)
            lst.append({"x_cat": ids, "delta": s["num"][:, n_cmd].astype(np.float32), "ctx_cat": s["cat"][:, ctx_idx],
                        "ctx_num": s["num"].astype(np.float32), "y": int(s["y_v9b"]), "ev_y": s["ev_y_v9b"].astype(np.float32),
                        "dom": "atlas"})
        out[f"atlas_{sp}"] = lst
    rows = T.optc_rows()
    rng = np.random.default_rng(1)
    for sp, n_neg in (("train", 6000), ("val", 3000)):
        pos = [r for r in rows if r["split"] == sp and r["label"] == "1"]
        neg = [r for r in rows if r["split"] == sp and r["label"] == "0"]
        pick = pos + [neg[i] for i in rng.choice(len(neg), min(n_neg, len(neg)), replace=False)]
        out[f"optc_{sp}"] = [{"x_cat": s["x_cat"], "delta": s["delta"], "ctx_cat": None, "ctx_num": None, "has_ctx": 0.0,
                              "y": int(s["y"]), "ev_y": np.full(len(s["delta"]), -1, np.float32), "dom": "optc"}
                             for s in T.load_optc(pick)]
    return out


def logits(model, samples, device, bs=64):
    from kltn_features.dl_stream import predict
    return np.asarray([p["z"] for p in predict(model, samples, device=device, bs=bs)]) if samples else np.zeros(0)


def run(parent: Path, domain: str, data: dict, out: Path, tag: str) -> dict:
    import torch
    import torch.nn.functional as F
    from kltn_features.dl_stream import DLVocab, build_model, collate
    t0 = time.time()
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    pm = json.loads((parent / "manifest.json").read_text())
    vocab = json.loads((parent / "preprocess/vocab.json").read_text())
    config = json.loads((parent / "model/config.json").read_text())
    sd = torch.load(parent / "model/weights.pt", map_location="cpu", weights_only=True)
    model = build_model(sd, config)
    parent_model = build_model(sd, config)
    wins = windows_of(domain, data["events"], DLVocab(vocab))
    cnt = {"ext": {f: Counter() for f in vocab["fields"]}, "ctx": {f: Counter() for f in vocab["ctx_fields"]}, "bag": Counter()}
    pos = [vocab["cat_fields"].index(f) for f in vocab["ctx_fields"]]
    for w in wins:
        if w["split"] != "train":
            continue
        for ev in w["enc"]["optc_raw"]:
            for f, v in zip(vocab["fields"], ev):
                if v != "<MISSING>":
                    cnt["ext"][f][v] += 1
        for tok in w["enc"]["tok_raw"]:
            for f, p in zip(vocab["ctx_fields"], pos):
                cnt["ctx"][f][tok[p]] += 1
        for b in w["enc"]["bag_raw"]:
            cnt["bag"].update(set(b))
    new_vocab = grow(model, vocab, cnt)
    vrt = DLVocab(new_vocab)
    with_bag = domain == "linux-audit"
    D = {}
    for sp in ("train", "val", "test"):
        D[sp] = []
        for w in wins:
            if w["split"] == sp:
                x = vrt.sample(w["enc"], with_bag=with_bag)
                x.update(y=w["y"], ev_y=w["ev_y"], dom="new")
                D[sp].append(x)
    R = replay_sets(vrt, vrt.n_cmd)
    model.to(dev)
    eq = float(np.abs(logits(model, D["val"][:128], dev) - logits(parent_model.to(dev), D["val"][:128], dev)).max()) if D["val"] else 0.0
    t_optc = json.loads((IL1 / "code/DL/pretrained_optc_model/threshold.json").read_text())["threshold"]
    old_thr = {"sl700_val": pm["domains"]["linux-audit"]["threshold_logit"], "atlas_val": pm["domains"]["windows-cbc"]["threshold_logit"],
               "optc_val": math.log(t_optc / (1 - t_optc))}
    before = {k: f1_at(np.asarray([s["y"] for s in R[k]]), logits(parent_model, R[k], dev), t) for k, t in old_thr.items()}
    groups = {"new": [], "old_body": [], "old_emb": []}
    for n, p in model.named_parameters():
        groups["old_emb" if (n.startswith("embeddings.") and ".old." in n) else
               "old_body" if n.startswith(("event_encoder.", "lstm.", "classifier.")) else "new"].append(p)
    hist, best = [], (-1.0, None, 0)
    y_val = np.asarray([s["y"] for s in D["val"]])
    for stage, n_ep, plan in (("A", EPOCHS[0], {"new": 1e-3}), ("B", EPOCHS[1], {"new": 5e-4, "old_body": 1e-4}),
                              ("C", EPOCHS[2], {"new": 5e-4, "old_body": 1e-4, "old_emb": 2.5e-5})):
        for g, ps in groups.items():
            for p in ps:
                p.requires_grad = g in plan
        opt = torch.optim.AdamW([{"params": groups[g], "lr": lr} for g, lr in plan.items()], weight_decay=1e-4)
        for _ in range(n_ep):
            model.train()
            ep = list(D["train"])
            for key, (npos, nneg) in (("sl700_train", (100, 400)), ("atlas_train", (100, 400)), ("optc_train", (150, 450))):
                P = [s for s in R[key] if s["y"] == 1]; N = [s for s in R[key] if s["y"] == 0]
                ep += random.sample(P, min(npos, len(P))) + random.sample(N, min(nneg, len(N)))
            random.shuffle(ep)
            pw = math.sqrt(max(1, sum(1 for s in D["train"] if s["y"] == 0)) / max(1, sum(s["y"] for s in D["train"])))
            for i in range(0, len(ep), 64):
                b = ep[i:i + 64]
                inp = collate(b, with_bag=hasattr(model, "bag_emb"), device=dev)
                z, _zo, evl, _st, mask = model(**inp)
                y = torch.tensor([s["y"] for s in b], dtype=torch.float32, device=dev)
                w = torch.where(y > 0, torch.full_like(y, pw), torch.ones_like(y))
                loss = (F.binary_cross_entropy_with_logits(z, y, reduction="none") * w).sum() / w.sum()
                L = evl.shape[1]
                evy = torch.full((len(b), L), -1.0, device=dev)
                for k, s in enumerate(b):
                    evy[k, :len(s["ev_y"])] = torch.as_tensor(s["ev_y"], device=dev)
                m = evy >= 0
                if m.any():
                    loss = loss + 0.5 * F.binary_cross_entropy_with_logits(evl[m], evy[m])
                opt.zero_grad(); loss.backward()
                torch.nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.0)
                opt.step()
            model.eval()
            zv = logits(model, D["val"], dev)
            f_new = f1_at(y_val, zv, best_thr(y_val, zv)) if len(zv) else 0.0
            f_old = {k: f1_at(np.asarray([s["y"] for s in R[k]]), logits(model, R[k], dev), t) for k, t in old_thr.items()}
            score = float(np.mean([f_new] + list(f_old.values())))
            hist.append({"stage": stage, "val_new": f_new, **f_old, "score": score})
            if score > best[0]:
                best = (score, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}, len(hist))
    model.load_state_dict(best[1])
    zv, zt = logits(model, D["val"], dev), logits(model, D["test"], dev)
    thr = best_thr(y_val, zv) if len(zv) else 0.0
    y_te = np.asarray([s["y"] for s in D["test"]])
    th_parent = pm["domains"].get(domain, {}).get("threshold_logit", 0.0)
    new_dom = {"windows": {sp: len(D[sp]) for sp in D}, "attack_windows": {sp: int(sum(s["y"] for s in D[sp])) for sp in D},
               "before_test_f1": f1_at(y_te, logits(parent_model, D["test"], dev), th_parent),
               "after_val_f1": f1_at(y_val, zv, thr), "after_test_f1": f1_at(y_te, zt, thr), "threshold_logit": thr}
    after = {k: f1_at(np.asarray([s["y"] for s in R[k]]), logits(model, R[k], dev), t) for k, t in old_thr.items()}
    forgetting_ok = all(before[k] - after[k] <= FORGET_TOL for k in before)
    improves = new_dom["after_test_f1"] >= new_dom["before_test_f1"]
    (out / "model").mkdir(parents=True)
    sd_new = {k: v.detach().cpu() for k, v in model.state_dict().items()}
    torch.save(sd_new, out / "model/weights.pt")
    jdump(out / "model/config.json", config)
    jdump(out / "preprocess/vocab.json", new_vocab)
    rt = build_model(torch.load(out / "model/weights.pt", map_location="cpu", weights_only=True), config)
    dz = float(np.abs(logits(rt, D["val"][:256], "cpu") - logits(model.cpu(), D["val"][:256], "cpu")).max()) if D["val"] else 0.0
    fx = json.loads((parent / "evidence/fixture_windows.json").read_text())
    for dom, items in fx.items():
        samples = [{k: np.asarray(v) for k, v in it["inputs"].items()} for it in items]
        for s in samples:
            for k in ("x_cat", "ctx_cat", "bag"):
                if k in s:
                    s[k] = s[k].astype(np.int64)
        for it, zz in zip(items, logits(rt, samples, "cpu")):
            it["z"] = float(zz)
    jdump(out / "evidence/fixture_windows.json", fx)
    passed = dz < 1e-4 and eq < 1e-4
    blockers = [b for b, ok in (("parity", passed), ("forgetting", forgetting_ok), ("no_improvement_on_new_domain", improves)) if not ok]
    metrics = {"new_domain": new_dom, "old_domains_val_f1": {"before": before, "after": after}, "history": hist,
               "best_epoch": best[2], "growth_equivalence_max_abs_dz": eq, "runtime_max_abs_dz": dz, "elapsed_s": round(time.time() - t0)}
    jdump(out / "evidence/il_step.json", metrics)
    jdump(out / "evidence/parity.json", {"growth_equivalence": eq, "runtime_vs_trained": dz, "passed": passed,
                                         "verified_at": datetime.now(timezone.utc).isoformat()})
    domains = json.loads(json.dumps(pm["domains"]))
    domains.setdefault(domain, {}).update(threshold_logit=thr, validation="validated",
                                          threshold_source=f"lab VALIDATION incidents ({tag})",
                                          offline={"lab_window_test_f1": new_dom["after_test_f1"]})
    manifest = dict(pm)
    manifest.update(bundle_id=f"host-dl-il{len(pm['lineage']) + 1}-{tag}", created_at=datetime.now(timezone.utc).isoformat(),
                    parent_bundle_id=pm["bundle_id"], lineage=pm["lineage"] + [{"step": len(pm["lineage"]) + 1, "domain": f"lab {domain}"}],
                    domains=domains, runtime_code_sha256=runtime_code_hashes(), vendored=vendored_provenance(),
                    parity={"passed": passed, "evidence": "evidence/parity.json", "fixtures": ["evidence/fixture_windows.json"],
                            "verified_at": datetime.now(timezone.utc).isoformat()},
                    activation={"eligible": not blockers, "blockers": blockers})
    manifest.pop("artifacts", None)
    manifest["artifacts"] = artifacts(out)
    jdump(out / "manifest.json", manifest)
    return {"bundle_id": manifest["bundle_id"], "eligible": not blockers, "blockers": blockers, "metrics": metrics}
