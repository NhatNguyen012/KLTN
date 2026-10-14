"""Audit evidence-gated high-ML veto using frozen conditional-v4 outputs.

Only the events already vetoed by the prior policy can change. Validation
selects the evidence gate; TEST labels are used only after freezing that gate.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "preprocess"))
from host_shards import HostShardDataset
from cascade_runtime import metrics, safe, sha
from ego import EgoGraphs
from relational_sage import RelationalSAGE

RULES = ("any_create", "root_create", "any_create_resolved",
         "root_create_resolved", "any_create_untruncated")
MIN_F1_GAIN = 0.0001
MIN_DISTINCT_BENIGN_GRAPHS = 2
MAX_ADDITIONAL_FN = 0


def atomic_json(path, value):
    path = safe(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)


def get_shard(data, shard):
    from host_shards import decode_shard
    return decode_shard(data.path_for(shard), data.width, shard)


def key_for_row(x, row):
    start, stop = int(x.indptr[row]), int(x.indptr[row + 1])
    cols = x.indices[start:stop]
    if len(cols) > 1 and np.any(cols[:-1] >= cols[1:]):
        raise ValueError("Host columns are not strictly increasing")
    return cols.astype("<u4", copy=False).tobytes()


def evidence(graph):
    creates = [(int(a), int(b)) for a, b, relation in graph["edges"]
               if relation == "creates"]
    flags = set(graph["flags"])
    content = graph["x"].tobytes() + repr(graph["edges"]).encode()
    return dict(nodes=int(len(graph["x"])), edges=len(graph["edges"]),
                create_edges=len(creates), root_create=any(b == graph["root"] for _, b in creates),
                unresolved="unresolved_relation" in flags,
                truncated="truncated" in flags,
                missing_identity="missing_identity_or_time" in flags,
                graph_input_sha256=hashlib.sha256(content).hexdigest())


def gate(rule, item):
    if item["missing_identity"]:
        return False
    create = item["create_edges"] > 0
    root = item["root_create"]
    if rule == "any_create":
        return create
    if rule == "root_create":
        return root
    if rule == "any_create_resolved":
        return create and not item["unresolved"]
    if rule == "root_create_resolved":
        return root and not item["unresolved"]
    if rule == "any_create_untruncated":
        return create and not item["truncated"]
    raise ValueError(f"Unknown gate: {rule}")


def revised_counts(conditional, rows, rule):
    conf = dict(conditional)
    kept_fp, kept_fn = [], []
    reverted_fp, reverted_fn = [], []
    for row in rows:
        if gate(rule, row["evidence"]):
            (kept_fp if row["label"] == 0 else kept_fn).append(row)
            continue
        if row["label"] == 0:
            conf["fp"] += 1; conf["tn"] -= 1; reverted_fp.append(row)
        else:
            conf["tp"] += 1; conf["fn"] -= 1; reverted_fn.append(row)
    return metrics(np.array([conf[k] for k in ("tp", "fp", "fn", "tn")], dtype=np.int64)), dict(
        vetoed_fp=len(kept_fp), vetoed_fn=len(kept_fn),
        reverted_fp=len(reverted_fp), rescued_fn=len(reverted_fn),
        distinct_vetoed_benign_graphs=len({r["evidence"]["graph_input_sha256"] for r in kept_fp}),
        distinct_vetoed_malicious_graphs=len({r["evidence"]["graph_input_sha256"] for r in kept_fn}),
        vetoed_benign_sources=len({r["source_id"] for r in kept_fp}))


def select_rule(conditional, candidates):
    base = metrics(np.array([conditional[k] for k in ("tp", "fp", "fn", "tn")], dtype=np.int64))
    assessed = {}
    for rule in RULES:
        result, audit = revised_counts(conditional, candidates, rule)
        eligible = (result["f1"] >= base["f1"] + MIN_F1_GAIN
                    and result["confusion"]["fn"] <= conditional["fn"] + MAX_ADDITIONAL_FN
                    and audit["distinct_vetoed_benign_graphs"] >= MIN_DISTINCT_BENIGN_GRAPHS)
        assessed[rule] = dict(metrics=result, audit=audit, eligible=eligible)
    winners = [r for r in RULES if assessed[r]["eligible"]]
    winner = max(winners, key=lambda r: (assessed[r]["metrics"]["f1"],
                 -assessed[r]["metrics"]["confusion"]["fn"], -RULES.index(r))) if winners else None
    return dict(selected=winner or "conditional_unchanged", accepted=bool(winner),
                rules=assessed, minimum_f1_gain=MIN_F1_GAIN,
                minimum_distinct_benign_graphs=MIN_DISTINCT_BENIGN_GRAPHS,
                maximum_additional_fn=MAX_ADDITIONAL_FN,
                selection_basis="validation labels only; fixed prior graph threshold and scores")


def _rows(path):
    with Path(path).open() as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def _cache_graph(cache, split, index, shard, identity, n):
    path = cache / f"{split}-graph-{index:04d}.npz"
    receipt = json.loads(path.with_suffix(".json").read_text())
    if (receipt["identity"] != identity or receipt["source_id"] != shard["source_id"]
            or receipt["shard_sha256"] != shard["sha256"] or sha(path) != receipt["sha256"]):
        raise ValueError(f"Frozen score cache mismatch: {path}")
    with np.load(path, allow_pickle=False) as f:
        scores = f["graph"]
    if scores.shape != (n,):
        raise ValueError("Score cache row count mismatch")
    return scores


def validation_candidates(data, previous, cache, policy):
    high = {}
    for row in _rows(previous / "validation_per_vector_audit.jsonl"):
        if row["validation_ml_band"] == "high":
            high[bytes.fromhex(row["vector_key"])] = float(row["validation_ml_score"])
    candidate = []
    for index, shard in enumerate(data.meta["shards"]):
        if shard["split"] != "val":
            continue
        x, y, lines = get_shard(data, shard)
        scores = _cache_graph(cache, "val", index, shard, policy["identity"], len(y))
        threshold = policy["policy"]["high_threshold"]
        for i in range(len(y)):
            key = key_for_row(x, i)
            # Native Kaggle and NumPy cache differ at ~1e-17 for a threshold
            # tie. The frozen native policy treats equality as positive.
            if (key not in high or not np.isfinite(scores[i])
                    or scores[i] >= threshold - 1e-15):
                continue
            candidate.append(dict(source_id=shard["source_id"], source_line=int(lines[i]),
                label=int(y[i]), ml_score=high[key], graph_score=float(scores[i]),
                vector_key=key.hex()))
    labels = Counter(row["label"] for row in candidate)
    if (labels[0], labels[1]) != (policy["policy"]["high_vetoed_fp"],
                                   policy["policy"]["high_extra_fn"]):
        raise ValueError(f"Validation veto candidates do not reproduce frozen policy: {dict(labels)}; "
                         f"expected {policy['policy']['high_vetoed_fp']}/"
                         f"{policy['policy']['high_extra_fn']}; malicious="
                         f"{[(r['source_id'][:8], r['source_line'], r['graph_score']) for r in candidate if r['label']==1]}")
    return candidate


def enrich(rows, db, ego, model, expected_split):
    for row in rows:
        target = db.execute("SELECT host,proc,t,split FROM target WHERE source=? AND line=?",
                            (row["source_id"], row["source_line"])).fetchone()
        if target is None or target[3] != expected_split:
            raise ValueError("Frozen target/split mismatch")
        graph = ego.build(*target[:3])
        score = model.predict(graph)["probability"]
        if abs(score - row["graph_score"]) > 1e-10:
            raise ValueError("Cached GraphSAGE score differs from frozen checkpoint")
        row["evidence"] = evidence(graph)
    return rows


def run(manifest_path, bundle, previous, cache, output, volume_root_ssd=None):
    manifest_path, bundle, previous, cache, output = map(lambda x: Path(x).resolve(),
                                                         (manifest_path, bundle, previous, cache, output))
    safe(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output must be a new empty directory")
    for source in (bundle, previous, cache, manifest_path.parent):
        if output == source or output.is_relative_to(source):
            raise ValueError("Output overlaps an input")
    policy = json.loads((previous / "frozen_policy.json").read_text())
    identity = policy["identity"]
    if not policy["policy"]["accepted"]:
        raise ValueError("Prior conditional policy was not accepted")
    # The approved seed02 manifest was relocated after the v4 run: its volume
    # path changed, while run ID, split/vocabulary identities and shard hashes
    # were preserved. Validate those contents below, not its historical bytes.
    for path, expected in ((bundle / "bundle_manifest.json", identity["bundle_sha256"]),
                           (bundle / "provenance/graph.sqlite", identity["graph_sha256"]),
                           (bundle / "provenance/model_numpy.npz", identity["graph_model_sha256"]),
                           (bundle / "models/lgbm_model.txt", identity["host_model_sha256"]),
                           (manifest_path.parent / "assets/vocab.json", identity["schema_sha256"])):
        if sha(path) != expected:
            raise ValueError(f"Frozen input SHA mismatch: {path}")
    cache_meta = json.loads((cache / "cache_manifest.json").read_text())
    if cache_meta["identity"] != identity:
        raise ValueError("Graph score cache identity mismatch")
    data = HostShardDataset(manifest_path, volume_roots={"ssd": volume_root_ssd} if volume_root_ssd else None)
    if (data.meta["vocab_size"] != identity["feature_width"]
            or sha(manifest_path.parent / "assets/split_manifest.json") != data.meta["split_sha256"]
            or sha(manifest_path.parent / "assets/vocab.json") != data.meta["vocabulary_sha256"]):
        raise ValueError("Relocated manifest split/vocabulary identity mismatch")
    old_val = json.loads((previous / "validation_metrics.json").read_text())
    if old_val["identity"] != identity:
        raise ValueError("Prior validation result identity mismatch")
    val = validation_candidates(data, previous, cache, policy)
    db_path = bundle / "provenance/graph.sqlite"
    db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("PRAGMA cache_size=-262144")
        ego = EgoGraphs(db)
        model = RelationalSAGE.load(bundle / "provenance/model_numpy.npz")
        enrich(val, db, ego, model, 2)
        choice = select_rule(old_val["selected"]["confusion"], val)
        output.mkdir(parents=True, exist_ok=True)
        atomic_json(output / "frozen_policy.json", dict(identity=identity, policy=choice,
            prior_conditional_sha256=sha(previous / "frozen_policy.json")))
        atomic_json(output / "validation_metrics.json", dict(identity=identity,
            legacy=old_val["legacy"], conditional=old_val["selected"],
            selected=choice["rules"][choice["selected"]]["metrics"] if choice["accepted"] else old_val["selected"],
            candidate_count=len(val), gate=choice))
        with (output / "validation_veto_evidence.jsonl").open("w") as f:
            for row in val:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        frozen = json.loads((output / "frozen_policy.json").read_text())
        if frozen["policy"] != choice:
            raise ValueError("Frozen policy changed")
        # Open TEST metrics and event labels only after the validation gate has
        # been frozen on disk.
        old_test = json.loads((previous / "test_metrics.json").read_text())
        if old_test["identity"] != identity:
            raise ValueError("Prior TEST result identity mismatch")
        test = [r for r in _rows(previous / "event_transition_audit.jsonl")
                if r["reason"] == "collision_high_veto"]
        test_labels = Counter(r["label"] for r in test)
        if (test_labels[0], test_labels[1]) != (43, 6):
            raise ValueError("Prior TEST high-band transitions mismatch")
        enrich(test, db, ego, model, 3)
        rule = choice["selected"]
        if choice["accepted"]:
            selected, audit = revised_counts(old_test["selected"]["confusion"], test, rule)
        else:
            selected, audit = old_test["selected"], dict(vetoed_fp=43, vetoed_fn=6,
                reverted_fp=0, rescued_fn=0)
        atomic_json(output / "test_metrics.json", dict(identity=identity,
            legacy=old_test["legacy"], conditional=old_test["selected"], selected=selected,
            gate=rule, audit=audit, graph_calls_added=0,
            prior_graph_calls=old_test["routing"]["selected_graph"],
            evidence_graphs_reconstructed=len(val)+len(test)))
        with (output / "test_veto_evidence.jsonl").open("w") as f:
            for row in test:
                row["gate_allowed"] = gate(rule, row["evidence"]) if choice["accepted"] else True
                f.write(json.dumps(row, sort_keys=True) + "\n")
        prior_errors = list(_rows(previous / "test_errors_full_scores.jsonl"))
        prior_transitions = list(_rows(previous / "event_transition_audit.jsonl"))
        reverted = {(r["source_id"], r["source_line"]): r for r in test if not r["gate_allowed"]}
        errors = {(r["source_id"], r["source_line"]): r for r in prior_errors}
        for key, row in reverted.items():
            if row["label"] == 0:
                errors[key] = dict(source_id=key[0], source_line=key[1], label=0,
                    ml_score=row["ml_score"], graph_score=row["graph_score"], collision=True,
                    route_reason="evidence_gate_kept_lightgbm", prediction=1,
                    legacy_prediction=1, error="FP")
            else:
                if key not in errors or errors[key]["error"] != "FN":
                    raise ValueError("Reverted FN absent from prior error export")
                del errors[key]
        if len(errors) != selected["confusion"]["fp"] + selected["confusion"]["fn"]:
            raise ValueError("Final errors do not reconcile")
        with (output / "test_errors_full_scores.jsonl").open("w") as f:
            for key in sorted(errors):
                f.write(json.dumps(errors[key], sort_keys=True) + "\n")
        changes = [r for r in prior_transitions if (r["source_id"], r["source_line"]) not in reverted]
        if len(changes) != 51 - len(reverted):
            raise ValueError("Final transitions do not reconcile")
        with (output / "event_transition_audit.jsonl").open("w") as f:
            for row in changes:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        report = ["# Evidence-gated veto over frozen LightGBM v4 conditional routing", "",
            "Validation selected the gate before TEST labels were read. The original Host/graph models, "
            "scores, thresholds and graph construction remain unchanged.", "",
            f"Selected gate: **{rule}**; accepted: **{choice['accepted']}**.", "",
            "| Split | Policy | TP | FP | FN | TN | F1 |", "|---|---|---:|---:|---:|---:|---:|"]
        for split, doc in (("Validation", json.loads((output / "validation_metrics.json").read_text())),
                           ("TEST", json.loads((output / "test_metrics.json").read_text()))):
            for name in ("legacy", "conditional", "selected"):
                m = doc[name]; c = m["confusion"]
                report.append(f"| {split} | {name} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {m['f1']:.6f} |")
        report += ["", f"Only {len(val)} validation and {len(test)} TEST veto candidates needed graph reconstruction; "
            "no full GraphSAGE rerun was performed.",
            "The old TEST informed this research hypothesis. Its result is exploratory, not a fresh held-out confirmation. "
            "Independent host/time/campaign validation is still needed."]
        (output / "summary.md").write_text("\n".join(report) + "\n")
        return dict(validation=choice, test=selected)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    for name in ("manifest", "bundle", "previous", "cache", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--volume-root-ssd")
    args = parser.parse_args()
    run(args.manifest, args.bundle, args.previous, args.cache, args.output,
        volume_root_ssd=args.volume_root_ssd)


if __name__ == "__main__":
    main()
