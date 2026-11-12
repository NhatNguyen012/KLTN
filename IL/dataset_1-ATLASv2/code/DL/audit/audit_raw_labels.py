#!/usr/bin/env python3
"""Full CBC stream audit, reproducing legacy windows without changing source labels."""
from __future__ import annotations
import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import numpy as np

DL = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(DL / "model"), str(DL / "preprocess"), str(DL.parent)]
from research_paths import ROOT, validate_output_dir
from preprocess.label_refiner import LabelRefiner
from preprocess.cbc_adapter import CBCAdapter
from preprocess.common_schema import extract_basename
from build_network_shards import get_split_from_event


def utc(ts):
    return datetime.fromtimestamp(ts / 1e6, tz=timezone.utc).isoformat()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", type=Path, default=ROOT / "IL/dataset_1-ATLASv2/output/raw_cbc/atlasv2/data")
    ap.add_argument("--output-dir", type=Path, default=DL / "output/research_20261111/raw_audit")
    args = ap.parse_args()
    out = validate_output_dir(args.output_dir); out.mkdir(parents=True, exist_ok=True)
    ref = LabelRefiner(ROOT / "DATASET/ATLASv2_staged/reapr-ground-truth/atlasv2")
    adapter = CBCAdapter(ref)
    report, traces, positives = {}, [], []
    manifest = {r["sample_id"]:r for r in csv.DictReader((DL / "preprocess/output/split/network_sample_manifest.csv").open())}
    wanted = {"endpoint.event.netconn", "endpoint.event.procstart", "endpoint.event.crossproc"}
    for path in sorted(args.raw_dir.rglob("*.jsonl")):
        if path.parent.name != "cbc-edr": continue
        sc = path.stem.split("-")[-1]
        counts, missing, stage_counts, type_counts = Counter(), Counter(), Counter(), Counter()
        evs, line_ids = [], []
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for line_id, line in enumerate(f, 1):
                digest.update(line); counts["raw_rows"] += 1
                try: raw = json.loads(line)
                except ValueError:
                    counts["invalid_json"] += 1; continue
                if raw.get("type") not in wanted: continue
                e = adapter.parse_record(raw, sc)
                if e is None:
                    counts["rejected"] += 1; continue
                evs.append(e); line_ids.append(line_id); type_counts[e.event_type] += 1
                guids = ref.scenario_attack_guids.get(sc, set())
                is_actor = e.process_guid in guids
                if is_actor: counts["reapr_actor_events"] += 1
                if e.target_guid in guids and not is_actor:
                    counts["attack_target_benign_actor"] += 1
                    if not e.label: counts["attack_target_ignored"] += 1
                if is_actor and e.timestamp < ref.scenario_attack_micros.get(sc, 0):
                    counts["reapr_actor_before_gate"] += 1
                for k in ("remote_ip", "remote_port", "childproc_name", "crossproc_name"):
                    if raw.get(k) is None: missing[k] += 1
                if e.label:
                    counts["refined_positive"] += 1
                    stg = ref.get_event_stage(e)[1]; stage_counts[stg] += 1
                    positives.append(dict(source=path.name, line=line_id, scenario=sc, timestamp=utc(e.timestamp),
                        event_type=e.event_type, process=extract_basename(e.process_path),
                        target=e.target_path, remote_ip=e.remote_ip, remote_port=e.remote_port, stage=stg,
                        action=raw.get("action"), process_guid=e.process_guid))
        indexed = sorted(zip(evs, line_ids), key=lambda x:x[0].timestamp)
        evs, line_ids = [x[0] for x in indexed], [x[1] for x in indexed]
        if not evs: continue
        times = [e.timestamp for e in evs]
        memberships = defaultdict(set)
        w_idx, mismatches = 0, 0
        for start in range(times[0], times[-1] + 1, 30_000_000):
            lo, hi = bisect_left(times, start), bisect_right(times, start + 180_000_000)
            if hi - lo < 2: continue
            split = get_split_from_event(sc, times[lo])
            for chunk, cstart in enumerate(range(lo, hi, 512)):
                cend = min(cstart + 512, hi)
                sub = evs[cstart:cend]
                sid = f"{evs[0].hostname}_{sc}_w{w_idx:04d}_c{chunk:02d}"
                if sid not in manifest: continue  # legacy train undersampling
                stages = [ref.get_event_stage(e)[1] for e in sub if e.label]
                legacy_stage = stages[-1] if stages else 0
                old = manifest[sid]
                mismatches += int(int(old["stage"]) != legacy_stage or int(old["event_count"]) != len(sub))
                for idx in range(cstart,cend): memberships[line_ids[idx]].add(split)
                traces.append(dict(sample_id=sid, source=path.name, scenario=sc, split=split,
                    start=utc(times[cstart]), end=utc(times[cend-1]), stage=legacy_stage,
                    positive_events=len(stages), event_count=len(sub), stage_set="|".join(map(str,sorted(set(stages)))),
                    source_lines="|".join(str(line_ids[i]) for i in range(cstart,cend)),
                    label_stage_match=int(int(old["stage"]) == legacy_stage)))
            w_idx += 1
        report[path.name] = dict(counts=counts, missing=missing, types=type_counts, stages=stage_counts,
            sha256=digest.hexdigest(), first=utc(times[0]), last=utc(times[-1]),
            gate=utc(ref.scenario_attack_micros[sc]) if sc in ref.scenario_attack_micros else None,
            gate_after_file_end=ref.scenario_attack_micros.get(sc, 0) > times[-1],
            reconstructed_mismatches=mismatches,
            cross_split_source_events=sum(len(v)>1 for v in memberships.values()),
            unique_positive_guids=len({e.process_guid for e in evs if e.label}))
        print(path.name, dict(counts), "mismatches", mismatches, flush=True)
    for name, rows in [("window_trace.csv", traces), ("positive_events.csv", positives)]:
        if rows:
            with (out/name).open("w") as f:
                w=csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    temp=out/"raw_summary.json.tmp"; temp.write_text(json.dumps(report, indent=2));temp.replace(out/"raw_summary.json")


if __name__ == "__main__": main()
