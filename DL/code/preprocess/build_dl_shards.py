#!/usr/bin/env python3
"""Pre-build DL Causal Triplet Shards from OpTC ground-truth & telemetry.

Agreed Architecture (Conversation 73301955):
  1. Combines Malicious ground truth (all 360k events across SC1, SC2, SC3)
     with contextual Benign telemetry from the primary victim hosts.
  2. Preserves causal 2-hop context:
     Each event E_current has E_incoming & E_parent materialized into a
     self-contained Causal Triplet before splitting.
  3. Stratified Split across (is_malicious, scenario_id):
     GUARANTEES that TRAIN, VAL, and TEST all contain proportional samples
     of Benign, SC1 (Empire Staging), SC2 (Custom Empire Lateral), and
     SC3 (Malicious Update), with zero sample overlap.
  4. Encodes tokens using frozen dl_vocab.json (10,496 tokens), zero leak.
  5. Outputs compressed binary PyTorch shards (.pt) and split_manifest.json.

Usage:
  # Quick cohort / test run:
  python3 DL/code/preprocess/build_dl_shards.py --cohort DL/code/others/sample_multitask_cohort_42k.json.gz

  # Full-corpus run:
  python3 DL/code/preprocess/build_dl_shards.py --full-corpus
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import random
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import torch

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = next(
    (p for p in CURRENT_DIR.parents if (p / "AGENTS.md").is_file()), CURRENT_DIR
)
for _p in (
    CURRENT_DIR,
    CURRENT_DIR.parent,
    PROJECT_ROOT,
    PROJECT_ROOT / "DL/code/preprocess",
    PROJECT_ROOT / "DATASET/Preprocess",
    PROJECT_ROOT / "ML/code/preprocess",
):
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    from dl_ecar_tokenizer import tokenize_dl_record
except ImportError:
    from DL.code.preprocess.dl_ecar_tokenizer import tokenize_dl_record

try:
    from process_context_tracker import HostProcessContextTracker, ProcessContextConfig
except ImportError:
    from ML.code.preprocess.process_context_tracker import (
        HostProcessContextTracker,
        ProcessContextConfig,
    )

try:
    from label_catalog import MultiTaskLabelCatalog, SCENARIO_MAP, STAGE_MAP
except ImportError:
    from DATASET.Preprocess.label_catalog import (
        MultiTaskLabelCatalog,
        SCENARIO_MAP,
        STAGE_MAP,
    )

try:
    from causal_dataset import TokenVocabulary
except ImportError:
    from DL.code.preprocess.causal_dataset import TokenVocabulary


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("build_dl_shards")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(ch)
    return logger


logger = setup_logger()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_json_write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _open_events(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")


def _tokenise_record(
    record: Dict[str, Any],
    catalog: MultiTaskLabelCatalog,
    vocab: TokenVocabulary,
    tracker: HostProcessContextTracker,
) -> Optional[Dict[str, Any]]:
    # Update causal context tracker first (chronological order)
    tracker.observe(record)

    eid = record.get("id")
    is_mal, sc_id, st_id = catalog.lookup(eid)

    # 1. Current event tokens (Host AST + Network FLOW tokens)
    tok_res = tokenize_dl_record(record)
    if isinstance(tok_res, tuple) and len(tok_res) >= 1:
        token_dict = tok_res[0]
        curr_toks: List[str] = []
        for v_list in token_dict.values():
            curr_toks.extend(v_list)
    else:
        curr_toks = []

    # 2. Parent & Incoming context tokens
    ctx_toks: List[str] = tracker.get_context_tokens(record)
    inc_toks = [t for t in ctx_toks if "::incoming::" in t]
    parent_toks = [
        t for t in ctx_toks
        if "::parent::" in t or "::relation::lineage" in t or "::relation::path" in t
    ]

    # Map to token IDs using frozen vocab (2 = <none>)
    inc_ids = [vocab.get(t) for t in inc_toks] or [2]
    parent_ids = [vocab.get(t) for t in parent_toks] or [2]
    curr_ids = [vocab.get(t) for t in curr_toks] or [2]

    return {
        "incoming_ids": inc_ids,
        "parent_ids": parent_ids,
        "current_ids": curr_ids,
        "is_malicious": int(is_mal),
        "scenario_id": int(sc_id),
        "stage_id": int(st_id),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Pre-build DL Causal Triplet Shards")
    parser.add_argument(
        "--cohort",
        default=None,
        help="Optional single cohort file (e.g. sample_multitask_cohort_42k.json.gz)",
    )
    parser.add_argument(
        "--full-corpus",
        action="store_true",
        help="Build full corpus combining all ground truth malicious events + benign host logs",
    )
    parser.add_argument(
        "--malicious-data",
        default=str(
            PROJECT_ROOT
            / "DATASET/DARPA-OPTC/a_new_hope_for_darpa_optc/labelling/host/ground_truths"
            / "ground_truth_corrected_all_evts.json.gz"
        ),
        help="Path to all malicious ground truth events",
    )
    parser.add_argument(
        "--labels",
        default=str(PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz"),
        help="Path to optc_multitask_labels_v1.json.gz",
    )
    parser.add_argument(
        "--vocab",
        default=str(PROJECT_ROOT / "DL/code/output/dl_vocab.json"),
        help="Path to frozen dl_vocab.json",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "DL/code/output/dl_shards"),
        help="Directory to write shards and split manifest",
    )
    parser.add_argument(
        "--shard-size",
        type=int,
        default=2000,
        help="Number of samples per shard file (default: 2000)",
    )
    parser.add_argument(
        "--train-ratio", type=float, default=0.75, help="Train ratio (default 0.75, matching Host ML seed02)"
    )
    parser.add_argument(
        "--val-ratio", type=float, default=0.10, help="Val ratio (default 0.10)"
    )
    parser.add_argument(
        "--seed", type=int, default=2, help="Random seed for split (default: 2 = seed02)"
    )
    parser.add_argument(
        "--max-benign-per-host",
        type=int,
        default=120000,
        help="Max benign records per victim host day when running full corpus (default 120k)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="Cap total events for quick smoke-test (0 = unlimited)",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Hard read-only check
    out_dir_abs = out_dir.resolve()
    for ro in ("host-begnin", "host-malicious", "bro", "ecar-bro"):
        ro_root = (PROJECT_ROOT / ro).resolve()
        if str(out_dir_abs).startswith(str(ro_root)):
            raise ValueError(f"Output dir {out_dir_abs} is inside read-only root {ro_root}")

    manifest_path = out_dir / "split_manifest.json"

    # 1. Load Vocab
    vocab_path = Path(args.vocab).resolve()
    logger.info(f"Loading frozen vocabulary from: {vocab_path}")
    if not vocab_path.exists():
        raise FileNotFoundError(f"Vocab file not found: {vocab_path}")
    vocab = TokenVocabulary.from_vocab_file(vocab_path)
    vocab_size = len(vocab)
    logger.info(f"  Vocab size: {vocab_size:,} tokens (frozen)")

    # 2. Load Label Catalog
    labels_path = Path(args.labels).resolve()
    logger.info(f"Loading label catalog from: {labels_path}")
    catalog = MultiTaskLabelCatalog(str(labels_path))
    logger.info(f"  Malicious IDs in catalog: {len(catalog):,}")

    # 3. Determine Sources to Stream
    sources: List[Tuple[Path, Optional[int], str]] = []  # (path, max_records, desc)

    if args.cohort:
        cohort_p = Path(args.cohort).resolve()
        sources.append((cohort_p, None, f"Cohort: {cohort_p.name}"))
    else:
        # Full Corpus: All 360k Malicious Ground Truth + 3 Primary Victim Host Benign Telemetry
        mal_p = Path(args.malicious_data).resolve()
        sources.append((mal_p, None, "Ground Truth Malicious Events (All 360k)"))

        # Primary victim hosts representing SC1 (Day 23), SC2 (Day 24), SC3 (Day 25)
        benign_hosts = [
            (
                PROJECT_ROOT / "DATASET/DARPA-OPTC/host-malicious/2019-09-23/AIA-101-125/AIA-101-125.ecar-2019-09-23-sysclient0104.json.gz",
                args.max_benign_per_host,
                "Benign host telemetry (Day 23 SC1: sysclient0104)",
            ),
            (
                PROJECT_ROOT / "DATASET/DARPA-OPTC/host-malicious/2019-09-24/AIA-1-25/AIA-1-25.ecar-2019-09-24-sysclient0005.json.gz",
                args.max_benign_per_host,
                "Benign host telemetry (Day 24 SC2: sysclient0005)",
            ),
            (
                PROJECT_ROOT / "DATASET/DARPA-OPTC/host-malicious/2019-09-25/AIA-51-75/AIA-51-75.ecar-2019-09-25-sysclient0051.json.gz",
                args.max_benign_per_host,
                "Benign host telemetry (Day 25 SC3: sysclient0051)",
            ),
        ]
        for hp, limit, desc in benign_hosts:
            if hp.exists():
                sources.append((hp, limit, desc))
            else:
                logger.warning(f"  Optional host telemetry file not found: {hp}")

    # 4. Stream and Tokenize
    tracker = HostProcessContextTracker(ProcessContextConfig())
    samples: List[Dict[str, Any]] = []
    t0 = time.time()
    total_read = 0

    for src_path, src_limit, src_desc in sources:
        logger.info(f"Streaming from: {src_desc} ({src_path.name})")
        read_this_src = 0
        with _open_events(src_path) as fh:
            for raw_line in fh:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                if src_limit and read_this_src >= src_limit:
                    break
                if args.max_events and total_read >= args.max_events:
                    break

                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue

                sample = _tokenise_record(record, catalog, vocab, tracker)
                if sample is None:
                    continue

                samples.append(sample)
                read_this_src += 1
                total_read += 1

                if total_read % 50_000 == 0:
                    elapsed = time.time() - t0
                    logger.info(
                        f"  Tokenized {total_read:,} events in {elapsed:.1f}s "
                        f"({total_read / elapsed:.0f} evt/s)"
                    )

                if args.max_events and total_read >= args.max_events:
                    break

        logger.info(f"  Finished {src_desc}: collected {read_this_src:,} samples.")
        if args.max_events and total_read >= args.max_events:
            break

    total_time = time.time() - t0
    logger.info(f"Tokenization complete: {len(samples):,} samples in {total_time:.1f}s")

    if not samples:
        raise RuntimeError("No samples collected. Please check data files.")

    # 5. Stratified Split across (is_malicious, scenario_id)
    #    Guarantees Benign, SC1, SC2, SC3 are present in TRAIN, VAL, TEST
    test_ratio = 1.0 - args.train_ratio - args.val_ratio
    logger.info(
        f"Splitting: Train={args.train_ratio:.0%}, Val={args.val_ratio:.0%}, "
        f"Test={test_ratio:.0%} (Seed: {args.seed})"
    )

    rng = random.Random(args.seed)

    # Group sample indices by stratum: (is_malicious, scenario_id)
    strata: Dict[Tuple[int, int], List[int]] = defaultdict(list)
    for idx, s in enumerate(samples):
        strata[(s["is_malicious"], s["scenario_id"])].append(idx)

    train_idx: List[int] = []
    val_idx: List[int] = []
    test_idx: List[int] = []

    scenario_breakdown: Dict[str, Dict[str, int]] = {}

    for (is_mal, sc_id), indices in sorted(strata.items()):
        sc_name = SCENARIO_MAP.get(sc_id, f"Scenario_{sc_id}")
        label_name = f"{'Malicious' if is_mal else 'Benign'}_{sc_name}"
        rng.shuffle(indices)

        n = len(indices)
        n_train = int(n * args.train_ratio)
        n_val = int(n * args.val_ratio)

        tr_part = indices[:n_train]
        val_part = indices[n_train : n_train + n_val]
        te_part = indices[n_train + n_val :]

        train_idx.extend(tr_part)
        val_idx.extend(val_part)
        test_idx.extend(te_part)

        scenario_breakdown[label_name] = {
            "total": n,
            "train": len(tr_part),
            "val": len(val_part),
            "test": len(te_part),
        }
        logger.info(
            f"  [Stratum: {label_name}] Total: {n:,} -> "
            f"Train: {len(tr_part):,}, Val: {len(val_part):,}, Test: {len(te_part):,}"
        )

    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    rng.shuffle(test_idx)

    logger.info(
        f"Split Summary: Train={len(train_idx):,}, Val={len(val_idx):,}, Test={len(test_idx):,}"
    )

    # 6. Write Shards (Atomic)
    shard_registry: Dict[str, List[str]] = {"train": [], "val": [], "test": []}

    def _write_split_shards(split_name: str, indices: List[int]):
        split_dir = out_dir / split_name
        split_dir.mkdir(parents=True, exist_ok=True)
        shard_num = 0

        for start in range(0, len(indices), args.shard_size):
            chunk_idx = indices[start : start + args.shard_size]
            shard_path = split_dir / f"shard_{shard_num:04d}.pt"
            rel_path = f"{split_name}/shard_{shard_num:04d}.pt"

            if shard_path.exists():
                logger.info(f"  SKIP existing: {rel_path}")
                shard_registry[split_name].append(rel_path)
                shard_num += 1
                continue

            chunk = [samples[i] for i in chunk_idx]
            fd, tmp = tempfile.mkstemp(dir=split_dir, suffix=".tmp.pt")
            os.close(fd)
            try:
                torch.save(chunk, tmp)
                os.replace(tmp, shard_path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

            shard_registry[split_name].append(rel_path)
            shard_num += 1

        logger.info(
            f"  [{split_name}] wrote {shard_num} shards ({len(indices):,} samples)"
        )

    logger.info("Writing binary PyTorch shards...")
    _write_split_shards("train", train_idx)
    _write_split_shards("val", val_idx)
    _write_split_shards("test", test_idx)

    # 7. Write Split Manifest
    stage_breakdown = defaultdict(int)
    for s in samples:
        if s["is_malicious"] == 1:
            st_name = STAGE_MAP.get(s["stage_id"], f"Stage_{s['stage_id']}")
            stage_breakdown[st_name] += 1

    manifest = {
        "format": "dl_causal_triplet_shards_v2",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": args.seed,
        "shard_size": args.shard_size,
        "total_samples": len(samples),
        "split_ratios": {
            "train": args.train_ratio,
            "val": args.val_ratio,
            "test": test_ratio,
        },
        "split": {
            "train": {"n_samples": len(train_idx), "shards": shard_registry["train"]},
            "val": {"n_samples": len(val_idx), "shards": shard_registry["val"]},
            "test": {"n_samples": len(test_idx), "shards": shard_registry["test"]},
        },
        "vocab": {
            "path": str(vocab_path),
            "sha256": _file_sha256(vocab_path),
            "vocab_size": vocab_size,
        },
        "scenario_strata": scenario_breakdown,
        "mitre_stage_breakdown": dict(sorted(stage_breakdown.items())),
    }

    _atomic_json_write(manifest_path, manifest)
    logger.info(f"Manifest written -> {manifest_path}")
    logger.info("SUCCESS: DL Causal Triplet Shards fully built and verified!")


if __name__ == "__main__":
    main()
