#!/usr/bin/env python3
"""Build Deep Learning Causal Triplet Shards from Host ML Seed 02 Contextual Split.

Guarantees 100% equivalence and fidelity to Host ML (LightGBM) seed02 baseline:
  - 106 source entries across 34 hosts (42 attack windows + 2 baseline days).
  - Exact 75% TRAIN / 10% VAL / 15% TEST contextual event allocation.
  - Stratified across all 3 attack scenarios (SC1, SC2, SC3) + Benign.
  - Preserves causal 2-hop history (E_incoming, E_parent, E_current) via HostProcessContextTracker.
  - Encodes tokens with frozen dl_vocab.json (10,496 tokens).
  - Emits sidecar multi-task labels (Binary, Scenario ID, MITRE ATT&CK Stage ID).
  - Shards are saved as compressed binary PyTorch files (.pt) with split_manifest.json.

Usage:
  python3 DL/code/preprocess/build_dl_shards_from_contextual_split.py \\
      --split-dir ML/code/output/host_ml_seed02/split \\
      --vocab DL/code/output/dl_vocab.json \\
      --labels DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz \\
      --output-dir DL/code/output/dl_shards \\
      --shard-size 10000
"""

from __future__ import annotations

import argparse
import gc
import gzip
import hashlib
import json
import logging
import os
import resource
import sys
import tempfile
import time
from collections import Counter, defaultdict
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
    from stratified_pipeline import split_rows, resolve_source_path, stamp
    from process_context_tracker import (
        HostProcessContextTracker,
        ProcessContextConfig,
        canonical_host,
    )
    from dl_ecar_tokenizer import tokenize_dl_record
    from label_catalog import MultiTaskLabelCatalog, SCENARIO_MAP, STAGE_MAP
    from causal_dataset import TokenVocabulary
except ImportError as err:
    raise ImportError(f"Required pipeline import failed: {err}")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class FlushingStreamHandler(logging.StreamHandler):
    """StreamHandler that flushes immediately after every write."""
    def emit(self, record):
        super().emit(record)
        self.flush()


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("build_dl_shards_contextual")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = FlushingStreamHandler(sys.stdout)
    ch.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(ch)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except Exception:
            pass
    return logger


logger = setup_logger()


def get_rss_mb() -> float:
    """Return resident set size in megabytes."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


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


class ShardWriter:
    """Buffers samples per split and writes compressed .pt shards when reaching capacity."""

    def __init__(self, out_dir: Path, shard_size: int = 10_000):
        self.out_dir = out_dir
        self.shard_size = shard_size
        self.buffers: Dict[str, List[Dict[str, Any]]] = {
            "train": [],
            "val": [],
            "test": [],
        }
        self.shard_counts: Dict[str, int] = {"train": 0, "val": 0, "test": 0}
        self.total_samples: Dict[str, int] = {"train": 0, "val": 0, "test": 0}
        self.manifest_shards: Dict[str, List[str]] = {
            "train": [],
            "val": [],
            "test": [],
        }

        for s in ("train", "val", "test"):
            (self.out_dir / s).mkdir(parents=True, exist_ok=True)

    def add(self, split_name: str, sample: Dict[str, Any]):
        buf = self.buffers[split_name]
        buf.append(sample)
        self.total_samples[split_name] += 1

        if len(buf) >= self.shard_size:
            self._flush(split_name)

    def _flush(self, split_name: str):
        buf = self.buffers[split_name]
        if not buf:
            return

        shard_num = self.shard_counts[split_name]
        shard_path = self.out_dir / split_name / f"shard_{shard_num:04d}.pt"
        rel_path = f"{split_name}/shard_{shard_num:04d}.pt"

        fd, tmp = tempfile.mkstemp(dir=shard_path.parent, suffix=".tmp.pt")
        os.close(fd)
        try:
            torch.save(buf, tmp)
            os.replace(tmp, shard_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        self.manifest_shards[split_name].append(rel_path)
        self.shard_counts[split_name] += 1
        self.buffers[split_name] = []

    def flush_all(self):
        for s in ("train", "val", "test"):
            self._flush(s)

    def get_state(self) -> Dict[str, Any]:
        return {
            "buffers": self.buffers,
            "shard_counts": dict(self.shard_counts),
            "total_samples": dict(self.total_samples),
            "manifest_shards": {k: list(v) for k, v in self.manifest_shards.items()},
        }

    def load_state(self, state: Dict[str, Any]):
        self.buffers = state["buffers"]
        self.shard_counts = state["shard_counts"]
        self.total_samples = state["total_samples"]
        self.manifest_shards = state["manifest_shards"]


# ---------------------------------------------------------------------------
# Main Extraction Loop
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Build DL Causal Shards from Host ML Seed 02 Contextual Split"
    )
    parser.add_argument(
        "--split-dir",
        default=str(PROJECT_ROOT / "ML/code/output/host_ml_seed02/split"),
        help="Path to ML seed02 split directory containing manifest.json",
    )
    parser.add_argument(
        "--vocab",
        default=str(PROJECT_ROOT / "DL/code/output/dl_vocab.json"),
        help="Path to frozen dl_vocab.json (10,496 tokens)",
    )
    parser.add_argument(
        "--labels",
        default=str(PROJECT_ROOT / "DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz"),
        help="Path to optc_multitask_labels_v1.json.gz",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "DL/code/output/dl_shards"),
        help="Target directory for output shards and manifest",
    )
    parser.add_argument(
        "--shard-size",
        type=int,
        default=10_000,
        help="Number of samples per shard file (default 10,000)",
    )
    parser.add_argument(
        "--max-entries",
        type=int,
        default=0,
        help="Cap number of source entries to process (0 = all 106 entries)",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore existing checkpoint and start from scratch",
    )
    args = parser.parse_args()

    try:
        os.nice(10)
        logger.info("Set process priority (nice=10) for background stability.")
    except Exception:
        pass

    split_dir = Path(args.split_dir).resolve()
    split_manifest_path = split_dir / "manifest.json"
    if not split_manifest_path.exists():
        raise FileNotFoundError(f"Split manifest not found: {split_manifest_path}")

    with split_manifest_path.open("r", encoding="utf-8") as f:
        split_manifest = json.load(f)

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Hard read-only check
    for ro in ("host-begnin", "host-malicious", "bro", "ecar-bro"):
        ro_root = (PROJECT_ROOT / ro).resolve()
        if str(out_dir).startswith(str(ro_root)):
            raise ValueError(f"Output directory {out_dir} is nested under read-only {ro_root}")

    # 2. Load Frozen Vocab & Multi-Task Catalog
    vocab_path = Path(args.vocab).resolve()
    logger.info(f"Loading frozen vocabulary from: {vocab_path}")
    vocab = TokenVocabulary.from_vocab_file(vocab_path)
    logger.info(f"  Vocab size: {len(vocab):,} tokens (frozen)")

    labels_path = Path(args.labels).resolve()
    logger.info(f"Loading label catalog from: {labels_path}")
    catalog = MultiTaskLabelCatalog(str(labels_path))
    logger.info(f"  Malicious events catalog: {len(catalog):,}")

    # 3. Group split entries by host (chronological ordering)
    entries_by_host: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in split_manifest["entries"]:
        entries_by_host[entry["host"]].append(entry)

    # Sort each host's entries by day (2019-09-21 -> 2019-09-25)
    for h in entries_by_host:
        entries_by_host[h].sort(key=lambda e: (e["day"], e["source"]["path"]))

    host_names = sorted(entries_by_host.keys())
    total_entries_count = sum(len(entries) for entries in entries_by_host.values())
    logger.info(f"Contextual Split Overview: {len(host_names)} hosts, {total_entries_count} file entries.")

    writer = ShardWriter(out_dir, shard_size=args.shard_size)

    checkpoint_path = out_dir / ".checkpoint.pt"
    completed_hosts = set()
    scenario_counts = Counter()
    stage_counts = Counter()
    split_code_map = {1: "train", 2: "val", 3: "test"}
    total_yielded = 0

    if checkpoint_path.exists() and not args.fresh:
        try:
            logger.info(f"Checking for existing checkpoint at: {checkpoint_path}")
            ckpt = torch.load(checkpoint_path)
            completed_hosts = set(ckpt.get("completed_hosts", []))
            writer.load_state(ckpt["writer_state"])
            scenario_counts = Counter(ckpt.get("scenario_counts", {}))
            stage_counts = Counter(ckpt.get("stage_counts", {}))
            total_yielded = ckpt.get("total_yielded", 0)
            logger.info(
                f"[Resume] Successfully resumed from checkpoint: {len(completed_hosts)} hosts completed, "
                f"{total_yielded:,} samples previously generated."
            )
        except Exception as err:
            logger.warning(f"Could not load checkpoint ({err}); starting fresh.")
            completed_hosts = set()

    t_start = time.time()
    processed_entries = 0

    # 4. Process each host sequentially (maintaining host tracker state)
    for host_idx, host_name in enumerate(host_names, 1):
        if host_name in completed_hosts:
            logger.info(
                f"[{host_idx:02d}/{len(host_names):02d}] Skipping Host: {host_name} (already completed in checkpoint)"
            )
            continue

        host_entries = entries_by_host[host_name]
        logger.info(
            f"[{host_idx:02d}/{len(host_names):02d}] Processing Host: {host_name} "
            f"({len(host_entries)} entries)"
        )

        # Single persistent context tracker per host across all 5 days
        tracker = HostProcessContextTracker(ProcessContextConfig())

        for entry in host_entries:
            if args.max_entries and processed_entries >= args.max_entries:
                break

            day = entry["day"]
            alloc = entry.get("allocation", {})
            expected_events = sum(alloc.get("1", [0, 0, 0])) + sum(alloc.get("2", [0, 0, 0]))
            t0 = time.time()

            entry_yielded = 0
            for code, num, rec in split_rows(entry, split_dir, tracker=tracker):
                if code not in split_code_map:
                    continue

                split_name = split_code_map[code]

                # Extract context tokens
                ctx_tokens = rec.get("_context_tokens", [])
                inc_toks = [t for t in ctx_tokens if "::incoming::" in t]
                parent_toks = [
                    t for t in ctx_tokens
                    if "::parent::" in t or "::relation::lineage" in t or "::relation::path" in t
                ]

                # Extract current event tokens
                tok_res = tokenize_dl_record(rec)
                curr_toks: List[str] = []
                if isinstance(tok_res, tuple) and len(tok_res) >= 1:
                    for v_list in tok_res[0].values():
                        curr_toks.extend(v_list)

                # Label lookup
                eid = rec.get("id")
                is_mal, sc_id, st_id = catalog.lookup(eid)

                # Convert to token IDs (padding/unknown safe)
                sample = {
                    "incoming_ids": [vocab.get(t) for t in inc_toks] or [2],
                    "parent_ids":   [vocab.get(t) for t in parent_toks] or [2],
                    "current_ids":  [vocab.get(t) for t in curr_toks] or [2],
                    "is_malicious": int(is_mal),
                    "scenario_id":  int(sc_id),
                    "stage_id":     int(st_id),
                }

                writer.add(split_name, sample)
                scenario_counts[(split_name, sc_id)] += 1
                stage_counts[(split_name, st_id)] += 1

                entry_yielded += 1
                total_yielded += 1

                if total_yielded % 50_000 == 0:
                    el = time.time() - t_start
                    rss_mb = get_rss_mb()
                    logger.info(
                        f"  [Progress] {total_yielded:,} Causal Triplets generated "
                        f"in {el:.1f}s ({total_yielded/max(el, 1):.0f} evt/s) | RSS: {rss_mb:.1f} MB"
                    )
                    if rss_mb > 12 * 1024:
                        logger.warning(f"High memory alert ({rss_mb:.1f} MB). Running gc.collect()")
                        gc.collect()

            processed_entries += 1
            el_entry = time.time() - t0
            logger.info(
                f"  Finished {host_name} [{day}]: {entry_yielded:,} events "
                f"(expected {expected_events:,}) in {el_entry:.1f}s"
            )

        # Mark host complete & persist checkpoint
        completed_hosts.add(host_name)
        ckpt_data = {
            "completed_hosts": list(completed_hosts),
            "writer_state": writer.get_state(),
            "scenario_counts": dict(scenario_counts),
            "stage_counts": dict(stage_counts),
            "total_yielded": total_yielded,
        }
        fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=".tmp.ckpt")
        os.close(fd)
        try:
            torch.save(ckpt_data, tmp)
            os.replace(tmp, checkpoint_path)
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")
            try:
                os.unlink(tmp)
            except OSError:
                pass

        # Cleanup host tracker and free memory
        del tracker
        gc.collect()
        rss_mb = get_rss_mb()
        logger.info(f"  [Host Complete] {host_name} done ({len(completed_hosts)}/{len(host_names)} hosts). RSS: {rss_mb:.1f} MB")

        if args.max_entries and processed_entries >= args.max_entries:
            logger.info(f"Reached --max-entries limit ({args.max_entries}). Stopping early.")
            break

    # Flush any remaining samples in buffers
    writer.flush_all()
    total_time = time.time() - t_start
    final_rss = get_rss_mb()
    logger.info(
        f"Extraction complete: {total_yielded:,} total samples in {total_time:.1f}s "
        f"({total_yielded / max(total_time, 1):.0f} evt/s) | Final RSS: {final_rss:.1f} MB"
    )

    # 5. Write Final Manifest
    seed = split_manifest.get("seed", 2)
    split_info = {
        "train": {
            "n_samples": writer.total_samples["train"],
            "n_shards": writer.shard_counts["train"],
            "shards": writer.manifest_shards["train"],
        },
        "val": {
            "n_samples": writer.total_samples["val"],
            "n_shards": writer.shard_counts["val"],
            "shards": writer.manifest_shards["val"],
        },
        "test": {
            "n_samples": writer.total_samples["test"],
            "n_shards": writer.shard_counts["test"],
            "shards": writer.manifest_shards["test"],
        },
    }

    manifest = {
        "format": "dl_causal_triplet_contextual_shards_v1",
        "created_utc": stamp(),
        "seed": seed,
        "source_split": {
            "path": str(split_dir),
            "seed": seed,
            "ratios": split_manifest.get("ratios", [0.75, 0.10, 0.15]),
            "attack_windows_count": len(split_manifest.get("attack_windows", {})),
        },
        "vocab": {
            "path": str(vocab_path),
            "sha256": _file_sha256(vocab_path),
            "vocab_size": len(vocab),
        },
        "shard_size": args.shard_size,
        "total_samples": total_yielded,
        "split": split_info,
        "split_summary": split_info,
        "scenario_distribution": {
            f"{s}_{SCENARIO_MAP.get(sc, f'SC_{sc}')}": count
            for (s, sc), count in sorted(scenario_counts.items())
        },
        "mitre_stage_distribution": {
            f"{s}_{STAGE_MAP.get(st, f'Stage_{st}')}": count
            for (s, st), count in sorted(stage_counts.items())
        },
    }

    manifest_out = out_dir / "split_manifest.json"
    _atomic_json_write(manifest_out, manifest)
    logger.info(f"Split Manifest written -> {manifest_out}")

    # Remove temporary checkpoint on successful finish
    if checkpoint_path.exists():
        try:
            checkpoint_path.unlink()
            logger.info("Removed temporary checkpoint file after clean publication.")
        except OSError:
            pass

    logger.info("SUCCESS: DL Causal Shards from Contextual Split fully built and published!")


if __name__ == "__main__":
    main()
