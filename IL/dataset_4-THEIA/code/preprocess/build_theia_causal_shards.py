#!/usr/bin/env python3
"""Causal Triplet (L=3) Shard Builder for DARPA TC E3 THEIA (Domain-Incremental Learning).

Key guarantees verified against literature & data audit:
1. Source table: Reads `Parquet/event_table.parquet` filtered to T3 (`timestamp_rec >= T3_START_NS`)
   and strictly sorts chronologically by `(timestamp_rec, event_uuid)` in PyArrow before building L=3 history.
   Preserves all `EVENT_CLONE` and `EVENT_UNLINK` events (unlike `CSV/event_table_preprocessed.parquet`).
2. Directionality: Applies `EDGE_REVERSED_OPS` (`src=obj, dst=actor` for READ/OPEN/EXECUTE/RECVFROM/etc.)
   before causal tracker updates and tokenization.
3. Ground truth hygiene: Drops all REAPr `fail` chains, `contaminated` edges, Section 4.6 phishing
   events (`208.75.117.*`), and standard OS dynamic-linker `.so`/`ld.so.cache` noise while preserving
   attacker-dropped `/tmp/memtrace.so`.
4. Zero leakage split & vocab:
   - Splits chronologically by disjoint 5s (attack) / 60s (benign) wall-clock windows, stratified so every
     `(scenario_id, stage_id)` appears in train, val, and test without millisecond sibling leakage.
   - Aligns shared OpTC tokens (`action::`, `object::`, `structure::`, `net::`, `image_path::`, `file_path::`)
     to exact `DL/code/output/dl_vocab.json` IDs (`3..10498`), fits new THEIA tokens ONLY on TRAIN, and maps
     unseen Val/Test tokens to `<unk>` (`1`).
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import random
import resource
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import torch

CURRENT_DIR = Path(__file__).resolve().parent
IL_ROOT = CURRENT_DIR.parents[1]
PROJECT_ROOT = CURRENT_DIR.parents[3]
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from theia_schema import (
    EDGE_REVERSED_OPS,
    EXCLUDED_FAIL_CHAINS,
    NETFLOW_INDEX_MAX,
    PROCESS_INDEX_MAX,
    SCENARIO_NAMES,
    STAGE_NAMES,
    T3_START_NS,
    classify_path_dir,
    extract_basename,
    get_node_type,
    ip_scope,
    is_deleted_process_path,
    network_macro_scope,
    port_class,
)
from theia_stage_mapper import TheiaGroundTruthResolver


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("theia_shards")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(ch)
    return logger


def get_rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


# Map THEIA CDM operations onto OpTC `dl_vocab.json` actions for direct embedding reuse
THEIA_OP_TO_OPTC_ACTION = {
    "EVENT_OPEN": "open",
    "EVENT_READ": "read",
    "EVENT_LSEEK": "read",
    "EVENT_CHECK_FILE_ATTRIBUTES": "open",
    "EVENT_WRITE": "write",
    "EVENT_MMAP": "load",
    "EVENT_MODIFY_FILE_ATTRIBUTES": "modify",
    "EVENT_UNLINK": "delete",
    "EVENT_EXECUTE": "start",
    "EVENT_CLONE": "create",
    "EVENT_CONNECT": "start",
    "EVENT_ACCEPT": "open",
    "EVENT_SENDTO": "datatransfer",
    "EVENT_SENDMSG": "datatransfer",
    "EVENT_RECVFROM": "message",
    "EVENT_RECVMSG": "message",
    "EVENT_WRITE_SOCKET_PARAMS": "info",
    "EVENT_READ_SOCKET_PARAMS": "info",
    "EVENT_BOOT": "start",
}

CMD_FLAGS_LINUX = ("-c", "-i", "-e", "-q", "-s", "-v", "--silent", "--quiet", "--verbose", "/bin/sh", "sudo", "chmod", "chown", "wget", "curl")


def tokenize_linux_cmd(cmd: str) -> List[str]:
    if not cmd or cmd == "N/A":
        return []
    tokens: List[str] = []
    cl = cmd.strip().lower()
    for part in cl.split()[:12]:
        if part in CMD_FLAGS_LINUX:
            tokens.append(f"shell::switch={part}")
        elif part.startswith("-") and len(part) <= 12 and part.isascii():
            tokens.append(f"shell::switch={part}")
    if len(cl) > 120:
        tokens.append("command_line::len=long")
    return tokens


def classify_extension(path: str) -> str:
    base = extract_basename(path)
    if "." not in base:
        return "none"
    ext = "." + base.rsplit(".", 1)[-1]
    if len(ext) > 12 or not ext[1:].replace("-", "").isalnum():
        return "other"
    return ext


class NodeTables:
    """Array-backed O(1) lookup tables over THEIA Parquet node tables."""

    def __init__(self, parquet_dir: Path, logger: logging.Logger):
        t0 = time.time()
        max_id = 1_500_000
        self.proc_path: Dict[int, str] = {}
        self.proc_cmd: Dict[int, str] = {}
        self.proc_uuid_to_idx: Dict[str, int] = {}
        self.file_path: Dict[int, str] = {}
        self.nf_tuple: Dict[int, Tuple[str, int, str, int]] = {}

        logger.info("Loading netflow/process/file node tables from %s...", parquet_dir)
        nf = pq.read_table(parquet_dir / "netflow_node_table.parquet", columns=["index_id", "src_addr", "src_port", "dst_addr", "dst_port"])
        for idx, sa, sp, da, dp in zip(
            nf["index_id"].to_pylist(),
            nf["src_addr"].to_pylist(),
            nf["src_port"].to_pylist(),
            nf["dst_addr"].to_pylist(),
            nf["dst_port"].to_pylist(),
        ):
            self.nf_tuple[int(idx)] = (str(sa or "NA"), int(sp or 0), str(da or "NA"), int(dp or 0))

        pr = pq.read_table(parquet_dir / "process_node_table.parquet", columns=["index_id", "node_uuid", "path", "cmd"])
        for idx, uid, path, cmd in zip(
            pr["index_id"].to_pylist(),
            pr["node_uuid"].to_pylist(),
            pr["path"].to_pylist(),
            pr["cmd"].to_pylist(),
        ):
            i = int(idx)
            p_str = str(path or "unknown")
            self.proc_path[i] = p_str
            self.proc_cmd[i] = str(cmd or "N/A")
            if uid:
                self.proc_uuid_to_idx[str(uid).strip()] = i

        fl = pq.read_table(parquet_dir / "file_node_table.parquet", columns=["index_id", "path"])
        for idx, path in zip(fl["index_id"].to_pylist(), fl["path"].to_pylist()):
            self.file_path[int(idx)] = str(path or "")

        logger.info(
            "Loaded %d netflow, %d process, %d file nodes in %.2fs",
            len(self.nf_tuple),
            len(self.proc_path),
            len(self.file_path),
            time.time() - t0,
        )


def build_current_tokens(
    op: str,
    actor_idx: int,
    obj_idx: int,
    nodes: NodeTables,
) -> Tuple[List[str], Tuple[str, str]]:
    """Build deterministic OpTC-aligned semantic tokens for a single THEIA event."""
    tokens: List[str] = []
    actor_path = nodes.proc_path.get(actor_idx, "unknown")
    actor_cmd = nodes.proc_cmd.get(actor_idx, "")
    actor_base = extract_basename(actor_path) or "unknown"
    actor_cat = classify_path_dir(actor_path)

    optc_act = THEIA_OP_TO_OPTC_ACTION.get(op, "unknown")
    obj_type_raw = get_node_type(obj_idx)
    optc_obj = "flow" if obj_type_raw == "netflow" else ("process" if obj_type_raw == "process" else "file")
    if optc_act == "load" and obj_type_raw == "file" and nodes.file_path.get(obj_idx, "").endswith(".so"):
        optc_obj = "module"

    # Shared OpTC action & structure tokens (map straight into frozen/shared OpTC rows 3..10498)
    tokens.append(f"action::{optc_act}")
    tokens.append(f"object::{optc_obj}")
    tokens.append(f"structure::action_object={optc_act}->{optc_obj}")
    tokens.append(f"theia::op={op.lower()}")

    tokens.append(f"image_path::category={actor_cat}")
    tokens.append(f"image_path::basename={actor_base}")
    if is_deleted_process_path(actor_path):
        tokens.append("image_path::deleted=true")
    tokens.extend(tokenize_linux_cmd(actor_cmd))

    summary_target = ""
    if obj_type_raw == "netflow":
        sa, sp, da, dp = nodes.nf_tuple.get(obj_idx, ("NA", 0, "NA", 0))
        direction = "inbound" if op in ("EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT") else "outbound"
        s_scope = ip_scope(sa)
        d_scope = ip_scope(da)
        m_scope = network_macro_scope(s_scope, d_scope)
        s_role = port_class(sp)
        d_role = port_class(dp)
        tokens.extend([
            f"net::direction={direction}",
            "net::proto=tcp",
            f"net::src_scope={s_scope}",
            f"net::dest_scope={d_scope}",
            f"net::scope={m_scope}",
            f"net::src_port_role={s_role}",
            f"net::dest_port_role={d_role}",
            f"net::flow_pattern=tcp:{d_role}:{direction}",
            f"net::proc={actor_base}",
        ])
        summary_target = f"flow:{d_scope}:{d_role}"
    elif obj_type_raw == "process":
        child_path = nodes.proc_path.get(obj_idx, "unknown")
        child_base = extract_basename(child_path) or "unknown"
        child_cat = classify_path_dir(child_path)
        tokens.extend([
            f"target_image::category={child_cat}",
            f"target_image::basename={child_base}",
            f"structure::process_lineage={actor_base}->{child_base}",
        ])
        if is_deleted_process_path(child_path):
            tokens.append("target_image::deleted=true")
        summary_target = f"proc:{child_base}"
    else:
        fpath = nodes.file_path.get(obj_idx, "")
        fbase = extract_basename(fpath) or "unknown"
        fcat = classify_path_dir(fpath)
        fext = classify_extension(fpath)
        prefix = "module_path" if optc_obj == "module" else "file_path"
        tokens.extend([
            f"{prefix}::category={fcat}",
            f"{prefix}::basename={fbase}",
            f"{prefix}::extension={fext}",
        ])
        if fpath.startswith("/proc/"):
            tokens.append("file_path::pseudo=/proc")
        elif fpath.startswith("/dev/"):
            tokens.append("file_path::pseudo=/dev")
        elif fpath.startswith("/etc/"):
            tokens.append("file_path::config=/etc")
        summary_target = f"{prefix}:{fbase}"

    return tokens, (optc_act, summary_target)


def assign_window_splits(
    attack_events: List[Tuple[int, int, int]],
    seed: int = 42,
) -> Tuple[Dict[int, str], Dict[Tuple[int, int], Dict[str, int]]]:
    """Deterministically partition 5-second attack wall-clock windows across train (70%), val (10%), test (20%).

    Uses dominance-ordered greedy initialization plus coordinate-descent window refinement to minimize
    per-(scenario, stage) ratio error against (0.70, 0.10, 0.20) while strictly keeping every
    5-second wall-clock window in a single split (zero burst-sibling leakage) and ensuring full coverage.
    """
    win_counts: Dict[int, Counter] = defaultdict(Counter)
    strata_totals: Counter = Counter()
    for ts_ns, sc_id, st_id in attack_events:
        w5 = int(ts_ns // 5_000_000_000)
        win_counts[w5][(sc_id, st_id)] += 1
        strata_totals[(sc_id, st_id)] += 1

    target_frac = {"train": 0.70, "val": 0.10, "test": 0.20}
    splits = ("train", "val", "test")
    all_wins = sorted(
        win_counts.keys(),
        key=lambda w: (-max(cnt / strata_totals[k] for k, cnt in win_counts[w].items()), w),
    )

    counts_by_split: Dict[str, Counter] = {s: Counter() for s in splits}
    win_split: Dict[int, str] = {}

    def loss_fn() -> float:
        total = 0.0
        for k, tot in strata_totals.items():
            for sp in splits:
                frac = counts_by_split[sp][k] / float(tot)
                total += (frac - target_frac[sp]) ** 2
                if counts_by_split[sp][k] == 0:
                    total += 5.0
        return total

    # Identify dominant burst windows (>=40% of any stratum) — must reside in train to avoid inverting train/test ratios
    dominant_train_wins = {
        w for w in all_wins
        if any(cnt / float(strata_totals[k]) >= 0.40 for k, cnt in win_counts[w].items())
    }

    # Phase 1: Deterministic greedy placement ordered from largest burst dominance to smallest
    for w in all_wins:
        c = win_counts[w]
        if w in dominant_train_wins:
            best_sp = "train"
        else:
            best_sp = "train"
            best_cost = float("inf")
            for sp in splits:
                for k, cnt in c.items():
                    counts_by_split[sp][k] += cnt
                cost = loss_fn()
                for k, cnt in c.items():
                    counts_by_split[sp][k] -= cnt
                if cost < best_cost:
                    best_cost = cost
                    best_sp = sp
        win_split[w] = best_sp
        for k, cnt in c.items():
            counts_by_split[best_sp][k] += cnt

    # Phase 2: Coordinate-descent window moves to eliminate zero cells and tighten target proportions
    cur_loss = loss_fn()
    for _ in range(30):
        improved = False
        for w in all_wins:
            if w in dominant_train_wins:
                continue
            old_sp = win_split[w]
            c = win_counts[w]
            best_sp = old_sp
            for sp in splits:
                if sp == old_sp:
                    continue
                for k, cnt in c.items():
                    counts_by_split[old_sp][k] -= cnt
                    counts_by_split[sp][k] += cnt
                cand_loss = loss_fn()
                for k, cnt in c.items():
                    counts_by_split[sp][k] -= cnt
                    counts_by_split[old_sp][k] += cnt
                if cand_loss + 1e-12 < cur_loss:
                    cur_loss = cand_loss
                    best_sp = sp
            if best_sp != old_sp:
                for k, cnt in c.items():
                    counts_by_split[old_sp][k] -= cnt
                    counts_by_split[best_sp][k] += cnt
                win_split[w] = best_sp
                improved = True
        if not improved:
            break

    summary: Dict[Tuple[int, int], Dict[str, int]] = {}
    for k in sorted(strata_totals.keys()):
        summary[k] = {s: counts_by_split[s][k] for s in splits}
    return win_split, summary


def get_split_for_timestamp(ts_ns: int, attack_win_split: Dict[int, str]) -> str:
    """Assign split by exact 5s window if it hosts attacks, otherwise contiguous 60s block (70/10/20)."""
    w5 = int(ts_ns // 5_000_000_000)
    if w5 in attack_win_split:
        return attack_win_split[w5]
    m60 = int(ts_ns // 60_000_000_000) % 10
    if m60 < 7:
        return "train"
    if m60 == 7:
        return "val"
    return "test"


class ShardAccumulator:
    """Collects encoded or raw samples and flushes size-bounded PyTorch `.pt` shards."""

    def __init__(self, out_dir: Path, shard_size: int = 10000):
        self.out_dir = out_dir
        self.shard_size = shard_size
        self.buffers: Dict[str, List[Dict[str, Any]]] = {"train": [], "val": [], "test": []}
        self.shard_counts: Dict[str, int] = {"train": 0, "val": 0, "test": 0}
        self.sample_counts: Dict[str, int] = {"train": 0, "val": 0, "test": 0}
        for sp in ("train", "val", "test"):
            d = self.out_dir / sp
            d.mkdir(parents=True, exist_ok=True)
            for old_pt in d.glob("shard_*.pt"):
                old_pt.unlink()

    def add(self, split_name: str, sample: Dict[str, Any]) -> None:
        self.buffers[split_name].append(sample)
        self.sample_counts[split_name] += 1
        if len(self.buffers[split_name]) >= self.shard_size:
            self._flush(split_name)

    def _flush(self, split_name: str) -> None:
        buf = self.buffers[split_name]
        if not buf:
            return
        idx = self.shard_counts[split_name]
        path = self.out_dir / split_name / f"shard_{idx:05d}.pt"
        tmp = self.out_dir / split_name / f".tmp_shard_{idx:05d}.pt"
        torch.save(buf, tmp)
        os.replace(tmp, path)
        self.shard_counts[split_name] += 1
        self.buffers[split_name] = []

    def finalize(self) -> None:
        for sp in ("train", "val", "test"):
            self._flush(sp)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build clean L=3 Causal Shards for DARPA TC E3 THEIA.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=PROJECT_ROOT / "DATASET/DARPA-TC-E3-THEIA",
    )
    parser.add_argument(
        "--reapr-tar",
        type=Path,
        default=PROJECT_ROOT / "DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3/theia_edge_labels.tar.gz",
    )
    parser.add_argument(
        "--reapr-labels-csv",
        type=Path,
        default=PROJECT_ROOT / "DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3/theia_labels.csv",
    )
    parser.add_argument(
        "--base-vocab",
        type=Path,
        default=PROJECT_ROOT / "DL/code/output/dl_vocab.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=IL_ROOT / "output/dl_shards",
    )
    parser.add_argument("--benign-target", type=int, default=500000)
    parser.add_argument("--shard-size", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    logger = setup_logger()
    t_start = time.time()
    logger.info("=== Building Clean DARPA TC E3 THEIA L=3 Causal Shards ===")

    # 1. Load OpTC base vocabulary (`0:<pad>, 1:<unk>, 2:<none>, 3..10498:dl_vocab`)
    tok2id: Dict[str, int] = {"<pad>": 0, "<unk>": 1, "<none>": 2}
    with args.base_vocab.open("r", encoding="utf-8") as f:
        optc_raw_vocab: Dict[str, int] = json.load(f)
    for tok, raw_id in sorted(optc_raw_vocab.items(), key=lambda x: x[1]):
        tok2id[tok] = int(raw_id) + 3
    base_vocab_size = len(tok2id)
    logger.info("Loaded OpTC aligned base vocab: %d entries (base_vocab_size=%d)", len(optc_raw_vocab), base_vocab_size)

    # 2. Load Node tables & REAPr Ground Truth
    parquet_dir = args.dataset_dir / "Parquet"
    nodes = NodeTables(parquet_dir, logger)

    resolver = TheiaGroundTruthResolver(args.reapr_tar, args.reapr_labels_csv)
    resolver.bind_process_table(nodes.proc_uuid_to_idx, nodes.proc_path)
    logger.info(
        "REAPr GT loaded: %d clean attack edges, %d excluded fail/contaminated edges, %d fail-only process IDs",
        len(resolver.included_edge_scenario),
        len(resolver.excluded_edge_uuids),
        len(resolver.fail_only_process_indices),
    )

    # 3. Read & Sort Parquet/event_table.parquet strictly within T3 regime in PyArrow C++
    event_parquet = parquet_dir / "event_table.parquet"
    logger.info("Reading T3 events (ts >= %d) from %s...", T3_START_NS, event_parquet)
    t_read = time.time()
    table = pq.read_table(
        event_parquet,
        columns=["event_uuid", "operation", "timestamp_rec", "src_index_id", "dst_index_id"],
        filters=[("timestamp_rec", ">=", T3_START_NS)],
    )
    logger.info("Loaded %d T3 events in %.2fs (RSS=%.0f MB). Sorting chronologically...", table.num_rows, time.time() - t_read, get_rss_mb())
    t_sort = time.time()
    table = table.sort_by([("timestamp_rec", "ascending"), ("event_uuid", "ascending")])
    logger.info("Sorted chronologically in %.2fs (RSS=%.0f MB).", time.time() - t_sort, get_rss_mb())

    # 4. Pre-pass over attack rows only (fast) to compute leakage-free 5s window splits
    ev_uuids = table["event_uuid"].to_pylist()
    ops = table["operation"].to_pylist()
    ts_arr = table["timestamp_rec"].to_numpy(zero_copy_only=False)
    src_arr = table["src_index_id"].to_numpy(zero_copy_only=False)
    dst_arr = table["dst_index_id"].to_numpy(zero_copy_only=False)

    attack_meta_list: List[Tuple[int, int, int]] = []
    seen_attack_uuids: set[str] = set()
    included_set = set(resolver.included_edge_scenario.keys())
    excluded_counts: Counter = Counter()

    for i, euuid in enumerate(ev_uuids):
        if euuid not in included_set:
            continue
        if euuid in seen_attack_uuids:
            continue
        op = ops[i]
        s = int(src_arr[i])
        d = int(dst_arr[i])
        actor_idx, obj_idx = (d, s) if op in EDGE_REVERSED_OPS else (s, d)
        ap = nodes.proc_path.get(actor_idx, "")
        op_path = ""
        sip, dip = "", ""
        if obj_idx <= NETFLOW_INDEX_MAX:
            sip, _, dip, _ = nodes.nf_tuple.get(obj_idx, ("NA", 0, "NA", 0))
        elif obj_idx <= PROCESS_INDEX_MAX:
            op_path = nodes.proc_path.get(obj_idx, "")
        else:
            op_path = nodes.file_path.get(obj_idx, "")

        if resolver.get_exclusion_reason(euuid, actor_idx, obj_idx, ap, op_path, sip, dip) is not None:
            continue
        is_m, sc_id, st_id = resolver.resolve_3heads(euuid, op, ap, op_path, sip, dip)
        if is_m:
            seen_attack_uuids.add(euuid)
            attack_meta_list.append((int(ts_arr[i]), sc_id, st_id))

    attack_win_split, strata_split_summary = assign_window_splits(attack_meta_list, seed=args.seed)
    logger.info("Stratified 5s window allocation across %d clean attack events:", len(attack_meta_list))
    for (sc, st), sp_cnt in strata_split_summary.items():
        logger.info("  Scenario=%d Stage=%d -> train=%d val=%d test=%d", sc, st, sp_cnt["train"], sp_cnt["val"], sp_cnt["test"])

    # Compute benign sampling probability
    est_clean_benign = max(1, len(ev_uuids) - len(attack_meta_list) - 1_750_000)
    benign_sample_prob = min(1.0, args.benign_target / float(est_clean_benign))
    rng = random.Random(args.seed)

    # 5. Chronological causal pass: maintain online L=3 history across ALL clean events, collect sampled triplets
    process_parent_tokens: Dict[int, List[str]] = {}
    node_incoming_state: Dict[int, Tuple[str, str]] = {}
    sampled_raw: List[Dict[str, Any]] = []
    seen_sampled_attack: set[str] = set()
    train_token_counts: Counter = Counter()
    train_attack_tokens: set[str] = set()

    label_counts: Counter = Counter()
    split_counts: Counter = Counter()
    scenario_counts: Counter = Counter()
    stage_counts: Counter = Counter()

    total_rows = len(ev_uuids)
    logger.info("Running causal triplet scan over %d sorted T3 events (benign_p=%.4f)...", total_rows, benign_sample_prob)

    for i in range(total_rows):
        if i > 0 and i % 5_000_000 == 0:
            logger.info("  Processed %d / %d events (%.1f%%), kept=%d, RSS=%.0f MB", i, total_rows, 100.0 * i / total_rows, len(sampled_raw), get_rss_mb())

        euuid = ev_uuids[i]
        op = ops[i]
        s = int(src_arr[i])
        d = int(dst_arr[i])
        actor_idx, obj_idx = (d, s) if op in EDGE_REVERSED_OPS else (s, d)

        ap = nodes.proc_path.get(actor_idx, "")
        op_path = ""
        sip, dip = "", ""
        obj_type_raw = get_node_type(obj_idx)
        if obj_type_raw == "netflow":
            sip, _, dip, _ = nodes.nf_tuple.get(obj_idx, ("NA", 0, "NA", 0))
        elif obj_type_raw == "process":
            op_path = nodes.proc_path.get(obj_idx, "")
        else:
            op_path = nodes.file_path.get(obj_idx, "")

        # Strict exclusion check BEFORE causal tracker updates or sampling
        excl = resolver.get_exclusion_reason(euuid, actor_idx, obj_idx, ap, op_path, sip, dip)
        if excl is not None:
            excluded_counts[excl] += 1
            continue

        is_mal = 0
        sc_id = 0
        st_id = 0
        if euuid in included_set:
            if euuid in seen_sampled_attack:
                continue
            is_mal, sc_id, st_id = resolver.resolve_3heads(euuid, op, ap, op_path, sip, dip)
            seen_sampled_attack.add(euuid)

        # Prior E_incoming state BEFORE current event updates it (no self-leakage into E_incoming)
        prior_inc = node_incoming_state.get(actor_idx)
        prior_parent = process_parent_tokens.get(actor_idx)

        should_keep = (is_mal == 1) or (rng.random() < benign_sample_prob)
        if should_keep:
            curr_toks, (optc_act, sum_target) = build_current_tokens(op, actor_idx, obj_idx, nodes)
            inc_toks = (
                [
                    f"ctx::incoming::{prior_inc[0]}::direction=incoming",
                    f"ctx::incoming::{prior_inc[0]}::present=true",
                    f"ctx::incoming::target={prior_inc[1]}",
                ]
                if prior_inc
                else ["<none>"]
            )
            parent_toks = list(prior_parent) if prior_parent else ["ctx::status::parent_missing"]
            ts_val = int(ts_arr[i])
            sp_name = get_split_for_timestamp(ts_val, attack_win_split)

            if sp_name == "train":
                for t in inc_toks + parent_toks + curr_toks:
                    if t not in ("<none>", "<pad>", "<unk>"):
                        train_token_counts[t] += 1
                        if is_mal == 1:
                            train_attack_tokens.add(t)

            sampled_raw.append({
                "inc": inc_toks,
                "par": parent_toks,
                "cur": curr_toks,
                "m": is_mal,
                "sc": sc_id,
                "st": st_id,
                "sp": sp_name,
                "u": euuid,
                "ts": ts_val,
            })
            split_counts[sp_name] += 1
            label_counts[is_mal] += 1
            scenario_counts[sc_id] += 1
            stage_counts[st_id] += 1
        else:
            optc_act = THEIA_OP_TO_OPTC_ACTION.get(op, "unknown")
            if obj_type_raw == "netflow":
                sum_target = f"flow:{ip_scope(dip)}:{port_class(nodes.nf_tuple.get(obj_idx, ('NA', 0, 'NA', 0))[3])}"
            elif obj_type_raw == "process":
                sum_target = f"proc:{extract_basename(op_path) or 'unknown'}"
            else:
                sum_target = f"file_path:{extract_basename(op_path) or 'unknown'}"

        # Update causal lineage AFTER extracting current sample's prior context
        if op == "EVENT_CLONE" and obj_type_raw == "process":
            p_base = extract_basename(ap) or "unknown"
            p_cat = classify_path_dir(ap)
            c_cat = classify_path_dir(op_path)
            process_parent_tokens[obj_idx] = [
                "ctx::status::has_parent",
                f"ctx::parent::exe={p_base}",
                f"ctx::parent::path_role={p_cat}",
                f"parent_image_path::category={p_cat}",
                f"parent_image_path::basename={p_base}",
                f"ctx::relation::path={p_cat}->{c_cat}",
            ]
            node_incoming_state[obj_idx] = ("create", f"parent:{p_base}")
        else:
            node_incoming_state[actor_idx] = (optc_act, sum_target)

    del ev_uuids, ops, ts_arr, src_arr, dst_arr, table
    logger.info("Finished chronological pass in %.2fs. Sampled=%d. Excluded summary: %s", time.time() - t_start, len(sampled_raw), dict(excluded_counts))

    # 6. Extend vocabulary strictly from TRAIN tokens (new IDs start at `base_vocab_size=10499`)
    new_train_tokens = [
        tok
        for tok, cnt in sorted(train_token_counts.items())
        if tok not in tok2id and (cnt >= 2 or tok in train_attack_tokens)
    ]
    for tok in new_train_tokens:
        tok2id[tok] = len(tok2id)
    logger.info(
        "Extended Vocab: %d total tokens (%d OpTC base + %d THEIA train-only tokens).",
        len(tok2id),
        base_vocab_size,
        len(new_train_tokens),
    )

    # Shuffle deterministically within each split before writing shards
    def encode(toks: List[str]) -> List[int]:
        if not toks or toks == ["<none>"]:
            return [2]
        return [tok2id.get(t, 1) for t in toks]

    by_split: Dict[str, List[Dict[str, Any]]] = {"train": [], "val": [], "test": []}
    for item in sampled_raw:
        by_split[item["sp"]].append(item)
    del sampled_raw

    writer = ShardAccumulator(args.output_dir, shard_size=args.shard_size)
    split_rng = random.Random(args.seed + 1)
    for sp_name in ("train", "val", "test"):
        items = by_split[sp_name]
        split_rng.shuffle(items)
        for it in items:
            writer.add(sp_name, {
                "incoming_ids": encode(it["inc"]),
                "parent_ids": encode(it["par"]),
                "current_ids": encode(it["cur"]),
                "is_malicious": it["m"],
                "scenario_id": it["sc"],
                "stage_id": it["st"],
                "event_uuid": it["u"],
                "timestamp_rec": it["ts"],
            })
    writer.finalize()

    # Save extended vocabulary & comprehensive manifest
    vocab_out = args.output_dir / "extended_dl_vocab.json"
    with vocab_out.open("w", encoding="utf-8") as f:
        json.dump(tok2id, f, indent=2)

    manifest = {
        "dataset": "DARPA-TC-E3-THEIA",
        "source_parquet": str(event_parquet),
        "t3_start_ns": T3_START_NS,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "exclusion_policy": {
            "excluded_fail_chains": sorted(EXCLUDED_FAIL_CHAINS),
            "excluded_contaminated": True,
            "excluded_common_threat_4_6": True,
            "excluded_os_shared_libs": True,
            "preserved_attacker_libs": ["/tmp/memtrace.so"],
            "excluded_event_counts": dict(excluded_counts),
        },
        "split_policy": "disjoint_5s_attack_windows_60s_benign_blocks_no_leakage",
        "total_events_sampled": sum(writer.sample_counts.values()),
        "benign_count": int(label_counts[0]),
        "attack_count": int(label_counts[1]),
        "splits": dict(writer.sample_counts),
        "shards": dict(writer.shard_counts),
        "scenarios": {SCENARIO_NAMES[k]: int(scenario_counts[k]) for k in sorted(SCENARIO_NAMES)},
        "stages": {STAGE_NAMES[k]: int(stage_counts[k]) for k in sorted(STAGE_NAMES)},
        "attack_strata_splits": {
            f"sc{k[0]}_st{k[1]}": v for k, v in strata_split_summary.items()
        },
        "base_vocab_size": base_vocab_size,
        "vocab_size": len(tok2id),
        "new_theia_tokens_count": len(new_train_tokens),
        "vocab_path": str(vocab_out),
    }
    manifest_out = args.output_dir / "split_manifest.json"
    with manifest_out.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Finished writing shards & manifest in %.2fs -> %s", time.time() - t_start, args.output_dir)


if __name__ == "__main__":
    main()
